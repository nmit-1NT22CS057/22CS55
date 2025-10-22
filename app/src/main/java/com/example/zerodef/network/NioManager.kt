package com.example.zerodef.network

import android.util.Log
import com.example.zerodef.ZeroDefVpnService
import java.io.Closeable
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.*
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

class NioManager(
    private val networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>,
    private val vpnService: ZeroDefVpnService
) : Runnable, Closeable {
    private val selector: Selector = Selector.open()
    private val connectionTracker = ConnectionTracker(vpnService)
    private var lastCleanup = 0L
    private var lastStatsLog = 0L
    private val isRunning = AtomicBoolean(true)
    private val selectorLock = ReentrantLock()

    private var packetsProcessed = 0L
    private var bytesProcessed = 0L
    private var lastProcessCount = 0L

    companion object {
        const val TAG = "NioManager"
        const val IDLE_TIMEOUT_MS = 15000L
        const val SELECT_TIMEOUT_MS = 50L
        const val CLEANUP_INTERVAL_MS = 2000L
        const val STATS_INTERVAL_MS = 10000L
    }

    override fun run() {
        Log.i(TAG, "NioManager performance-optimized version started")

        while (isRunning.get() && !Thread.currentThread().isInterrupted) {
            try {
                val startTime = System.nanoTime()

                selectorLock.lock()
                try {
                    val selected = selector.select(SELECT_TIMEOUT_MS)
                    if (selected > 0) {
                        processSelectedKeys()
                    }
                } finally {
                    selectorLock.unlock()
                }

                cleanupIdleConnections()
                logStatsIfNeeded()

                val processingTime = System.nanoTime() - startTime
                if (processingTime > 100000000L) {
                    Log.w(TAG, "Slow processing detected: ${processingTime / 1000000}ms")
                }

            } catch (e: ClosedSelectorException) {
                break
            } catch (e: IOException) {
                if (isRunning.get()) {
                    Log.w(TAG, "Selector error: ${e.message}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Unexpected error in run loop", e)
            }
        }

        Log.i(TAG, "NioManager stopped")
    }

    private fun processSelectedKeys() {
        val keys = selector.selectedKeys()
        val iterator = keys.iterator()

        while (iterator.hasNext()) {
            val key = iterator.next()
            iterator.remove()

            if (!key.isValid) continue

            try {
                when {
                    key.isConnectable -> handleConnect(key)
                    key.isReadable -> handleRead(key)
                }
            } catch (e: CancelledKeyException) {
                // Ignore - key was cancelled
            } catch (e: ClosedChannelException) {
                cleanupConnection(key.attachment() as? Connection, key)
            } catch (e: IOException) {
                val connection = key.attachment() as? Connection
                Log.d(TAG, "IO error for $connection: ${e.message}")
                cleanupConnection(connection, key)
            }
        }
    }

    fun processPacket(packet: Packet) {
        packetsProcessed++
        bytesProcessed += packet.backingBuffer.remaining()

        try {
            when (packet.ipHeader.protocol) {
                Protocol.TCP -> handleTcpPacket(packet)
                Protocol.UDP -> handleUdpPacket(packet)
                else -> {
                    // Silently ignore unsupported protocols
                }
            }
        } catch (e: Exception) {
            if (packetsProcessed % 1000 == 0L) {
                Log.w(TAG, "Error processing packet after $packetsProcessed packets: ${e.message}")
            }
        }
    }

    private fun handleTcpPacket(packet: Packet) {
        val tcpHeader = packet.transportHeader as TCPHeader
        val connection = Connection(
            Protocol.TCP,
            packet.ipHeader.sourceAddress,
            tcpHeader.sourcePort,
            packet.ipHeader.destinationAddress,
            tcpHeader.destinationPort
        )

        val state = connectionTracker.getState(connection)
        state?.lastActivity = System.currentTimeMillis()

        when {
            tcpHeader.isSYN -> handleSyn(tcpHeader, connection, state)
            state == null -> {
                if (!tcpHeader.isRST) {
                    val rstPacket = buildTcpPacket(connection, TCP_FLAG_RST, 0, 0, ByteBuffer.allocate(0))
                    queuePacketForDevice(rstPacket)
                }
            }
            tcpHeader.isRST -> {
                cleanupConnection(connection, null)
            }
            tcpHeader.isFIN -> handleFin(tcpHeader, connection, state)
            tcpHeader.isACK -> handleAck(packet, tcpHeader, connection, state)
        }
    }

    private fun handleFin(tcpHeader: TCPHeader, connection: Connection, state: TCPState) {
        state.clientSeq = tcpHeader.sequenceNumber + 1

        when (state.state) {
            TCPConnectionState.ESTABLISHED -> {
                state.state = TCPConnectionState.CLOSE_WAIT
                val ackPacket = buildTcpPacket(connection, TCP_FLAG_ACK,
                    state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
                queuePacketForDevice(ackPacket)

                val finPacket = buildTcpPacket(connection, TCP_FLAG_FIN or TCP_FLAG_ACK,
                    state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
                queuePacketForDevice(finPacket)
                state.serverSeq++
                state.state = TCPConnectionState.LAST_ACK
            }
            TCPConnectionState.CLOSE_WAIT -> {
                state.state = TCPConnectionState.LAST_ACK
            }
            else -> {
                val rstPacket = buildTcpPacket(connection, TCP_FLAG_RST, 0, state.clientSeq, ByteBuffer.allocate(0))
                queuePacketForDevice(rstPacket)
                cleanupConnection(connection, null)
            }
        }
    }

    private fun handleUdpPacket(packet: Packet) {
        val udpHeader = packet.transportHeader as UDPHeader
        val connection = Connection(
            Protocol.UDP,
            packet.ipHeader.sourceAddress,
            udpHeader.sourcePort,
            packet.ipHeader.destinationAddress,
            udpHeader.destinationPort
        )

        val channel = connectionTracker.getOrCreateChannel(connection) as? DatagramChannel ?: return

        try {
            if (channel.keyFor(selector) == null) {
                selectorLock.lock()
                try {
                    if (channel.isOpen) {
                        val key = channel.register(selector, SelectionKey.OP_READ)
                        key.attach(connection)
                    }
                } finally {
                    selectorLock.unlock()
                }
            }

            channel.write(packet.payload)
        } catch (e: IOException) {
            connectionTracker.closeConnection(connection)
        }
    }

    private fun handleSyn(tcpHeader: TCPHeader, connection: Connection, state: TCPState?) {
        if (state != null && state.state == TCPConnectionState.SYN_RECEIVED) {
            val synAckPacket = buildTcpPacket(connection, TCP_FLAG_SYN or TCP_FLAG_ACK,
                state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
            queuePacketForDevice(synAckPacket)
            return
        }

        val channel = connectionTracker.getOrCreateChannel(connection) as? SocketChannel ?: return
        val newState = connectionTracker.getState(connection) ?: return

        newState.clientSeq = tcpHeader.sequenceNumber + 1
        newState.serverSeq = Random().nextInt(0x7FFFFFFF).toLong()
        newState.state = TCPConnectionState.SYN_SENT

        selectorLock.lock()
        try {
            if (channel.isOpen) {
                val key = channel.register(selector, SelectionKey.OP_CONNECT)
                key.attach(connection)
            }
        } finally {
            selectorLock.unlock()
        }
    }

    private fun handleAck(packet: Packet, tcpHeader: TCPHeader, connection: Connection, state: TCPState) {
        if (state.state == TCPConnectionState.SYN_RECEIVED) {
            if (tcpHeader.acknowledgmentNumber == state.serverSeq) {
                state.state = TCPConnectionState.ESTABLISHED
                state.clientAck = tcpHeader.acknowledgmentNumber

                val channel = connectionTracker.getOrCreateChannel(connection) as? SocketChannel ?: return
                selectorLock.lock()
                try {
                    val key = channel.keyFor(selector)
                    if (key != null && key.isValid) {
                        key.interestOps(SelectionKey.OP_READ)
                    }
                } finally {
                    selectorLock.unlock()
                }
            }
            return
        }

        if (state.state == TCPConnectionState.LAST_ACK && tcpHeader.acknowledgmentNumber == state.serverSeq) {
            cleanupConnection(connection, null)
            return
        }

        if (state.state != TCPConnectionState.ESTABLISHED) return

        val payload = packet.payload
        if (!payload.hasRemaining()) return

        val channel = connectionTracker.getOrCreateChannel(connection) as? SocketChannel ?: return

        try {
            val bytesWritten = channel.write(payload)
            if (bytesWritten > 0) {
                state.clientSeq += bytesWritten

                val ackPacket = buildTcpPacket(connection, TCP_FLAG_ACK,
                    state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
                queuePacketForDevice(ackPacket)
            }
        } catch (e: IOException) {
            val rstPacket = buildTcpPacket(connection, TCP_FLAG_RST or TCP_FLAG_ACK,
                0, state.clientSeq, ByteBuffer.allocate(0))
            queuePacketForDevice(rstPacket)
            cleanupConnection(connection, null)
        }
    }

    private fun handleConnect(key: SelectionKey) {
        val connection = key.attachment() as? Connection ?: return
        val channel = key.channel() as? SocketChannel ?: return
        val state = connectionTracker.getState(connection) ?: return

        try {
            if (channel.finishConnect()) {
                selectorLock.lock()
                try {
                    if (key.isValid) {
                        key.interestOps(SelectionKey.OP_READ)
                    }
                } finally {
                    selectorLock.unlock()
                }

                state.state = TCPConnectionState.SYN_RECEIVED
                val synAckPacket = buildTcpPacket(connection, TCP_FLAG_SYN or TCP_FLAG_ACK,
                    state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
                queuePacketForDevice(synAckPacket)
                state.serverSeq++
            }
        } catch (e: IOException) {
            val rstPacket = buildTcpPacket(connection, TCP_FLAG_RST or TCP_FLAG_ACK,
                0, state.clientSeq, ByteBuffer.allocate(0))
            queuePacketForDevice(rstPacket)
            cleanupConnection(connection, key)
        }
    }

    private fun handleRead(key: SelectionKey) {
        val connection = key.attachment() as? Connection ?: return

        try {
            when (val channel = key.channel()) {
                is SocketChannel -> readTcp(key, channel, connection)
                is DatagramChannel -> readUdp(channel, connection)
            }
        } catch (e: Exception) {
            // Minimal error handling for performance
        }
    }

    private fun readTcp(key: SelectionKey, channel: SocketChannel, connection: Connection) {
        val state = connectionTracker.getState(connection) ?: run {
            cleanupConnection(connection, key)
            return
        }

        if (!channel.isOpen || !channel.isConnected) {
            cleanupConnection(connection, key)
            return
        }

        state.lastActivity = System.currentTimeMillis()

        val buffer = connectionTracker.getBuffer()
        try {
            buffer.clear()
            val bytesRead = channel.read(buffer)

            when {
                bytesRead == -1 -> {
                    if (key.isValid) key.interestOps(0)
                    state.state = TCPConnectionState.CLOSE_WAIT
                    val finPacket = buildTcpPacket(connection, TCP_FLAG_FIN or TCP_FLAG_ACK,
                        state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
                    queuePacketForDevice(finPacket)
                    state.serverSeq++
                }
                bytesRead > 0 -> {
                    buffer.flip()
                    val responsePacket = buildTcpPacket(connection, TCP_FLAG_PSH or TCP_FLAG_ACK,
                        state.serverSeq, state.clientSeq, buffer)
                    queuePacketForDevice(responsePacket)
                    state.serverSeq += bytesRead
                }
            }
        } catch (e: ClosedChannelException) {
            cleanupConnection(connection, key)
        } catch (e: IOException) {
            val rstPacket = buildTcpPacket(connection, TCP_FLAG_RST or TCP_FLAG_ACK,
                state.serverSeq, state.clientSeq, ByteBuffer.allocate(0))
            queuePacketForDevice(rstPacket)
            cleanupConnection(connection, key)
        } finally {
            connectionTracker.returnBuffer(buffer)
        }
    }

    private fun readUdp(channel: DatagramChannel, connection: Connection) {
        if (!channel.isOpen) {
            connectionTracker.closeConnection(connection)
            return
        }

        val buffer = connectionTracker.getBuffer()
        try {
            buffer.clear()
            val bytesRead = channel.read(buffer)
            if (bytesRead > 0) {
                buffer.flip()
                val responsePacket = buildUdpPacket(connection, buffer)
                queuePacketForDevice(responsePacket)
            }
        } catch (e: IOException) {
            connectionTracker.closeConnection(connection)
        } finally {
            connectionTracker.returnBuffer(buffer)
        }
    }

    private fun queuePacketForDevice(packet: ByteBuffer) {
        // Create a copy of the packet data to avoid buffer management issues
        val packetCopy = ByteBuffer.allocate(packet.remaining())
        packetCopy.put(packet)
        packetCopy.flip()

        if (!networkToDeviceQueue.offer(packetCopy)) {
            Log.w(TAG, "Device queue full, dropping packet")
        }

        // Always return the original buffer to the pool
        connectionTracker.returnBuffer(packet)
    }

    private fun cleanupIdleConnections() {
        val now = System.currentTimeMillis()
        if (now - lastCleanup < CLEANUP_INTERVAL_MS) return

        connectionTracker.cleanupIdleConnections(now, IDLE_TIMEOUT_MS)
        lastCleanup = now
    }

    private fun logStatsIfNeeded() {
        val now = System.currentTimeMillis()
        if (now - lastStatsLog < STATS_INTERVAL_MS) return

        val currentPackets = packetsProcessed
        val packetRate = (currentPackets - lastProcessCount) * 1000 / STATS_INTERVAL_MS
        lastProcessCount = currentPackets
        lastStatsLog = now

        Log.i(TAG, "Stats: ${packetRate}pps, ${connectionTracker.getStats()}")
    }

    private fun cleanupConnection(connection: Connection?, key: SelectionKey?) {
        try {
            key?.cancel()
            connection?.let { connectionTracker.closeConnection(it) }
        } catch (e: Exception) {
            // Ignore cleanup errors
        }
    }

    override fun close() {
        isRunning.set(false)
        selectorLock.lock()
        try {
            selector.wakeup()
        } finally {
            selectorLock.unlock()
        }
        connectionTracker.closeAll()

        try {
            selector.close()
        } catch (e: Exception) {
            // Ignore close errors
        }
    }
}