package com.example.zerodef.network

import android.util.Log
import com.example.zerodef.ZeroDefVpnService
import java.io.Closeable
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ArrayBlockingQueue

class NioManager(
    private val networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>,
    private val vpnService: ZeroDefVpnService
) : Runnable, Closeable {
    private val selector: Selector = Selector.open()
    private val buffer = ByteBuffer.allocate(32767)
    private val tcpTracker = TCPTracker(vpnService)
    private val udpTracker = UDPTracker(vpnService)
    private var lastCleanup = 0L

    companion object {
        const val TAG = "NioManager"
        const val IDLE_TIMEOUT_MS = 30000L // 30 seconds
    }

    fun processPacket(packet: Packet) {
        try {
            when (packet.ipHeader.protocol) {
                Protocol.TCP -> handleTcpPacket(packet)
                Protocol.UDP -> handleUdpPacket(packet)
                else -> {}
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet", e)
        }
    }

    private fun handleTcpPacket(packet: Packet) {
        val tcpHeader = packet.transportHeader as TCPHeader
        val connection = TCPConnection(packet.ipHeader.sourceAddress, tcpHeader.sourcePort, packet.ipHeader.destinationAddress, tcpHeader.destinationPort)
        val state = tcpTracker.getState(connection)

        state?.lastActivity = System.currentTimeMillis()

        if (tcpHeader.flags and TCP_FLAG_SYN != 0 && state == null) {
            val channel = tcpTracker.getOrCreateChannel(connection) ?: return
            val newState = tcpTracker.getState(connection)!!
            newState.clientSeq = tcpHeader.sequenceNumber
            newState.clientAck = tcpHeader.acknowledgmentNumber
            newState.serverSeq = 1
            newState.serverAck = tcpHeader.sequenceNumber + 1
            val key = channel.register(selector, SelectionKey.OP_CONNECT)
            key.attach(packet)
            return
        }

        if (state == null) return

        if (tcpHeader.flags and TCP_FLAG_FIN != 0) {
            state.clientSeq += 1
            val finAckPacket = buildTcpPacket(packet.ipHeader, tcpHeader, ByteBuffer.allocate(0), TCP_FLAG_FIN or TCP_FLAG_ACK, state.serverSeq, state.clientSeq)
            networkToDeviceQueue.offer(finAckPacket)
            cleanupConnection(connection, null)
            return
        }

        if (tcpHeader.flags and TCP_FLAG_RST != 0) {
            cleanupConnection(connection, null)
            return
        }

        val channel = tcpTracker.getOrCreateChannel(connection) ?: return
        if (!channel.isConnected) return

        if (tcpHeader.flags and TCP_FLAG_ACK != 0) {
            val payload = packet.payload
            if (payload.remaining() > 0) {
                try {
                    val bytesWritten = channel.write(payload)
                    state.serverAck += bytesWritten
                    val ackPacket = buildTcpPacket(packet.ipHeader, tcpHeader, ByteBuffer.allocate(0), TCP_FLAG_ACK, state.serverSeq, state.serverAck)
                    networkToDeviceQueue.offer(ackPacket)
                } catch (e: IOException) {
                    Log.e(TAG, "Failed to write to TCP channel", e)
                    cleanupConnection(connection, null)
                }
            }
        }
    }

    private fun handleUdpPacket(packet: Packet) {
        val udpHeader = packet.transportHeader as UDPHeader
        val connection = UDPConnection(packet.ipHeader.sourceAddress, udpHeader.sourcePort, packet.ipHeader.destinationAddress, udpHeader.destinationPort)
        val channel = udpTracker.getOrCreateChannel(connection) ?: return

        if (channel.keyFor(selector) == null) {
            val key = channel.register(selector, SelectionKey.OP_READ)
            key.attach(packet)
        }

        try {
            channel.write(packet.payload)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to write to UDP channel", e)
            udpTracker.closeConnection(connection)
        }
    }

    override fun run() {
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (selector.select(1000) == 0) {
                    cleanupIdleConnections()
                    continue
                }

                val keys = selector.selectedKeys()
                val iterator = keys.iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()

                    if (!key.isValid) continue

                    if (key.isConnectable) {
                        handleConnect(key)
                    } else if (key.isReadable) {
                        handleRead(key)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NioManager run loop CRITICAL error", e)
            }
        }
    }

    private fun handleConnect(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        val originalPacket = key.attachment() as Packet
        val originalTcpHeader = originalPacket.transportHeader as TCPHeader
        val connection = TCPConnection(originalPacket.ipHeader.sourceAddress, originalTcpHeader.sourcePort, originalPacket.ipHeader.destinationAddress, originalTcpHeader.destinationPort)
        val state = tcpTracker.getState(connection) ?: return

        try {
            if (channel.finishConnect()) {
                key.interestOps(SelectionKey.OP_READ)
                state.lastActivity = System.currentTimeMillis()
                val synAckPacket = buildTcpPacket(originalPacket.ipHeader, originalTcpHeader, ByteBuffer.allocate(0), TCP_FLAG_SYN or TCP_FLAG_ACK, state.serverSeq, state.serverAck)
                networkToDeviceQueue.offer(synAckPacket)
                state.serverSeq++
            }
        } catch (e: IOException) {
            Log.e(TAG, "Connection failed: $connection", e)
            cleanupConnection(connection, key)
        }
    }

    private fun handleRead(key: SelectionKey) {
        when (val channel = key.channel()) {
            is SocketChannel -> readTcp(key, channel)
            is DatagramChannel -> readUdp(key, channel)
        }
    }

    private fun readTcp(key: SelectionKey, channel: SocketChannel) {
        val originalPacket = key.attachment() as Packet
        val originalTcpHeader = originalPacket.transportHeader as TCPHeader
        val connection = TCPConnection(originalPacket.ipHeader.sourceAddress, originalTcpHeader.sourcePort, originalPacket.ipHeader.destinationAddress, originalTcpHeader.destinationPort)
        val state = tcpTracker.getState(connection)

        if (state == null) { cleanupConnection(connection, key); return }

        state.lastActivity = System.currentTimeMillis()

        try {
            buffer.clear()
            val bytesRead = channel.read(buffer)
            if (bytesRead == -1) {
                val finPacket = buildTcpPacket(originalPacket.ipHeader, originalTcpHeader, ByteBuffer.allocate(0), TCP_FLAG_FIN or TCP_FLAG_ACK, state.serverSeq, state.serverAck)
                networkToDeviceQueue.offer(finPacket)
                cleanupConnection(connection, key)
            } else if (bytesRead > 0) {
                buffer.flip()
                val responsePacket = buildTcpPacket(originalPacket.ipHeader, originalTcpHeader, buffer, TCP_FLAG_PSH or TCP_FLAG_ACK, state.serverSeq, state.serverAck)
                networkToDeviceQueue.offer(responsePacket)
                state.serverSeq += bytesRead
            }
        } catch (e: IOException) {
            Log.e(TAG, "TCP Read error: $connection", e)
            cleanupConnection(connection, key)
        }
    }

    private fun readUdp(key: SelectionKey, channel: DatagramChannel) {
        val originalPacket = key.attachment() as Packet
        try {
            buffer.clear()
            val bytesRead = channel.read(buffer)
            if (bytesRead > 0) {
                buffer.flip()
                val responsePacket = buildUdpPacket(originalPacket.ipHeader, originalPacket.transportHeader as UDPHeader, buffer)
                networkToDeviceQueue.offer(responsePacket)
            }
        } catch (e: IOException) {
            Log.e(TAG, "UDP Read error", e)
        }
    }

    private fun cleanupIdleConnections() {
        val now = System.currentTimeMillis()
        if (now - lastCleanup < 5000L) return // Cleanup every 5 seconds

        tcpTracker.cleanupIdleConnections(now, IDLE_TIMEOUT_MS)
        lastCleanup = now
    }

    private fun cleanupConnection(connection: TCPConnection, key: SelectionKey?) {
        key?.cancel()
        tcpTracker.closeConnection(connection)
    }

    override fun close() {
        try {
            selector.close()
            tcpTracker.closeAll()
            udpTracker.closeAll()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing NioManager resources", e)
        }
    }
}
