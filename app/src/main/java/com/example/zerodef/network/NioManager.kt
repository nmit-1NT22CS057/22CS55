package com.example.zerodef.network



import android.util.Log

import com.example.zerodef.ZeroDefVpnService

import java.io.Closeable

import java.io.IOException

import java.nio.ByteBuffer

import java.nio.channels.*

import java.util.*

import java.util.concurrent.ArrayBlockingQueue

import java.util.concurrent.ConcurrentLinkedQueue

import java.util.concurrent.atomic.AtomicBoolean

import java.util.concurrent.atomic.AtomicLong

import kotlin.math.min



// --- PHASE 2: Refactored to a type-safe enum ---

enum class ChangeType {

    CONNECT,

    READ

}

data class ChangeRequest(val channel: SelectableChannel, val type: ChangeType, val key: ConnectionKey)



class NioManager(

    private val networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>,

    vpnService: ZeroDefVpnService

) : Runnable, Closeable {

    private val selector: Selector = Selector.open()

    private val connectionTracker = ConnectionTracker(vpnService)

    private var lastCleanup = 0L

    private var lastStatsLog = 0L

    private val isRunning = AtomicBoolean(true)

    private val pendingChanges = ConcurrentLinkedQueue<ChangeRequest>()

    private val packetsProcessed = AtomicLong(0)

    private val bytesProcessed = AtomicLong(0)

    private val packetsDropped = AtomicLong(0)

    private var lastProcessCount = 0L



    companion object {

        const val TAG = "NioManager"

        const val IDLE_TIMEOUT_MS = 30000L

        const val KEEP_ALIVE_TIMEOUT_MS = 120000L

        const val SELECT_TIMEOUT_MS = 100L

        const val CLEANUP_INTERVAL_MS = 5000L

        const val STATS_INTERVAL_MS = 10000L

        const val RETRANSMISSION_CHECK_INTERVAL_MS = 100L

    }



    override fun run() {

        Log.i(TAG, "NioManager Production-ready version started")

        var lastRetransmissionCheck = 0L



        while (isRunning.get() && !Thread.currentThread().isInterrupted) {

            try {

                processPendingChanges()



                val now = System.currentTimeMillis()

                if (now - lastRetransmissionCheck >= RETRANSMISSION_CHECK_INTERVAL_MS) {

                    checkAndRetransmitPackets(now)

                    lastRetransmissionCheck = now

                }



                selector.select(SELECT_TIMEOUT_MS)



                val keys = selector.selectedKeys()

                if (keys.isEmpty()) {

                    cleanupIdleConnections()

                    logStatsIfNeeded()

                    continue

                }



                processSelectedKeys(keys)

                cleanupIdleConnections()

                logStatsIfNeeded()



            } catch (_: ClosedSelectorException) {

                break

            } catch (e: IOException) {

                if (isRunning.get()) Log.w(TAG, "Selector error: ${e.message}")

            } catch (e: Exception) {

                Log.e(TAG, "Critical error in NioManager run loop", e)

            }

        }

        Log.i(TAG, "NioManager stopped")

    }



    private fun processPendingChanges() {

        while (pendingChanges.isNotEmpty()) {

            val change = pendingChanges.poll() ?: continue

            try {

                when (change.type) {

                    ChangeType.CONNECT -> change.channel.register(selector, SelectionKey.OP_CONNECT, change.key)

                    ChangeType.READ -> {

                        val key = change.channel.keyFor(selector)

                        if (key == null || !key.isValid) {

                            change.channel.register(selector, SelectionKey.OP_READ, change.key)

                        } else {

                            key.interestOps(SelectionKey.OP_READ)

                        }

                    }

                }

            } catch (e: ClosedChannelException) {

                cleanupConnection(change.key, null)

            } catch (e: Exception) {

                Log.e(TAG, "Error processing change request for ${change.key}", e)

                cleanupConnection(change.key, null)

            }

        }

    }



    private fun processSelectedKeys(keys: MutableSet<SelectionKey>) {

        val iterator = keys.iterator()

        while (iterator.hasNext()) {

            val key = iterator.next()

            iterator.remove()

            if (!key.isValid) continue

            val connectionKey = key.attachment() as? ConnectionKey ?: continue

            try {

                when {

                    key.isConnectable -> handleConnect(key, connectionKey)

                    key.isReadable -> handleRead(key, connectionKey)

                }

            } catch (e: CancelledKeyException) {

                cleanupConnection(connectionKey, key)

            } catch (e: ClosedChannelException) {

                cleanupConnection(connectionKey, key)

            } catch (e: IOException) {

                Log.w(TAG, "IO error for $connectionKey: ${e.message}")

                cleanupConnection(connectionKey, key)

            } catch (e: Exception) {

                Log.e(TAG, "Unexpected error processing key for $connectionKey", e)

                cleanupConnection(connectionKey, key)

            }

        }

    }



    fun processPacket(packet: Packet) {

        packetsProcessed.incrementAndGet()

        bytesProcessed.addAndGet(packet.backingBuffer.remaining().toLong())

        try {

            when (packet.ipHeader.protocol) {

                Protocol.TCP -> handleTcpPacket(packet)

                Protocol.UDP -> handleUdpPacket(packet)

                else -> {}

            }

        } catch (e: Exception) {

            Log.e(TAG, "Error processing packet: ${e.message}", e)

        }

    }



    private fun handleTcpPacket(packet: Packet) {

        val tcpHeader = packet.transportHeader as? TCPHeader ?: return

        val key = ConnectionKey(Protocol.TCP, packet.ipHeader.sourceAddress, tcpHeader.sourcePort, packet.ipHeader.destinationAddress, tcpHeader.destinationPort)

        val connection = connectionTracker.getConnection(key)

        connection?.updateActivity()



        val clientState = connection?.clientState



        when {

            tcpHeader.isSYN -> handleSyn(packet, tcpHeader, key, connection)

            connection == null || clientState == null -> {

                if (!tcpHeader.isRST) sendRstPacket(key, 0, tcpHeader.sequenceNumber + 1)

            }

            tcpHeader.isRST -> cleanupConnection(key, null)

            tcpHeader.isFIN -> handleFin(tcpHeader, key, clientState)

            tcpHeader.isACK -> handleAck(packet, tcpHeader, key, connection, clientState)

        }

    }



    private fun handleSyn(packet: Packet, tcpHeader: TCPHeader, key: ConnectionKey, existingConnection: Connection?) {

        val clientState = existingConnection?.clientState

        if (clientState?.state == TCPConnectionState.SYN_RECEIVED) {

            val options = TcpOptions(mss = clientState.mss, windowScale = 7, sackPermitted = true)

            val (synAckPacket, retransmitPacket) = buildTcpPacket(key, TCP_FLAG_SYN or TCP_FLAG_ACK, clientState.serverSeq, clientState.clientSeq, ByteBuffer.allocate(0), options, connectionTracker.getBufferPool())

            queuePacketForDevice(key, clientState, synAckPacket, retransmitPacket?.copy(isSyn = true))

            return

        }



        val connection = existingConnection ?: connectionTracker.createAndTrackConnection(key) ?: return

        val newClientState = connection.clientState



        // --- PHASE 1: MSS CLAMPING LOGIC ---

        val clientMss = tcpHeader.options?.mss

        if (clientMss != null) {

            val clampedMss = min(clientMss, 1400)

            newClientState.mss = clampedMss

            Log.d(TAG, "Client MSS is $clientMss, clamped to ${newClientState.mss} for $key")

        }



        newClientState.clientSeq = tcpHeader.sequenceNumber + 1

        newClientState.serverSeq = Random().nextInt(Int.MAX_VALUE).toLong()

        newClientState.clientAck = tcpHeader.sequenceNumber // Ack the client's SYN

        newClientState.state = TCPConnectionState.SYN_SENT

        newClientState.clientWindowSize = tcpHeader.windowSize



        pendingChanges.add(ChangeRequest(connection.channel, ChangeType.CONNECT, key))

        selector.wakeup()

    }



    private fun handleFin(tcpHeader: TCPHeader, key: ConnectionKey, clientState: TCPState) {

        clientState.clientSeq = tcpHeader.sequenceNumber + 1

        clientState.isKeepAlivePacketSent = false



        when (clientState.state) {

            TCPConnectionState.ESTABLISHED -> {

                clientState.state = TCPConnectionState.CLOSE_WAIT

                val (ackPacket, _) = buildTcpPacket(key, TCP_FLAG_ACK, clientState.serverSeq, clientState.clientSeq, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

                queuePacketForDevice(key, clientState, ackPacket, null)

            }

            TCPConnectionState.FIN_WAIT_1 -> {

                clientState.state = TCPConnectionState.CLOSING

                val (ackPacket, _) = buildTcpPacket(key, TCP_FLAG_ACK, clientState.serverSeq, clientState.clientSeq, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

                queuePacketForDevice(key, clientState, ackPacket, null)

            }

            else -> cleanupConnection(key, null)

        }

    }



    private fun handleAck(packet: Packet, tcpHeader: TCPHeader, key: ConnectionKey, connection: Connection, clientState: TCPState) {

        // This ACK is from the client. It is acknowledging data WE sent TO THE CLIENT.

        clientState.onClientAckReceived(tcpHeader.acknowledgmentNumber)

        clientState.clientWindowSize = tcpHeader.windowSize

        clientState.isKeepAlivePacketSent = false



        when (clientState.state) {

            TCPConnectionState.SYN_RECEIVED -> {

                if (tcpHeader.acknowledgmentNumber == clientState.serverSeq + 1) { // They ACKed our SYN

                    clientState.state = TCPConnectionState.ESTABLISHED

                    Log.i(TAG, "Connection ESTABLISHED for $key")

                    pendingChanges.add(ChangeRequest(connection.channel, ChangeType.READ, key))

                    selector.wakeup()

                }

            }

            TCPConnectionState.LAST_ACK -> { if (tcpHeader.acknowledgmentNumber == clientState.serverSeq + 1) cleanupConnection(key, null) }

            TCPConnectionState.FIN_WAIT_1 -> { if (tcpHeader.acknowledgmentNumber == clientState.serverSeq + 1) clientState.state = TCPConnectionState.FIN_WAIT_2 }

            TCPConnectionState.CLOSING -> { if (tcpHeader.acknowledgmentNumber == clientState.serverSeq + 1) { clientState.state = TCPConnectionState.TIME_WAIT; cleanupConnection(key, null) } }

            else -> {}

        }



        val payload = packet.payload

        if (payload.hasRemaining()) {

            clientState.clientSeq = tcpHeader.sequenceNumber + payload.remaining()

            val payloadCopy = ByteBuffer.allocate(payload.remaining())

            payloadCopy.put(payload)

            payloadCopy.flip()

            synchronized(clientState.pendingDataToRemote) {

                clientState.pendingDataToRemote.add(payloadCopy)

            }

        }



        if (clientState.state == TCPConnectionState.ESTABLISHED) {

            trySendPendingData(key, connection, clientState)

        }

    }



    // --- FINAL FIX: This function sends data TO THE SERVER ---

    private fun trySendPendingData(key: ConnectionKey, connection: Connection, clientState: TCPState) {

        val channel = connection.channel as? SocketChannel ?: return

        synchronized(clientState.pendingDataToRemote) {

            while (clientState.pendingDataToRemote.isNotEmpty()) {

                val bufferToSend = clientState.pendingDataToRemote.peek()!!



                try {

                    val bytesWritten = channel.write(bufferToSend)



                    if (bytesWritten > 0) {

                        // Data was written to the kernel's socket buffer.

                        // The kernel is responsible for retransmission to the server.

                        // We just need to ACK the client that we received this data.



                        // We already advanced clientSeq in handleAck

                        val (ackPacket, _) = buildTcpPacket(key, TCP_FLAG_ACK, clientState.serverSeq, clientState.clientSeq, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

                        queuePacketForDevice(key, clientState, ackPacket, null)

                    }



                    if (!bufferToSend.hasRemaining()) {

                        clientState.pendingDataToRemote.poll()

                    }



                    if (bytesWritten == 0) {

                        break // Socket buffer is full

                    }



                } catch (e: IOException) {

                    Log.e(TAG, "Error writing to TCP socket for $key", e)

                    sendRstPacket(key, clientState.serverSeq, clientState.clientSeq)

                    cleanupConnection(key, null)

                    break

                }

            }

        }

    }



    private fun handleUdpPacket(packet: Packet) {

        val udpHeader = packet.transportHeader as? UDPHeader ?: return

        val key = ConnectionKey(Protocol.UDP, packet.ipHeader.sourceAddress, udpHeader.sourcePort, packet.ipHeader.destinationAddress, udpHeader.destinationPort)

        val connection = connectionTracker.getConnection(key) ?: connectionTracker.createAndTrackConnection(key) ?: return

        val channel = connection.channel as? DatagramChannel ?: return

        try {

            if (channel.keyFor(selector) == null) {

                pendingChanges.add(ChangeRequest(channel, ChangeType.READ, key))

                selector.wakeup()

            }

            channel.write(packet.payload)

        } catch (e: IOException) {

            Log.e(TAG, "Error writing to UDP socket for $key", e)

            connectionTracker.closeConnection(key)

        }

    }



    private fun handleConnect(key: SelectionKey, connectionKey: ConnectionKey) {

        val connection = connectionTracker.getConnection(connectionKey) ?: return

        val channel = connection.channel as? SocketChannel ?: return

        val clientState = connection.clientState

        try {

            if (channel.finishConnect()) {

                key.interestOps(SelectionKey.OP_READ)

                clientState.state = TCPConnectionState.SYN_RECEIVED



                // --- Send SYN-ACK to client ---

                val options = TcpOptions(mss = clientState.mss, windowScale = 7, sackPermitted = true)

                val (synAckPacket, clientSynAckPacket) = buildTcpPacket(connectionKey, TCP_FLAG_SYN or TCP_FLAG_ACK, clientState.serverSeq, clientState.clientSeq, ByteBuffer.allocate(0), options, connectionTracker.getBufferPool())

                queuePacketForDevice(connectionKey, clientState, synAckPacket, clientSynAckPacket?.copy(isSyn = true))

            }

        } catch (e: IOException) {

            Log.e(TAG, "Failed to connect for $connectionKey", e)

            sendRstPacket(connectionKey, 0, clientState.clientSeq)

            cleanupConnection(connectionKey, key)

        }

    }



    private fun handleRead(key: SelectionKey, connectionKey: ConnectionKey) {

        val connection = connectionTracker.getConnection(connectionKey) ?: return

        connection.updateActivity()

        connection.clientState.isKeepAlivePacketSent = false

        when (val channel = connection.channel) {

            is SocketChannel -> readTcp(key, channel, connectionKey, connection.clientState)

            is DatagramChannel -> readUdp(channel, connectionKey)

            else -> {}

        }

    }



    private fun readTcp(key: SelectionKey, channel: SocketChannel, connectionKey: ConnectionKey, clientState: TCPState) {

        val buffer = connectionTracker.getBufferPool().borrowBuffer()

        buffer.limit(clientState.mss)

        try {

            val bytesRead = channel.read(buffer)

            if (bytesRead > 0) {

                buffer.flip()

                // This data is from the server. We must packetize it and send it to the client.



                val payloadCopy = ByteBuffer.allocate(buffer.remaining())

                payloadCopy.put(buffer)

                payloadCopy.flip()



                // Add to client's "to-be-sent" queue

                synchronized(clientState.receivedDataBuffer) {

                    clientState.receivedDataBuffer[clientState.serverSeq] = payloadCopy

                }

                processReassemblyBuffer(connectionKey, clientState)

            } else if (bytesRead == -1) {

                // Server closed the connection

                key.interestOps(0)

                clientState.state = TCPConnectionState.CLOSE_WAIT

                val (finPacket, retransmitPacket) = buildTcpPacket(connectionKey, TCP_FLAG_FIN or TCP_FLAG_ACK, clientState.serverSeq, clientState.clientSeq, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

                queuePacketForDevice(connectionKey, clientState, finPacket, retransmitPacket?.copy(isFin = true))

            }

        } finally {

            buffer.limit(buffer.capacity())

            connectionTracker.getBufferPool().returnBuffer(buffer)

        }

    }



    private fun processReassemblyBuffer(key: ConnectionKey, state: TCPState) {

        synchronized(state.receivedDataBuffer) {

            val iterator = state.receivedDataBuffer.entries.iterator()

            while (iterator.hasNext()) {

                val entry = iterator.next()

                val seq = entry.key

                val data = entry.value

                if (seq == state.serverSeq) {

                    // This is the next packet we expected to send to the client

                    val (dataPacket, retransmitPacket) = buildTcpPacket(key, TCP_FLAG_PSH or TCP_FLAG_ACK, seq, state.clientSeq, data, null, connectionTracker.getBufferPool())

                    queuePacketForDevice(key, state, dataPacket, retransmitPacket)

                    state.serverSeq += data.capacity() // This is the sequence number for data *to* the client

                    iterator.remove()

                } else if (seq < state.serverSeq) {

                    iterator.remove()

                } else {

                    Log.d(TAG, "Out-of-order packet for $key. Expected: ${state.serverSeq}, got: $seq. Buffering.")

                    break

                }

            }

            // Send an ACK for the highest contiguous byte received

            val (ackPacket, _) = buildTcpPacket(key, TCP_FLAG_ACK, state.serverSeq, state.clientSeq, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

            queuePacketForDevice(key, state, ackPacket, null)

        }

    }



    private fun readUdp(channel: DatagramChannel, connectionKey: ConnectionKey) {

        val buffer = connectionTracker.getBufferPool().borrowBuffer()

        try {

            val bytesRead = channel.read(buffer)

            if (bytesRead > 0) {

                buffer.flip()

                val responsePacket = buildUdpPacket(connectionKey, buffer, connectionTracker.getBufferPool())

                queuePacketForDevice(connectionKey, null, responsePacket, null)

            }

        } finally {

            connectionTracker.getBufferPool().returnBuffer(buffer)

        }

    }



    private fun sendRstPacket(key: ConnectionKey, seq: Long, ack: Long) {

        val (rstPacket, _) = buildTcpPacket(key, TCP_FLAG_RST or TCP_FLAG_ACK, seq, ack, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

        queuePacketForDevice(key, null, rstPacket, null)

    }



    private fun queuePacketForDevice(key: ConnectionKey, state: TCPState?, packetBuffer: ByteBuffer, retransmitPacket: RetransmitPacket?) {

        // This function sends data TO THE CLIENT (device)

        val bufferToQueue = if (packetBuffer.isDirect) {

            val copy = ByteBuffer.allocate(packetBuffer.remaining())

            copy.put(packetBuffer)

            copy.flip()

            connectionTracker.getBufferPool().returnBuffer(packetBuffer)

            copy

        } else {

            packetBuffer

        }



        if (retransmitPacket != null) {

            state?.onPacketSentToClient(retransmitPacket)

        }



        if (!networkToDeviceQueue.offer(bufferToQueue)) {

            packetsDropped.incrementAndGet()

            Log.w(TAG, "Device queue full, dropping packet for $key")

        }

    }



    fun returnBufferToPool(buffer: ByteBuffer) {

        connectionTracker.getBufferPool().returnBuffer(buffer)

    }



    // --- FINAL FIX: This function ONLY retransmits TO THE CLIENT ---

    private fun checkAndRetransmitPackets(now: Long) {

        connectionTracker.getAllTcpConnections().forEach { (key, connection) ->

            val clientState = connection.clientState



            // Check retransmissions TO THE CLIENT (Downloads)

            if (clientState.duplicateAckCount >= 3) {

                clientState.getPacketsForClientRetransmission(now, isFastRetransmit = true).firstOrNull()?.let { retransmitPacket ->

                    Log.w(TAG, "CLIENT Fast Retransmitting packet for $key, seq: ${retransmitPacket.sequenceNumber}")

                    clientState.duplicateAckCount = 0

                    retransmitPacket.buffer.rewind()

                    val (packetToResend, newRetransmitPacket) = buildTcpPacket(key, TCP_FLAG_PSH or TCP_FLAG_ACK, retransmitPacket.sequenceNumber, clientState.clientSeq, retransmitPacket.buffer, null, connectionTracker.getBufferPool())

                    retransmitPacket.sentTime = now

                    // We must re-queue the packet with its updated info

                    queuePacketForDevice(key, clientState, packetToResend, retransmitPacket)

                }

            }

            clientState.getPacketsForClientRetransmission(now, isFastRetransmit = false).forEach { retransmitPacket ->

                if (retransmitPacket.retransmitCount > 5) {

                    Log.w(TAG, "Max client retransmissions for $key. Closing.")

                    cleanupConnection(key, connection.channel.keyFor(selector))

                    return@forEach

                }

                Log.w(TAG, "CLIENT Timeout Retransmitting packet for $key, seq: ${retransmitPacket.sequenceNumber}, count: ${retransmitPacket.retransmitCount + 1}")

                clientState.onPacketLoss(isFastRecovery = false)

                retransmitPacket.retransmitCount++

                retransmitPacket.sentTime = now

                retransmitPacket.buffer.rewind()

                val (packetToResend, newRetransmitPacket) = buildTcpPacket(key, TCP_FLAG_PSH or TCP_FLAG_ACK, retransmitPacket.sequenceNumber, clientState.clientSeq, retransmitPacket.buffer, null, connectionTracker.getBufferPool())

                // We must re-queue the packet with its updated info

                queuePacketForDevice(key, clientState, packetToResend, retransmitPacket)

            }

        }

    }



    private fun cleanupIdleConnections() {

        val now = System.currentTimeMillis()

        if (now - lastCleanup < CLEANUP_INTERVAL_MS) return

        connectionTracker.getAllTcpConnections().forEach { (key, connection) ->

            val state = connection.clientState // Use client state for keep-alive tracking

            if (state.state != TCPConnectionState.ESTABLISHED) return@forEach

            val idleDuration = now - state.lastActivity

            if (idleDuration > KEEP_ALIVE_TIMEOUT_MS) {

                Log.i(TAG, "Closing connection due to keep-alive timeout: $key")

                cleanupConnection(key, null)

            } else if (idleDuration > IDLE_TIMEOUT_MS && !state.isKeepAlivePacketSent) {

                Log.d(TAG, "Sending keep-alive for idle connection: $key")

                val (keepAlivePacket, _) = buildTcpPacket(key, TCP_FLAG_ACK, state.serverSeq, state.clientSeq, ByteBuffer.allocate(0), null, connectionTracker.getBufferPool())

                queuePacketForDevice(key, state, keepAlivePacket, null)

                state.isKeepAlivePacketSent = true

            }

        }

        lastCleanup = now

    }



    private fun logStatsIfNeeded() {

        val now = System.currentTimeMillis()

        if (now - lastStatsLog < STATS_INTERVAL_MS) return

        val currentPackets = packetsProcessed.get()

        val packetRate = if (STATS_INTERVAL_MS > 0) (currentPackets - lastProcessCount) * 1000 / STATS_INTERVAL_MS else 0

        lastProcessCount = currentPackets

        lastStatsLog = now

        Log.i(TAG, "Stats: ${packetRate}pps, ${connectionTracker.getStats()}")

    }



    private fun cleanupConnection(connectionKey: ConnectionKey?, key: SelectionKey?) {

        key?.cancel()

        connectionKey?.let { connectionTracker.closeConnection(it) }

    }



    fun getStats(): String {

        val packets = packetsProcessed.get()

        val mbProcessed = bytesProcessed.get() / (1024 * 1024)

        return "Packets: $packets, MB: $mbProcessed, Dropped: ${packetsDropped.get()}, ${connectionTracker.getStats()}"

    }



    override fun close() {

        isRunning.set(false)

        selector.wakeup()

        try {

            selector.close()

        } catch (e: IOException) {

            Log.w(TAG, "Error closing selector", e)

        }

        connectionTracker.closeAll()

    }

}