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

    companion object {
        const val TAG = "NioManager"
    }

    fun processPacket(packet: Packet) {
        when (packet.ipHeader.protocol) {
            Protocol.TCP -> handleTcpPacket(packet)
            Protocol.UDP -> handleUdpPacket(packet)
            else -> {}
        }
    }

    private fun handleTcpPacket(packet: Packet) {
        val tcpHeader = packet.transportHeader as TCPHeader
        val connection = TCPConnection(packet.ipHeader.sourceAddress, tcpHeader.sourcePort, packet.ipHeader.destinationAddress, tcpHeader.destinationPort)

        val state = tcpTracker.getState(connection)

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
            val finAckPacket = buildTcpPacket(
                packet.ipHeader,
                tcpHeader,
                ByteBuffer.allocate(0),
                TCP_FLAG_FIN or TCP_FLAG_ACK,
                tcpHeader.sequenceNumber + 1,
                tcpHeader.acknowledgmentNumber
            )
            networkToDeviceQueue.offer(finAckPacket)
            tcpTracker.closeConnection(connection)
            return
        }

        if (tcpHeader.flags and TCP_FLAG_RST != 0) {
            tcpTracker.closeConnection(connection)
            return
        }

        val channel = tcpTracker.getOrCreateChannel(connection) ?: return
        if (!channel.isConnected) return

        if (tcpHeader.flags and TCP_FLAG_ACK != 0) {
            val payload = packet.payload
            if (payload.remaining() > 0) {
                try {
                    val bytesWritten = channel.write(payload)
                    val ackForDevice = tcpHeader.sequenceNumber + bytesWritten
                    state.clientSeq += bytesWritten

                    val ackPacket = buildTcpPacket(
                        packet.ipHeader,
                        tcpHeader,
                        ByteBuffer.allocate(0),
                        TCP_FLAG_ACK,
                        ackForDevice,      // Use the correctly calculated ACK number
                        state.serverSeq    // The server's sequence number is correct here
                    )
                    networkToDeviceQueue.offer(ackPacket)
                } catch (e: IOException) {
                    Log.e(TAG, "Failed to write to TCP channel", e)
                    tcpTracker.closeConnection(connection)
                }
            }
        }
    }

    private fun handleUdpPacket(packet: Packet) {
        val udpHeader = packet.transportHeader as UDPHeader
        val connection = UDPConnection(packet.ipHeader.sourceAddress, udpHeader.sourcePort, packet.ipHeader.destinationAddress, udpHeader.destinationPort)
        val channel = udpTracker.getOrCreateChannel(connection) ?: return

        val key = channel.register(selector, SelectionKey.OP_READ)
        key.attach(packet)

        val payload = packet.payload
        try {
            channel.write(payload)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to write to UDP channel", e)
            udpTracker.closeConnection(connection)
        }
    }

    override fun run() {
        while (!Thread.currentThread().isInterrupted) {
            try {
                val readyChannels = selector.select()
                if (readyChannels == 0) {
                    Thread.sleep(10)
                    continue
                }

                val keys = selector.selectedKeys()
                val iterator = keys.iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()

                    if (!key.isValid) continue

                    when {
                        key.isConnectable -> handleConnect(key)
                        key.isReadable -> handleRead(key)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NioManager error", e)
            }
        }
    }

    private fun handleConnect(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        val packet = key.attachment() as Packet
        val tcpHeader = packet.transportHeader as TCPHeader
        val connection = TCPConnection(packet.ipHeader.sourceAddress, tcpHeader.sourcePort, packet.ipHeader.destinationAddress, tcpHeader.destinationPort)
        val state = tcpTracker.getState(connection)!!

        try {
            if (channel.finishConnect()) {
                key.interestOps(SelectionKey.OP_READ)

                val synAckPacket = buildTcpPacket(
                    packet.ipHeader,
                    tcpHeader,
                    ByteBuffer.allocate(0),
                    TCP_FLAG_SYN or TCP_FLAG_ACK,
                    state.serverAck,
                    state.serverSeq
                )
                networkToDeviceQueue.offer(synAckPacket)
                state.serverSeq++
            }
        } catch (e: IOException) {
            Log.e(TAG, "Connection failed", e)
            key.cancel()
        }
    }

    private fun handleRead(key: SelectionKey) {
        when (key.channel()) {
            is SocketChannel -> readTcp(key)
            is DatagramChannel -> readUdp(key)
        }
    }

    private fun readTcp(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        val originalPacketFromDevice = key.attachment() as Packet
        val originalTcpHeader = originalPacketFromDevice.transportHeader as TCPHeader

        val connection = TCPConnection(
            originalPacketFromDevice.ipHeader.sourceAddress,
            originalTcpHeader.sourcePort,
            originalPacketFromDevice.ipHeader.destinationAddress,
            originalTcpHeader.destinationPort
        )
        val state = tcpTracker.getState(connection)

        if (state == null) {
            key.cancel()
            channel.close()
            return
        }

        try {
            buffer.clear()
            val bytesRead = channel.read(buffer)
            if (bytesRead == -1) {
                key.cancel()
                channel.close()

                val finPacket = buildTcpPacket(
                    originalPacketFromDevice.ipHeader,
                    originalTcpHeader,
                    ByteBuffer.allocate(0),
                    TCP_FLAG_FIN or TCP_FLAG_ACK,
                    state.serverAck, 
                    state.serverSeq 
                )
                networkToDeviceQueue.offer(finPacket)
                tcpTracker.closeConnection(connection)
            } else if (bytesRead > 0) {
                buffer.flip()

                val responseSeqNumber = state.serverSeq
                val responseAckNumber = state.serverAck

                val responsePacket = buildTcpPacket(
                    originalPacketFromDevice.ipHeader,
                    originalTcpHeader,
                    buffer, 
                    TCP_FLAG_PSH or TCP_FLAG_ACK,
                    responseAckNumber,
                    responseSeqNumber
                )
                networkToDeviceQueue.offer(responsePacket)
                
                state.serverSeq += bytesRead
            }
        } catch (e: IOException) {
            Log.e(TAG, "TCP Read error", e)
            key.cancel()
            channel.close()
            tcpTracker.closeConnection(connection)
        }
    }

    private fun readUdp(key: SelectionKey) {
        val channel = key.channel() as DatagramChannel
        val packet = key.attachment() as Packet

        try {
            buffer.clear()
            val bytesRead = channel.read(buffer)
            if (bytesRead > 0) {
                buffer.flip()
                val responsePacket = buildUdpPacket(
                    packet.ipHeader,
                    packet.transportHeader as UDPHeader,
                    buffer
                )
                networkToDeviceQueue.offer(responsePacket)
            }
        } catch (e: IOException) {
            Log.e(TAG, "UDP Read error", e)
        }
    }

    override fun close() {
        selector.close()
        tcpTracker.closeAll()
        udpTracker.closeAll()
    }
}
