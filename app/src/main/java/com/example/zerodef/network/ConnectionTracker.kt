package com.example.zerodef.network

import android.net.VpnService
import android.util.Log
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

// --- PHASE 3: Upgraded for IPv6 Support ---
data class ConnectionKey(
    val protocol: Protocol,
    val sourceAddress: InetAddress,
    val sourcePort: Int,
    val destAddress: InetAddress,
    val destPort: Int
)

class Connection(

    val channel: SelectableChannel,
    // --- FINAL REWORK: A proxy only manages ONE custom TCP state: the client's. ---
    val clientState: TCPState // Manages client <-> vpn

) {

    fun updateActivity() {

        clientState.lastActivity = System.currentTimeMillis()

    }

}



class ConnectionTracker(private val vpnService: VpnService) {

    private val connections = ConcurrentHashMap<ConnectionKey, Connection>()

    // --- Made internal to be accessible from NioManager ---

    internal val bufferPool = DirectBufferPool(32, 65536)

    private val activeConnections = AtomicInteger(0)



    companion object {

        const val TAG = "ConnectionTracker"

        // --- PHASE 2: Connection Limiting ---

        const val MAX_CONNECTIONS = 1000

        const val SOCKET_BUFFER_SIZE = 65536

    }



    fun getConnection(key: ConnectionKey): Connection? {

        return connections[key]

    }



    // --- PHASE 2: Enforce Connection Limiting ---

    fun createAndTrackConnection(key: ConnectionKey): Connection? {

        if (activeConnections.get() >= MAX_CONNECTIONS) {

            Log.w(TAG, "Maximum connections reached, rejecting new connection for $key")

            return null

        }



        return try {

            val newChannel = when (key.protocol) {

                Protocol.TCP -> createOptimizedSocketChannel(key)

                Protocol.UDP -> createOptimizedDatagramChannel(key)

                else -> null

            }



            newChannel?.let { channel ->

                val newConnection = Connection(

                    channel = channel,

                    // --- FINAL REWORK: Initialize client state only ---

                    clientState = TCPState()

                )

                connections[key] = newConnection

                activeConnections.incrementAndGet()

                newConnection

            }

        } catch (e: IOException) {

            Log.w(TAG, "Failed to create channel for $key: ${e.message}")

            null

        }

    }



    private fun createOptimizedSocketChannel(key: ConnectionKey): SocketChannel {

        val channel = SocketChannel.open()

        channel.configureBlocking(false)

        vpnService.protect(channel.socket()) || throw IOException("Failed to protect TCP socket")



        channel.socket().apply {

            soTimeout = 15000

            keepAlive = true

            tcpNoDelay = true

            reuseAddress = true

            receiveBufferSize = SOCKET_BUFFER_SIZE

            sendBufferSize = SOCKET_BUFFER_SIZE

        }



        channel.connect(InetSocketAddress(key.destAddress, key.destPort))

        return channel

    }



    private fun createOptimizedDatagramChannel(key: ConnectionKey): DatagramChannel {

        val channel = DatagramChannel.open()

        channel.configureBlocking(false)

        vpnService.protect(channel.socket()) || throw IOException("Failed to protect UDP socket")



        channel.socket().apply {

            reuseAddress = true

            receiveBufferSize = SOCKET_BUFFER_SIZE

            sendBufferSize = SOCKET_BUFFER_SIZE

        }



        channel.connect(InetSocketAddress(key.destAddress, key.destPort))

        return channel

    }



    fun getAllTcpConnections(): List<Pair<ConnectionKey, Connection>> = connections.entries

        .filter { it.key.protocol == Protocol.TCP }

        .map { it.key to it.value }



    fun getBufferPool(): DirectBufferPool = bufferPool



    fun closeConnection(key: ConnectionKey) {

        connections.remove(key)?.let { connection ->

            try {

                connection.channel.close()

            } catch (e: IOException) {

                // Ignore close errors

            } finally {

                activeConnections.decrementAndGet()

            }

        }

    }



    fun closeAll() {

        connections.values.forEach {

            try { it.channel.close() } catch (e: IOException) { /* ignore */ }

        }

        connections.clear()

        bufferPool.clear()

        activeConnections.set(0)

    }



    fun getStats(): String {

        return "Connections: ${activeConnections.get()}, Buffers: ${bufferPool.getStats()}"

    }

}



class DirectBufferPool(private val maxBuffers: Int, private val bufferSize: Int) {

    private val availableBuffers = LinkedList<ByteBuffer>()

    private val createdCount = AtomicInteger(0)

    private val borrowedCount = AtomicInteger(0)

    private val returnedCount = AtomicInteger(0)



    fun borrowBuffer(): ByteBuffer {

        borrowedCount.incrementAndGet()

        synchronized(availableBuffers) {

            return if (availableBuffers.isNotEmpty()) {

                val buffer = availableBuffers.removeFirst()

                buffer.clear()

                buffer

            } else {

                createNewBuffer()

            }

        }

    }



    fun returnBuffer(buffer: ByteBuffer) {

        returnedCount.incrementAndGet()

        synchronized(availableBuffers) {

            if (availableBuffers.size < maxBuffers && buffer.capacity() == bufferSize) {

                buffer.clear()

                availableBuffers.addLast(buffer)

            }

        }

    }



    private fun createNewBuffer(): ByteBuffer {

        val count = createdCount.incrementAndGet()

        if (count > maxBuffers * 2) {

            Log.w("DirectBufferPool", "Creating many buffers: $count")

        }

        return ByteBuffer.allocateDirect(bufferSize)

    }



    fun clear() {

        synchronized(availableBuffers) {

            availableBuffers.clear()

        }

    }



    fun getStats(): String =

        "available=${availableBuffers.size}, created=$createdCount, " +

                "borrowed=$borrowedCount, returned=$returnedCount"

}

















