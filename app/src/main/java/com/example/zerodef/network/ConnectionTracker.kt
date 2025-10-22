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

data class Connection(
    val protocol: Protocol,
    val sourceAddress: InetAddress,
    val sourcePort: Int,
    val destAddress: InetAddress,
    val destPort: Int,
    val connectionId: Long = System.nanoTime()
) {
    val key: String = "$protocol:${sourceAddress.hostAddress}:$sourcePort-${destAddress.hostAddress}:$destPort"
}

class ConnectionTracker(private val vpnService: VpnService) {
    private val channels = ConcurrentHashMap<String, SelectableChannel>()
    private val states = ConcurrentHashMap<String, TCPState>()
    private val bufferPool = DirectBufferPool(32, 65536)

    private val connectionPool = ConnectionPool(100)
    private val activeConnections = AtomicInteger(0)

    companion object {
        const val TAG = "ConnectionTracker"
        const val MAX_CONNECTIONS = 500
    }

    fun getOrCreateChannel(connection: Connection): SelectableChannel? {
        if (activeConnections.get() >= MAX_CONNECTIONS) {
            Log.w(TAG, "Maximum connections reached, rejecting new connection")
            return null
        }

        return channels[connection.key] ?: tryCreateChannel(connection)
    }

    private fun tryCreateChannel(connection: Connection): SelectableChannel? {
        return try {
            val newChannel = when (connection.protocol) {
                Protocol.TCP -> createOptimizedSocketChannel(connection)
                Protocol.UDP -> createOptimizedDatagramChannel(connection)
                else -> null
            }

            newChannel?.let { channel ->
                channels[connection.key] = channel
                if (connection.protocol == Protocol.TCP) {
                    states[connection.key] = TCPState()
                }
                activeConnections.incrementAndGet()
                channel
            }
        } catch (e: IOException) {
            Log.w(TAG, "Failed to create channel for $connection: ${e.message}")
            null
        }
    }

    private fun createOptimizedSocketChannel(connection: Connection): SocketChannel {
        val channel = SocketChannel.open()
        channel.configureBlocking(false)

        if (!vpnService.protect(channel.socket())) {
            channel.close()
            throw IOException("Failed to protect socket")
        }

        val socket = channel.socket()
        socket.soTimeout = 15000
        socket.keepAlive = true
        socket.tcpNoDelay = true
        socket.reuseAddress = true
        socket.receiveBufferSize = 65536
        socket.sendBufferSize = 65536

        channel.connect(InetSocketAddress(connection.destAddress, connection.destPort))
        return channel
    }

    private fun createOptimizedDatagramChannel(connection: Connection): DatagramChannel {
        val channel = DatagramChannel.open()
        channel.configureBlocking(false)

        if (!vpnService.protect(channel.socket())) {
            channel.close()
            throw IOException("Failed to protect socket")
        }

        val socket = channel.socket()
        socket.reuseAddress = true
        socket.receiveBufferSize = 65536
        socket.sendBufferSize = 65536

        channel.connect(InetSocketAddress(connection.destAddress, connection.destPort))
        return channel
    }

    fun getState(connection: Connection): TCPState? = states[connection.key]

    fun getBuffer(): ByteBuffer = bufferPool.borrowBuffer()

    fun returnBuffer(buffer: ByteBuffer) = bufferPool.returnBuffer(buffer)

    fun closeConnection(connection: Connection) {
        try {
            channels.remove(connection.key)?.close()
            states.remove(connection.key)
            activeConnections.decrementAndGet()
        } catch (e: IOException) {
            // Ignore close errors
        }
    }

    fun closeAll() {
        channels.values.forEach {
            try { it.close() } catch (e: IOException) { /* ignore */ }
        }
        channels.clear()
        states.clear()
        bufferPool.clear()
        activeConnections.set(0)
    }

    fun cleanupIdleConnections(now: Long, timeout: Long) {
        val iterator = states.entries.iterator()
        var cleaned = 0

        while (iterator.hasNext()) {
            val (key, state) = iterator.next()
            if (now - state.lastActivity > timeout) {
                channels.remove(key)?.close()
                iterator.remove()
                activeConnections.decrementAndGet()
                cleaned++
            }

            if (cleaned >= 10) break
        }

        if (cleaned > 0) {
            Log.d(TAG, "Cleaned up $cleaned idle connections")
        }
    }

    fun getStats(): String {
        return "Connections: ${activeConnections.get()}, Buffers: ${bufferPool.getStats()}"
    }
}

class DirectBufferPool(private val maxBuffers: Int, private val bufferSize: Int) {
    private val availableBuffers = LinkedList<ByteBuffer>()
    private val createdCount = AtomicInteger(0)

    fun borrowBuffer(): ByteBuffer {
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
        synchronized(availableBuffers) {
            if (availableBuffers.size < maxBuffers) {
                availableBuffers.addLast(buffer)
            }
        }
    }

    private fun createNewBuffer(): ByteBuffer {
        createdCount.incrementAndGet()
        return ByteBuffer.allocateDirect(bufferSize)
    }

    fun clear() {
        synchronized(availableBuffers) {
            availableBuffers.clear()
        }
    }

    fun getStats(): String = "available=${availableBuffers.size}, created=$createdCount"
}

class ConnectionPool(private val maxSize: Int) {
    private val pool = LinkedHashMap<String, Long>(maxSize, 0.75f, true)

    @Synchronized
    fun touch(connectionKey: String) {
        pool[connectionKey] = System.currentTimeMillis()

        if (pool.size > maxSize) {
            val iterator = pool.entries.iterator()
            if (iterator.hasNext()) {
                iterator.next()
                iterator.remove()
            }
        }
    }

    @Synchronized
    fun contains(connectionKey: String): Boolean = pool.containsKey(connectionKey)
}