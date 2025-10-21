package com.example.zerodef.network

import android.net.VpnService
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap

data class TCPConnection(
    val sourceAddress: InetAddress,
    val sourcePort: Int,
    val destAddress: InetAddress,
    val destPort: Int
) {
    val key: String = "${sourceAddress.hostAddress}:$sourcePort-${destAddress.hostAddress}:$destPort"
}

class TCPTracker(private val vpnService: VpnService) {
    private val channels = ConcurrentHashMap<String, SocketChannel>()
    private val states = ConcurrentHashMap<String, TCPState>()

    fun getOrCreateChannel(connection: TCPConnection): SocketChannel? {
        channels[connection.key]?.let { return it }
        return try {
            val newChannel = SocketChannel.open()
            vpnService.protect(newChannel.socket())
            newChannel.configureBlocking(false)
            newChannel.connect(InetSocketAddress(connection.destAddress, connection.destPort))
            channels[connection.key] = newChannel
            states[connection.key] = TCPState()
            newChannel
        } catch (e: IOException) {
            null
        }
    }

    fun getState(connection: TCPConnection): TCPState? = states[connection.key]

    fun closeConnection(connection: TCPConnection) {
        channels.remove(connection.key)?.close()
        states.remove(connection.key)
    }

    fun closeAll() {
        channels.values.forEach { it.close() }
        channels.clear()
        states.clear()
    }

    fun cleanupIdleConnections(now: Long, timeout: Long) {
        states.entries.removeIf { 
            val shouldRemove = now - it.value.lastActivity > timeout
            if (shouldRemove) {
                channels.remove(it.key)?.close()
            }
            shouldRemove
        }
    }
}
