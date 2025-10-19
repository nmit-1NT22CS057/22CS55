package com.example.zerodef.network

import android.net.VpnService
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap

data class UDPConnection(
    val sourceAddress: InetAddress,
    val sourcePort: Int,
    val destAddress: InetAddress,
    val destPort: Int
) {
    val key: String = "${sourceAddress.hostAddress}:$sourcePort-${destAddress.hostAddress}:$destPort"
}

class UDPTracker(private val vpnService: VpnService) {
    private val channels = ConcurrentHashMap<String, DatagramChannel>()

    fun getOrCreateChannel(connection: UDPConnection): DatagramChannel? {
        channels[connection.key]?.let { return it }
        return try {
            val newChannel = DatagramChannel.open()
            vpnService.protect(newChannel.socket())
            newChannel.configureBlocking(false)
            newChannel.connect(InetSocketAddress(connection.destAddress, connection.destPort))
            channels[connection.key] = newChannel
            newChannel
        } catch (e: IOException) {
            null
        }
    }

    fun closeConnection(connection: UDPConnection) {
        channels.remove(connection.key)?.close()
    }

    fun closeAll() {
        channels.values.forEach { it.close() }
        channels.clear()
    }
}
