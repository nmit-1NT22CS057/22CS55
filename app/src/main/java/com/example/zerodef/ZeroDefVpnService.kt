package com.example.zerodef

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.example.zerodef.network.NioManager
import com.example.zerodef.network.Packet
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class ZeroDefVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private lateinit var networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>
    private lateinit var executor: ExecutorService
    private var nioManager: NioManager? = null
    private val isShuttingDown = AtomicBoolean(false)

    companion object {
        var isRunning = false
        const val ACTION_START = "com.example.zerodef.START_VPN"
        const val ACTION_STOP = "com.example.zerodef.STOP_VPN"
        const val BROADCAST_VPN_STATE = "com.example.zerodef.VPN_STATE"
        private const val DNS_SERVER = "8.8.8.8"
        private const val QUEUE_CAPACITY = 5000
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                if (!isRunning) {
                    startVpn()
                }
            }
        }
        return START_STICKY
    }

    private fun startVpn() {
        isRunning = true
        isShuttingDown.set(false)
        sendStateBroadcast()
        startForeground(1, createNotification())

        try {
            val builder = Builder()
            builder.setSession("ZeroDef VPN")
            builder.addAddress("10.0.0.2", 32)
            builder.addDnsServer(DNS_SERVER)
            builder.addRoute("0.0.0.0", 0)
            builder.setMtu(1500)
            vpnInterface = builder.establish()

            networkToDeviceQueue = ArrayBlockingQueue(QUEUE_CAPACITY)
            nioManager = NioManager(networkToDeviceQueue, this)

            executor = Executors.newFixedThreadPool(2)
            executor.submit(nioManager)
            executor.submit(PacketProcessor(vpnInterface!!, networkToDeviceQueue, nioManager!!))

        } catch (e: Exception) {
            Log.e("ZeroDefVpnService", "Failed to start VPN", e)
            stopVpn()
        }
    }

    private inner class PacketProcessor(
        private val vpnInterface: ParcelFileDescriptor,
        private val networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>,
        private val nioManager: NioManager
    ) : Runnable {
        private val vpnInput = FileInputStream(vpnInterface.fileDescriptor)
        private val vpnOutput = FileOutputStream(vpnInterface.fileDescriptor)
        private val readBuffer = ByteArray(32767)

        override fun run() {
            Log.i("PacketProcessor", "Packet processor started")
            while (isRunning && !isShuttingDown.get()) {
                try {
                    // Read from device
                    val readBytes = vpnInput.read(readBuffer)
                    if (readBytes > 0) {
                        val packetData = ByteBuffer.wrap(readBuffer, 0, readBytes)
                        nioManager.processPacket(Packet(packetData))
                    }

                    // Write to device (simple non-batched version)
                    val packetToWrite = networkToDeviceQueue.poll()
                    if (packetToWrite != null) {
                        vpnOutput.write(packetToWrite.array(), 0, packetToWrite.limit())
                    }

                } catch (e: IOException) {
                    if (isRunning && !isShuttingDown.get()) {
                        Log.w("PacketProcessor", "I/O error: ${e.message}")
                    }
                    break
                } catch (e: Exception) {
                    Log.e("PacketProcessor", "Unexpected error", e)
                }
            }
            Log.i("PacketProcessor", "Packet processor stopped")
        }
    }

    private fun stopVpn() {
        isShuttingDown.set(true)
        isRunning = false

        executor.shutdownNow()
        nioManager?.close()

        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.e("ZeroDefVpnService", "Error closing VPN interface", e)
        }

        sendStateBroadcast()
        stopForeground(true)
        stopSelf()
    }

    private fun sendStateBroadcast() {
        val intent = Intent(BROADCAST_VPN_STATE)
        intent.putExtra("isRunning", isRunning)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    private fun createNotification(): Notification {
        createNotificationChannel()
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

        return NotificationCompat.Builder(this, "vpn_channel")
            .setContentTitle("ZeroDef VPN")
            .setContentText("VPN is active")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                "vpn_channel",
                "VPN Service Channel",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(serviceChannel)
        }
    }
}