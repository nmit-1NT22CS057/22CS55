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
import com.example.zerodef.network.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class ZeroDefVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private lateinit var vpnInput: FileInputStream
    private lateinit var vpnOutput: FileOutputStream
    private lateinit var networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>
    private lateinit var executor: ExecutorService
    private var nioManager: NioManager? = null

    companion object {
        var isRunning = false
        const val ACTION_START = "com.example.zerodef.START_VPN"
        const val ACTION_STOP = "com.example.zerodef.STOP_VPN"
        const val BROADCAST_VPN_STATE = "com.example.zerodef.VPN_STATE"
        private const val DNS_SERVER = "8.8.8.8"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        if (!isRunning) {
            startVpn()
        }

        return START_STICKY
    }

    private fun startVpn() {
        isRunning = true
        sendStateBroadcast()
        startForeground(1, createNotification())

        val builder = Builder()
        builder.setSession("ZeroDef VPN")
        builder.addAddress("10.0.0.2", 32)
        builder.addDnsServer(DNS_SERVER)
        builder.addRoute("0.0.0.0", 0)
        vpnInterface = builder.establish()!!

        vpnInput = FileInputStream(vpnInterface!!.fileDescriptor)
        vpnOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
        networkToDeviceQueue = ArrayBlockingQueue(2000)

        nioManager = NioManager(networkToDeviceQueue, this)
        executor = Executors.newFixedThreadPool(3) // Reader, Writer, NioManager
        executor.submit(nioManager)
        executor.submit(DeviceReader(nioManager!!))
        executor.submit(DeviceWriter())
    }

    private inner class DeviceReader(private val nioManager: NioManager) : Runnable {
        override fun run() {
            val buffer = ByteBuffer.allocate(32767)
            while (isRunning) {
                try {
                    val readBytes = vpnInput.read(buffer.array())
                    if (readBytes > 0) {
                        val packetData = buffer.array().copyOf(readBytes)
                        nioManager.processPacket(Packet(ByteBuffer.wrap(packetData)))
                    }
                    buffer.clear()
                } catch (e: IOException) {
                    if (isRunning) Log.e("VpnService", "Error reading from VPN", e)
                } catch (e: Exception) {
                    if (isRunning) Log.e("VpnService", "DeviceReader exception", e)
                }
            }
        }
    }

    private inner class DeviceWriter : Runnable {
        override fun run() {
            while (isRunning) {
                try {
                    val buffer = networkToDeviceQueue.take()
                    vpnOutput.write(buffer.array(), 0, buffer.limit())
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                } catch (e: IOException) {
                   if (isRunning) Log.e("VpnService", "Error writing to VPN", e)
                }
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        sendStateBroadcast()
        if (this::executor.isInitialized) {
            executor.shutdownNow()
        }
        nioManager?.close()
        try { vpnInterface?.close() } catch (e: IOException) {}
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
        val pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, "vpn_channel")
            .setContentTitle("ZeroDef VPN")
            .setContentText("VPN is active")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel("vpn_channel", "VPN Service Channel", NotificationManager.IMPORTANCE_DEFAULT)
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(serviceChannel)
        }
    }
}
