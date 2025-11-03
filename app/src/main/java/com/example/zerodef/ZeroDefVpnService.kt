
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

import com.example.zerodef.network.ConnectionTracker

import com.example.zerodef.network.IPV4_HEADER_SIZE

import com.example.zerodef.network.IPV6_HEADER_SIZE

import com.example.zerodef.network.NioManager

import com.example.zerodef.network.Packet

import java.io.FileInputStream

import java.io.FileOutputStream

import java.io.IOException

import java.nio.ByteBuffer

import java.util.concurrent.ArrayBlockingQueue

import java.util.concurrent.ExecutorService

import java.util.concurrent.Executors

import java.util.concurrent.ScheduledExecutorService

import java.util.concurrent.TimeUnit

import java.util.concurrent.atomic.AtomicBoolean



class ZeroDefVpnService : VpnService() {



    private var vpnInterface: ParcelFileDescriptor? = null

    private lateinit var networkToDeviceQueue: ArrayBlockingQueue<ByteBuffer>

    private lateinit var executor: ExecutorService

    private var maintenanceExecutor: ScheduledExecutorService? = null

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

            // --- PHASE 3: Add IPv6 routing ---

            builder.addAddress("10.0.0.2", 32)

            builder.addAddress("fd00:1:2:3::10", 128) // Example IPv6 address

            builder.addDnsServer(DNS_SERVER)

            builder.addRoute("0.0.0.0", 0)

            builder.addRoute("::", 0) // Route all IPv6 traffic

            builder.setMtu(1500)



            vpnInterface = builder.establish()



            networkToDeviceQueue = ArrayBlockingQueue(QUEUE_CAPACITY)

            nioManager = NioManager(networkToDeviceQueue, this)



            executor = Executors.newFixedThreadPool(2)

            executor.submit(nioManager)

            executor.submit(PacketProcessor(vpnInterface!!, networkToDeviceQueue, nioManager!!))



            maintenanceExecutor = Executors.newSingleThreadScheduledExecutor()

            maintenanceExecutor?.scheduleAtFixedRate({

                try {

                    nioManager?.let { manager ->

                        Log.i("ZeroDefVpnService", "VPN Stats: ${manager.getStats()}")

                    }

                } catch (e: Exception) {

                    Log.e("ZeroDefVpnService", "Maintenance error", e)

                }

            }, 30, 30, TimeUnit.SECONDS)



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

        private val vpnInput = FileInputStream(vpnInterface.fileDescriptor).channel

        private val vpnOutput = FileOutputStream(vpnInterface.fileDescriptor).channel

        private val readBuffer = ByteBuffer.allocateDirect(ConnectionTracker.SOCKET_BUFFER_SIZE)



        override fun run() {

            Log.i("PacketProcessor", "Packet processor started")



            val writerThread = Thread(PacketWriter())

            writerThread.start()



            while (isRunning && !isShuttingDown.get()) {

                try {

                    readBuffer.clear()

                    val bytesRead = vpnInput.read(readBuffer)



                    if (bytesRead > 0) {

                        readBuffer.flip()

                        while (readBuffer.hasRemaining()) {

                            val packetStart = readBuffer.position()



                            if (readBuffer.remaining() < 1) break

                            val version = (readBuffer.get(packetStart).toInt() shr 4) and 0xF



                            // --- PHASE 3: Support IPv4 and IPv6 ---

                            val totalLength = when(version) {

                                4 -> {

                                    if (readBuffer.remaining() < IPV4_HEADER_SIZE) break

                                    readBuffer.getShort(packetStart + 2).toInt() and 0xFFFF

                                }

                                6 -> {

                                    if (readBuffer.remaining() < IPV6_HEADER_SIZE) break

                                    (readBuffer.getShort(packetStart + 4).toInt() and 0xFFFF) + IPV6_HEADER_SIZE

                                }

                                else -> {

                                    Log.w("PacketProcessor", "Unknown IP version: $version")

                                    readBuffer.position(readBuffer.limit())

                                    continue

                                }

                            }



                            if (totalLength <= 0 || totalLength > readBuffer.remaining()) {

                                Log.w("PacketProcessor", "Invalid packet length: $totalLength. Discarding buffer.")

                                readBuffer.position(readBuffer.limit())

                                continue

                            }



                            val packetBuffer = readBuffer.slice()

                            packetBuffer.limit(totalLength)

                            nioManager.processPacket(Packet(packetBuffer))



                            readBuffer.position(packetStart + totalLength)

                        }

                    }

                } catch (e: Exception) {

                    if (isRunning && !isShuttingDown.get()) {

                        Log.e("PacketProcessor", "Read error", e)

                    }

                }

            }



            writerThread.interrupt()

            Log.i("PacketProcessor", "Packet processor stopped")

        }



        private inner class PacketWriter : Runnable {

            override fun run() {

                while (isRunning && !isShuttingDown.get()) {

                    try {

                        val packet = networkToDeviceQueue.take()

                        while (packet.hasRemaining()) {

                            vpnOutput.write(packet)

                        }



                        // --- FIX: Return buffer to the pool using the correct function ---

                        if (packet.isDirect && packet.capacity() == 65536) {

                            nioManager.returnBufferToPool(packet)

                        }

                    } catch (_: InterruptedException) {

                        Log.i("PacketWriter", "Writer thread interrupted, shutting down.")

                        Thread.currentThread().interrupt()

                    } catch (e: IOException) {

                        if (isRunning && !isShuttingDown.get()) {

                            Log.e("PacketWriter", "Write error", e)

                        }

                    }

                }

            }

        }

    }



    private fun stopVpn() {

        if (!isShuttingDown.compareAndSet(false, true)) {

            return

        }

        isRunning = false



        maintenanceExecutor?.shutdownNow()

        maintenanceExecutor = null



        executor.shutdownNow()



        nioManager?.close()

        nioManager = null



        try {

            vpnInterface?.close()

            vpnInterface = null

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