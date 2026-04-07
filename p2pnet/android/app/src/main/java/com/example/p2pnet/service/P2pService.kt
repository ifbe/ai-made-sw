package com.example.p2pnet.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Binder
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import com.example.p2pnet.R
import com.example.p2pnet.data.remote.WsClient

class P2pService : Service() {

    private val binder = LocalBinder()
    lateinit var wsClient: WsClient
        private set

    private var wifiLock: WifiManager.MulticastLock? = null
    private var wakeLock: PowerManager.WakeLock? = null

    inner class LocalBinder : Binder() {
        fun getService(): P2pService = this@P2pService
    }

    override fun onCreate() {
        super.onCreate()
        wsClient = WsClient()
        acquireLocks()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, createNotification())
        return START_STICKY
    }

    override fun onBind(intent: Intent): Binder = binder

    override fun onDestroy() {
        releaseLocks()
        super.onDestroy()
    }

    private fun acquireLocks() {
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        wifiLock = wifi.createMulticastLock("p2pnet_wifi").apply { acquire() }

        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK or PowerManager.ON_AFTER_RELEASE,
            "p2pnet_wake"
        ).apply {
            acquire(10 * 60 * 60 * 1000L) // 10h max
        }
    }

    private fun releaseLocks() {
        try { wifiLock?.release() } catch (_: Exception) {}
        try { wakeLock?.release() } catch (_: Exception) {}
        wifiLock = null
        wakeLock = null
    }

    private fun createNotification(): Notification {
        createNotificationChannel()
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("p2pnet")
            .setContentText("连接运行中")
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "p2pnet 连接",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "保持 WebSocket 和 UDP 连接"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    companion object {
        private const val CHANNEL_ID = "p2pnet_service"
        private const val NOTIFICATION_ID = 1
    }
}
