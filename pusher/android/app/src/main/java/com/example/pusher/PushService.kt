package com.example.pusher

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.pusher.utils.AppLog

class PushService : Service() {

    companion object {
        private const val TAG = "PushService"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "push_service_channel"
        const val ACTION_STOP = "com.example.pusher.action.STOP_PUSH"
        const val ACTION_REFRESH = "com.example.pusher.action.REFRESH_NOTIFICATION"

        private const val WIFI_LOCK_TAG = "pusher:wifi"

        /**
         * 通知栏“停止推流”按钮的回调。Activity 在推流期间注册（主线程调用）。
         * 用进程内的回调而不是广播，避免额外的组件与权限。
         */
        @Volatile
        var onStopRequested: (() -> Unit)? = null

        fun start(context: Context) {
            val intent = Intent(context, PushService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, PushService::class.java)
            context.stopService(intent)
        }

        /**
         * 让服务把通知补发一次。
         *
         * 首次推流时通知权限可能还没授予（用户正在看系统弹窗），那条通知会被系统丢掉；
         * 用户点"允许"之后调这个，状态栏才会立刻出现"推流中"。
         */
        fun refreshNotification(context: Context) {
            try {
                context.startService(
                    Intent(context, PushService::class.java).setAction(ACTION_REFRESH)
                )
            } catch (t: Throwable) {
                // Android 12+ 不允许从后台启动服务；这里只是"补个通知"，失败无所谓
                Log.w(TAG, "refreshNotification failed", t)
            }
        }
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        try {
            startForegroundWithType()
        } catch (t: Throwable) {
            // 极端情况下（例如服务在后台被系统拉起、前台服务类型/权限不被允许）startForeground
            // 会抛异常（Android 12+ 的 ForegroundServiceStartNotAllowedException 等），
            // 这里退化成“不启动服务”，不要让它变成崩溃。
            Log.e(TAG, "startForeground failed, giving up foreground service", t)
            stopSelf()
            return
        }
        // 前台服务本身**不会**阻止系统进 Doze：息屏一段时间后 CPU 会睡、WiFi 会省电，
        // 推流可能卡住甚至断连。CPU/WiFi 唤醒锁在这里拿到，服务销毁时释放。
        acquireLocks()
    }

    override fun onDestroy() {
        releaseLocks()
        super.onDestroy()
    }

    /** CPU + WiFi 唤醒锁：息屏继续推流的关键（前台服务不阻止 Doze） */
    @Suppress("DEPRECATION")
    private fun acquireLocks() {
        if (wakeLock == null) {
            try {
                val pm = getSystemService(PowerManager::class.java)
                wakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$TAG:push")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
                if (wakeLock != null) AppLog.log("已持有 CPU 唤醒锁（息屏继续推流）")
            } catch (t: Throwable) {
                Log.e(TAG, "acquire wake lock failed", t)
            }
        }
        if (wifiLock == null) {
            try {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                wifiLock = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    wm?.createWifiLock(WIFI_LOCK_TAG)
                } else {
                    wm?.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, WIFI_LOCK_TAG)
                }?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
                if (wifiLock != null) AppLog.log("已持有 WiFi 高性能锁（减少息屏省电带来的卡顿）")
            } catch (t: Throwable) {
                Log.e(TAG, "acquire wifi lock failed", t)
            }
        }
    }

    private fun releaseLocks() {
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (t: Throwable) {
            Log.w(TAG, "release wake lock failed", t)
        }
        wakeLock = null
        try {
            wifiLock?.let { if (it.isHeld) it.release() }
        } catch (t: Throwable) {
            Log.w(TAG, "release wifi lock failed", t)
        }
        wifiLock = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_REFRESH) {
            // 通知权限刚拿到：把通知补发一次（首次推流时那条通知可能已被系统丢弃）
            try {
                startForegroundWithType()
            } catch (t: Throwable) {
                Log.w(TAG, "refresh notification failed", t)
            }
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_STOP) {
            Log.d(TAG, "stop action received from notification")
            try {
                onStopRequested?.invoke()
            } catch (t: Throwable) {
                Log.e(TAG, "stop callback failed", t)
            }
            stopSelf()
        }
        // 不要用 START_STICKY：进程被回收后系统会在后台把服务重新拉起，
        // 而 onCreate 里的 startForeground 在后台是不被允许的（Android 12+）→ 崩溃。
        // 推流由 Activity 主动启动，需要时它会重新 start 服务。
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /**
     * 兼容所有 Android 版本启动前台服务
     * Android 14+ (API 34) 必须指定前台服务类型
     */
    private fun startForegroundWithType() {
        val notification = createNotification()

        when {
            // Android 14+ (API 34) - 必须指定服务类型
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA or
                            ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
                )
            }
            // Android 10-13 (API 29-33) - 可以指定类型（推荐）
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
                )
            }
            // Android 9 及以下 (API 28-) - 不需要类型
            else -> {
                startForeground(NOTIFICATION_ID, notification)
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "推流服务",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "保持推流服务在后台运行"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        // 点击通知返回应用
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE
        )

        // “停止推流”动作：后台推流时不用回到应用就能停
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, PushService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("推流中")
            .setContentText("正在推流")
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setAutoCancel(false)
            .addAction(android.R.drawable.ic_media_pause, "停止推流", stopIntent)
            .build()
    }
}