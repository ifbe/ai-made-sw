package com.example.p2pnet.service

import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.p2pnet.MainActivity
import com.example.p2pnet.R
import com.example.p2pnet.data.remote.WsClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 承载 WebSocket 连接的前台服务（UDP 的 socket 目前不在这里，见下方说明）。
 *
 * 解决的问题：按 Home 键或锁屏后，进程被 LMK 回收 / 被 Doze 冻结 → [WsClient] 里的
 * socket 跟着断，现象就是「切到后台或息屏一会儿连接就没了」。
 *
 * 保活手段（参考 ../chatroom/TcpForegroundService、../pusher/PushService）：
 * - 前台服务 + 常驻通知：进程不再是 cached 进程，不会被冻结/回收，通知栏可见
 * - PARTIAL_WAKE_LOCK：锁屏后 CPU 不被挂起，socket 收发线程才能继续跑（**故意不设超时**）
 * - WiFiLock（HIGH_PERF）：息屏后 Wi-Fi 射频不进入省电休眠，减少丢包/延迟
 * - MulticastLock：保留原有行为（组播/广播包的接收许可，顺带让射频保持活跃）
 *
 * ⚠️ 现在这个服务持有 WebSocket，并且从 2026-09 起也持有 **UDP 打洞产出的 session**
 * （[SessionManager] + [com.example.p2pnet.net.UdpSession] 都在服务作用域里跑），
 * 所以按 Home / Activity 被系统回收都不会再把对端 socket 弄丢。
 *
 * 注意：前台服务本身**不阻止**系统进入 Doze，Doze 下网络会被挂起，
 * 所以 MainActivity 还会引导用户把 app 加入电池优化白名单。
 */
class P2pService : Service() {

    private val binder = LocalBinder()
    lateinit var wsClient: WsClient
        private set

    /**
     * P2P session 的 owner：打洞产出的 UDP socket + 读循环 + usage 都挂在这里，
     * 跑在服务作用域里，所以按 Home / Activity 被回收都不会把 UDP 停掉。
     */
    private val sessionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val sessionManager = SessionManager(sessionScope)

    /** CPU 部分唤醒锁：不设超时，连接结束（服务销毁）时才释放 */
    private var wakeLock: PowerManager.WakeLock? = null
    /** Wi-Fi 锁：息屏后不让 Wi-Fi 省电休眠 */
    private var wifiLock: WifiManager.WifiLock? = null
    /** 组播锁（原有行为） */
    private var multicastLock: WifiManager.MulticastLock? = null

    /** 心跳诊断用（见 companion.heartbeatReport） */
    private val heartbeatScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var heartbeatJob: Job? = null

    inner class LocalBinder : Binder() {
        fun getService(): P2pService = this@P2pService
    }

    override fun onCreate() {
        super.onCreate()
        wsClient = WsClient()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // ⚠️ 只要是被 startForegroundService() 拉起来的，就必须在 5s 内 startForeground()，
        // 否则系统抛 ForegroundServiceDidNotStartInTimeException 直接干掉进程。
        // START_STICKY 自启、点通知回来时这里会再走一次，实现是幂等的。
        startInForeground()
        acquireLocks()
        refreshPowerState(applicationContext)
        startHeartbeat()
        Log.i(TAG, "onStartCommand 完成，${status}｜${heartbeatReport()}")
        return START_STICKY
    }

    override fun onBind(intent: Intent): Binder = binder

    /**
     * 用户从「最近任务」列表里划掉 app 时调用（按 Home 键不会触发这里）。
     * 默认 stopWithTask=false，服务本来就会继续跑；这里补一次 start，
     * 防止部分 ROM 把 started 状态一起清掉导致服务被销毁。
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.i(TAG, "onTaskRemoved: 尝试重新拉起前台服务")
        try {
            val restart = Intent(applicationContext, P2pService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                applicationContext.startForegroundService(restart)
            } else {
                applicationContext.startService(restart)
            }
        } catch (t: Throwable) {
            // Android 12+ 后台启动前台服务可能被拒，失败只降级为「靠 started 状态继续跑」
            Log.w(TAG, "onTaskRemoved restart failed: ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    override fun onDestroy() {
        alive = false
        foregroundState = "服务已销毁"
        destroyCount++
        // 服务没了，它拥有的 session 也一起收掉（socket 生命周期跟着服务走）
        try { sessionManager.closeAll() } catch (t: Throwable) {
            Log.w(TAG, "closeAll sessions failed: ${t.message}")
        }
        sessionScope.cancel()
        heartbeatJob?.cancel()
        heartbeatScope.cancel()
        Log.w(TAG, "onDestroy！destroyCount=$destroyCount")
        releaseLocks()
        super.onDestroy()
    }

    private fun startInForeground() {
        val notification = buildNotification()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, FOREGROUND_SERVICE_TYPE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            foregroundState = "前台服务 OK(connectedDevice)"
            Log.i(TAG, "startForeground OK")
        } catch (t: Throwable) {
            // 权限/类型不匹配、Android 12+ 后台启动被拒等都会抛异常，
            // 不 catch 的话进程被系统直接杀掉，socket 全断。
            // 这条异常会通过 status 显示到 App 日志里（MainActivity.onResume）。
            foregroundState = "前台服务启动失败: ${t.javaClass.simpleName}: ${t.message}"
            Log.e(TAG, "startForeground FAILED: ${t.javaClass.simpleName}: ${t.message}", t)
        }
    }

    /**
     * CPU + WiFi 唤醒锁，幂等（重复调用不会叠引用计数）。
     *
     * ⚠️ 故意不设超时：只有存在连接时才会走到这里（服务随连接起停），
     * 连接结束 / 服务销毁时释放。旧实现是 acquire(10h)，到期后悄悄放开，
     * 锁屏久了设备一睡 socket 就静默断掉。
     */
    @Suppress("DEPRECATION")
    private fun acquireLocks() {
        val parts = mutableListOf<String>()

        if (wakeLock == null) {
            try {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$TAG:cpu").apply {
                    setReferenceCounted(false)
                    acquire()
                }
                if (wakeLock != null) {
                    parts += "CPU=OK"
                    Log.i(TAG, "已持有 CPU 唤醒锁（锁屏继续收发）")
                }
            } catch (t: Throwable) {
                parts += "CPU=FAIL(${t.javaClass.simpleName})"
                Log.e(TAG, "acquire wake lock failed: ${t.javaClass.simpleName}: ${t.message}", t)
            }
        } else {
            parts += "CPU=已持有"
        }

        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        if (wifi != null) {
            if (wifiLock == null) {
                try {
                    // 用 HIGH_PERF 而不是 WIFI_MODE_FULL_LOW_LATENCY：
                    // LOW_LATENCY 锁在息屏时会被系统关掉，而那正是最需要它的场景。
                    wifiLock = wifi.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "$TAG:wifi").apply {
                        setReferenceCounted(false)
                        acquire()
                    }
                    if (wifiLock != null) {
                        parts += "WiFi=OK"
                        Log.i(TAG, "已持有 WiFi 唤醒锁（息屏不断网）")
                    }
                } catch (t: Throwable) {
                    parts += "WiFi=FAIL(${t.javaClass.simpleName})"
                    Log.e(TAG, "acquire wifi lock failed: ${t.javaClass.simpleName}: ${t.message}", t)
                }
            } else {
                parts += "WiFi=已持有"
            }
            if (multicastLock == null) {
                try {
                    multicastLock = wifi.createMulticastLock("$TAG:multicast").apply {
                        setReferenceCounted(false)
                        acquire()
                    }
                    parts += "Multicast=OK"
                } catch (t: Throwable) {
                    parts += "Multicast=FAIL(${t.javaClass.simpleName})"
                    Log.e(TAG, "acquire multicast lock failed: ${t.javaClass.simpleName}: ${t.message}", t)
                }
            } else {
                parts += "Multicast=已持有"
            }
        } else {
            parts += "WiFi=无法获取WifiManager"
        }

        lockState = parts.joinToString(" ")
    }

    private fun releaseLocks() {
        try { wakeLock?.let { if (it.isHeld) it.release() } } catch (t: Throwable) {
            Log.w(TAG, "release wake lock failed: ${t.message}")
        }
        wakeLock = null
        try { wifiLock?.let { if (it.isHeld) it.release() } } catch (t: Throwable) {
            Log.w(TAG, "release wifi lock failed: ${t.message}")
        }
        wifiLock = null
        try { multicastLock?.let { if (it.isHeld) it.release() } } catch (t: Throwable) {
            Log.w(TAG, "release multicast lock failed: ${t.message}")
        }
        multicastLock = null
    }

    /**
     * 心跳：服务活着的时候每 5s 记一个时间戳（只留最近 24 个 = 2 分钟）。
     *
     * 这是判断「按 Home 后到底是被冻结/被杀，还是代码自己把连接拆了」的关键证据：
     * - 回到前台时 [heartbeatReport] 里最大空档 ≈ 5s → 进程/服务一直活着 → 问题在业务循环或网络
     * - 出现几十秒 ~ 几分钟的空档 → 进程在后台被冻结（前台服务没生效 / ROM 省电策略）
     * - 完全没有心跳记录 → 进程被系统杀过（内存状态全丢）
     */
    private fun startHeartbeat() {
        alive = true
        if (heartbeatJob?.isActive == true) return
        heartbeatJob = heartbeatScope.launch {
            while (isActive) {
                recordHeartbeat(System.currentTimeMillis(), currentImportance())
                delay(HEARTBEAT_INTERVAL_MS)
            }
        }
    }

    /**
     * 自己进程当前的 oom_adj 优先级，跟着心跳一起记。
     *
     * 这是判断「冻结到底是前台服务没生效，还是设备睡了」的关键：
     * - 冻结前是 FOREGROUND_SERVICE(125) → 前台服务是生效的，进程不是 cached，
     *   那这次挂起就是设备侧（Doze / 厂商省电）把 CPU 停了 → 需要电池优化白名单
     * - 冻结前是 CACHED(700) / SERVICE(400) → 前台服务根本没生效，进程被当成 cached 冻住了
     *   → 要看 startForeground 是不是抛异常了
     */
    private fun currentImportance(): Int = try {
        val info = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(info)
        info.importance
    } catch (t: Throwable) {
        -1
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_desc)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        // 点通知回到 app（不新建 task，复用已开的界面）
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(R.drawable.ic_stat_p2p)
            .setContentIntent(contentIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setOngoing(true)
            .setShowWhen(false)
            .setOnlyAlertOnce(true)
            .setAutoCancel(false)
            .build()
    }

    companion object {
        private const val TAG = "P2pService"
        private const val CHANNEL_ID = "p2pnet_service"
        private const val NOTIFICATION_ID = 1

        private const val HEARTBEAT_INTERVAL_MS = 5_000L
        private const val HEARTBEAT_KEEP = 24

        /** connectedDevice 类型：与 manifest 里 android:foregroundServiceType 保持一致 */
        private const val FOREGROUND_SERVICE_TYPE = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE

        /** 一次心跳采样：时间戳 + 当时的进程优先级 */
        private data class HeartbeatSample(val at: Long, val importance: Int)

        /** 心跳采样环形缓冲（诊断用，进程重启就没了 —— 这本身也是信息） */
        private val heartbeats = ArrayDeque<HeartbeatSample>()

        @Volatile private var alive = false
        @Volatile private var foregroundState = "未启动"
        @Volatile private var lockState = "未获取"

        /** Doze 电池优化白名单状态：false = 未加入（Doze 会挂起网络+忽略唤醒锁） */
        @Volatile private var dozeExempt: Boolean? = null

        /** 服务被销毁次数（正常断开也会 +1；进程被系统杀掉重启后这里归零） */
        @Volatile var destroyCount: Int = 0
            private set

        /** Activity 被销毁次数：>0 说明按 Home 后系统回收过 Activity（进程可能还活着） */
        @Volatile var activityDestroyCount: Int = 0
            private set

        /** 供 App 日志显示的服务状态一行摘要 */
        val status: String
            get() = "服务=${if (alive) "存活" else "未存活"}；$foregroundState；锁=$lockState" +
                "；Doze白名单=${when (dozeExempt) {
                    true -> "已加入"
                    false -> "未加入 ⚠️"
                    null -> "未知"
                }}" +
                "；service销毁=$destroyCount 次；activity销毁=$activityDestroyCount 次"

        /** MainActivity.onDestroy 调，用来判断「回前台后界面重置」是不是系统回收 Activity 导致的 */
        fun noteActivityDestroyed() {
            activityDestroyCount++
        }

        /** 刷新 Doze 白名单状态（服务启动时 + Activity onResume 时各刷一次） */
        fun refreshPowerState(context: Context) {
            try {
                val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
                dozeExempt = pm?.isIgnoringBatteryOptimizations(context.packageName)
            } catch (t: Throwable) {
                Log.w(TAG, "refreshPowerState failed: ${t.message}")
            }
        }

        private fun recordHeartbeat(now: Long, importance: Int) {
            synchronized(heartbeats) {
                heartbeats.addLast(HeartbeatSample(now, importance))
                while (heartbeats.size > HEARTBEAT_KEEP) heartbeats.removeFirst()
            }
        }

        /** 最近这批采样里的最大空档（秒）：>0 就是后台被挂起的最长时间 */
        fun maxGapSeconds(): Long {
            synchronized(heartbeats) {
                if (heartbeats.size < 2) return 0
                var maxGap = 0L
                var prev = heartbeats.first().at
                for (h in heartbeats) {
                    val g = h.at - prev
                    if (g > maxGap) maxGap = g
                    prev = h.at
                }
                return maxGap / 1000
            }
        }

        private fun importanceName(v: Int): String = when (v) {
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND -> "FOREGROUND(100)"
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE -> "FOREGROUND_SERVICE(125)"
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE -> "VISIBLE(200)"
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_PERCEPTIBLE -> "PERCEPTIBLE(230)"
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE -> "SERVICE(400)"
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED -> "CACHED(700)"
            ActivityManager.RunningAppProcessInfo.IMPORTANCE_EMPTY -> "EMPTY(1000)"
            else -> "UNKNOWN($v)"
        }

        /**
         * 一行结论：把「挂起时长 + 前台服务状态 + 服务销毁次数 + Doze 白名单」揉成一句人话，
         * 直接告诉我们是哪一类后台挂起。
         */
        fun diagnosis(): String {
            val gap = maxGapSeconds()
            if (gap < 60) return "结论：后台没被挂起过（或还没进过后台）"
            val fgOk = foregroundState.startsWith("前台服务 OK")
            return "结论：后台被挂起${gap}s → " + when {
                !fgOk -> "前台服务根本没生效（$foregroundState）→ 先修 startForeground"
                destroyCount > 0 -> "服务在后台被销毁/重启过 ${destroyCount} 次 → 前台服务没扛住，检查电池/自启动白名单"
                dozeExempt == false -> "前台服务正常，但 Doze 白名单未加入 → Doze 挂起了 CPU 和网络 → 加电池优化白名单"
                else -> "前台服务正常、Doze 白名单已加入 → 厂商 ROM 省电/自启动策略强杀冻结 → 手动加自启动白名单"
            }
        }

        /**
         * 心跳报告：最大空档 = 后台被挂起的最长时长，并给出**挂起前**的进程优先级。
         *
         * 判读：
         * - 最大空档 ≈ 5s                     → 进程一直在后台跑着，问题不在冻结
         * - 空档大 + 挂起前 FOREGROUND_SERVICE → 前台服务生效，是设备/Doze 把 CPU 停了 → 加电池优化白名单
         * - 空档大 + 挂起前 CACHED/SERVICE     → 前台服务没生效（进程被当 cached 冻住）→ 查 startForeground
         * - 心跳=无记录                        → 进程被系统杀过
         */
        fun heartbeatReport(): String {
            val now = System.currentTimeMillis()
            val fmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            synchronized(heartbeats) {
                if (heartbeats.isEmpty()) {
                    return "心跳=无记录（进程可能刚被系统杀掉重启过）"
                }
                val list = heartbeats.toList()
                var maxGap = 0L
                var gapIdx = -1
                for (i in 1 until list.size) {
                    val g = list[i].at - list[i - 1].at
                    if (g > maxGap) {
                        maxGap = g
                        gapIdx = i - 1
                    }
                }
                val last = list.last()
                val gapWarn = if (maxGap > HEARTBEAT_INTERVAL_MS * 3) {
                    val before = if (gapIdx >= 0) importanceName(list[gapIdx].importance) else "?"
                    " ⚠️后台被挂起${maxGap / 1000}s（挂起前进程优先级=$before）"
                } else ""
                return "心跳=采样${list.size}个 最后=${fmt.format(Date(last.at))}(${(now - last.at) / 1000}s 前)" +
                    " 最大空档=${maxGap / 1000}s$gapWarn"
            }
        }
    }
}
