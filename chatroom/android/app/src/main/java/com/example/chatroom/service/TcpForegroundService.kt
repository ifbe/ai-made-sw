package com.example.chatroom.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.chatroom.MainActivity
import com.example.chatroom.R
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.SessionManager
import com.example.chatroom.participants.SocketParticipant
import com.example.chatroom.participants.SocketType
import com.example.chatroom.participants.WsParticipant
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * 承载所有「网络 socket」参与者（TCP / WS / UDP）的前台服务。
 *
 * 解决的问题：应用切到后台后，进程被 LMK 杀掉或被 Doze 冻结 → 网络 socket 跟着死。
 * 通过前台服务 + PARTIAL_WAKE_LOCK，让进程在后台保持运行、socket 不会断。
 * **完全靠业务数据流保活**，不发送任何心跳/探针/魔术字节，绝不污染用户数据流。
 *
 * 触发规则：
 * - 第一个网络参与者加入时 → startForeground + 通知 + 拿 wake lock
 * - 最后一个网络参与者离开时 → stopForeground + stopSelf + 放 wake lock
 * - 没有网络参与者时 service 不存在（用户开纯 PTY/AI 会话时不打扰）
 *
 * 生命周期：
 * - service 由第一个 ChatFragment 启动，先 startForegroundService 再 bindService（仿 locate）
 * - service 内的各 participant 持续读 message：
 *   1. 存到 SessionManager（fragment 重建后能拿历史）
 *   2. 路由到当前活跃的 callback（如果 fragment 还活着）
 * - fragment 切换（onStop）→ unregisterCallback，service 内 participant 继续跑
 * - fragment 重新显示（onStart）→ registerCallback，从 SessionManager 拿历史
 *
 * 不在本服务里管的：SERIAL（/dev/ttyS* 本机 fd）、PTY（/dev/ptmx 本机 fd）、
 * AI（HTTP 短连）、ECHO（纯内存）、AGENT（一次性 HTTP）。这些不受 Doze 影响，
 * 留在 fragment 里跑更轻量。
 */
class TcpForegroundService : Service() {

    private val binder = LocalBinder()
    /** TCP participants（SocketType.TCP） */
    private val participants = ConcurrentHashMap<String, SocketParticipant>()
    /** WS participants（OkHttp WebSocket） */
    private val wsParticipants = ConcurrentHashMap<String, WsParticipant>()
    /** UDP participants（SocketType.UDP，复用 SocketParticipant 实现） */
    private val udpParticipants = ConcurrentHashMap<String, SocketParticipant>()
    private val callbacks = ConcurrentHashMap<String, (Message) -> Unit>()     // sessionId -> 当前活跃 fragment 的回调
    private val configToSession = ConcurrentHashMap<String, String>()          // configId -> sessionId（生命周期不依赖 callbacks 泅否清空）

    /** 当前已连上的网络 configId（算「会话链路是否正常」用） */
    private val upConfigs: MutableSet<String> =
        Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    /** sessionId -> 链路状态变化回调（ChatFragment 注册，用来刷新 tab 的删除线） */
    private val linkStateCallbacks = ConcurrentHashMap<String, (Boolean) -> Unit>()

    /** 网络参与者总数（TCP + WS + UDP），用于 startForeground / wake lock 生命周期判断 */
    private val networkParticipantsCount: Int
        get() = participants.size + wsParticipants.size + udpParticipants.size

    private var wakeLock: PowerManager.WakeLock? = null
    /** 记录 startForeground 是否成功跑过（用来诊断 onDestroy 原因） */
    private var startedFlag = false

    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * onStartCommand 时还没有任何网络 participant 的延迟兜底：
     * 给 onServiceConnected 里 addXxx 一点时间，到点还是没有就撤前台 + stopSelf。
     */
    private val stopIfEmptyRunnable = Runnable {
        if (networkParticipantsCount == 0) {
            Log.w(TAG, "onStartCommand 后 ${EMPTY_CHECK_DELAY_MS}ms 仍无网络 participant，stopForeground + stopSelf")
            stopInForeground()
            stopSelf()
        }
    }

    inner class LocalBinder : Binder() {
        fun getService(): TcpForegroundService = this@TcpForegroundService
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        Log.w(TAG, "onCreate")
        isRunning = true
        wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Chatroom:TcpWakeLock")
    }

    /**
     * 用户从"最近任务"列表里滑掉 app 时调（不是按 Home 键）
     * 不处理的话 service 会跟着进程被 destroy
     * 重启 service 让 TCP 继续在后台保持
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.w(TAG, "onTaskRemoved!  user swiped app from recents, restarting service")
        val restart = Intent(applicationContext, TcpForegroundService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                applicationContext.startForegroundService(restart)
            } else {
                applicationContext.startService(restart)
            }
            Log.i(TAG, "onTaskRemoved: restart intent sent")
        } catch (e: Exception) {
            Log.e(TAG, "onTaskRemoved: restart FAILED: ${e.javaClass.simpleName}: ${e.message}", e)
            postErrorToChat("❌ onTaskRemoved 重启 service 失败: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.w(TAG, "onStartCommand: flags=$flags startId=$startId action=${intent?.action}, " +
            "startedFlag=$startedFlag count=${networkParticipantsCount}")

        // MainActivity 关 tab 时，如果 fragment 已经回收/没绑定，会发这个 action 让我们自己清理。
        // 这条路径不是 startForegroundService 拉的，所以不需要走下面的 startForeground() 契约。
        if (intent?.action == ACTION_REMOVE_SESSION) {
            val sessionId = intent.getStringExtra(EXTRA_SESSION_ID)
            if (sessionId != null) removeSessionParticipants(sessionId)
            return START_STICKY
        }

        // ⚠️ 只要是被 startForegroundService() 拉起来的，就必须在 5s 内调 startForeground()，
        // 否则系统抛 ForegroundServiceDidNotStartInTimeException 直接把进程干掉（已踩过）。
        // 所以即使当前一个网络 participant 都没有（系统 START_STICKY 自启、fragment 还没来得及
        // addTcpParticipant 等），也要先 startForeground() 满足约束，再撤掉前台状态。
        startInForeground()
        if (networkParticipantsCount > 0) {
            // 仿 locate 的 LocationTrackerService.onStartCommand：
            // 每次被系统回调都重新前台化 + 确保 wake lock 还握着（现在不设超时，见 acquireWakeLock 注释）。
            // service 被 kill 后 START_STICKY 会用 null intent 自启，此时把已存的 participant
            // 重新前台化，service 立刻进入工作状态。
            acquireWakeLock()
        } else {
            // 没有网络 participant，两种可能：
            //   1) fragment 刚 startForegroundService、participant 还在 onServiceConnected 路上（毫秒级）
            //   2) 配置无效 / START_STICKY 自启但内存状态已丢，永远不会加
            // 先保持前台一小会儿：期间有 participant 加进来就照常跑（也避免通知闪一下又没），
            // 否则撤掉前台 + 清掉 started 状态（有 binding 时 service 不会立刻销毁）
            mainHandler.removeCallbacks(stopIfEmptyRunnable)
            mainHandler.postDelayed(stopIfEmptyRunnable, EMPTY_CHECK_DELAY_MS)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        val count = networkParticipantsCount
        val reason = detectDestroyReason()
        mainHandler.removeCallbacks(stopIfEmptyRunnable)
        Log.w(TAG, "onDestroy! disconnecting $count participants (tcp=${participants.size} ws=${wsParticipants.size} udp=${udpParticipants.size}), reason=$reason", Throwable("onDestroy stack"))
        // 兜底：所有 participant 都断开（TCP / WS / UDP 都跑这里）
        participants.values.forEach { it.disconnect() }
        wsParticipants.values.forEach { it.disconnect() }
        udpParticipants.values.forEach { it.disconnect() }
        participants.clear()
        wsParticipants.clear()
        udpParticipants.clear()
        callbacks.clear()
        linkStateCallbacks.clear()
        upConfigs.clear()
        wakeLock?.let { if (it.isHeld) it.release() }
        // 推到聊天区：onDestroy = 进程保活失效
        postErrorToChat("❌ TcpForegroundService.onDestroy\n" +
            "count=$count 原因=$reason\n" +
            "→ TCP/WS/UDP 连接被主动断开，需要重新进入会话才能重连")
    }

    /**
     * 推断 onDestroy 的原因（聊天区里给用户看的）
     * - startedFlag=false → startForeground 没成功，service 还是普通后台服务，unbind 时被 destroy
     * - startedFlag=true → 前台服务也被杀（极少见：系统资源极紧张 / 强杀进程）
     */
    private fun detectDestroyReason(): String {
        return if (startedFlag) {
            "前台服务被系统强杀（startedFlag=true）"
        } else {
            "前台服务没启动成功（startedFlag=false）→ 只是普通 service，unbind 后被 destroy"
        }
    }

    /**
     * ChatFragment 调用：注册/更新当前 session 的 message 回调。
     * 同一个 sessionId 后注册的 callback 会覆盖前一个。
     */
    fun registerCallback(sessionId: String, onMessage: (Message) -> Unit) {
        callbacks[sessionId] = onMessage
    }

    fun unregisterCallback(sessionId: String) {
        callbacks.remove(sessionId)
    }

    /**
     * ChatFragment 调用：注册/注销某会话的「链路状态」回调（true=正常 / false=断开或连不上）。
     * 用来刷新 tabbar 上会话名的删除线。回调已在主线程。
     *
     * 注册时会**立刻推一次当前状态**：后台断线时 fragment 已经 unregister（收不到回调），
     * 切回前台重新绑定时要靠这次同步把 tab 的删除线纠正过来。
     */
    fun registerLinkStateCallback(sessionId: String, onLinkState: (Boolean) -> Unit) {
        linkStateCallbacks[sessionId] = onLinkState
        // 没有网络 participant 的会话（纯 ECHO/PTY/AI…）没有链路状态可报，跳过
        if (!configToSession.containsValue(sessionId)) return
        val up = configToSession.entries.any { it.value == sessionId && it.key in upConfigs }
        SessionManager.setSessionLinkUp(sessionId, up)
        mainHandler.post { onLinkState(up) }
    }

    fun unregisterLinkStateCallback(sessionId: String) {
        linkStateCallbacks.remove(sessionId)
    }

    /**
     * 某个网络 participant 的链路状态变了（socket 线程回调）。
     * 聚合到会话级：只要该会话还有任意一个网络 participant 在线，会话就算正常。
     */
    private fun onParticipantLinkChanged(configId: String, sessionId: String, up: Boolean) {
        // participant 已被移除/替换（旧实例的迟到回调）→ 忽略
        if (!hasNetworkParticipant(configId)) {
            upConfigs.remove(configId)
            return
        }
        if (up) upConfigs.add(configId) else upConfigs.remove(configId)
        refreshSessionLinkState(sessionId)
    }

    /** 重新算并广播某会话的链路状态 */
    private fun refreshSessionLinkState(sessionId: String) {
        val up = configToSession.entries.any { it.value == sessionId && it.key in upConfigs }
        SessionManager.setSessionLinkUp(sessionId, up)
        mainHandler.post { linkStateCallbacks[sessionId]?.invoke(up) }
    }

    /**
     * ChatFragment 调用：增加一个 TCP participant。
     * - 如果同 configId 已存在 participant，直接返回（幂等）
     * - 如果是第一个网络参与者，启前台 + 拿 wake lock
     */
    fun addTcpParticipant(
        configId: String,
        sessionId: String,
        ip: String,
        port: Int,
        onMessage: (Message) -> Unit
    ): SocketParticipant {
        Log.i(TAG, "addTcpParticipant: configId=$configId $ip:$port, before net=${networkParticipantsCount}")
        configToSession[configId] = sessionId
        callbacks[sessionId] = onMessage

        // 同 configId 已存在 → 复用
        participants[configId]?.let { return it }

        val participant = SocketParticipant(
            sessionId = sessionId,
            ip = ip,
            port = port,
            sockType = SocketType.TCP,
            onMessage = { msg ->
                // message 路径：
                //   1. 存 SessionManager（保证 fragment 重建后能拿到历史）
                //   2. 路由给当前活跃的 callback（如果 fragment 还活着）
                SessionManager.addMessage(sessionId, msg)
                callbacks[sessionId]?.invoke(msg)
            },
            onStateChange = { up -> onParticipantLinkChanged(configId, sessionId, up) }
        )
        participants[configId] = participant

        if (networkParticipantsCount == 1) {
            ensureStarted()
            startInForeground()
            acquireWakeLock()
        } else {
            updateNotification()
        }
        participant.connect()
        Log.i(TAG, "addTcpParticipant: done, after net=${networkParticipantsCount}")
        return participant
    }

    /**
     * ChatFragment 调用：增加一个 WS participant（OkHttp WebSocket）。
     * - 同 configId 已存在 → 复用（幂等）
     * - 第一个网络参与者 → 启前台 + 拿 wake lock
     */
    fun addWsParticipant(
        configId: String,
        sessionId: String,
        ip: String,
        port: Int,
        path: String,
        onMessage: (Message) -> Unit
    ): WsParticipant {
        Log.i(TAG, "addWsParticipant: configId=$configId $ip:$port$path, before net=${networkParticipantsCount}")
        configToSession[configId] = sessionId
        callbacks[sessionId] = onMessage

        wsParticipants[configId]?.let { return it }

        val participant = WsParticipant(
            sessionId = sessionId,
            ip = ip,
            port = port,
            path = path,
            onMessage = { msg ->
                SessionManager.addMessage(sessionId, msg)
                callbacks[sessionId]?.invoke(msg)
            },
            onStateChange = { up -> onParticipantLinkChanged(configId, sessionId, up) }
        )
        wsParticipants[configId] = participant

        if (networkParticipantsCount == 1) {
            ensureStarted()
            startInForeground()
            acquireWakeLock()
        } else {
            updateNotification()
        }
        participant.connect()
        Log.i(TAG, "addWsParticipant: done, after net=${networkParticipantsCount}")
        return participant
    }

    /**
     * ChatFragment 调用：增加一个 UDP participant（复用 SocketParticipant + SocketType.UDP）。
     * - 同 configId 已存在 → 复用（幂等）
     * - 第一个网络参与者 → 启前台 + 拿 wake lock
     */
    fun addUdpParticipant(
        configId: String,
        sessionId: String,
        ip: String,
        port: Int,
        onMessage: (Message) -> Unit
    ): SocketParticipant {
        Log.i(TAG, "addUdpParticipant: configId=$configId $ip:$port, before net=${networkParticipantsCount}")
        configToSession[configId] = sessionId
        callbacks[sessionId] = onMessage

        udpParticipants[configId]?.let { return it }

        val participant = SocketParticipant(
            sessionId = sessionId,
            ip = ip,
            port = port,
            sockType = SocketType.UDP,
            onMessage = { msg ->
                SessionManager.addMessage(sessionId, msg)
                callbacks[sessionId]?.invoke(msg)
            },
            onStateChange = { up -> onParticipantLinkChanged(configId, sessionId, up) }
        )
        udpParticipants[configId] = participant

        if (networkParticipantsCount == 1) {
            ensureStarted()
            startInForeground()
            acquireWakeLock()
        } else {
            updateNotification()
        }
        participant.connect()
        Log.i(TAG, "addUdpParticipant: done, after net=${networkParticipantsCount}")
        return participant
    }

    /**
     * ChatFragment 调用：移除一个网络 participant（TCP / WS / UDP 都走这里）。
     * configId 全局唯一，依次从三个 map 里试一遍，哪个命中清哪个。
     * - 全部清空后 → stopForeground + stopSelf + 放 wake lock
     */
    fun removeNetworkParticipant(configId: String, sessionId: String) {
        callbacks.remove(sessionId)
        configToSession.remove(configId)
        participants.remove(configId)?.disconnect()
        wsParticipants.remove(configId)?.disconnect()
        udpParticipants.remove(configId)?.disconnect()
        upConfigs.remove(configId)
        refreshSessionLinkState(sessionId)

        if (networkParticipantsCount == 0) {
            stopInForeground()
            stopSelf()
            releaseWakeLock()
        } else {
            updateNotification()
        }
    }

    /**
     * 按 sessionId 清理该会话的所有网络 participant（TCP / WS / UDP）。
     * 走 [ACTION_REMOVE_SESSION] Intent 时用：MainActivity 关 tab 但 fragment 已经回收 / 没绑定时，
     * 只有 service 自己知道哪些 configId 属于这个会话。
     */
    private fun removeSessionParticipants(sessionId: String) {
        callbacks.remove(sessionId)
        val configIds = configToSession.filterValues { it == sessionId }.keys.toList()
        Log.i(TAG, "removeSessionParticipants: sessionId=$sessionId configs=${configIds.size}")
        configIds.forEach { configId ->
            configToSession.remove(configId)
            participants.remove(configId)?.disconnect()
            wsParticipants.remove(configId)?.disconnect()
            udpParticipants.remove(configId)?.disconnect()
            upConfigs.remove(configId)
        }
        refreshSessionLinkState(sessionId)
        mainHandler.removeCallbacks(stopIfEmptyRunnable)
        if (networkParticipantsCount == 0) {
            stopInForeground()
            stopSelf()
            releaseWakeLock()
        } else {
            updateNotification()
        }
    }

    /**
     * 兼容旧名字：等价于 removeNetworkParticipant。
     * 保留是为了避免外部调用方 break，但 ChatFragment 已迁到 removeNetworkParticipant。
     */
    fun removeTcpParticipant(configId: String, sessionId: String) {
        removeNetworkParticipant(configId, sessionId)
    }

    /**
     * 通用 sendInput：TCP / WS / UDP 都接受。
     * 实际发到哪个由 configId 命中哪个 map 决定。
     */
    fun sendInput(configId: String, text: String) {
        participants[configId]?.sendInput(text)
            ?: wsParticipants[configId]?.sendInput(text)
            ?: udpParticipants[configId]?.sendInput(text)
    }

    /**
     * WS 专用的二进制发送（图片等）。TCP / UDP 不走这里。
     */
    fun sendBinaryWs(configId: String, bytes: ByteArray) {
        wsParticipants[configId]?.sendBinary(bytes)
    }

    /** 当前 service 里有没有任何网络参与者（TCP / WS / UDP 任意一个） */
    fun hasNetworkParticipants(): Boolean = networkParticipantsCount > 0

    /** 该 configId 当前是否在 service 里（TCP / WS / UDP 任意一个） */
    fun hasNetworkParticipant(configId: String): Boolean =
        participants.containsKey(configId) ||
            wsParticipants.containsKey(configId) ||
            udpParticipants.containsKey(configId)

    /** 兼容旧名字：等价于 hasNetworkParticipants */
    fun hasTcpParticipants(): Boolean = hasNetworkParticipants()

    /**
     * 把 service 重新标记成 started（这样 fragment unbind 后它仍然存活，socket 不断）。
     *
     * 用在第一个网络 participant 加入时：onStartCommand 在没有 participant 时会 stopSelf()
     * 清掉 started 状态，之后 participant 才加进来，必须在这里补一下。
     * 调用点在 App 前台（用户操作 / onServiceConnected），且 service 本来就在跑，
     * startService 不会被后台启动限制拦；失败只降级为「unbind 后销毁」，不影响当前连接。
     */
    private fun ensureStarted() {
        try {
            startService(Intent(applicationContext, TcpForegroundService::class.java))
        } catch (e: Exception) {
            Log.w(TAG, "ensureStarted failed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun startInForeground() {
        val notification = buildNotification()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            startedFlag = true
            Log.i(TAG, "startForeground OK, net=${networkParticipantsCount}")
        } catch (e: Exception) {
            // API 26+ startForeground 失败会拋异常（权限、type 错误、没在 5s 内调等），
            // 不 catch 整个 service 会被 kill，TCP socket 跟着全断
            Log.e(TAG, "startForeground FAILED: ${e.javaClass.simpleName}: ${e.message}", e)
            // 推一个错误消息到 SessionManager，ChatFragment 下次 onStart 能从 loadMessages 里看到
            postErrorToChat("❌ 前台服务启动失败: ${e.javaClass.simpleName}: ${e.message}\n" +
                "→ 进程在后台可能被 LMK 杀，TCP 会被迫断开")
        }
    }

    /**
     * 把错误 / 警告信息推到 SessionManager，下次 ChatFragment 起来时从 loadMessages 看到。
     * 这样 service 死了或没启动前台，用户还是能在聊天区看到原因。
     */
    private fun postErrorToChat(content: String) {
        // 从 configToSession 拿一个 sessionId（不依赖 callbacks 是否被 unregister 清空）
        val sessionId = configToSession.values.firstOrNull() ?: return
        val msg = Message(
            senderId = "system",
            senderType = ParticipantType.AGENT,
            senderName = "TcpForeground",
            content = content,
            isInfo = true
        )
        SessionManager.addMessage(sessionId, msg)
        // 同时调一下 callback（如果还有活跃 fragment），不活跃的话仅存 SessionManager
        // 下次 ChatFragment 起来 loadMessages 会从 SessionManager 拿到这条消息
        callbacks[sessionId]?.invoke(msg)
    }

    private fun stopInForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun updateNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification())
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val count = networkParticipantsCount
        val title = "Chatroom"
        val text = if (count == 1) {
            "1 个网络连接运行中"
        } else {
            "$count 个网络连接运行中"
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pi)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    /**
     * 拿 wake lock。
     *
     * ⚠️ 这里**故意不加超时**：只要还有网络 participant（= 还有 TCP/WS/UDP 连接），就一直是部分唤醒，
     * 这样按 Home / 锁屏后 CPU 不会被挂起，socket 才能继续收数据。
     * 之前用 `acquire(10min)` + 只在 onStartCommand 里续期 —— 后台时 onStartCommand 不会被调用，
     * 10 分钟后锁自动释放，设备一睡 TCP 就静默断掉（用户反馈的"切回 home 久了连接就没了"）。
     * 代价是耗电，所以 count 归零 / service 销毁时必须 release（调用方保证）。
     * 用 isHeld 判断保证幂等：重复 acquire 不会叠引用计数，release 一次就能真放掉。
     */
    private fun acquireWakeLock() {
        wakeLock?.let { if (!it.isHeld) it.acquire() }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
    }

    companion object {
        const val NOTIFICATION_ID = 7777
        const val CHANNEL_ID = "chatroom_tcp_foreground"

        /** Intent action：让 service 自己清掉某个会话的全部网络 participant（关 tab 时用） */
        const val ACTION_REMOVE_SESSION = "com.example.chatroom.action.REMOVE_SESSION"
        const val EXTRA_SESSION_ID = "sessionId"

        /** service 当前是否活着（供 MainActivity 判断要不要发 [ACTION_REMOVE_SESSION]） */
        @Volatile
        var isRunning: Boolean = false
            private set

        private const val EMPTY_CHECK_DELAY_MS = 2000L  // onStartCommand 无 participant 时的兜底检查延迟
        private const val TAG = "TcpFgService"
    }
}
