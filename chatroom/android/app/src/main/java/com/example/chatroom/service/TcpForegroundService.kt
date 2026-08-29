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
import android.os.IBinder
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
import java.util.concurrent.ConcurrentHashMap

/**
 * 承载所有 TCP 连接的前台服务。
 *
 * 解决的问题：应用切到后台后，进程被 LMK 杀掉或被 Doze 冻结 → TCP socket 跟着死。
 * 通过前台服务 + PARTIAL_WAKE_LOCK，让进程在后台保持运行、socket 不会断。
 * **完全靠业务数据流保活**，不发送任何心跳/探针/魔术字节，绝不污染用户数据流。
 *
 * 触发规则：
 * - 第一个 TCP 加入时 → startForeground + 通知 + 拿 wake lock
 * - 最后一个 TCP 离开时 → stopForeground + stopSelf + 放 wake lock
 * - 没有 TCP 时 service 不存在（用户开 PTY-only 会话时不打扰）
 *
 * 生命周期：
 * - service 由第一个 ChatFragment 启动，被 `bindService(BIND_AUTO_CREATE)` 拉起
 * - service 内的 SocketParticipant 持续读 message：
 *   1. 存到 SessionManager（fragment 重建后能拿历史）
 *   2. 路由到当前活跃的 callback（如果 fragment 还活着）
 * - fragment 切换（onStop）→ unregisterCallback，service 内 SocketParticipant 继续跑
 * - fragment 重新显示（onStart）→ registerCallback，从 SessionManager 拿历史
 */
class TcpForegroundService : Service() {

    private val binder = LocalBinder()
    private val participants = ConcurrentHashMap<String, SocketParticipant>()  // configId -> participant
    private val callbacks = ConcurrentHashMap<String, (Message) -> Unit>()     // sessionId -> 当前活跃 fragment 的回调
    private val configToSession = ConcurrentHashMap<String, String>()          // configId -> sessionId（生命周期不依赖 callbacks 泅否清空）

    private var wakeLock: PowerManager.WakeLock? = null
    /** 记录 startForeground 是否成功跑过（用来诊断 onDestroy 原因） */
    private var startedFlag = false

    inner class LocalBinder : Binder() {
        fun getService(): TcpForegroundService = this@TcpForegroundService
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        Log.w(TAG, "onCreate")
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
        Log.w(TAG, "onStartCommand: flags=$flags startId=$startId intent=${intent?.action}, " +
            "startedFlag=$startedFlag count=${participants.size}")
        return START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        super.onDestroy()
        val count = participants.size
        val reason = detectDestroyReason()
        Log.w(TAG, "onDestroy! disconnecting $count participants, reason=$reason", Throwable("onDestroy stack"))
        // 兜底：所有 participant 都断开
        participants.values.forEach { it.disconnect() }
        participants.clear()
        callbacks.clear()
        wakeLock?.let { if (it.isHeld) it.release() }
        // 推到聊天区：onDestroy = 进程保活失效
        postErrorToChat("❌ TcpForegroundService.onDestroy\n" +
            "count=$count 原因=$reason\n" +
            "→ TCP 连接被主动断开，需要重新进入会话才能重连")
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
     * ChatFragment 调用：增加一个 TCP participant。
     * - 如果同 sessionId 已存在 participant，直接返回（幂等）
     * - 如果是第一个 TCP，启前台 + 拿 wake lock
     */
    fun addTcpParticipant(
        configId: String,
        sessionId: String,
        ip: String,
        port: Int,
        onMessage: (Message) -> Unit
    ): SocketParticipant {
        Log.i(TAG, "addTcpParticipant: configId=$configId $ip:$port, before count=${participants.size}")
        configToSession[configId] = sessionId
        callbacks[sessionId] = onMessage

        // 同 configId 已存在 → 复用
        participants[configId]?.let { return it }

        val participant = SocketParticipant(sessionId, ip, port, SocketType.TCP) { msg ->
            // message 路径：
            //   1. 存 SessionManager（保证 fragment 重建后能拿到历史）
            //   2. 路由给当前活跃的 callback（如果 fragment 还活着）
            SessionManager.addMessage(sessionId, msg)
            callbacks[sessionId]?.invoke(msg)
        }
        participants[configId] = participant

        if (participants.size == 1) {
            startInForeground()
            acquireWakeLock()
        } else {
            updateNotification()
        }
        participant.connect()
        Log.i(TAG, "addTcpParticipant: done, after count=${participants.size}")
        return participant
    }

    /**
     * ChatFragment 调用：移除一个 TCP participant。
     * - 如果是最后一个，stopForeground + stopSelf
     */
    fun removeTcpParticipant(configId: String, sessionId: String) {
        callbacks.remove(sessionId)
        configToSession.remove(configId)
        participants.remove(configId)?.disconnect()

        if (participants.isEmpty()) {
            stopInForeground()
            stopSelf()
            releaseWakeLock()
        } else {
            updateNotification()
        }
    }

    fun sendInput(configId: String, text: String) {
        participants[configId]?.sendInput(text)
    }

    fun hasTcpParticipants(): Boolean = participants.isNotEmpty()

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
            Log.i(TAG, "startForeground OK, count=${participants.size}")
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
        val count = participants.size
        val title = "Chatroom"
        val text = if (count == 1) {
            "1 个 TCP 连接运行中"
        } else {
            "$count 个 TCP 连接运行中"
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

    private fun acquireWakeLock() {
        wakeLock?.acquire(WAKE_LOCK_TIMEOUT_MS)
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
    }

    companion object {
        const val NOTIFICATION_ID = 7777
        const val CHANNEL_ID = "chatroom_tcp_foreground"
        private const val WAKE_LOCK_TIMEOUT_MS = 10 * 60 * 1000L  // 10 分钟超时（系统会自动续 acquire）
        private const val TAG = "TcpFgService"
    }
}
