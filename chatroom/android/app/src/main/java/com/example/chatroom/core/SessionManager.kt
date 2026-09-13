package com.example.chatroom.core

import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * 管理所有活跃 Session。
 *
 * 内存数据在进程被杀后清空，因此这里在每次会话 / 参与者变更时调 [persist] 落盘
 * （见 [SessionStore]），下次启动由 [restoreFromStore] 恢复。恢复出来的会话
 * 连接状态一律是 false，需要用户在聊天页展开重连面板手动重连。
 */
object SessionManager {

    // sessionId -> participants 配置列表
    val sessions = ConcurrentHashMap<String, MutableList<ParticipantConfig>>()

    // sessionId -> 聊天消息
    val messages = ConcurrentHashMap<String, MutableList<Message>>()

    // sessionId -> 当前输入模式
    val inputModes = ConcurrentHashMap<String, InputMode>()

    /**
     * 会话创建顺序。ConcurrentHashMap 不保证迭代顺序，tab 顺序 / 落盘顺序
     * 都依赖它，所以单独维护一份有序列表。
     */
    private val order = Collections.synchronizedList(mutableListOf<String>())

    /** sessionId -> 是否已连接。纯进程内状态：新建会话 = true，落盘恢复 = false */
    private val connected = ConcurrentHashMap<String, Boolean>()

    /**
     * sessionId -> 网络连接是否活着（由 TcpForegroundService 在 participant 连上/失败/断开时报告）。
     * 缺失 = 该会话没有网络 participant（纯 ECHO/PTY 等），视为正常。
     */
    private val linkUp = ConcurrentHashMap<String, Boolean>()

    fun createSession(): String {
        val id = "session_${System.currentTimeMillis()}"
        sessions[id] = mutableListOf()
        messages[id] = mutableListOf()
        inputModes[id] = InputMode.TEXT
        synchronized(order) { if (!order.contains(id)) order.add(id) }
        connected[id] = true   // 新建即连接，保持旧行为
        persist()
        return id
    }

    /**
     * 进程重启后从磁盘恢复一个会话：参与者配置在、消息为空、连接状态 = 未连接。
     * 本次进程内已存在（刚创建过）则忽略。
     */
    fun restoreSession(sessionId: String, participants: List<ParticipantConfig>) {
        if (sessions.containsKey(sessionId)) return
        sessions[sessionId] = participants.toMutableList()
        messages[sessionId] = mutableListOf()
        inputModes[sessionId] = InputMode.TEXT
        synchronized(order) { if (!order.contains(sessionId)) order.add(sessionId) }
        connected[sessionId] = false
    }

    /** MainActivity.onCreate 调：把上次进程落盘的会话全部恢复到内存，返回恢复的 id 列表 */
    fun restoreFromStore(): List<String> {
        val restored = SessionStore.load()
        restored.forEach { restoreSession(it.id, it.participants) }
        return restored.map { it.id }
    }

    fun removeSession(sessionId: String) {
        sessions.remove(sessionId)
        messages.remove(sessionId)
        inputModes.remove(sessionId)
        connected.remove(sessionId)
        linkUp.remove(sessionId)
        synchronized(order) { order.remove(sessionId) }
        persist()
    }

    /** 按创建顺序返回会话 id 列表（tab 顺序 = 这个顺序） */
    fun getSessionOrder(): List<String> = synchronized(order) { order.toList() }

    /** 会话当前是否已连接（恢复出来的会话为 false） */
    fun isSessionConnected(sessionId: String): Boolean = connected[sessionId] ?: false

    /** 连接 / 断开状态标记。注意不落盘：重启后必然回到未连接 */
    fun setSessionConnected(sessionId: String, value: Boolean) {
        connected[sessionId] = value
    }

    /** TcpForegroundService 报告某会话的网络链路状态（连带触发 tab 文案刷新） */
    fun setSessionLinkUp(sessionId: String, up: Boolean) {
        linkUp[sessionId] = up
    }

    /**
     * 会话是否处于「正常」状态（tab 名字不加删除线）。
     * = 已激活（新建 / 手动重连过）且网络链路没报告过失败；
     * 没有网络 participant 的会话（纯 ECHO/PTY/AI…）没有链路可失败，视为正常。
     */
    fun isSessionUp(sessionId: String): Boolean {
        if (!isSessionConnected(sessionId)) return false
        return linkUp[sessionId] ?: true
    }

    fun addParticipant(sessionId: String, config: ParticipantConfig) {
        sessions[sessionId]?.add(config)
        persist()
    }

    fun removeParticipant(sessionId: String, participantId: String) {
        sessions[sessionId]?.removeAll { it.id == participantId }
        persist()
    }

    fun addMessage(sessionId: String, message: Message) {
        messages.getOrPut(sessionId) { mutableListOf() }.add(message)
    }

    fun getMessages(sessionId: String): List<Message> {
        return messages[sessionId] ?: emptyList()
    }

    fun getParticipants(sessionId: String): List<ParticipantConfig> {
        return sessions[sessionId] ?: emptyList()
    }

    fun setInputMode(sessionId: String, mode: InputMode) {
        inputModes[sessionId] = mode
    }

    fun getInputMode(sessionId: String): InputMode {
        return inputModes[sessionId] ?: InputMode.TEXT
    }

    /** 把当前会话 / 参与者配置落盘（消息不落盘） */
    fun persist() {
        val snapshot = getSessionOrder().map { sid ->
            PersistedSession(
                id = sid,
                createdAt = sid.removePrefix("session_").toLongOrNull() ?: 0L,
                participants = sessions[sid]?.toList() ?: emptyList()
            )
        }
        SessionStore.save(snapshot)
    }
}
