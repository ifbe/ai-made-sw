package com.example.chatroom.core

import java.util.concurrent.ConcurrentHashMap

/** 管理所有活跃 Session */
object SessionManager {

    // sessionId -> participants 配置列表
    val sessions = ConcurrentHashMap<String, MutableList<ParticipantConfig>>()

    // sessionId -> 聊天消息
    val messages = ConcurrentHashMap<String, MutableList<Message>>()

    // sessionId -> 当前输入模式
    val inputModes = ConcurrentHashMap<String, InputMode>()

    fun createSession(): String {
        val id = "session_${System.currentTimeMillis()}"
        sessions[id] = mutableListOf()
        messages[id] = mutableListOf()
        inputModes[id] = InputMode.TEXT
        return id
    }

    fun removeSession(sessionId: String) {
        sessions.remove(sessionId)
        messages.remove(sessionId)
        inputModes.remove(sessionId)
    }

    fun addParticipant(sessionId: String, config: ParticipantConfig) {
        sessions[sessionId]?.add(config)
    }

    fun removeParticipant(sessionId: String, participantId: String) {
        sessions[sessionId]?.removeAll { it.id == participantId }
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
}
