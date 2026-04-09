package com.example.chatroom.ui.chat

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageButton
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.SessionManager
import com.example.chatroom.participants.PtyParticipant
import com.example.chatroom.participants.AiParticipant
import com.example.chatroom.participants.SerialParticipant
import com.example.chatroom.participants.SocketParticipant
import com.example.chatroom.participants.SocketType
import com.google.android.material.button.MaterialButton

class ChatFragment : Fragment() {

    private var sessionId: String = ""
    private lateinit var adapter: MessageAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var editInput: EditText
    private lateinit var btnSend: MaterialButton
    private lateinit var btnAttach: ImageButton

    private val activeParticipants = mutableMapOf<String, Any>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sessionId = arguments?.getString("sessionId") ?: ""
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_chat, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        recyclerView = view.findViewById(R.id.recyclerMessages)
        editInput = view.findViewById(R.id.editInput)
        btnSend = view.findViewById(R.id.btnSend)
        btnAttach = view.findViewById(R.id.btnAttach)

        adapter = MessageAdapter()
        recyclerView.layoutManager = LinearLayoutManager(requireContext()).apply {
            stackFromEnd = true
        }
        recyclerView.adapter = adapter

        // 连接所有参与者（会打印"xxx 已加入"系统消息）
        connectParticipants()

        // 加载历史消息（首次全部提交）
        val initial = SessionManager.getMessages(sessionId).toList()
        adapter.submitList(initial)
        recyclerView.scrollToPosition(initial.size - 1)

        // 发送按钮
        btnSend.setOnClickListener {
            val text = editInput.text?.toString() ?: ""
            if (text.isNotEmpty()) {
                // 显示发送info（所有人都有）
                val sendInfo = Message(
                    senderId = "self",
                    senderType = ParticipantType.SOCKET,
                    senderName = "我",
                    content = "📤 发送: $text",
                    isInfo = true
                )
                SessionManager.addMessage(sessionId, sendInfo)

                // 广播给各参与者
                broadcastToParticipants(text)

                // 清输入框并刷新
                editInput.text?.clear()
                val msgs = SessionManager.getMessages(sessionId).toList()
                adapter.submitList(msgs)
                recyclerView.scrollToPosition(msgs.size - 1)
            }
        }

        btnAttach.setOnClickListener {
            // TODO: 文件选择
        }
    }

    private fun connectParticipants() {
        val configs = SessionManager.getParticipants(sessionId)

        configs.forEach { config ->
            val joinMsg = Message(
                senderId = "system",
                senderType = config.type,
                senderName = "系统",
                content = "${config.type.icon} ${config.name} 已加入会话",
                isInfo = true
            )
            SessionManager.addMessage(sessionId, joinMsg)

            when (config.type) {
                ParticipantType.PTY -> {
                    val device = config.params["device"] ?: "/dev/ptmx"
                    val shell = config.params["shell"] ?: "/system/bin/sh"
                    val pty = PtyParticipant(sessionId) { msg ->
                        SessionManager.addMessage(sessionId, msg)
                        val msgs = SessionManager.getMessages(sessionId).toList()
                        adapter.submitList(msgs)
                        recyclerView.post {
                            recyclerView.scrollToPosition(msgs.size - 1)
                        }
                    }
                    pty.connect(device, shell)
                    activeParticipants[config.id] = pty
                }
                ParticipantType.SOCKET -> {
                    val ip = config.params["ip"] ?: ""
                    val port = config.params["port"]?.toIntOrNull() ?: 0
                    val sockTypeStr = config.params["sockType"] ?: "TCP"
                    val sockType = try { SocketType.valueOf(sockTypeStr) } catch (e: Exception) { SocketType.TCP }
                    if (ip.isNotBlank() && port > 0) {
                        val socket = SocketParticipant(sessionId, ip, port, sockType) { msg ->
                            SessionManager.addMessage(sessionId, msg)
                            val msgs = SessionManager.getMessages(sessionId).toList()
                            adapter.submitList(msgs)
                            recyclerView.post {
                                recyclerView.scrollToPosition(msgs.size - 1)
                            }
                        }
                        socket.connect()
                        activeParticipants[config.id] = socket
                    } else {
                        val msg = Message(
                            senderId = "system",
                            senderType = ParticipantType.SOCKET,
                            senderName = "系统",
                            content = "❌ SOCKET 配置错误：需要 ip 和 port",
                            isInfo = true
                        )
                        SessionManager.addMessage(sessionId, msg)
                    }
                }
                ParticipantType.SERIAL -> {
                    val device = config.params["device"] ?: ""
                    val baud = config.params["baud"]?.toIntOrNull() ?: 115200
                    if (device.isNotBlank()) {
                        val serial = SerialParticipant(sessionId, device, baud) { msg ->
                            SessionManager.addMessage(sessionId, msg)
                            val msgs = SessionManager.getMessages(sessionId).toList()
                            adapter.submitList(msgs)
                            recyclerView.post {
                                recyclerView.scrollToPosition(msgs.size - 1)
                            }
                        }
                        serial.connect()
                        activeParticipants[config.id] = serial
                    } else {
                        val msg = Message(
                            senderId = "system",
                            senderType = ParticipantType.SERIAL,
                            senderName = "系统",
                            content = "❌ SERIAL 配置错误：需要 device",
                            isInfo = true
                        )
                        SessionManager.addMessage(sessionId, msg)
                    }
                }
                ParticipantType.AI -> {
                    val ip = config.params["ip"] ?: ""
                    val port = config.params["port"] ?: ""
                    val apiKey = config.params["apiKey"] ?: ""
                    val model = config.params["model"] ?: ""
                    if (ip.isNotBlank() && port.isNotBlank()) {
                        val ai = AiParticipant(sessionId, ip, port, apiKey, model) { msg ->
                            SessionManager.addMessage(sessionId, msg)
                            val msgs = SessionManager.getMessages(sessionId).toList()
                            adapter.submitList(msgs)
                            recyclerView.post {
                                recyclerView.scrollToPosition(msgs.size - 1)
                            }
                        }
                        ai.connect()
                        activeParticipants[config.id] = ai
                    } else {
                        val msg = Message(
                            senderId = "system",
                            senderType = ParticipantType.AI,
                            senderName = "系统",
                            content = "❌ AI 配置错误：需要 ip 和 port",
                            isInfo = true
                        )
                        SessionManager.addMessage(sessionId, msg)
                    }
                }
                else -> {
                    // TODO: 其他类型
                }
            }
        }

        if (configs.isEmpty()) {
            val msg = Message(
                senderId = "system",
                senderType = ParticipantType.SOCKET,
                senderName = "系统",
                content = "该会话没有任何参与者",
                isInfo = true
            )
            SessionManager.addMessage(sessionId, msg)
        }

        val msgs = SessionManager.getMessages(sessionId).toList()
        adapter.submitList(msgs)
        recyclerView.scrollToPosition(msgs.size - 1)
    }

    /** 广播消息给所有参与者 */
    private fun broadcastToParticipants(text: String) {
        val configs = SessionManager.getParticipants(sessionId)
        configs.forEach { config ->
            when (config.type) {
                ParticipantType.PTY -> {
                    (activeParticipants[config.id] as? PtyParticipant)?.sendInput(text)
                }
                ParticipantType.SOCKET -> {
                    (activeParticipants[config.id] as? SocketParticipant)?.sendInput(text)
                }
                ParticipantType.SERIAL -> {
                    (activeParticipants[config.id] as? SerialParticipant)?.sendInput(text)
                }
                ParticipantType.AI -> {
                    (activeParticipants[config.id] as? AiParticipant)?.sendInput(text)
                }
                else -> {
                    // TODO
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        activeParticipants.values.forEach { participant ->
            (participant as? PtyParticipant)?.disconnect()
        }
        activeParticipants.clear()
    }

    companion object {
        fun newInstance(sessionId: String): ChatFragment {
            return ChatFragment().apply {
                arguments = Bundle().apply {
                    putString("sessionId", sessionId)
                }
            }
        }
    }
}
