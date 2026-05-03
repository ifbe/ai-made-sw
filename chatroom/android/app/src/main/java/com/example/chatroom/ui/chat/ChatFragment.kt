package com.example.chatroom.ui.chat

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Spinner
import com.example.chatroom.ui.common.AxisView
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.SessionManager
import com.example.chatroom.participants.AiParticipant
import com.example.chatroom.participants.PtyParticipant
import com.example.chatroom.participants.SerialParticipant
import com.example.chatroom.participants.SocketParticipant
import com.example.chatroom.participants.SocketType

enum class ChatInputMode { TEXT, REMOTE, DIM3, VOICE, FILE }

class ChatFragment : Fragment() {

    private var sessionId: String = ""
    private lateinit var adapter: MessageAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var editInput: EditText
    private lateinit var btnSend: MaterialButton
    private val activeParticipants = mutableMapOf<String, Any>()

    private lateinit var inputBarText: View
    private lateinit var inputBarRemote: View
    private lateinit var inputBarVoice: View
    private lateinit var inputBarFile: View
    private lateinit var inputBarDim3: View

    private var currentInputMode = ChatInputMode.TEXT

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

        inputBarText = view.findViewById(R.id.inputBarText)
        inputBarRemote = view.findViewById(R.id.inputBarRemote)
        inputBarVoice = view.findViewById(R.id.inputBarVoice)
        inputBarFile = view.findViewById(R.id.inputBarFile)
        inputBarDim3 = view.findViewById(R.id.inputBarDim3)

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

        setupInputModeSpinners()
        setupRemoteControls()
        setupNumPad()

        // 发送按钮
        btnSend.setOnClickListener {
            val text = editInput.text?.toString() ?: ""
            if (text.isNotEmpty()) {
                // 气泡消息（显示在上方）
                val sendBubble = Message(
                    senderId = "self",
                    senderType = ParticipantType.USER,
                    senderName = "我",
                    content = text,
                    isInfo = false
                )
                // 灰字消息（显示在下方）
                val sendInfo = Message(
                    senderId = "self",
                    senderType = ParticipantType.USER,
                    senderName = "我",
                    content = "📤 发送: $text",
                    isInfo = true
                )
                SessionManager.addMessage(sessionId, sendBubble)
                SessionManager.addMessage(sessionId, sendInfo)
                broadcastToParticipants(text)
                editInput.text?.clear()
                val msgs = SessionManager.getMessages(sessionId).toList()
                adapter.submitList(msgs)
                recyclerView.scrollToPosition(msgs.size - 1)
            }
        }
    }

    private fun setupInputModeSpinners() {
        val v = requireView()
        val modes = listOf("📝文字", "🎮遥控", "📐三维", "🎤语音", "📁文件")

        fun configureSpinner(spinner: Spinner) {
            val selAdapter = ArrayAdapter(requireContext(), R.layout.spinner_selected, modes)
            val dropAdapter = ArrayAdapter(requireContext(), R.layout.spinner_dropdown, modes)
            spinner.adapter = selAdapter
            spinner.setSelection(currentInputMode.ordinal, false)
        }

        configureSpinner(v.findViewById<Spinner>(R.id.spinnerInputMode))
        configureSpinner(v.findViewById<Spinner>(R.id.spinnerInputModeRemote))
        configureSpinner(v.findViewById<Spinner>(R.id.spinnerInputModeDim3))
        configureSpinner(v.findViewById<Spinner>(R.id.spinnerInputModeVoice))
        configureSpinner(v.findViewById<Spinner>(R.id.spinnerInputModeFile))

        val allSpinners = listOf(
            v.findViewById<Spinner>(R.id.spinnerInputMode),
            v.findViewById<Spinner>(R.id.spinnerInputModeRemote),
            v.findViewById<Spinner>(R.id.spinnerInputModeDim3),
            v.findViewById<Spinner>(R.id.spinnerInputModeVoice),
            v.findViewById<Spinner>(R.id.spinnerInputModeFile)
        )

        fun syncSpinners(selected: ChatInputMode) {
            currentInputMode = selected
            allSpinners.forEach { it.setSelection(selected.ordinal, true) }

            inputBarText.visibility = if (selected == ChatInputMode.TEXT) View.VISIBLE else View.GONE
            inputBarRemote.visibility = if (selected == ChatInputMode.REMOTE) View.VISIBLE else View.GONE
            inputBarVoice.visibility = if (selected == ChatInputMode.VOICE) View.VISIBLE else View.GONE
            inputBarDim3.visibility = if (selected == ChatInputMode.DIM3) View.VISIBLE else View.GONE
            inputBarFile.visibility = if (selected == ChatInputMode.FILE) View.VISIBLE else View.GONE
        }

        allSpinners.forEach { spinner ->
            spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, pos: Int, id: Long) {
                    syncSpinners(ChatInputMode.entries[pos])
                }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
        }

        // 初始化显示
        syncSpinners(ChatInputMode.TEXT)
    }

    private fun setupRemoteControls() {
        val v = requireView()
        val directions = listOf(
            R.id.btnRemoteUp to "↑",
            R.id.btnRemoteDown to "↓",
            R.id.btnRemoteLeft to "←",
            R.id.btnRemoteRight to "→",
            R.id.btnRemoteUpLeft to "↖",
            R.id.btnRemoteUpRight to "↗",
            R.id.btnRemoteDownLeft to "↙",
            R.id.btnRemoteDownRight to "↘",
            R.id.btnRemoteCenter to "◉"
        )

        directions.forEach { (btnId, label) ->
            v.findViewById<TextView>(btnId)!!.setOnClickListener {
                val sendBubble = Message(
                    senderId = "self",
                    senderType = ParticipantType.USER,
                    senderName = "我",
                    content = label,
                    isInfo = false
                )
                val sendInfo = Message(
                    senderId = "self",
                    senderType = ParticipantType.USER,
                    senderName = "我",
                    content = "📤 发送: $label",
                    isInfo = true
                )
                SessionManager.addMessage(sessionId, sendBubble)
                SessionManager.addMessage(sessionId, sendInfo)
                broadcastToParticipants(label)
                val msgs = SessionManager.getMessages(sessionId).toList()
                adapter.submitList(msgs)
                recyclerView.scrollToPosition(msgs.size - 1)
            }
        }

        setupDim3Controls()
    }

    private fun setupDim3Controls() {
        val v = requireView()


        // 上箭头和下箭头（上下移动）
        listOf(R.id.btnDim3Up to "+", R.id.btnDim3DownBtn to "-").forEach { (btnId, label) ->
            v.findViewById<TextView>(btnId)!!.setOnClickListener {
                sendMessage(label)
            }
        }


        // 3x3方向键
        val dim3Directions = listOf(
            R.id.btnDim3UpLeft to "↖", R.id.btnDim3Up2 to "↑", R.id.btnDim3UpRight to "↗",
            R.id.btnDim3Left to "←", R.id.btnDim3Center to "◉", R.id.btnDim3Right to "→",
            R.id.btnDim3DownLeft to "↙", R.id.btnDim3Down to "↓", R.id.btnDim3DownRight to "↘"
        )
        dim3Directions.forEach { (btnId, label) ->
            v.findViewById<TextView>(btnId)!!.setOnClickListener {
                sendMessage(label)
            }
        }

        // 坐标轴 6 轴旋转按钮
        val axisView = v.findViewById<AxisView>(R.id.axisViewDim3)
        axisView?.listener = object : AxisView.OnRotationClickListener {
            override fun onXRotateCW()  { sendMessage("X+⟳") }
            override fun onXRotateCCW() { sendMessage("X-⟲") }
            override fun onYRotateCW()  { sendMessage("Y+⟳") }
            override fun onYRotateCCW() { sendMessage("Y-⟲") }
            override fun onZRotateCW()  { sendMessage("Z+⟳") }
            override fun onZRotateCCW() { sendMessage("Z-⟲") }
        }
    }

    private fun sendMessage(label: String) {
        val sendBubble = Message(
            senderId = "self",
            senderType = ParticipantType.USER,
            senderName = "我",
            content = label,
            isInfo = false
        )
        val sendInfo = Message(
            senderId = "self",
            senderType = ParticipantType.USER,
            senderName = "我",
            content = "📤 发送: $label",
            isInfo = true
        )
        SessionManager.addMessage(sessionId, sendBubble)
        SessionManager.addMessage(sessionId, sendInfo)
        broadcastToParticipants(label)
        val msgs = SessionManager.getMessages(sessionId).toList()
        adapter.submitList(msgs)
        recyclerView.scrollToPosition(msgs.size - 1)
    }

    private fun setupNumPad() {
        val v = requireView()
        val numDirections = listOf(
            R.id.btnNum1 to "1", R.id.btnNum2 to "2", R.id.btnNum3 to "3",
            R.id.btnNum4 to "4", R.id.btnNum5 to "5", R.id.btnNum6 to "6",
            R.id.btnNum7 to "7", R.id.btnNum8 to "8", R.id.btnNum9 to "9"
        )

        numDirections.forEach { (btnId, label) ->
            v.findViewById<TextView>(btnId)!!.setOnClickListener {
                val sendBubble = Message(
                    senderId = "self",
                    senderType = ParticipantType.USER,
                    senderName = "我",
                    content = label,
                    isInfo = false
                )
                val sendInfo = Message(
                    senderId = "self",
                    senderType = ParticipantType.USER,
                    senderName = "我",
                    content = "📤 发送: $label",
                    isInfo = true
                )
                SessionManager.addMessage(sessionId, sendBubble)
                SessionManager.addMessage(sessionId, sendInfo)
                broadcastToParticipants(label)
                val msgs = SessionManager.getMessages(sessionId).toList()
                adapter.submitList(msgs)
                recyclerView.scrollToPosition(msgs.size - 1)
            }
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
