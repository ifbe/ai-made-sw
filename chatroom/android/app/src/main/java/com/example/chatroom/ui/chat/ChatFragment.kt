package com.example.chatroom.ui.chat

import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import androidx.core.view.children
import androidx.core.view.updateLayoutParams
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
import com.example.chatroom.service.TcpForegroundService
import com.example.chatroom.ui.common.AxisView
import com.google.android.material.button.MaterialButton

enum class ChatInputMode { EMPTY, TEXT, REMOTE, DIM3, VOICE, FILE }

class ChatFragment : Fragment() {

    private var sessionId: String = ""
    private lateinit var adapter: MessageAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var editInput: EditText
    private lateinit var btnSend: MaterialButton
    private val activeParticipants = mutableMapOf<String, Any>()

    // === TcpForegroundService 绑定（仅 TCP participant 走 service，其他不变）===
    private var tcpService: TcpForegroundService? = null
    private var tcpServiceBound = false

    /**
     * Service 还没连上时，缓存"等下要加入的 TCP 配置"，等 onServiceConnected 再调
     */
    private val pendingTcpConfigs = mutableListOf<PendingTcpConfig>()
    private data class PendingTcpConfig(
        val configId: String,
        val sessionId: String,
        val ip: String,
        val port: Int,
        val sockType: SocketType  // 当前只支持 TCP（UDP 走原路径）
    )

    private lateinit var inputBarText: View
    private lateinit var inputBarRemote: View
    private lateinit var inputBarVoice: View
    private lateinit var inputBarFile: View
    private lateinit var inputBarDim3: View
    private lateinit var inputBarEmpty: View
    private lateinit var emptyText: TextView

    // ===== 新结构相关 =====
    /** 整个输入区（顶部 handle + 5 种 inputBar 区域），高度由 drag / maximize 调整 */
    private lateinit var inputArea: LinearLayout
    /** 顶部 handle 行里的中间 "拖拽" 标签（同时是 touch 热区） */
    private lateinit var handleLabel: TextView
    /** 顶部 handle 行最右边的全屏切换按钮 */
    private lateinit var btnMaximize: TextView
    /** 顶部 handle 行最左边的单一共用 spinner */
    private lateinit var spinnerInputMode: Spinner

    private var currentInputMode = ChatInputMode.TEXT
    /** 是否处于全屏模式：true 时 RecyclerView 隐藏 + inputArea 撑满屏幕 */
    private var isMaximized = false

    // ===== 拖拽状态 =====
    private var dragStartY = 0f
    private var dragStartHeight = 0
    private var isDragging = false
    /** 退出最大化时恢复到上次手动拖出来的高度；如果从未拖动过则用当前模式的最小值 */
    private var lastNonMaximizedHeightPx = 0

    /** 各模式 inputArea 的最小高度（dp），保证该模式的内容不被裁剪 */
    private val minHeightDpByMode = mapOf(
        ChatInputMode.TEXT to 110,    // handle 36 + EditText + Send 等
        ChatInputMode.REMOTE to 200,  // handle 36 + 9 宫格 150 + padding
        ChatInputMode.DIM3 to 280,    // handle 36 + 3D 控制 200 + padding
        ChatInputMode.VOICE to 80,    // handle 36 + TODO
        ChatInputMode.FILE to 80,
        ChatInputMode.EMPTY to 80     // handle 36 + 空白 + padding
    )

    /** handle 行固定高度（dp），同时作为 inputArea 的内置常量 */
    private val handleRowHeightDp = 26

    /** 一行 chat 消息预估高度（dp），用于计算 maxInputArea 高度 */
    private val chatMinRowHeightDp = 60

    /** 本地消息列表（贴底自动滚动的状态机由 RecyclerView.onScrolled 维护） */
    private val messageList = mutableListOf<Message>()
    private var autoScroll = true
    private val autoScrollThreshold = 3

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sessionId = arguments?.getString("sessionId") ?: ""
    }

    // === TcpForegroundService 绑定：onStart bind、onStop unbind ===
    // fragment 不可见时不持有 service 引用，但 service 本身继续在后台跑（保持 socket 不断）
    // fragment 重新可见时再 bind 并 registerCallback
    private val tcpServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val svc = (binder as? TcpForegroundService.LocalBinder)?.getService() ?: return
            tcpService = svc
            tcpServiceBound = true
            // 注册当前 fragment 的 message 回调
            svc.registerCallback(sessionId) { msg ->
                recyclerView.post { appendMessage(msg) }
            }
            // 把等 service 期间的 pending TCP 配置拿出去加入
            pendingTcpConfigs.forEach { p ->
                if (p.sockType == SocketType.TCP) {
                    svc.addTcpParticipant(p.configId, p.sessionId, p.ip, p.port) { msg ->
                        recyclerView.post { appendMessage(msg) }
                    }
                }
                // 注：UDP 暂不进 service（用户明确说 TCP），如果需要可以再加 UDP 路径
            }
            pendingTcpConfigs.clear()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            tcpService = null
            tcpServiceBound = false
        }
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(requireContext(), TcpForegroundService::class.java)
        requireContext().bindService(intent, tcpServiceConnection, Context.BIND_AUTO_CREATE)
        // 切回前台时：从 SessionManager 拿新消息（service 在 onDestroy 写的诊断信息等）
        if (messageList.isNotEmpty()) {
            loadMessages()
        }
    }

    override fun onStop() {
        super.onStop()
        if (tcpServiceBound) {
            tcpService?.unregisterCallback(sessionId)
            try {
                requireContext().unbindService(tcpServiceConnection)
            } catch (e: Exception) {
                // ignore: 可能已经 unbind
            }
            tcpServiceBound = false
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_chat, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        recyclerView = view.findViewById(R.id.recyclerMessages)
        editInput = view.findViewById(R.id.editInput)
        btnSend = view.findViewById(R.id.btnSend)

        inputArea = view.findViewById(R.id.inputArea)
        spinnerInputMode = view.findViewById(R.id.spinnerInputMode)
        handleLabel = view.findViewById(R.id.handleLabel)
        btnMaximize = view.findViewById(R.id.btnMaximize)

        inputBarText = view.findViewById(R.id.inputBarText)
        inputBarRemote = view.findViewById(R.id.inputBarRemote)
        inputBarVoice = view.findViewById(R.id.inputBarVoice)
        inputBarFile = view.findViewById(R.id.inputBarFile)
        inputBarDim3 = view.findViewById(R.id.inputBarDim3)
        inputBarEmpty = view.findViewById(R.id.inputBarEmpty)
        emptyText = view.findViewById(R.id.emptyText)

        adapter = MessageAdapter()
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter

        recyclerView.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                autoScroll = isAtBottom()
            }
        })

        // 先把 SessionManager 里残留的历史消息 load 进 RecyclerView，
        // 否则 connectParticipants 没东西给你看
        loadMessages()
        connectParticipants()

        setupInputModeSpinner()
        setupDragHandle()
        setupMaximizeButton()
        setupRemoteControls()
        setupNumPad()

        // 首次绘制时把 inputArea 高度锁到当前模式最小值，避免残留旧状态导致空白
        view.post { setInputAreaHeightPx(minHeightForCurrentModePx()) }

        btnSend.setOnClickListener {
            val text = editInput.text?.toString() ?: ""
            if (text.isNotEmpty()) {
                sendMessage(text)
                editInput.text?.clear()
            }
        }
    }

    /**
     * 单一 spinner（顶部 handle 行）。任何时刻只有一个 inputBar 可见，所以不需要 5 个互相 sync。
     */
    private fun setupInputModeSpinner() {
        // 2 字显示：emoji + 1 字
        val modes = listOf("⬜空白", "📝文字", "🎮遥控", "📐三维", "🎤语音", "📁文件")
        spinnerInputMode.adapter = ArrayAdapter(requireContext(), R.layout.spinner_selected, modes)
        spinnerInputMode.setSelection(currentInputMode.ordinal, false)
        spinnerInputMode.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                val pickedMode = ChatInputMode.entries[pos]
                if (pickedMode != currentInputMode) {
                    currentInputMode = pickedMode
                    applyInputModeVisibility()
                    // 切到新模式时，如果当前输入区高度不足，吸附回该模式最小值
                    ensureInputAreaMeetsCurrentMin()
                    // 切到 EMPTY 后，下个 frame 更新尺寸文本
                    if (pickedMode == ChatInputMode.EMPTY) {
                        inputArea.post { updateEmptySize() }
                    }
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        applyInputModeVisibility()
    }

    /** 仅显示对应 inputBar，其他全 GONE */
    private fun applyInputModeVisibility() {
        inputBarText.visibility   = if (currentInputMode == ChatInputMode.TEXT)   View.VISIBLE else View.GONE
        inputBarRemote.visibility = if (currentInputMode == ChatInputMode.REMOTE) View.VISIBLE else View.GONE
        inputBarDim3.visibility   = if (currentInputMode == ChatInputMode.DIM3)   View.VISIBLE else View.GONE
        inputBarVoice.visibility  = if (currentInputMode == ChatInputMode.VOICE)  View.VISIBLE else View.GONE
        inputBarFile.visibility   = if (currentInputMode == ChatInputMode.FILE)   View.VISIBLE else View.GONE
        inputBarEmpty.visibility  = if (currentInputMode == ChatInputMode.EMPTY)  View.VISIBLE else View.GONE
    }

    /**
     * 拖拽 handle 的 touch 监听：
     * - ACTION_DOWN：记录起始 Y 和当前 inputArea 高度
     * - ACTION_MOVE：实时改 inputArea 高度，clamp 在 [当前模式最小, 屏幕-一行chat-handle]
     * - ACTION_UP/CANCEL：松手
     * 最大化时返回 false 禁用拖拽（handleLabel 也被 setEnabled(false) 视觉提示）
     */
    @SuppressLint("ClickableViewAccessibility")
    private fun setupDragHandle() {
        handleLabel.setOnTouchListener { _, ev ->
            if (isMaximized) {
                return@setOnTouchListener false
            }
            return@setOnTouchListener when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    isDragging = true
                    dragStartY = ev.rawY
                    dragStartHeight = inputArea.height
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    if (!isDragging) return@setOnTouchListener false
                    val delta = (dragStartY - ev.rawY).toInt()  // 向上拖 = 正
                    val target = (dragStartHeight + delta)
                        .coerceIn(minHeightForCurrentModePx(), maxInputAreaHeightPx())
                    setInputAreaHeightPx(target)
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    isDragging = false
                    true
                }
                else -> false
            }
        }
    }

    /** 顶部 handle 行最右边的全屏切换按钮 */
    private fun setupMaximizeButton() {
        btnMaximize.setOnClickListener {
            isMaximized = !isMaximized
            applyMaximizeState()
        }
        applyMaximizeState()
    }

    /**
     * 切换全屏：true 时 RecyclerView GONE + inputArea 撑满；false 时还原到拖拽留下的高度。
     * 同时控制 handleLabel.isEnabled（最大化时灰掉，不可拖）。
     */
    private fun applyMaximizeState() {
        if (isMaximized) {
            handleLabel.isEnabled = false
            recyclerView.visibility = View.GONE
            lastNonMaximizedHeightPx = inputArea.height.takeIf { it > 0 } ?: minHeightForCurrentModePx()
            inputArea.updateLayoutParams<LinearLayout.LayoutParams> {
                height = LinearLayout.LayoutParams.MATCH_PARENT
            }
            btnMaximize.text = "⤡ 退出"
        } else {
            handleLabel.isEnabled = true
            recyclerView.visibility = View.VISIBLE
            val restoreH = if (lastNonMaximizedHeightPx > 0) lastNonMaximizedHeightPx else minHeightForCurrentModePx()
            setInputAreaHeightPx(restoreH)
            btnMaximize.text = "⤢ 全屏"
        }
        inputArea.requestLayout()
    }

    /** 当前模式对应的 inputArea 最小像素高度（不可被拖得更小） */
    private fun minHeightForCurrentModePx(): Int {
        val dpVal = minHeightDpByMode[currentInputMode] ?: 120
        return (dpVal * resources.displayMetrics.density).toInt()
    }

    /** inputArea 最大高度：保证 chat 区域至少留一行消息可见 */
    private fun maxInputAreaHeightPx(): Int {
        val density = resources.displayMetrics.density
        return (resources.displayMetrics.heightPixels
            - (chatMinRowHeightDp * density).toInt()
            - (handleRowHeightDp * density).toInt()).coerceAtLeast(minHeightForCurrentModePx())
    }

    /** 设置 inputArea 高度（像素） */
    private fun setInputAreaHeightPx(heightPx: Int) {
        inputArea.updateLayoutParams<LinearLayout.LayoutParams> { this.height = heightPx }
        inputArea.requestLayout()
        // EMPTY 模式下，下个 frame 再更新尺寸文本（layout 还没 pass）
        if (currentInputMode == ChatInputMode.EMPTY) {
            inputArea.post { updateEmptySize() }
        }
    }

    /**
     * 空白模式下，把 inputArea (实际是 inputBarEmpty) 的宽 × 高写到 emptyText。
     * 单位用 dp 更可读；如果当前不是 EMPTY 模式则 no-op。
     */
    private fun updateEmptySize() {
        if (currentInputMode != ChatInputMode.EMPTY) return
        if (!::emptyText.isInitialized) return
        val parent = emptyText.parent as View
        val w = parent.width
        val h = parent.height
        if (w > 0 && h > 0) {
            val density = resources.displayMetrics.density
            val wDp = (w / density).toInt()
            val hDp = (h / density).toInt()
            emptyText.text = "${wDp}dp × ${hDp}dp"
        }
    }

    /** 如果当前 inputArea 高度低于该模式最小值，则吸附回最小 */
    private fun ensureInputAreaMeetsCurrentMin() {
        if (isMaximized) return
        val minPx = minHeightForCurrentModePx()
        if (inputArea.height in 1 until minPx) {
            setInputAreaHeightPx(minPx)
        }
    }

    private fun setupRemoteControls() {
        val v = requireView()
        val directions = listOf(
            R.id.btnRemoteUp to "w",
            R.id.btnRemoteDown to "x",
            R.id.btnRemoteLeft to "a",
            R.id.btnRemoteRight to "d",
            R.id.btnRemoteUpLeft to "q",
            R.id.btnRemoteUpRight to "e",
            R.id.btnRemoteDownLeft to "z",
            R.id.btnRemoteDownRight to "c",
            R.id.btnRemoteCenter to "s"
        )

        directions.forEach { (btnId, label) ->
            v.findViewById<TextView>(btnId)!!.setOnClickListener { sendMessage(label) }
        }

        setupDim3Controls()
    }

    private fun setupDim3Controls() {
        val v = requireView()

        listOf(R.id.btnDim3Up to "+", R.id.btnDim3DownBtn to "-").forEach { (btnId, label) ->
            v.findViewById<TextView>(btnId)!!.setOnClickListener {
                sendMessage(label)
            }
        }

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

        val axisView = v.findViewById<AxisView>(R.id.axisViewDim3)
        axisView?.listener = object : AxisView.OnRotationClickListener {
            override fun onXRotateCW()  { sendMessage("x") }
            override fun onXRotateCCW() { sendMessage("X") }
            override fun onYRotateCW()  { sendMessage("y") }
            override fun onYRotateCCW() { sendMessage("Y") }
            override fun onZRotateCW()  { sendMessage("z") }
            override fun onZRotateCCW() { sendMessage("Z") }
        }
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
                sendMessage(label)
            }
        }
    }

    private fun sendMessage(label: String) {
        appendMessage(
            Message(
                senderId = "self",
                senderType = ParticipantType.USER,
                senderName = "我",
                content = label,
                isInfo = false
            )
        )
        appendMessage(
            Message(
                senderId = "self",
                senderType = ParticipantType.USER,
                senderName = "我",
                content = "📤 发送: $label",
                isInfo = true
            )
        )
        broadcastToParticipants(label)
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
            appendMessage(joinMsg)

            when (config.type) {
                ParticipantType.PTY -> {
                    val device = config.params["device"] ?: "/dev/ptmx"
                    val shell = config.params["shell"] ?: "/system/bin/sh"
                    val pty = PtyParticipant(sessionId) { msg ->
                        recyclerView.post { appendMessage(msg) }
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
                        if (sockType == SocketType.TCP) {
                            // TCP 走 TcpForegroundService：切到后台后保持 socket 不断
                            val svc = tcpService
                            if (svc != null) {
                                svc.addTcpParticipant(config.id, sessionId, ip, port) { msg ->
                                    recyclerView.post { appendMessage(msg) }
                                }
                            } else {
                                // service 还没连上，先缓存等 onServiceConnected
                                pendingTcpConfigs.add(
                                    PendingTcpConfig(config.id, sessionId, ip, port, sockType)
                                )
                            }
                        } else {
                            // UDP 暂不进 service（无连接无 NAT 问题）
                            val socket = SocketParticipant(sessionId, ip, port, sockType) { msg ->
                                recyclerView.post { appendMessage(msg) }
                            }
                            socket.connect()
                            activeParticipants[config.id] = socket
                        }
                    } else {
                        appendMessage(
                            Message(
                                senderId = "system",
                                senderType = ParticipantType.SOCKET,
                                senderName = "系统",
                                content = "❌ SOCKET 配置错误：需要 ip 和 port",
                                isInfo = true
                            )
                        )
                    }
                }
                ParticipantType.SERIAL -> {
                    val device = config.params["device"] ?: ""
                    val baud = config.params["baud"]?.toIntOrNull() ?: 115200
                    if (device.isNotBlank()) {
                        val serial = SerialParticipant(sessionId, device, baud) { msg ->
                            recyclerView.post { appendMessage(msg) }
                        }
                        serial.connect()
                        activeParticipants[config.id] = serial
                    } else {
                        appendMessage(
                            Message(
                                senderId = "system",
                                senderType = ParticipantType.SERIAL,
                                senderName = "系统",
                                content = "❌ SERIAL 配置错误：需要 device",
                                isInfo = true
                            )
                        )
                    }
                }
                ParticipantType.AI -> {
                    val ip = config.params["ip"] ?: ""
                    val port = config.params["port"] ?: ""
                    val apiKey = config.params["apiKey"] ?: ""
                    val model = config.params["model"] ?: ""
                    if (ip.isNotBlank() && port.isNotBlank()) {
                        val ai = AiParticipant(sessionId, ip, port, apiKey, model) { msg ->
                            recyclerView.post { appendMessage(msg) }
                        }
                        ai.connect()
                        activeParticipants[config.id] = ai
                    } else {
                        appendMessage(
                            Message(
                                senderId = "system",
                                senderType = ParticipantType.AI,
                                senderName = "系统",
                                content = "❌ AI 配置错误：需要 ip 和 port",
                                isInfo = true
                            )
                        )
                    }
                }
                else -> {
                    // TODO: 其他类型
                }
            }
        }

        if (configs.isEmpty()) {
            appendMessage(
                Message(
                    senderId = "system",
                    senderType = ParticipantType.SOCKET,
                    senderName = "系统",
                    content = "该会话没有任何参与者",
                    isInfo = true
                )
            )
        }
    }

    private fun broadcastToParticipants(text: String) {
        val configs = SessionManager.getParticipants(sessionId)
        configs.forEach { config ->
            when (config.type) {
                ParticipantType.PTY -> {
                    (activeParticipants[config.id] as? PtyParticipant)?.sendInput(text)
                }
                ParticipantType.SOCKET -> {
                    // TCP 走 service；UDP 还在 activeParticipants
                    val tcpSvc = tcpService
                    if (tcpSvc != null && tcpSvc.hasTcpParticipants()) {
                        tcpSvc.sendInput(config.id, text)
                    } else {
                        (activeParticipants[config.id] as? SocketParticipant)?.sendInput(text)
                    }
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

    private fun appendMessage(msg: Message) {
        SessionManager.addMessage(sessionId, msg)
        messageList.add(msg)
        // ⚠️ MessageAdapter 是 ListAdapter（AsyncListDiffer），
        // 必须 submitList 才会更新，否则 RecyclerView 知道更新但 getItem 拿到空 → 渲染空白
        // ⚠️ submitList 是异步的，itemCount 要等 diff commit 到主线程后才更新，
        // 所以 scrollToPosition 必须放在 commitCallback 里，否则滚到旧的 size-1
        adapter.submitList(messageList.toList()) {
            if (autoScroll && messageList.isNotEmpty()) {
                recyclerView.scrollToPosition(messageList.size - 1)
            }
        }
    }

    /**
     * 从 SessionManager 加载 / 追加历史消息。
     * SessionManager 是 object 单例，messages 字典跨 ChatFragment 实例保持，
     * 本地的 messageList 是 fragment 级，所以创建时必须从这里 reload。
     *
     * 语义：
     * - messageList 为空（首次创建）→ clear 后 addAll
     * - messageList 已有（切回前台、Service onDestroy 后 onStart 重走）→ 只 add 不在的
     */
    private fun loadMessages() {
        val existing = SessionManager.getMessages(sessionId)
        if (messageList.isEmpty()) {
            messageList.addAll(existing)
        } else {
            val knownIds = messageList.map { it.id }.toHashSet()
            val newOnes = existing.filter { it.id !in knownIds }
            if (newOnes.isEmpty()) return
            messageList.addAll(newOnes)
        }
        // 同 appendMessage：submitList 异步，scroll 放 commitCallback
        adapter.submitList(messageList.toList()) {
            if (messageList.isNotEmpty()) {
                recyclerView.scrollToPosition(messageList.size - 1)
            }
        }
    }

    private fun isAtBottom(): Boolean {
        val lm = recyclerView.layoutManager as? LinearLayoutManager ?: return false
        val total = lm.itemCount
        if (total == 0) return true
        val lastVisible = lm.findLastVisibleItemPosition()
        return lastVisible >= total - autoScrollThreshold
    }

    override fun onDestroyView() {
        super.onDestroyView()
        // PTY 必须在 fragment 销毁时断（占用 fd）
        // SOCKET (TCP) 不在这里断——由 TcpForegroundService 持有，切后台/重建 fragment 时都保留
        // SOCKET (UDP) / SERIAL / AI 也不在这里断（没显式 disconnect 入口，与原先一致）
        activeParticipants.values.forEach { participant ->
            (participant as? PtyParticipant)?.disconnect()
        }
        activeParticipants.clear()
        pendingTcpConfigs.clear()
    }

    override fun onDestroy() {
        super.onDestroy()
        // fragment 真正销毁（用户点 tab ×、应用退出）时，释放 TcpForegroundService 里的 TCP participant
        closeSession()
    }

    /**
     * 会话彻底关闭（用户点 tab 上的 ×）时调用：让 TcpForegroundService 释放对应 TCP participant。
     * 普通切到后台 / 切换 tab 不调用——TCP 在 service 内继续跑。
     */
    private fun closeSession() {
        val svc = tcpService ?: return
        val configs = SessionManager.getParticipants(sessionId)
        configs.forEach { config ->
            if (config.type == ParticipantType.SOCKET) {
                svc.removeTcpParticipant(config.id, sessionId)
            }
        }
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
