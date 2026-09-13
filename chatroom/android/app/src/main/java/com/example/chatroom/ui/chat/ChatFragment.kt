package com.example.chatroom.ui.chat

import android.Manifest
import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.IBinder
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.view.children
import androidx.core.view.updateLayoutParams
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.chatroom.R
import com.example.chatroom.core.BlobSniffer
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.SessionManager
import com.example.chatroom.core.VoiceRecorder
import com.example.chatroom.participants.AgentParticipant
import com.example.chatroom.participants.EchoParticipant
import com.example.chatroom.participants.AiParticipant
import com.example.chatroom.participants.PtyParticipant
import com.example.chatroom.participants.SerialParticipant
import com.example.chatroom.participants.SocketParticipant
import com.example.chatroom.participants.SocketType
import com.example.chatroom.participants.WsParticipant
import com.example.chatroom.service.TcpForegroundService
import com.example.chatroom.ui.common.AxisView
import com.example.chatroom.ui.common.MaxHeightScrollView
import com.google.android.material.button.MaterialButton
import java.util.Locale

enum class ChatInputMode { EMPTY, TEXT, REMOTE, DIM3, VOICE, FILE }

class ChatFragment : Fragment() {

    private var sessionId: String = ""
    private lateinit var adapter: MessageAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var editInput: EditText
    private lateinit var btnSend: MaterialButton
    private val activeParticipants = mutableMapOf<String, Any>()

    // === TcpForegroundService 绑定（TCP / WS / UDP 都走 service，保证后台不断）===
    private var tcpService: TcpForegroundService? = null
    private var tcpServiceBound = false

    /**
     * Service 还没连上时，缓存"等下要加入的网络配置"，等 onServiceConnected 再调
     * 同时覆盖 TCP / WS / UDP 三种类型，统一下发到 service。
     */
    private val pendingNetworkConfigs = mutableListOf<PendingNetworkConfig>()
    private sealed class PendingNetworkConfig {
        abstract val configId: String
        abstract val sessionId: String
        abstract val ip: String
        abstract val port: Int

        data class Tcp(
            override val configId: String,
            override val sessionId: String,
            override val ip: String,
            override val port: Int
        ) : PendingNetworkConfig()

        data class Ws(
            override val configId: String,
            override val sessionId: String,
            override val ip: String,
            override val port: Int,
            val path: String
        ) : PendingNetworkConfig()

        data class Udp(
            override val configId: String,
            override val sessionId: String,
            override val ip: String,
            override val port: Int
        ) : PendingNetworkConfig()
    }

    private lateinit var inputBarText: View
    private lateinit var inputBarRemote: View
    private lateinit var inputBarVoice: View
    private lateinit var inputBarFile: View
    private lateinit var inputBarDim3: View
    private lateinit var inputBarEmpty: View
    private lateinit var emptyText: TextView
    private lateinit var btnPickImage: Button

    // ===== 重连面板（输入区下方 / tabbar 上方）=====
    /** 面板是否展开。由 MainActivity 在 tab 上点 ⓘ 时调 [toggleReconnectPanel] */
    private var reconnectPanelOpen = false
    /** view 还没建好时收到的「展开面板」请求，onViewCreated 里补上 */
    private var pendingReconnectPanelOpen = false
    private lateinit var reconnectPanel: LinearLayout
    private lateinit var reconnectScroll: MaxHeightScrollView
    private lateinit var reconnectList: LinearLayout
    private lateinit var reconnectTitle: TextView
    private lateinit var btnReconnect: MaterialButton
    private lateinit var btnCollapseReconnect: TextView

    /** 连接状态变化（重连成功）→ 通知 MainActivity 刷新 tab 文案 */
    var onConnectionStateChanged: (() -> Unit)? = null

    /** 从磁盘恢复出来的会话还没连过时，聊天区贴一次的提示 */
    private val restoredHintText =
        "🔌 该会话已从本地恢复，当前处于未连接状态\n点该会话标签左边的 ⓘ 可展开重连面板"

    // ===== 语音（VOICE mode）相关 =====
    private lateinit var btnVoiceStart: Button
    private lateinit var btnVoiceCancel: Button
    private lateinit var btnVoiceSend: Button
    private lateinit var voiceRecordingBar: View
    private var voiceRecorder: VoiceRecorder? = null
    private enum class VoiceState { IDLE, RECORDING }
    private var voiceState = VoiceState.IDLE

    /**
     * 系统文件选择器 launcher。mime filter 改为 * 通配，允许所有文件类型。
     * 走 GetContent 而不是 PickVisualMedia：不需要运行时权限，不需要额外依赖。
     */
    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) handlePickedImage(uri)
    }

    /**
     * RECORD_AUDIO 权限申请 launcher。
     * 进入 VOICE mode 时检查；缺权限就 launch 申请，通过 → initVoiceRecorder()。
     */
    private val requestAudioPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            initVoiceRecorder()
        } else {
            showVoiceUnavailable("未授权麦克风")
        }
    }

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
            // 链路状态变化（连上 / 断线 / 连不上）→ 让 MainActivity 刷新 tab 名字的删除线
            svc.registerLinkStateCallback(sessionId) {
                onConnectionStateChanged?.invoke()
                refreshReconnectPanel()
            }
            // 把等 service 期间的 pending 网络配置（TCP / WS / UDP）拿出去加入
            pendingNetworkConfigs.forEach { p ->
                when (p) {
                    is PendingNetworkConfig.Tcp -> {
                        svc.addTcpParticipant(p.configId, p.sessionId, p.ip, p.port) { msg ->
                            recyclerView.post { appendMessage(msg) }
                        }
                    }
                    is PendingNetworkConfig.Ws -> {
                        svc.addWsParticipant(p.configId, p.sessionId, p.ip, p.port, p.path) { msg ->
                            recyclerView.post { appendMessage(msg) }
                        }
                    }
                    is PendingNetworkConfig.Udp -> {
                        svc.addUdpParticipant(p.configId, p.sessionId, p.ip, p.port) { msg ->
                            recyclerView.post { appendMessage(msg) }
                        }
                    }
                }
            }
            pendingNetworkConfigs.clear()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            tcpService = null
            tcpServiceBound = false
        }
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(requireContext(), TcpForegroundService::class.java)
        // 只有本会话确实要建网络连接时，才把 service 推成「前台服务 + started」：
        // startForegroundService 要求 5s 内必须 startForeground()，否则进程直接被系统干掉
        // （ForegroundServiceDidNotStartInTimeException）。刚从磁盘恢复、还没重连的会话，
        // 以及纯 ECHO/PTY/AI 会话都没有网络 participant，不能走这条路径。
        // 网络 participant 真正加入时 service 内部会 ensureStarted() 补齐 started 状态。
        if (shouldStartForegroundService()) {
            requireContext().startForegroundService(intent)
        }
        // 再 bindService 让 fragment 拿到 binder
        requireContext().bindService(intent, tcpServiceConnection, Context.BIND_AUTO_CREATE)
        // 切回前台时：从 SessionManager 拿新消息（service 在 onDestroy 写的诊断信息等）
        if (messageList.isNotEmpty()) {
            loadMessages()
        }
    }

    /** 本会话是否拥有需要 service 承载的网络连接（已连接 + 至少一个 SOCKET 参与者） */
    private fun shouldStartForegroundService(): Boolean {
        if (!SessionManager.isSessionConnected(sessionId)) return false
        return SessionManager.getParticipants(sessionId).any { it.type == ParticipantType.SOCKET }
    }

    override fun onStop() {
        super.onStop()
        if (currentInputMode == ChatInputMode.VOICE) {
            releaseVoiceRecorder()
        }
        if (tcpServiceBound) {
            tcpService?.unregisterCallback(sessionId)
            tcpService?.unregisterLinkStateCallback(sessionId)
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
        btnPickImage = view.findViewById(R.id.btnPickImage)

        // 重连面板
        reconnectPanel = view.findViewById(R.id.reconnectPanel)
        reconnectScroll = view.findViewById(R.id.reconnectScroll)
        reconnectScroll.maxHeightPx = dp(200)
        reconnectList = view.findViewById(R.id.reconnectList)
        reconnectTitle = view.findViewById(R.id.reconnectTitle)
        btnReconnect = view.findViewById(R.id.btnReconnect)
        btnCollapseReconnect = view.findViewById(R.id.btnCollapseReconnect)
        btnReconnect.setOnClickListener { onClickReconnect() }
        btnCollapseReconnect.setOnClickListener { collapseReconnectPanel() }
        reconnectPanelOpen = false
        reconnectPanel.visibility = View.GONE
        refreshReconnectPanel()
        // tab 上点 ⓘ 时 view 还没建好（刚切页过来）：这里补展开
        if (pendingReconnectPanelOpen) {
            pendingReconnectPanelOpen = false
            expandReconnectPanel()
        }

        // 语音模式按钮
        btnVoiceStart = view.findViewById(R.id.btnVoiceStart)
        btnVoiceCancel = view.findViewById(R.id.btnVoiceCancel)
        btnVoiceSend = view.findViewById(R.id.btnVoiceSend)
        voiceRecordingBar = view.findViewById(R.id.voiceRecordingBar)
        btnVoiceStart.setOnClickListener { onClickStartVoice() }
        btnVoiceCancel.setOnClickListener { onClickCancelVoice() }
        btnVoiceSend.setOnClickListener { onClickSendVoice() }
        btnPickImage.setOnClickListener {
            pickImageLauncher.launch("*/*")
        }

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
        if (SessionManager.isSessionConnected(sessionId)) {
            connectParticipants()
        } else {
            // 从磁盘恢复出来的会话：参与者配置在，但不自动连。
            // 用户点 tab 展开重连面板 → 点「重连」才真正建立连接。
            showRestoredHintIfNeeded()
        }

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
                    // 离开 VOICE：丢掉进行中的录音，释放 AudioRecord
                    if (currentInputMode == ChatInputMode.VOICE) {
                        releaseVoiceRecorder()
                    }
                    // 进入 VOICE：检查权限（缺就弹 launcher）
                    if (pickedMode == ChatInputMode.VOICE) {
                        requestAudioPermissionIfNeeded()
                    }
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
                senderType = ParticipantType.SOCKET,
                senderName = "我",
                content = label,
                isInfo = false
            )
        )
        appendMessage(
            Message(
                senderId = "self",
                senderType = ParticipantType.SOCKET,
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
                        when (sockType) {
                            SocketType.TCP -> {
                                // TCP 走 TcpForegroundService：切到后台后保持 socket 不断
                                val svc = tcpService
                                if (svc != null) {
                                    svc.addTcpParticipant(config.id, sessionId, ip, port) { msg ->
                                        recyclerView.post { appendMessage(msg) }
                                    }
                                } else {
                                    // service 还没连上，先缓存等 onServiceConnected
                                    pendingNetworkConfigs.add(
                                        PendingNetworkConfig.Tcp(config.id, sessionId, ip, port)
                                    )
                                }
                            }
                            SocketType.UDP -> {
                                // UDP 也走 service：和 TCP 同套生命周期，一起在后台保活
                                val svc = tcpService
                                if (svc != null) {
                                    svc.addUdpParticipant(config.id, sessionId, ip, port) { msg ->
                                        recyclerView.post { appendMessage(msg) }
                                    }
                                } else {
                                    pendingNetworkConfigs.add(
                                        PendingNetworkConfig.Udp(config.id, sessionId, ip, port)
                                    )
                                }
                            }
                            SocketType.WS -> {
                                // WS 也走 service：和 TCP 同套生命周期，在后台避免 Doze 限制网络
                                val path = config.params["path"] ?: "/"
                                val svc = tcpService
                                if (svc != null) {
                                    svc.addWsParticipant(config.id, sessionId, ip, port, path) { msg ->
                                        recyclerView.post { appendMessage(msg) }
                                    }
                                } else {
                                    pendingNetworkConfigs.add(
                                        PendingNetworkConfig.Ws(config.id, sessionId, ip, port, path)
                                    )
                                }
                            }
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
                    val subType = config.params["subType"] ?: "text"
                    val voice = config.params["voice"] ?: "alloy"
                    if (ip.isNotBlank() && port.isNotBlank()) {
                        val ai = AiParticipant(sessionId, ip, port, apiKey, model, subType, voice) { msg ->
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
                ParticipantType.AGENT -> {
                    val addr = config.params["addr"] ?: ""
                    val port = config.params["port"] ?: ""
                    val username = config.params["username"] ?: ""
                    val password = config.params["password"] ?: ""
                    val subType = config.params["subType"] ?: "openclaw"
                    if (addr.isNotBlank() && port.isNotBlank()) {
                        val agent = AgentParticipant(
                            sessionId, config.name, addr, port, username, password, subType
                        ) { msg ->
                            recyclerView.post { appendMessage(msg) }
                        }
                        agent.connect()
                        activeParticipants[config.id] = agent
                    } else {
                        appendMessage(
                            Message(
                                senderId = "system",
                                senderType = ParticipantType.AGENT,
                                senderName = "系统",
                                content = "❌ AGENT 配置错误：需要 addr 和 port",
                                isInfo = true
                            )
                        )
                    }
                }
                ParticipantType.ECHO -> {
                    // 复读机：纯客户端，发什么回什么，无需任何配置
                    val delay = config.params["delay"]?.toFloatOrNull() ?: 0.5f
                    val echo = EchoParticipant(sessionId, delay) { msg ->
                        recyclerView.post { appendMessage(msg) }
                    }
                    echo.connect()
                    activeParticipants[config.id] = echo
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

    // ===== 重连面板（输入区下方 / tabbar 上方）=====

    /**
     * MainActivity 在 tab 上点 ⓘ 时调：
     * 面板已展开 → 收起（回到会话）；未展开 → 展开重连面板。
     * view 还没建好（点的是别的会话的 ⓘ，正在切页）时先记下，onViewCreated 里补展开。
     */
    fun toggleReconnectPanel() {
        if (view == null) {
            pendingReconnectPanelOpen = true
            return
        }
        if (reconnectPanelOpen) collapseReconnectPanel() else expandReconnectPanel()
    }

    /** 展开重连面板：位于输入区下方，把输入区向上挤 */
    fun expandReconnectPanel() {
        if (!isAdded || view == null) return
        if (!::reconnectPanel.isInitialized) return
        // 最大化时聊天区 GONE、输入区撑满整个窗口，没有空间放面板，先退出最大化
        if (isMaximized) {
            isMaximized = false
            applyMaximizeState()
        }
        refreshReconnectPanel()
        reconnectPanelOpen = true
        reconnectPanel.visibility = View.VISIBLE
        // 面板占掉高度后聊天区变矮，重新贴底
        recyclerView.post {
            if (messageList.isNotEmpty()) recyclerView.scrollToPosition(messageList.size - 1)
        }
    }

    /** 收起重连面板，回到会话 */
    fun collapseReconnectPanel() {
        if (!::reconnectPanel.isInitialized) return
        reconnectPanelOpen = false
        reconnectPanel.visibility = View.GONE
    }

    /** 用 SessionManager 当前参与者配置重建面板内容 */
    private fun refreshReconnectPanel() {
        if (!::reconnectList.isInitialized) return
        // 链路状态回调可能晚于 onStop 到达，view 没了就跳过
        if (!isAdded || view == null) return
        val configs = SessionManager.getParticipants(sessionId)
        val connected = SessionManager.isSessionConnected(sessionId)
        val up = SessionManager.isSessionUp(sessionId)

        // 标题按「链路是否正常」显示（connected 但连接失败时也应该显示未连接）
        reconnectTitle.text = if (up) "🔌 参与者 · 已连接" else "🔌 参与者 · 未连接"
        btnReconnect.text = if (connected) "🔁 重新连接" else "🔌 重连"

        reconnectList.removeAllViews()
        if (configs.isEmpty()) {
            reconnectList.addView(TextView(requireContext()).apply {
                text = "该会话没有参与者"
                textSize = 14f
                setTextColor(0xFF999999.toInt())
                setPadding(0, dp(8), 0, dp(8))
            })
        } else {
            val stateLabel = if (up) "已连接" else "未连接"
            configs.forEach { config ->
                // 复用主页的参与者卡片，保证两边样式一致；只把删除按钮藏掉
                val card = layoutInflater.inflate(R.layout.item_participant_card, reconnectList, false)
                card.findViewById<TextView>(R.id.textIcon).text = config.type.icon
                card.findViewById<TextView>(R.id.textName).text = config.name
                val params = config.params.entries.joinToString(" ") { "${it.key}=${it.value}" }
                card.findViewById<TextView>(R.id.textParams).text =
                    if (params.isBlank()) stateLabel else "$params · $stateLabel"
                card.findViewById<View>(R.id.btnDelete).visibility = View.GONE
                reconnectList.addView(card)
            }
        }
    }

    /**
     * 「重连」按钮：先断开本会话现有参与者，再按配置重新连一遍。
     * 恢复出来的会话本来就没连（首次连接）；已连接的会话则是一次强制重连。
     */
    private fun onClickReconnect() {
        disconnectActiveParticipants()
        SessionManager.setSessionConnected(sessionId, true)
        appendMessage(
            Message(
                senderId = "system",
                senderType = ParticipantType.SOCKET,
                senderName = "系统",
                content = "🔌 开始重连会话…",
                isInfo = true
            )
        )
        connectParticipants()
        refreshReconnectPanel()
        onConnectionStateChanged?.invoke()
        // 断开老连接时可能把 service 清空过一次（触发过 stopSelf 清掉 started 状态）；
        // 网络 participant 重新加入时 TcpForegroundService.ensureStarted() 会把 started 续上，
        // 所以这里不需要额外 startForegroundService（那还会在无网络连接时白拉一次服务）
    }

    /** 断开本会话所有参与者（本地 fd / 线程 + service 里的网络 participant） */
    private fun disconnectActiveParticipants() {
        activeParticipants.values.forEach { participant ->
            when (participant) {
                is PtyParticipant -> participant.disconnect()
                is SerialParticipant -> participant.disconnect()
                is AiParticipant -> participant.disconnect()
                is AgentParticipant -> participant.disconnect()
                is EchoParticipant -> participant.disconnect()
            }
        }
        activeParticipants.clear()
        pendingNetworkConfigs.clear()

        val svc = tcpService ?: return
        SessionManager.getParticipants(sessionId)
            // 只移除确实在 service 里的（恢复出来的会话本来就没加过，避免无谓地清空/停服务）
            .filter { it.type == ParticipantType.SOCKET && svc.hasNetworkParticipant(it.id) }
            .forEach { svc.removeNetworkParticipant(it.id, sessionId) }
    }

    /** 未连接的恢复会话：聊天区贴一次提示（view 重建时不重复贴） */
    private fun showRestoredHintIfNeeded() {
        val already = SessionManager.getMessages(sessionId).any { it.content == restoredHintText }
        if (!already) {
            appendMessage(
                Message(
                    senderId = "system",
                    senderType = ParticipantType.SOCKET,
                    senderName = "系统",
                    content = restoredHintText,
                    isInfo = true
                )
            )
        }
        refreshReconnectPanel()
    }

    /** dp → px */
    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    /**
     * 把 binary bytes 派发给所有相关参与者：
     * - SOCKET/WS → 发 binary frame
     * - AI(subType=="stt") → 当作语音发给 STT API（/v1/audio/transcriptions）
     * - 其他（SOCKET/TCP/UDP、TEXT AI、PTY、SERIAL 等）→ no-op
     */
    private fun broadcastBinaryToParticipants(bytes: ByteArray) {
        val configs = SessionManager.getParticipants(sessionId)
        configs.forEach { config ->
            when (config.type) {
                ParticipantType.SOCKET -> {
                    val sockTypeStr = config.params["sockType"] ?: "TCP"
                    val sockType = try { SocketType.valueOf(sockTypeStr) } catch (e: Exception) { SocketType.TCP }
                    when (sockType) {
                        SocketType.WS -> tcpService?.sendBinaryWs(config.id, bytes)
                        SocketType.TCP, SocketType.UDP -> { /* TODO: TCP/UDP 二进制发送后面接 */ }
                    }
                }
                ParticipantType.AI -> {
                    val subType = config.params["subType"] ?: "text"
                    if (subType == "stt") {
                        (activeParticipants[config.id] as? AiParticipant)?.sendVoice(bytes)
                    }
                }
                ParticipantType.ECHO -> {
                    // 复读机：原样回吐收到的 bytes，adapter 按 mime 决定渲染分支
                    (activeParticipants[config.id] as? EchoParticipant)?.sendBinary(bytes)
                }
                else -> { /* PTY/SERIAL/SSH/TELNET/BLUETOOTH 等：binary no-op */ }
            }
        }
    }

    /**
     * 用户从系统文件选择器选完文件后的处理：
     * 1) 读取全部字节
     * 2) 贴一个自己发出去的 imageBytes 气泡（adapter 用 BlobSniffer 分流：image 走图片，audio 走音频，其他走文本 fallback）
     * 3) 打印一条 📤 发送 info 行（带上嗅探出的 type + 尺寸）
     * 4) 广播给所有 WS participant
     */
    private fun handlePickedImage(uri: Uri) {
        try {
            val resolver = requireContext().contentResolver
            val bytes = resolver.openInputStream(uri)?.use { it.readBytes() }
            if (bytes == null) {
                appendMessage(
                    Message(
                        senderId = "system",
                        senderType = ParticipantType.SOCKET,
                        senderName = "系统",
                        content = "❌ 图片读取失败：openInputStream 返回 null",
                        isInfo = true
                    )
                )
                return
            }

            // self image bubble（内存版，后面如加 disk cache 可改为 imageUri）
            appendMessage(
                Message(
                    senderId = "self",
                    senderType = ParticipantType.SOCKET,
                    senderName = "我",
                    content = "",
                    imageBytes = bytes
                )
            )

            // info 行：type + size + len
            val detected = BlobSniffer.detectType(bytes)
            val size = BlobSniffer.decodeImageSize(bytes)
            val sizeStr = if (size != null) " size=${size.first}x${size.second}" else ""
            appendMessage(
                Message(
                    senderId = "self",
                    senderType = ParticipantType.SOCKET,
                    senderName = "我",
                    content = "📤 发送 type=$detected$sizeStr len=${bytes.size}",
                    isInfo = true
                )
            )

            broadcastBinaryToParticipants(bytes)
        } catch (e: Exception) {
            val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            appendMessage(
                Message(
                    senderId = "system",
                    senderType = ParticipantType.SOCKET,
                    senderName = "系统",
                    content = "❌ 图片处理失败: $detail",
                    isInfo = true
                )
            )
        }
    }

    // ===== 语音模式 helpers =====

    /** 进入 VOICE mode 时调用：有权限就 init，没有就 launch 申请 */
    private fun requestAudioPermissionIfNeeded() {
        val ctx = requireContext()
        val perm = ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO)
        if (perm == PackageManager.PERMISSION_GRANTED) {
            initVoiceRecorder()
        } else {
            requestAudioPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
        }
    }

    /** 创建 VoiceRecorder（如还没），调 init；失败则禁用按钮 + 显示原因 */
    private fun initVoiceRecorder() {
        val recorder = voiceRecorder ?: VoiceRecorder().also { voiceRecorder = it }
        val ok = recorder.init(requireContext())
        if (!ok) {
            showVoiceUnavailable("麦克风不可用")
            return
        }
        showVoiceIdle()
    }

    /** 释放 VoiceRecorder；UI 复位到空闲态 */
    private fun releaseVoiceRecorder() {
        voiceRecorder?.release()
        voiceRecorder = null
        showVoiceIdle()
    }

    /** 「未在录音，点我开始」按钮点击：开始录音 */
    private fun onClickStartVoice() {
        val recorder = voiceRecorder
        if (recorder == null) {
            // 还没初始化（多半是因为权限被拒或麦克风不可用），重试
            requestAudioPermissionIfNeeded()
            return
        }
        if (!recorder.start()) {
            showVoiceUnavailable("录音启动失败")
            return
        }
        voiceState = VoiceState.RECORDING
        showVoiceRecording()
    }

    /** 「取消」按钮点击：丢弃本次录音，回到空闲态 */
    private fun onClickCancelVoice() {
        voiceRecorder?.cancel()
        voiceState = VoiceState.IDLE
        showVoiceIdle()
    }

    /** 「发送」按钮点击：停录音 → 贴气泡 + info → 广播 binary */
    private fun onClickSendVoice() {
        val recorder = voiceRecorder ?: return
        val result = recorder.stop()
        voiceState = VoiceState.IDLE
        showVoiceIdle()
        if (result == null) {
            // 空录音
            appendMessage(
                Message(
                    senderId = "system",
                    senderType = ParticipantType.SOCKET,
                    senderName = "系统",
                    content = "🎤 录音为空，未发送",
                    isInfo = true
                )
            )
            return
        }
        val wavBytes = result.wavBytes
        val durationMs = result.durationMs
        // self audio bubble（imageBytes 字段复用，adapter 用 BlobSniffer 分流到 audio 气泡）
        appendMessage(
            Message(
                senderId = "self",
                senderType = ParticipantType.SOCKET,
                senderName = "我",
                content = "",
                imageBytes = wavBytes
            )
        )
        // info 小灰字：📤 发送 type=audio/wav len=N duration=X.XXXs（秒，3 位小数）
        appendMessage(
            Message(
                senderId = "self",
                senderType = ParticipantType.SOCKET,
                senderName = "我",
                content = String.format(
                    Locale.US,
                    "📤 发送 type=audio/wav len=%d duration=%.3fs",
                    wavBytes.size,
                    durationMs / 1000.0
                ),
                isInfo = true
            )
        )
        broadcastBinaryToParticipants(wavBytes)
    }

    /** UI 切到空闲态：开始按钮可见、录音 bar 隐藏、按钮启用且文案恢复 */
    private fun showVoiceIdle() {
        voiceState = VoiceState.IDLE
        btnVoiceStart.visibility = View.VISIBLE
        btnVoiceStart.isEnabled = true
        btnVoiceStart.text = "未在录音，点我开始"
        voiceRecordingBar.visibility = View.GONE
    }

    /** UI 切到录音态：开始按钮隐藏、录音 bar 显示 */
    private fun showVoiceRecording() {
        btnVoiceStart.visibility = View.GONE
        voiceRecordingBar.visibility = View.VISIBLE
    }

    /** 显示「麦克风不可用」状态：禁用按钮，文案改成原因 */
    private fun showVoiceUnavailable(reason: String) {
        btnVoiceStart.text = reason
        btnVoiceStart.isEnabled = false
        btnVoiceStart.visibility = View.VISIBLE
        voiceRecordingBar.visibility = View.GONE
    }

    private fun broadcastToParticipants(text: String) {
        val configs = SessionManager.getParticipants(sessionId)
        configs.forEach { config ->
            when (config.type) {
                ParticipantType.PTY -> {
                    (activeParticipants[config.id] as? PtyParticipant)?.sendInput(text)
                }
                ParticipantType.SOCKET -> {
                    // TCP / WS / UDP 统一走 service.sendInput，service 内部分发到正确的 map
                    tcpService?.sendInput(config.id, text)
                }
                ParticipantType.SERIAL -> {
                    (activeParticipants[config.id] as? SerialParticipant)?.sendInput(text)
                }
                ParticipantType.AI -> {
                    (activeParticipants[config.id] as? AiParticipant)?.sendInput(text)
                }
                ParticipantType.AGENT -> {
                    (activeParticipants[config.id] as? AgentParticipant)?.sendInput(text)
                }
                ParticipantType.ECHO -> {
                    (activeParticipants[config.id] as? EchoParticipant)?.sendInput(text)
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
        // SOCKET (TCP/WS/UDP) 不在这里断——由 TcpForegroundService 持有，切后台/重建 fragment 时都保留
        // SERIAL / AI / AGENT / ECHO 也不在这里断（没显式 disconnect 入口，与原先一致）
        activeParticipants.values.forEach { participant ->
            (participant as? PtyParticipant)?.disconnect()
        }
        activeParticipants.clear()
        pendingNetworkConfigs.clear()
    }

    // ⚠️ 注意：这里**不能**再调 shutdownSession()。
    // 按 Home / 后台被 MIUI 之类的系统回收 Activity 时，fragment 会 onDestroy，但进程还活着、
    // service 里的 TCP/WS/UDP 也还活着——那时清理 participant 就会把连接断掉，
    // 而且 ViewPager2 回收 offscreen fragment 也会走到这里。
    // 会话彻底关闭只有一条路径：用户点 tab 上的 ×（MainActivity.closeSession）。

    /**
     * 会话彻底关闭时调用：让 TcpForegroundService 释放对应的 TCP / WS / UDP participant。
     * 只有用户点 tab 上的 ×（MainActivity.closeSession）会调；切后台 / 切换会话 / fragment 重建都不调。
     *
     * @return true = 处理完了（包括本来就没有网络 participant）；false = 当前没绑定 service，
     *         调用方需要改用 Intent 让 service 自己清理
     */
    fun shutdownSession(): Boolean {
        if (sessionId.isEmpty()) return true
        if (!SessionManager.isSessionConnected(sessionId)) return true
        val svc = tcpService ?: return false
        val configs = SessionManager.getParticipants(sessionId)
        configs.forEach { config ->
            if (config.type == ParticipantType.SOCKET) {
                svc.removeNetworkParticipant(config.id, sessionId)
            }
        }
        return true
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
