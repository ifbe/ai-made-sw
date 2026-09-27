package com.example.p2pnet.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.repository.P2pRepository
import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.service.SessionManager
import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.TabItem
import com.example.p2pnet.ui.WgConfig
import com.example.p2pnet.ui.WgInterface
import com.example.p2pnet.ui.WgPeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LoginViewModel(
    private val repository: P2pRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState(
        serverHost = repository.getServerHost()
    ))
    val uiState: StateFlow<LoginUiState> = _uiState

    var onStartService: (() -> Unit)? = null
    var onStopService: (() -> Unit)? = null

    private var messageCount = 0

    fun onServerHostChange(host: String) {
        _uiState.value = _uiState.value.copy(serverHost = host)
    }

    fun onServerPortChange(port: String) {
        _uiState.value = _uiState.value.copy(serverPort = port)
    }

    fun onUseWssChange(useWss: Boolean) {
        _uiState.value = _uiState.value.copy(useWss = useWss)
    }

    fun onUsernameChange(username: String) {
        _uiState.value = _uiState.value.copy(username = username)
    }

    fun onPasswordChange(password: String) {
        _uiState.value = _uiState.value.copy(password = password)
    }

    fun onTargetUsernameChange(target: String) {
        _uiState.value = _uiState.value.copy(targetUsername = target)
    }

    fun onList() {
        repository.sendList()
    }

    // target 默认取“对方用户名”输入框的值；节点卡片上的按钮会显式传自己的用户名
    fun onUdp(target: String = _uiState.value.targetUsername) {
        if (target.isNotEmpty()) {
            pendingUdpTarget = target
            repository.sendP2pUdp(target)
        }
    }

    fun onTcp(target: String = _uiState.value.targetUsername) {
        if (target.isNotEmpty()) {
            repository.sendP2pTcp(target)
        }
    }

    fun onWghelp(target: String = _uiState.value.targetUsername) {
        if (target.isNotEmpty()) {
            pendingUdpTarget = target
            repository.sendWghelp(target)
        }
    }

    fun onConnect() {
        val state = _uiState.value
        _uiState.value = state.copy(loading = true, error = null)

        val listener = object : com.example.p2pnet.data.remote.WsClient.Listener {
            override fun onConnected() {
                _uiState.value = _uiState.value.copy(loading = false, isConnected = true)
            }

            override fun onRawMessage(text: String) {
                handleServerMessage(text)
            }

            override fun onSend(text: String) {
                appendMessage(Direction.CLIENT, text)
            }

            override fun onUdpSend(text: String) {
                // burst/keep-alive 是 UDP 数据，用箭头；其余是系统事件，用 android:
                val dir = if (text.contains("burst") || text.contains("keep-alive")) Direction.UDP_SEND else Direction.SYSTEM
                appendMessage(dir, text)
            }

            override fun onUdpRecv(text: String) {
                // recv ← data 是 UDP 数据，用箭头；其余是系统事件，用 android:
                val dir = if (text.startsWith("recv") || text.startsWith("←")) Direction.UDP_RECV else Direction.SYSTEM
                appendMessage(dir, text)
            }

            override fun onHelloDone(info: com.example.p2pnet.data.remote.WsClient.PeerInfo?, sock: java.net.DatagramSocket?, peerIp: String, peerPort: Int, mode: String) {
                appendMessage(Direction.SYSTEM, "UDP hello 线程已退出")
            }

            override fun onUdpSocketBound(sock: java.net.DatagramSocket, localIp: String, localPort: Int) {
                adoptUdpSocket(sock, localIp, localPort)
            }

            override fun onUdpSocketStep(
                sock: java.net.DatagramSocket,
                step: com.example.p2pnet.data.remote.WsClient.UdpStep,
                myIp: String,
                myPort: Int,
                peerIp: String,
                peerPort: Int
            ) {
                sessionManager?.markStep(sock, step, myIp, myPort, peerIp, peerPort)
            }

            override fun onLoginSuccess(username: String) {
                _uiState.value = _uiState.value.copy(
                    loading = false, isLoggedIn = true, loggedInUsername = username, error = null
                )
            }

            override fun onLoginFailed(message: String) {
                _uiState.value = _uiState.value.copy(loading = false, error = message)
            }

            override fun onDisconnected() {
                _uiState.value = _uiState.value.copy(isConnected = false, isLoggedIn = false)
                appendMessage(Direction.SYSTEM, "disconnected")
            }

            override fun onError(message: String) {
                _uiState.value = _uiState.value.copy(loading = false, error = message)
                appendMessage(Direction.SYSTEM, message)
            }
        }

        repository.getClient().listener = listener
        onStartService?.invoke()
        repository.connectOnly(state.useWss, state.serverHost, state.serverPort.toIntOrNull() ?: 10000)
    }

    fun onDisconnect() {
        repository.disconnectOnly()
        onStopService?.invoke()
        // 不清空 messages：App 内日志跨连接保留，只有日志面板里的“清空”才会清
        _uiState.value = _uiState.value.copy(
            isConnected = false,
            isLoggedIn = false,
            loading = false,
            myIp = "",
            myPort = 0,
            peers = emptyList()
        )
        closeAllUdpSockets()
    }

    fun onLogin() {
        val state = _uiState.value
        if (state.username.isBlank() || state.password.isBlank()) {
            _uiState.value = state.copy(error = "请输入用户名和密码")
            return
        }

        _uiState.value = state.copy(loading = true, error = null)

        repository.onUdpSend = { text ->
            appendMessage(Direction.UDP_SEND, text)
        }
        repository.onUdpRecv = { text ->
            appendMessage(Direction.UDP_RECV, text)
        }
        repository.onUdpSocketBound = { sock, localIp, localPort ->
            adoptUdpSocket(sock, localIp, localPort)
        }
        repository.onUdpSocketStep = { sock, step, myIp, myPort, peerIp, peerPort ->
            sessionManager?.markStep(sock, step, myIp, myPort, peerIp, peerPort)
        }
        repository.onHelloDone = { info, sock, peerIp, peerPort, mode ->
            appendMessage(Direction.SYSTEM, "onHelloDone 被调用 mode=$mode")
            if (info != null && sock != null) {
                appendMessage(Direction.SYSTEM, "P2P已建立: ${info.name} (${info.peerIp}:${info.peerPort})")
                appendMessage(Direction.SYSTEM, "peer info: 本机=${info.myIp}:${info.myPort} 对方=${info.peerIp}:${info.peerPort}")
                if (mode == "wg") {
                    // wghelp 模式：找到已有的 WireGuard tab，更新数据后跳转
                    val tabs = _uiState.value.tabs
                    val wgIndex = tabs.indexOfFirst { it.page is Page.WireGuard }
                    if (wgIndex >= 0) {
                        val updatedPage = Page.WireGuard(
                            targetUsername = info.name,
                            myIp = info.myIp,
                            myPort = info.myPort,
                            peerIp = info.peerIp,
                            peerPort = info.peerPort
                        )
                        val updatedTabs = tabs.toMutableList()
                        updatedTabs[wgIndex] = updatedTabs[wgIndex].copy(page = updatedPage)
                        _uiState.value = _uiState.value.copy(tabs = updatedTabs, currentTabIndex = wgIndex, currentPage = updatedPage)
                        appendMessage(Direction.SYSTEM, "已跳转到 WireGuard tab")
                    } else {
                        appendMessage(Direction.SYSTEM, "WireGuard tab 未找到")
                    }
                    // 5. 交给下游消费者：WireGuard
                    sessionManager?.markStep(
                        sock,
                        com.example.p2pnet.data.remote.WsClient.UdpStep.HANDED_TO,
                        handedTo = "wg"
                    )
                } else {
                    // udp 模式：不再自动跳到 udptest 业务。
                    // 探测（第 3、4 步）由 SessionManager 在收到服务器回复时自动开始，
                    // 这里只记一笔日志，之后由用户在 socket 卡片上选用法。
                    appendMessage(Direction.SYSTEM, "打洞完成，等待在 socket 卡片上选用法")
                }
            } else {
                appendMessage(Direction.SYSTEM, "onHelloDone info=null（hello线程超时或异常）")
            }
        }
        repository.onSend = { text ->
            appendMessage(Direction.CLIENT, text)
        }
        repository.onRawMessage = { text ->
            handleServerMessage(text)
        }

        viewModelScope.launch {
            val result = repository.login(
                state.useWss,
                state.serverHost,
                state.serverPort.toIntOrNull() ?: 10000,
                state.username,
                state.password
            )
            when (result) {
                is P2pRepository.LoginResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        loading = false,
                        isLoggedIn = true,
                        isConnected = true,
                        loggedInUsername = result.username,
                        error = null
                    )
                }
                is P2pRepository.LoginResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        loading = false,
                        error = result.message
                    )
                }
            }
        }
    }

    fun onLogout() {
        // 只退出登录：给服务器发 logout，但保持 WebSocket 连接
        //（isConnected 不动、不停前台服务、不清空已输入的密码、也不清空 App 内日志）
        repository.logout(keepConnection = true)
        _uiState.value = _uiState.value.copy(
            isLoggedIn = false,
            loggedInUsername = "",
            myIp = "",
            myPort = 0,
            peers = emptyList()
        )
        closeAllUdpSockets()
    }


    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    // ── UDP P2P session（socket 本身归 P2pService 的 SessionManager，这里只留观察与转发）──
    private var sessionManager: SessionManager? = null

    /** 最近一次点 udp / wghelp 的目标，socket 建好后用它把卡片挂到对应的对方卡片下面 */
    private var pendingUdpTarget: String = ""

    private val _udpSockMessages = MutableStateFlow<List<String>>(emptyList())
    val udpSockMessages = _udpSockMessages

    // WireGuard tunnel 日志（独立的流）
    private val _wgLogMessages = MutableStateFlow<List<String>>(emptyList())
    val wgLogMessages = _wgLogMessages

    fun appendWgLog(text: String) {
        _wgLogMessages.value = _wgLogMessages.value + text
    }

    fun clearWgLog() {
        _wgLogMessages.value = emptyList()
    }

    fun clearMessages() {
        _uiState.value = _uiState.value.copy(messages = emptyList())
    }

    fun clearUdpSockMessages() {
        _udpSockMessages.value = emptyList()
    }

    /** 外部（MainActivity）往 App 日志里写一条系统信息 */
    fun appendSystemLog(text: String) {
        appendMessage(Direction.SYSTEM, text)
    }

    /**
     * UDP 日志统一入口：每条都带时间戳。
     * 后台被系统冻结 / 循环被中断时，日志里会直接出现时间跳变或明确的退出原因。
     */
    /** 日志出口：UDP 相关的日志（含 SessionManager / usage 产生的）都进这个列表 */
    private fun udpLog(text: String) {
        val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date())
        _udpSockMessages.value = _udpSockMessages.value + "[$ts] $text"
    }

    // ── P2P session：由 P2pService 的 SessionManager 拥有，这里只做转发和观察 ──

    /** socket 绑定完成（WsClient 回调）：交给 SessionManager 接管，之后 socket 归服务所有 */
    private fun adoptUdpSocket(sock: DatagramSocket, localIp: String, localPort: Int) {
        val manager = sessionManager
        if (manager == null) {
            appendMessage(Direction.SYSTEM, "后台服务未就绪，无法接管 socket ${localIp}:${localPort}")
            try { sock.close() } catch (_: Exception) {}
            return
        }
        manager.adopt(sock, pendingUdpTarget, localIp, localPort)
    }

    /** 服务绑定好之后由 MainActivity 调进来；之后 session 的增删改都跟着它走 */
    fun attachSessionManager(manager: SessionManager) {
        sessionManager = manager
        manager.onLog = { text -> udpLog(text) }
        // 把服务里已有的 session 立刻同步过来（Activity 重建后卡片不会丢）
        _uiState.value = _uiState.value.copy(udpSockets = manager.sessions.value)
        viewModelScope.launch {
            manager.sessions.collect { list ->
                if (list != _uiState.value.udpSockets) {
                    _uiState.value = _uiState.value.copy(udpSockets = list)
                }
            }
        }
    }

    /** socket 卡片上点击某个用法 */
    fun useUdpSocket(id: Long, usageId: String) {
        val card = _uiState.value.udpSockets.firstOrNull { it.id == id } ?: return
        // 已经交给它了，别重复交接
        if (card.handedTo == usageId) return
        val manager = sessionManager
        if (manager == null) {
            appendMessage(Direction.SYSTEM, "后台服务未就绪，无法交给 $usageId")
            return
        }

        if (usageId == "udptest") {
            // udptest 有自己的界面：建/切到 UDP tab，并把本机绑定写进页面
            val page = Page.UdpTest(
                targetUsername = card.target,
                myIp = card.myPublicIp,
                myPublicPort = card.myPublicPort,
                myLocalIp = card.localIp,
                myLocalPort = card.localPort,
                peerIp = card.peerPublicIp,
                peerPort = card.peerPublicPort
            )
            navigateTo(page)
            updateUdpPageLocalAddr(card.localIp, card.localPort)
        }

        if (!manager.attachUsage(id, usageId)) {
            appendMessage(Direction.SYSTEM, "socket 已关闭，无法交给 $usageId")
        } else if (usageId != "udptest") {
            // 尚未实现的用法：往 App 内日志也写一行，主页面上就能看到反馈
            appendMessage(
                Direction.SYSTEM,
                "$usageId 用法尚未实现（socket ${card.localIp}:${card.localPort}）"
            )
        }
    }

    /** 关闭某条 session（卡片上的 ✕） */
    fun closeUdpSocket(id: Long) {
        sessionManager?.close(id)
    }

    /** 断开 / 退出登录：把所有 session 和 socket 一起收掉 */
    private fun closeAllUdpSockets() {
        sessionManager?.closeAll()
    }

    /** 关掉 UDP tab：只摘掉用法（停 ping），session 和 socket 保留 */
    private fun detachUdpUsages() {
        sessionManager?.detachAllUsages()
    }


    /** 在主线程更新 UdpTest page 的本地地址 */
    private fun updateUdpPageLocalAddr(localIp: String, localPort: Int) {
        val tabs = _uiState.value.tabs.toMutableList()
        for (i in tabs.indices) {
            val p = tabs[i].page
            if (p is Page.UdpTest) {
                tabs[i] = TabItem(Page.UdpTest(
                    targetUsername = p.targetUsername,
                    myIp = p.myIp,
                    myPublicPort = p.myPublicPort,
                    myLocalIp = localIp,
                    myLocalPort = localPort,
                    peerIp = p.peerIp,
                    peerPort = p.peerPort
                ), tabs[i].title)
            }
        }
        _uiState.value = _uiState.value.copy(tabs = tabs)
    }

    // ── Tab navigation ──
    fun navigateTo(page: Page) {
        val tabs = _uiState.value.tabs
        val existing = tabs.indexOfFirst { it.page::class == page::class && it.page !is Page.Main }
        if (existing >= 0) {
            // 切换到已存在tab，不清空
            _uiState.value = _uiState.value.copy(currentTabIndex = existing, currentPage = page)
        } else {
            // 新建tab时才清空
            if (page is Page.UdpTest) {
                _udpSockMessages.value = emptyList()
            }
            val title = when (page) {
                is Page.Main -> "主页"
                is Page.UdpTest -> "UDP"
                is Page.VideoCall -> "视频通话"
                is Page.Chat -> "聊天"
                is Page.WireGuard -> "WireGuard"
            }
            _uiState.value = _uiState.value.copy(
                tabs = tabs + TabItem(page, title),
                currentTabIndex = tabs.size,
                currentPage = page
            )
        }
    }

    fun switchToTab(index: Int) {
        if (index in _uiState.value.tabs.indices) {
            _uiState.value = _uiState.value.copy(
                currentTabIndex = index,
                currentPage = _uiState.value.tabs[index].page
            )
        }
    }

    fun removeTab(index: Int) {
        val tabs = _uiState.value.tabs.toMutableList()
        if (index < 0 || index >= tabs.size || tabs.size <= 1) return
        val removed = tabs.removeAt(index)
        // 如果关闭的是 UDP tab，只摘掉用法（停 ping），session/socket 保留
        if (removed.page is Page.UdpTest) {
            detachUdpUsages()
        }
        var current = _uiState.value.currentTabIndex
        var page = _uiState.value.currentPage
        if (current >= tabs.size) {
            current = tabs.size - 1
            page = tabs[current].page
        } else if (current > index) {
            current--
            page = tabs[current].page
        }
        _uiState.value = _uiState.value.copy(tabs = tabs, currentTabIndex = current, currentPage = page)
    }

    private fun appendMessage(dir: Direction, content: String) {
        val item = MessageItem(
            id = System.currentTimeMillis(),
            direction = dir,
            content = content
        )
        _uiState.value = _uiState.value.copy(
            messages = _uiState.value.messages + item
        )
    }

    /** 服务端消息统一入口：记日志 + 解析 list 回复 */
    private fun handleServerMessage(text: String) {
        appendMessage(Direction.SERVER, text)
        tryParseListResult(text)
    }

    /**
     * 解析 list 回复：
     * {"type":"list_result","users":[{"username":..,"ip":..,"port":..,"udp_port":..}, ...]}
     * 把用户名等于自己的那条作为“我的 ip/port”，其余生成其他人的节点。
     */
    private fun tryParseListResult(text: String) {
        val obj = try {
            JSONObject(text)
        } catch (_: Exception) {
            return
        }
        if (obj.optString("type") != "list_result") return

        val arr = obj.optJSONArray("users")
        val count = arr?.length() ?: 0
        val entries = ArrayList<PeerEntry>(count)
        for (i in 0 until count) {
            val u = arr?.optJSONObject(i) ?: continue
            val name = u.optString("username", "")
            if (name.isEmpty()) continue
            entries.add(
                PeerEntry(
                    username = name,
                    ip = u.optString("ip", ""),
                    port = u.optInt("port", 0)
                )
            )
        }

        val myName = _uiState.value.loggedInUsername.ifBlank { _uiState.value.username }
        val mine = entries.firstOrNull { it.username == myName }

        _uiState.value = _uiState.value.copy(
            myIp = mine?.ip ?: "",
            myPort = mine?.port ?: 0,
            peers = entries.filter { it.username != myName }
        )
    }

    // ── WireGuard Tunnel ──

    /** 生成 WireGuard 密钥对（使用 BoringSSL/WebCrypto） */
    fun generateWgKeypair(callback: (publicKey: String, privateKey: String) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val privKey = generateRandomBase64(32)
                // 简单演示：实际需要用 WireGuard 指定的 Curve25519
                val pubKey = generateRandomBase64(32)
                launch(Dispatchers.Main) {
                    callback(pubKey, privKey)
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    callback("", "")
                }
            }
        }
    }

    /** 生成随机 base64 字符串（临时实现） */
    private fun generateRandomBase64(byteLen: Int): String {
        val bytes = ByteArray(byteLen)
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }

    /** 启动 WireGuard tunnel（手动模式，单 peer，保留兼容） */
    fun startWgTunnel(config: WgConfig, callback: (Boolean, String) -> Unit) {
        // 转换为 WgInterface 格式
        val iface = WgInterface(
            myIp = config.myIp,
            myPort = config.myPort,
            privateKey = config.myPrivateKey,
            peers = listOf(WgPeer(
                endpoint = config.peerEndpoint,
                publicKey = config.peerPublicKey,
                presharedKey = config.peerPresharedKey,
                allowedIPs = config.allowedIPs
            ))
        )
        startWgTunnelManual(iface, callback)
    }

    /** 启动 WireGuard tunnel（自动模式，wghelp 后调用） */
    fun startWgTunnelAuto(page: Page.WireGuard, callback: (Boolean, String) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // TODO: 自动模式需要知道对方的公钥（通过 wghelp 响应获取或提前配置）
                val autoInterface = WgInterface(
                    myIp = "10.0.0.2/24",
                    myPort = page.myPort,
                    privateKey = "", // 需要从本地存储读取
                    peers = listOf(WgPeer(
                        endpoint = "${page.peerIp}:${page.peerPort}",
                        publicKey = "", // 需要从对方获取
                        presharedKey = "",
                        allowedIPs = "0.0.0.0/0"
                    ))
                )
                val configText = buildWireGuardInterfaceConfig(autoInterface)
                android.util.Log.e("WireGuard", "Auto config:\n$configText")
                appendWgLog("WireGuard 自动配置生成完成: ${page.peerIp}:${page.peerPort}")
                launch(Dispatchers.Main) {
                    callback(true, "自动配置已生成")
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    callback(false, e.message ?: "未知错误")
                }
            }
        }
    }

    /** 停止 WireGuard tunnel */
    fun stopWgTunnel() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // TODO: 停止 WireGuard tunnel
                android.util.Log.e("WireGuard", "stopWgTunnel called")
            } catch (e: Exception) {
                android.util.Log.e("WireGuard", "stopWgTunnel error: ${e.message}")
            }
        }
    }

    /** 启动 WireGuard tunnel（手动模式，传入 WgInterface + 多 peer） */
    fun startWgTunnelManual(wgInterface: WgInterface, callback: ((Boolean, String) -> Unit)? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // TODO: 实际建立 WireGuard tunnel
                val configText = buildWireGuardInterfaceConfig(wgInterface)
                android.util.Log.e("WireGuard", "Manual config:\n$configText")
                appendWgLog("WireGuard 手动配置生成完成")
                launch(Dispatchers.Main) {
                    callback?.invoke(true, "配置已生成")
                }
            } catch (e: Exception) {
                appendWgLog("WireGuard 错误: ${e.message}")
                launch(Dispatchers.Main) {
                    callback?.invoke(false, e.message ?: "未知错误")
                }
            }
        }
    }

    /** 生成 WgInterface 的 wg-quick 格式配置（支持多 peer） */
    private fun buildWireGuardInterfaceConfig(iface: WgInterface): String = buildString {
        append("[Interface]\n")
        append("ListenPort = ${iface.myPort}\n")
        append("PrivateKey = ${iface.privateKey}\n")
        if (iface.myIp.isNotEmpty()) append("Address = ${iface.myIp}\n")
        append("\n")
        for (peer in iface.peers) {
            append("[Peer]\n")
            append("PublicKey = ${peer.publicKey}\n")
            if (peer.presharedKey.isNotEmpty()) append("PresharedKey = ${peer.presharedKey}\n")
            append("Endpoint = ${peer.endpoint}\n")
            append("AllowedIPs = ${peer.allowedIPs}\n")
            append("\n")
        }
    }

    // buildWireGuardConfig 已移除，请使用 buildWireGuardInterfaceConfig
}
