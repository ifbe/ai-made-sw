package com.example.p2pnet.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.repository.P2pRepository
import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.TabItem
import com.example.p2pnet.ui.WgConfig
import com.example.p2pnet.ui.WgInterface
import com.example.p2pnet.ui.WgPeer
import com.example.p2pnet.ui.toPage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

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

    fun onUdp() {
        repository.sendP2pUdp(_uiState.value.targetUsername)
    }

    fun onTcp() {
        repository.sendP2pTcp(_uiState.value.targetUsername)
    }

    fun onWghelp() {
        val target = _uiState.value.targetUsername
        if (target.isNotEmpty()) {
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
                appendMessage(Direction.SERVER, text)
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
        _uiState.value = _uiState.value.copy(
            isConnected = false,
            isLoggedIn = false,
            loading = false,
            messages = emptyList()
        )
        stopUdpPeerSocket()
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
                } else {
                    // udp 模式：创建新 tab 并跳转
                    navigateTo(info.toPage())
                    appendMessage(Direction.SYSTEM, "navigateTo 完成，启动 socket")
                    startUdpPeerSocket(info.toPage(), sock)
                }
            } else {
                appendMessage(Direction.SYSTEM, "onHelloDone info=null（hello线程超时或异常）")
            }
        }
        repository.onSend = { text ->
            appendMessage(Direction.CLIENT, text)
        }
        repository.onRawMessage = { text ->
            appendMessage(Direction.SERVER, text)
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
        repository.logout()
        onStopService?.invoke()
        _uiState.value = _uiState.value.copy(
            isConnected = false,
            isLoggedIn = false,
            loggedInUsername = "",
            messages = emptyList(),
            password = ""
        )
        stopUdpPeerSocket()
    }


    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    // ── UDP P2P socket ──
    private var udpSock: DatagramSocket? = null
    private var udpSockRunning = false
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

    // RTT 计算：跟踪每个 ping 的本地发送时刻，收到 pong 时查表算 RTT
    private val sentPings = mutableMapOf<Int, Long>()

    fun startUdpPeerSocket(page: Page.UdpTest, inheritedSock: DatagramSocket? = null) {
        try { udpSock?.close() } catch (_: Exception) {}
        udpSock = null
        udpSockRunning = false

        if (inheritedSock == null) {
            _udpSockMessages.value = _udpSockMessages.value + "android: 无可用 socket，无法建立 P2P 连接"
            return
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                udpSock = inheritedSock
                _udpSockMessages.value = _udpSockMessages.value + "android: 继承 hello socket 本地端口=${inheritedSock.localPort} 对方=${page.peerIp}:${page.peerPort}"

                // 延迟到后台线程再更新 UI tab 信息
                val localIp = udpSock!!.localAddress.hostAddress ?: ""
                val localPort = udpSock!!.localPort
                _udpSockMessages.value = _udpSockMessages.value + "android: P2P socket 启动 本机=$localIp:$localPort"
                _udpSockMessages.value = _udpSockMessages.value + "android: P2P socket 启动 对方=${page.peerIp}:${page.peerPort}"
                // 更新 tab 上的地址信息（在 coroutine 内做）
                updateUdpPageLocalAddr(localIp, localPort)

                udpSockRunning = true
                val sock = udpSock!!

                val addr = InetAddress.getByName(page.peerIp)
                var seq = 1

                // ---- 主循环：每秒发一个 ping ----
                while (udpSockRunning && !sock.isClosed) {
                    val ping = JSONObject().apply {
                        put("type", "ping")
                        put("seq", seq)
                        put("ts", System.currentTimeMillis())
                    }
                    sentPings[seq] = System.currentTimeMillis()
                    if (sentPings.size > 100) {
                        sentPings.keys.minOrNull()?.let { sentPings.remove(it) }
                    }
                    val bytes = ping.toString().toByteArray()
                    val pkt = DatagramPacket(bytes, bytes.size, addr, page.peerPort)
                    sock.send(pkt)
                    _udpSockMessages.value = _udpSockMessages.value + "send: ${addr.hostAddress}:${page.peerPort} $ping"

                    // ---- 接收：等待对方回包或 ping ----
                    val buf = ByteArray(2048)
                    val recvPkt = DatagramPacket(buf, buf.size)
                    try {
                        sock.soTimeout = 1000
                        sock.receive(recvPkt)
                        val data = recvPkt.data.copyOf(recvPkt.length)

                        // 尝试解析 JSON
                        try {
                            val msg = JSONObject(String(data, Charsets.UTF_8))
                            when (msg.optString("type")) {
                                "pong" -> {
                                    val pongSeq = msg.optInt("seq")
                                    val rtt = System.currentTimeMillis() - (sentPings.remove(pongSeq) ?: 0L)
                                    _udpSockMessages.value = _udpSockMessages.value + "recv: ${recvPkt.address.hostAddress}:${recvPkt.port} $msg RTT=${rtt}ms"
                                }
                                "ping" -> {
                                    // 回复 pong（和 udp.py 一致）
                                    val pong = JSONObject().apply {
                                        put("type", "pong")
                                        put("seq", msg.optInt("seq"))
                                        put("ts", msg.optLong("ts"))
                                    }
                                    val pongBytes = pong.toString().toByteArray()
                                    val pongPkt = DatagramPacket(pongBytes, pongBytes.size, recvPkt.address, recvPkt.port)
                                    sock.send(pongPkt)
                                    _udpSockMessages.value = _udpSockMessages.value + "recv: ${recvPkt.address.hostAddress}:${recvPkt.port} $msg"
                                    _udpSockMessages.value = _udpSockMessages.value + "send: ${recvPkt.address.hostAddress}:${recvPkt.port} $pong"
                                }
                                else -> {
                                    _udpSockMessages.value = _udpSockMessages.value + "recv: ${recvPkt.address.hostAddress}:${recvPkt.port} $msg"
                                }
                            }
                        } catch (_: Exception) {
                            // 非 JSON 包，直接记录原始数据
                            _udpSockMessages.value = _udpSockMessages.value + "recv: ${recvPkt.address.hostAddress}:${recvPkt.port} [${data.size} bytes]"
                        }
                    } catch (_: Exception) {
                        // 每秒超时一次（正常）
                    }

                    seq++
                    kotlinx.coroutines.delay(1000)
                }
            } catch (e: Exception) {
                val trace = e.stackTrace.take(3).joinToString("\n") { "  ${it}" }
                _udpSockMessages.value = _udpSockMessages.value + "android: error: ${e.javaClass.simpleName}: ${e.message}\n${trace}"
            } finally {
                try { udpSock?.close() } catch (_: Exception) {}
                udpSock = null
                udpSockRunning = false
                sentPings.clear()
            }
        }
    }

    fun stopUdpPeerSocket() {
        udpSockRunning = false
        try { udpSock?.close() } catch (_: Exception) {}
        udpSock = null
        sentPings.clear()
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
        // 如果关闭的是 UDP tab，停止 socket
        if (removed.page is Page.UdpTest) {
            stopUdpPeerSocket()
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
