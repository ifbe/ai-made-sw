package com.example.p2pnet.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.repository.P2pRepository
import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.TabItem
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
        repository.sendWghelp()
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

            override fun onHelloDone(info: com.example.p2pnet.data.remote.WsClient.PeerInfo?, sock: java.net.DatagramSocket?, peerIp: String, peerPort: Int) {
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
        repository.onHelloDone = { info, sock, peerIp, peerPort ->
            appendMessage(Direction.SYSTEM, "onHelloDone 被调用")
            if (info != null && sock != null) {
                appendMessage(Direction.SYSTEM, "P2P已建立: ${info.name} (${info.peerIp}:${info.peerPort})")
                appendMessage(Direction.SYSTEM, "peer info: 本机=${info.myIp}:${info.myPort} 对方=${info.peerIp}:${info.peerPort}")
                navigateTo(info.toPage())
                appendMessage(Direction.SYSTEM, "navigateTo 完成，启动 socket")
                startUdpPeerSocket(info.toPage(), sock)
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
}
