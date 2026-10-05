package com.example.p2pnet.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.remote.WsClient
import com.example.p2pnet.data.repository.P2pRepository
import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.service.SessionManager
import com.example.p2pnet.ui.MediaPageConfig
import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.ProxyPageConfig
import com.example.p2pnet.ui.SwitchPageConfig
import com.example.p2pnet.ui.TabItem
import com.example.p2pnet.ui.VpnPageConfig
import com.example.p2pnet.ui.WgConfig
import com.example.p2pnet.ui.WgInterface
import com.example.p2pnet.ui.WgPageConfig
import com.example.p2pnet.ui.WgPeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
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
        serverHost = repository.getServerHost(),
        // 两个配置页的配置从 LocalPrefs 恢复（JSON 原文 → data class）
        wgConfig = WgPageConfig.fromJson(repository.getWgConfigJson()),
        switchConfig = SwitchPageConfig.fromJson(repository.getSwitchConfigJson()),
        proxyConfig = ProxyPageConfig.fromJson(repository.getProxyConfigJson()),
        vpnConfig = VpnPageConfig.fromJson(repository.getVpnConfigJson()),
        mediaConfig = MediaPageConfig.fromJson(repository.getMediaConfigJson())
    ))
    val uiState: StateFlow<LoginUiState> = _uiState

    var onStartService: (() -> Unit)? = null
    var onStopService: (() -> Unit)? = null

    /**
     * 「调系统程序」那条路：把参数交给外部那个真正的 VPN 服务 app。
     * 由 MainActivity 接上（要 Context / PackageManager），返回是否真的拉起成功。
     */
    var onStartExternalVpn: ((action: String, pkg: String, listenPort: Int, peerIp: String, peerPort: Int) -> Boolean)? = null

    /**
     * media 页「拉起应用」：把打洞参数交给外部聊天程序。
     * 由 MainActivity 接上（要 Context / PackageManager），返回是否真的拉起来了。
     * 四个地址端口参数都是打洞结果：localaddr/localport 是本机侧，peeraddr/peerport 是**对方公网侧**。
     */
    var onLaunchMediaApp: ((
        action: String,
        pkg: String,
        localAddr: String,
        localPort: Int,
        peerAddr: String,
        peerPort: Int,
        recvProto: String,
        sendProto: String,
        capture: String
    ) -> Boolean)? = null

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

    /** 应用层 ping 的序号：从 1 开始，每点一次「ping」+1（只为了在日志里看出报文往返） */
    private var pingSeq = 1

    /**
     * 「我」卡片的 ping 按钮：发应用层 ping（`{"type":"ping","seq":N}`，服务器回 `{"type":"pong","seq":N}`）。
     * 不需要登录；发出的报文经 `onSend` 进 App 内日志（`client: {...}`），
     * 收到的 pong 经 `onRawMessage` → [handleServerMessage] 进日志（`server: {...}`）。
     */
    fun onPing() {
        val seq = pingSeq
        pingSeq++
        repository.sendAppPing(seq)
    }

    /**
     * WS **协议级**心跳的"同节奏日志"计时器（和应用层 ping 按钮不是一回事）。
     *
     * ⚠️ 真正的 0x9 ping 帧是 OkHttp 按 [WsClient.PING_INTERVAL_SECONDS] 自己发的，
     * 而 OkHttp **没有暴露"ping 已发出"的回调**，所以这里用同间隔的计时器来打那行日志：
     * 节奏与 OkHttp 的 ping 相同，但**不是严格同一瞬间**，与真实发帧可能相差不到 1 个周期。
     * 随连接起（`onConnected`）、随断开/心跳失败停（`onDisconnected`），断开后不会再刷。
     */
    private var wsPingLogJob: Job? = null

    private fun startWsPingLog() {
        wsPingLogJob?.cancel()
        wsPingLogJob = viewModelScope.launch {
            var n = 1
            while (isActive) {
                delay(WsClient.PING_INTERVAL_SECONDS * 1000L)
                appendMessage(
                    Direction.SYSTEM,
                    "WS 心跳：发出协议级 ping（第 $n 次，间隔 ${WsClient.PING_INTERVAL_SECONDS}s）"
                )
                n++
            }
        }
    }

    private fun stopWsPingLog() {
        wsPingLogJob?.cancel()
        wsPingLogJob = null
    }

    // ── WireGuard 页配置（「实现」三档 + 外部 VPN 应用）──

    fun onWgImplChange(impl: String) = updateWgConfig { it.copy(impl = impl) }
    fun onWgExtPackageChange(v: String) = updateWgConfig { it.copy(extPackage = v) }
    fun onWgExtActionChange(v: String) = updateWgConfig { it.copy(extAction = v) }

    private fun updateWgConfig(transform: (WgPageConfig) -> WgPageConfig) {
        val cfg = transform(_uiState.value.wgConfig)
        _uiState.value = _uiState.value.copy(wgConfig = cfg)
        repository.setWgConfigJson(cfg.toJson())
    }

    // ── Switch 页配置 ──

    fun onSwitchCardModeChange(v: String) = updateSwitchConfig { it.copy(cardMode = v) }
    fun onSwitchTunIpChange(v: String) = updateSwitchConfig { it.copy(tunIp = v) }
    fun onSwitchModeChange(v: String) = updateSwitchConfig { it.copy(mode = v) }
    fun onSwitchMtuChange(v: String) = updateSwitchConfig { it.copy(mtu = v) }
    fun onSwitchRouteTtlChange(v: String) = updateSwitchConfig { it.copy(routeTtl = v) }
    fun onSwitchDhcpEnabledChange(v: Boolean) = updateSwitchConfig { it.copy(dhcpEnabled = v) }
    fun onSwitchDhcpPoolChange(v: String) = updateSwitchConfig { it.copy(dhcpPool = v) }
    fun onSwitchDhcpGatewayChange(v: String) = updateSwitchConfig { it.copy(dhcpGateway = v) }
    fun onSwitchDhcpDnsChange(v: String) = updateSwitchConfig { it.copy(dhcpDns = v) }

    private fun updateSwitchConfig(transform: (SwitchPageConfig) -> SwitchPageConfig) {
        val cfg = transform(_uiState.value.switchConfig)
        _uiState.value = _uiState.value.copy(switchConfig = cfg)
        repository.setSwitchConfigJson(cfg.toJson())
    }

    // ── Proxy 页（端口转发）配置：一条洞 ↔ 一个固定端口 ──

    fun onProxyModeChange(v: String) = updateProxyConfig { it.copy(mode = v) }
    fun onProxyProtoChange(v: String) = updateProxyConfig { it.copy(proto = v) }
    fun onProxyKeepaliveChange(v: String) = updateProxyConfig { it.copy(keepaliveSec = v) }
    fun onProxyBindAddrChange(v: String) = updateProxyConfig { it.copy(bindAddr = v) }
    fun onProxyLocalPortChange(v: String) = updateProxyConfig { it.copy(localPort = v) }
    fun onProxyLListenIpChange(v: String) = updateProxyConfig { it.copy(lListenIp = v) }
    fun onProxyLListenPortChange(v: String) = updateProxyConfig { it.copy(lListenPort = v) }
    fun onProxyRTargetHostChange(v: String) = updateProxyConfig { it.copy(rTargetHost = v) }
    fun onProxyRTargetPortChange(v: String) = updateProxyConfig { it.copy(rTargetPort = v) }

    private fun updateProxyConfig(transform: (ProxyPageConfig) -> ProxyPageConfig) {
        val cfg = transform(_uiState.value.proxyConfig)
        _uiState.value = _uiState.value.copy(proxyConfig = cfg)
        repository.setProxyConfigJson(cfg.toJson())
    }

    /**
     * 启动/停止端口转发。真正的转发还没做（-L 要 listen/accept、-R 要 connect，
     * 之后都是「本地这一侧 ↔ 洞」互转），现在只改页面状态 + 把「按页面配置该起什么」写进日志。
     */
    fun onProxyStart() {
        val cfg = _uiState.value.proxyConfig
        _uiState.value = _uiState.value.copy(proxyRunning = true)
        appendMessage(Direction.SYSTEM, "proxy：按页面配置启动 —— ${cfg.summary()}")
        if (cfg.mode == ProxyPageConfig.MODE_L) {
            appendMessage(
                Direction.SYSTEM,
                "proxy：-L 会监听 ${formatHostPort(cfg.lListenIp, cfg.lListenPort.toIntOrNull() ?: 0)}，" +
                    "accept 后与洞互转（对端要跑 -R）"
            )
        } else {
            if (cfg.rTargetPort.toIntOrNull() == null) {
                appendMessage(Direction.SYSTEM, "proxy：-R 的目标端口还没填，启动后连不上目标")
            } else {
                appendMessage(
                    Direction.SYSTEM,
                    "proxy：-R 会 connect ${formatHostPort(cfg.rTargetHost, cfg.rTargetPort.toIntOrNull() ?: 0)}，" +
                        "与洞互转"
                )
            }
        }
        appendMessage(Direction.SYSTEM, "proxy：转发逻辑尚未实现（TODO），当前只有配置")
    }

    fun onProxyStop() {
        _uiState.value = _uiState.value.copy(proxyRunning = false)
        appendMessage(Direction.SYSTEM, "proxy：已停止（通道还在，socket 不受影响）")
    }

    // ── VPN 页（一对一 tun/tap）配置 ──

    fun onVpnCardModeChange(v: String) = updateVpnConfig { it.copy(cardMode = v) }
    fun onVpnTunIpChange(v: String) = updateVpnConfig { it.copy(tunIp = v) }
    fun onVpnModeChange(v: String) = updateVpnConfig { it.copy(mode = v) }
    fun onVpnMtuChange(v: String) = updateVpnConfig { it.copy(mtu = v) }
    fun onVpnRouteTtlChange(v: String) = updateVpnConfig { it.copy(routeTtl = v) }
    fun onVpnDhcpEnabledChange(v: Boolean) = updateVpnConfig { it.copy(dhcpEnabled = v) }
    fun onVpnDhcpPoolChange(v: String) = updateVpnConfig { it.copy(dhcpPool = v) }
    fun onVpnDhcpGatewayChange(v: String) = updateVpnConfig { it.copy(dhcpGateway = v) }
    fun onVpnDhcpDnsChange(v: String) = updateVpnConfig { it.copy(dhcpDns = v) }

    private fun updateVpnConfig(transform: (VpnPageConfig) -> VpnPageConfig) {
        val cfg = transform(_uiState.value.vpnConfig)
        _uiState.value = _uiState.value.copy(vpnConfig = cfg)
        repository.setVpnConfigJson(cfg.toJson())
    }

    /**
     * 启动/停止一对一 VPN。真正的 tun/tap + 转发还没做，
     * 现在只改页面状态 + 把「按页面配置该起什么」写进日志。
     */
    fun onVpnStart() {
        val cfg = _uiState.value.vpnConfig
        val channels = _uiState.value.udpSockets.filter { it.handedTo == "tun" }
        _uiState.value = _uiState.value.copy(vpnRunning = true)
        appendMessage(Direction.SYSTEM, "vpn：按页面配置启动 —— ${cfg.summary()}")
        if (channels.isEmpty()) {
            appendMessage(Direction.SYSTEM, "vpn：还没有接通道（在主页 socket 卡片第 5 行点 tun）")
        } else {
            appendMessage(
                Direction.SYSTEM,
                "vpn：一对一通道 = " + channels.joinToString("、") { "${it.target}(洞${it.localPort})" }
            )
            if (channels.size > 1) {
                appendMessage(Direction.SYSTEM, "vpn：一对一只需要一条通道，现在接了 ${channels.size} 条")
            }
        }
        appendMessage(Direction.SYSTEM, "vpn：tun/tap 与协议栈尚未实现（TODO），当前只有配置")
    }

    fun onVpnStop() {
        _uiState.value = _uiState.value.copy(vpnRunning = false)
        appendMessage(Direction.SYSTEM, "vpn：已停止（通道还在，socket 不受影响）")
    }

    // ── media 页（多媒体聊天）配置 ──
    // 我们只负责打洞；媒体流由外部聊天程序收发，所以这里只有配置 + 拉起。

    fun onMediaRecvProtoChange(v: String) = updateMediaConfig { it.copy(recvProto = v) }
    fun onMediaSendProtoChange(v: String) = updateMediaConfig { it.copy(sendProto = v) }
    fun onMediaCaptureChange(v: String) = updateMediaConfig { it.copy(capture = v) }
    fun onMediaAppPackageChange(v: String) = updateMediaConfig { it.copy(appPackage = v) }
    fun onMediaAppActionChange(v: String) = updateMediaConfig { it.copy(appAction = v) }

    private fun updateMediaConfig(transform: (MediaPageConfig) -> MediaPageConfig) {
        val cfg = transform(_uiState.value.mediaConfig)
        _uiState.value = _uiState.value.copy(mediaConfig = cfg)
        repository.setMediaConfigJson(cfg.toJson())
    }

    /**
     * 拉起聊天程序（多媒体聊天我们只负责打洞）。
     *
     * 传的参数（**全部是打洞结果**，不是人填的）：
     *   localaddr / localport = 本机这一侧（洞的本机地址:端口）
     *   peeraddr  / peerport  = **对方路由器公网的地址:端口**（对方内网地址端口不管）
     *   另外带上人选的 recv_proto / send_proto / capture，聊天程序靠它们决定怎么编解码。
     *
     * 契约：action = cfg.appAction（默认 com.p2pnet.action.MEDIA_CHAT）、package = cfg.appPackage（可留空）。
     */
    fun onMediaLaunchApp() {
        val cfg = _uiState.value.mediaConfig
        val channel = _uiState.value.udpSockets.firstOrNull { it.handedTo == "media" }
        if (channel == null) {
            appendMessage(
                Direction.SYSTEM,
                "media：还没打洞（先去主页 socket 卡片第 5 行点 media），拉起等于没有通道可用"
            )
            return
        }
        val action = cfg.appAction.ifBlank { MediaPageConfig.DEFAULT_ACTION }
        val pkg = cfg.appPackage.trim()
        appendMessage(
            Direction.SYSTEM,
            "media[拉起应用]：action=$action" +
                (if (pkg.isNotEmpty()) " package=$pkg" else "（未指定包名，按 action 找）") +
                " localaddr=${channel.localIp} localport=${channel.localPort}" +
                " peeraddr=${channel.peerPublicIp} peerport=${channel.peerPublicPort}" +
                " recv=${cfg.recvProto} send=${cfg.sendProto} capture=${cfg.capture}"
        )
        val starter = onLaunchMediaApp
        if (starter == null) {
            appendMessage(Direction.SYSTEM, "media：拉起外部程序的通道没接好（Activity 没注册 hook）")
            return
        }
        val ok = starter(
            action,
            pkg,
            channel.localIp,
            channel.localPort,
            channel.peerPublicIp,
            channel.peerPublicPort,
            cfg.recvProto,
            cfg.sendProto,
            cfg.capture
        )
        appendMessage(
            Direction.SYSTEM,
            if (ok) "media：已拉起聊天程序（$action）"
            else "media：没找到能拉起的程序（包名/action 不对，或者对方 app 没装？）"
        )
    }

    /**
     * 启动/停止交换机。真正的 hub（一个进程内多路转发）还没做，
     * 现在只改页面状态 + 把「按页面配置该起什么」写进日志，接入时照着填。
     */
    fun onSwitchStart() {
        val cfg = _uiState.value.switchConfig
        _uiState.value = _uiState.value.copy(switchRunning = true)
        appendMessage(Direction.SYSTEM, "switch：按页面配置启动 —— ${cfg.summary()}")
        appendMessage(Direction.SYSTEM, "switch：转发逻辑尚未实现（TODO），当前只有配置和网口编排")
    }

    fun onSwitchStop() {
        _uiState.value = _uiState.value.copy(switchRunning = false)
        appendMessage(Direction.SYSTEM, "switch：已停止（插着的网口还在，socket 不受影响）")
    }

    /** Switch 页上点某个网口 = 拔线：只摘掉这条用法，不动 session/socket */
    fun unplugSwitchPort(id: Long) {
        val card = _uiState.value.udpSockets.firstOrNull { it.id == id } ?: return
        sessionManager?.detachUsage(id)
        appendMessage(Direction.SYSTEM, "switch：已拔出 ${card.target}（socket ${formatHostPort(card.localIp, card.localPort)} 保留）")
    }

    // target 默认取“对方用户名”输入框的值；节点卡片上的按钮会显式传自己的用户名
    fun onUdp(target: String = _uiState.value.targetUsername) {
        if (target.isNotEmpty()) {
            pendingUdpTarget = target
            repository.sendP2pUdp(target)
        }
    }

    /**
     * direct：把自己的 v4/v6 地址列表交给服务器转给对方，拿到对方地址后并发 ICMP 探测。
     * 协议里只有地址、**没有端口**，所以不建 socket、不建隧道，卡片上只报「哪些地址可达」。
     * v6 全局地址本身就是端到端可路由的，这种情况报出来的可达地址就是真直连。
     */
    fun onDirect(target: String = _uiState.value.targetUsername) {
        if (target.isEmpty()) return
        val manager = sessionManager
        if (manager == null) {
            appendMessage(Direction.SYSTEM, "后台服务未就绪，无法发起 direct")
            return
        }
        val id = manager.startDirect(target)
        appendMessage(Direction.SYSTEM, "发起 direct（交换 v4/v6 地址并探测可达性）：target=$target 卡片=#$id")
    }

    /**
     * upnp：双方各自让路由器开洞，把映射出来的公网地址当作候选。
     * 目前**只显示流程**；真正的实现计划做在 net/UpnpPortMapper.kt 里，由 direct 流程调用。
     */
    fun onUpnp(target: String = _uiState.value.targetUsername) {
        showFlowPreview("upnp", target)
    }

    /**
     * tcp：TCP 打洞（3 个 socket 同端口 + listen/connect 竞速）。
     * 目前**只显示流程**：不建 socket、也不发 `p2ptcp` 信令——
     * 免得我们在毫无实现的情况下，把对端（Python 客户端）拉进真实的 TCP 打洞流程。
     * 真正的逻辑落地时，这里再补 `repository.sendP2pTcp(target)`。
     */
    fun onTcp(target: String = _uiState.value.targetUsername) {
        showFlowPreview("tcp", target)
    }

    /** tcp / upnp 两种「打洞方式」目前都只做流程预览（direct 已是真实流程） */
    private fun showFlowPreview(kind: String, target: String) {
        if (target.isEmpty()) return
        val manager = sessionManager
        if (manager == null) {
            appendMessage(Direction.SYSTEM, "后台服务未就绪，无法显示 $kind 流程")
            return
        }
        manager.previewFlow(kind, target)
        appendMessage(Direction.SYSTEM, "显示 $kind 流程（真实逻辑尚未实现）：target=$target")
    }

    fun onConnect() {
        val state = _uiState.value
        _uiState.value = state.copy(loading = true, error = null)

        val listener = object : com.example.p2pnet.data.remote.WsClient.Listener {
            override fun onConnected() {
                _uiState.value = _uiState.value.copy(loading = false, isConnected = true)
                // 连接建立 → 起"协议级心跳日志"计时器（断开时在 onDisconnected 里停）
                startWsPingLog()
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
                // 断开（含心跳失败）→ 停掉协议级心跳日志计时器，别在断开后继续刷
                stopWsPingLog()
                _uiState.value = _uiState.value.copy(isConnected = false, isLoggedIn = false)
                appendMessage(Direction.SYSTEM, "连接已断开（状态已回到未连接）")
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
        // 手动断开时也立刻停掉协议级心跳日志计时器（不等 OkHttp 回调，避免时序上多刷一行；
        // 回调里那次 stop 是幂等的）
        stopWsPingLog()
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
                // 打洞到这里就结束了：**不做任何「应用」行为**（不跳 tab、不自动交给某个用法）。
                // 第 3、4 步的探测由 SessionManager 在收到服务器回复时自动开始，
                // 之后由用户在 socket 卡片第 5 行选用法（udptest / tun / switch / wg）。
                appendMessage(Direction.SYSTEM, "打洞完成，等待在 socket 卡片上选用法")
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
    /**
     * WireGuard 相关的日志。
     * **不再单独开一个"消息历史"**——统一进 App 内日志（主页那颗悬浮「日志」按钮点开的矩形）。
     */
    fun appendWgLog(text: String) {
        appendMessage(Direction.SYSTEM, "wg: $text")
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
        manager.onLog = { text ->
            udpLog(text)
            // direct 和 UDP tab 没关系，日志同时镜像一份到「App 内日志」，不然看不到 ping 细节
            if (text.contains("[direct]")) appendMessage(Direction.SYSTEM, text)
        }
        // direct 的发送出口：SessionManager 不直接持有 WsClient，在这里接到 repository 上
        manager.sendDirect = { target, v4, v6 -> repository.sendP2pDirect(target, v4, v6) }
        manager.sendDirectReply = { target, v4, v6 -> repository.sendP2pDirectReply(target, v4, v6) }
        // 收到服务器转来的 direct 地址交换（请求要回一份地址，应答只探测）
        repository.onP2pDirect = { from, ipv4, ipv6, isReply ->
            val m = sessionManager
            if (m == null) {
                appendMessage(Direction.SYSTEM, "收到 $from 的 direct 地址交换，但后台服务未就绪")
            } else {
                appendMessage(
                    Direction.SYSTEM,
                    if (isReply) "收到 $from 的 direct 应答" else "收到 $from 的 direct 请求（自动回一份地址）"
                )
                m.onDirectFromPeer(from, ipv4, ipv6, isReply)
            }
        }
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

        when (usageId) {
            "udptest" -> {
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
            "wg" -> {
                // 先填地址并跳到 WireGuard 页（原 wghelp 的行为），
                // 再按 WG 页上的「实现」选择决定后续动作
                openWireGuardTab(card)
                routeWgByConfig(card)
            }
            "switch" -> {
                // 按 Switch 页的配置启动（或复用）交换机，然后这条 session 会占第一个空网口
                if (!_uiState.value.switchRunning) onSwitchStart()
                appendMessage(
                    Direction.SYSTEM,
                    "switch：把 ${card.target} 插到网口（对端 ${formatHostPort(card.peerPublicIp, card.peerPublicPort)}）"
                )
                navigateTo(Page.Switch)
            }
            "proxy" -> {
                // 按 Proxy 页的配置启动（或复用）端口转发，然后这条 session 变成那条通道
                if (!_uiState.value.proxyRunning) onProxyStart()
                appendMessage(
                    Direction.SYSTEM,
                    "proxy：把 ${card.target} 接成通道（洞本机端口 ${card.localPort}）"
                )
                navigateTo(Page.Proxy)
            }
            "tun" -> {
                // tun = 一对一 VPN 的隧道：按 VPN 页的配置启动/复用，然后跳到 vpn 页
                if (!_uiState.value.vpnRunning) onVpnStart()
                appendMessage(
                    Direction.SYSTEM,
                    "vpn：把 ${card.target} 接成一对一通道（洞本机端口 ${card.localPort}）"
                )
                navigateTo(Page.Vpn)
            }
            "media" -> {
                // media：只负责把这条洞接成通道，媒体去 media 页点「拉起应用」
                appendMessage(
                    Direction.SYSTEM,
                    "media：把 ${card.target} 接成多媒体通道（洞本机端口 ${card.localPort}），" +
                        "去 media 页点「拉起应用」"
                )
                navigateTo(Page.Media)
            }
        }

        if (!manager.attachUsage(id, usageId)) {
            appendMessage(Direction.SYSTEM, "socket 已关闭，无法交给 $usageId")
        }
    }

    /**
     * 按 WireGuard 页上的「实现」选择决定后续动作。
     *
     * 三档的区别只是"谁来跑协议栈"，共同点是 **UDP 出口必须是已经打洞的那个本地端口**
     * （card.localPort），否则打洞建立起来的 NAT 映射就废了。
     * 真正的三档实现都还没接入（本次只做页面 + 配置 + 路由），所以这里把"该走哪条路、
     * 用什么参数"明确写进 App 内日志，接入时照着分支填即可。
     */
    private fun routeWgByConfig(card: UdpSessionInfo) {
        val cfg = _uiState.value.wgConfig
        when (cfg.impl) {
            WgPageConfig.IMPL_SELF -> appendMessage(
                Direction.SYSTEM,
                "wg[自己实现]：复用已打洞 socket（本机端口 ${card.localPort}）跑自写协议栈 + 自建 VpnService；" +
                    "协议栈尚未接入（TODO）"
            )
            WgPageConfig.IMPL_OFFICIAL -> appendMessage(
                Direction.SYSTEM,
                "wg[官方库]：走官方 wireguard tunnel 库 + 自建 VpnService（本机端口 ${card.localPort}）；" +
                    "依赖尚未接入（TODO）"
            )
            else -> startExternalVpn(card, cfg)
        }
    }

    /**
     * impl = system：把这条洞的参数交给另一个真正的 VPN 服务 app（参数契约由我们自己定）。
     *
     *   action      = cfg.extAction（默认 com.p2pnet.action.START_VPN，manifest 的 <queries> 里声明）
     *   package     = cfg.extPackage（可留空 = 按 action 找）
     *   extras      = listen_port / peer_ip / peer_port / my_public_ip / my_public_port
     *
     * listen_port 必须是打洞时那个本地端口，对方 app 得 listen 在同一个端口上，NAT 映射才不废。
     */
    private fun startExternalVpn(card: UdpSessionInfo, cfg: WgPageConfig) {
        val action = cfg.extAction.ifBlank { WgPageConfig.DEFAULT_EXT_ACTION }
        val pkg = cfg.extPackage.trim()
        appendMessage(
            Direction.SYSTEM,
            "wg[调系统程序]：action=$action" +
                (if (pkg.isNotEmpty()) " package=$pkg" else "（未指定包名，按 action 找）") +
                " listen_port=${card.localPort}" +
                " peer=${formatHostPort(card.peerPublicIp, card.peerPublicPort)}" +
                " my_public=${formatHostPort(card.myPublicIp, card.myPublicPort)}"
        )
        val starter = onStartExternalVpn
        if (starter == null) {
            appendMessage(Direction.SYSTEM, "wg：拉起外部 VPN 服务的通道没接好（Activity 没注册 hook）")
            return
        }
        val ok = starter(action, pkg, card.localPort, card.peerPublicIp, card.peerPublicPort)
        appendMessage(
            Direction.SYSTEM,
            if (ok) "wg：已拉起外部 VPN 服务（$action）"
            else "wg：没找到能处理 $action 的 VPN 应用（对方 app 还没装？）"
        )
    }

    /** 把一条已打通的 session 交给 WireGuard 页：填公网地址并跳过去（原 wghelp 的行为） */
    private fun openWireGuardTab(card: UdpSessionInfo) {
        val tabs = _uiState.value.tabs
        val wgIndex = tabs.indexOfFirst { it.page is Page.WireGuard }
        if (wgIndex < 0) {
            appendMessage(Direction.SYSTEM, "WireGuard tab 未找到")
            return
        }
        val updatedPage = Page.WireGuard(
            targetUsername = card.target,
            myIp = card.myPublicIp,
            myPort = card.myPublicPort,
            peerIp = card.peerPublicIp,
            peerPort = card.peerPublicPort
        )
        val updatedTabs = tabs.toMutableList()
        updatedTabs[wgIndex] = updatedTabs[wgIndex].copy(page = updatedPage)
        _uiState.value = _uiState.value.copy(
            tabs = updatedTabs,
            currentTabIndex = wgIndex,
            currentPage = updatedPage
        )
        appendMessage(
            Direction.SYSTEM,
            "已交给 WireGuard：公网 ${formatHostPort(card.myPublicIp, card.myPublicPort)} ↔ 对端 ${formatHostPort(card.peerPublicIp, card.peerPublicPort)}"
        )
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
                is Page.WireGuard -> "wireguard"
                is Page.Switch -> "switch"
                is Page.Proxy -> "proxy"
                is Page.Vpn -> "vpn"
                is Page.Media -> "media"
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
        // 固定配置页（主页 / WireGuard / Switch）不给关，界面上的 × 也不会显示
        if (!tabs[index].closable) return
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
                        // WG 配置里的 Endpoint 是 host:port，v6 必须写成 [v6]:port
                        endpoint = formatHostPort(page.peerIp, page.peerPort),
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
