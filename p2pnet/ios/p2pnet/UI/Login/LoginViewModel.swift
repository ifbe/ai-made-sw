import Foundation
import Combine
import UIKit

@MainActor
class LoginViewModel: ObservableObject {
    @Published var uiState: LoginUiState

    private let repository: P2pRepository
    private var messageCount: Int = 0

    /// session（打洞产出的 socket / 卡片）的唯一 owner；ViewModel 只观察它
    /// （对应 Android 的 `P2pService.sessionManager`；iOS 没有前台 Service，所以放这儿）
    let sessionManager = SessionManager()

    @Published var udpSockMessages: [String] = []

    // Service callbacks (stub - no foreground service on iOS)
    var onStartService: (() -> Void)?
    var onStopService: (() -> Void)?

    init(repository: P2pRepository) {
        self.repository = repository
        // 两个配置页的配置从 LocalPrefs 恢复（JSON 原文 → struct，解析失败退回默认值）
        var state = LoginUiState(serverHost: repository.getServerHost())
        state.wgConfig = WgPageConfig.fromJson(repository.getWgConfigJson())
        state.switchConfig = SwitchPageConfig.fromJson(repository.getSwitchConfigJson())
        state.proxyConfig = ProxyPageConfig.fromJson(repository.getProxyConfigJson())
        state.vpnConfig = VpnPageConfig.fromJson(repository.getVpnConfigJson())
        state.mediaConfig = MediaPageConfig.fromJson(repository.getMediaConfigJson())
        self.uiState = state

        // 只观察：SessionManager 推快照 → uiState；它自己负责 socket 与进度
        sessionManager.onLog = { [weak self] text in
            // SessionManager.log() 已保证主线程回调；这里再判一次兜底，
            // 因为 udpLog 写的是 @Published（后台线程写会 "Publishing changes from
            // background threads is not allowed"，实测会卡死界面）
            if Thread.isMainThread {
                self?.udpLog(text)
            } else {
                DispatchQueue.main.async { self?.udpLog(text) }
            }
        }
        sessionManager.observer = { [weak self] sessions in
            // publish() 已经是派发到 main 的。这里不用 `MainActor.assumeIsolated`：
            // 那个一旦不在主线程会直接 trap 成崩溃，只做安全跳转更稳
            if Thread.isMainThread {
                self?.uiState.udpSockets = sessions
            } else {
                DispatchQueue.main.async { self?.uiState.udpSockets = sessions }
            }
        }
        // direct 的发送出口：SessionManager 不直接持有 WsClient，在这里接到 repository 上
        sessionManager.sendDirect = { [weak self] target, ipv4, ipv6 in
            self?.repository.sendP2pDirect(target, ipv4: ipv4, ipv6: ipv6)
        }
        sessionManager.sendDirectReply = { [weak self] target, ipv4, ipv6 in
            self?.repository.sendP2pDirectReply(target, ipv4: ipv4, ipv6: ipv6)
        }
        uiState.udpSockets = sessionManager.sessionsSnapshot()
    }

    /// UDP 日志统一入口（socket 卡片 / 进度 / ping 流量都进这个列表，UDP 页显示）
    private func udpLog(_ text: String) {
        udpSockMessages.append(text)
    }

    func onServerHostChange(_ host: String) {
        uiState.serverHost = host
    }

    func onServerPortChange(_ port: String) {
        uiState.serverPort = port
    }

    func onUseWssChange(_ useWss: Bool) {
        uiState.useWss = useWss
    }

    func onUsernameChange(_ username: String) {
        uiState.username = username
    }

    func onPasswordChange(_ password: String) {
        uiState.password = password
    }

    func onTargetUsernameChange(_ target: String) {
        uiState.targetUsername = target
    }

    /// 「我」卡片上 ping 按钮的序号：点一次 +1，从 1 开始
    /// （协议：发 `{"type":"ping","seq":N}` → 服务端原样回 `{"type":"pong","seq":N}`，不需要登录）
    private var pingSeq = 0

    /// 点「我」卡片的 ping 按钮：发一条应用层 ping，
    /// 出/入报文都会由 `sendJson`/接收循环经 `onSend`/`onRecv` 写进 App 内日志
    func onPing() {
        pingSeq += 1
        repository.sendAppPing(seq: pingSeq)
    }

    func onList() {
        repository.sendList()
    }

    func onUdp() {
        // 记下目标：socket 建好时 SessionManager 用它把卡片挂到对应的人上
        sessionManager.setPendingTarget(uiState.targetUsername)
        repository.sendP2pUdp(uiState.targetUsername)
    }

    func onTcp() {
        repository.sendP2pTcp(uiState.targetUsername)
    }

    // A3：`onWghelp()` 已删除（服务端 wghelp handler 已注释，发了只会收 error）。
    // wg 入口改成 socket 卡片上的 `wg` 按钮，按 WG 页的「实现」配置路由（阶段 3 落）。

    // MARK: - 其他人卡片上的打洞按钮（顺序固定：direct / upnp / udp / tcp）

    /// 其他人卡片上按了某个打洞方式（对齐 Android `MainPage.kt` 的 PeerNode：
    /// 这里只有打洞行为，「应用」行为在 socket 卡片第 5 行上选）
    func onPeerPunch(_ target: String, _ action: String) {
        switch action {
        case "direct": onDirect(target)
        case "upnp": onUpnp(target)
        case "udp": onUdp(target)
        case "tcp": onTcp(target)
        default: appendMessage(.system, "不认识的打洞方式: \(action)")
        }
    }

    /// udp：真正的打洞。记下目标，socket 建好时 SessionManager 用它把卡片挂到对应的人上
    func onUdp(_ target: String = "") {
        let t = target.isEmpty ? uiState.targetUsername : target
        guard !t.isEmpty else { return }
        sessionManager.setPendingTarget(t)
        repository.sendP2pUdp(t)
    }

    /// tcp：TCP 打洞（3 个 socket 同端口 + listen/connect 竞速）。
    /// 目前**只出流程预览**：不建 socket、也不发 `p2ptcp` 信令。
    func onTcp(_ target: String = "") {
        let t = target.isEmpty ? uiState.targetUsername : target
        guard !t.isEmpty else { return }
        sessionManager.previewFlow(kind: "tcp", target: t)
        appendMessage(.system, "显示 tcp 流程（真实逻辑尚未实现）：target=\(t)")
    }

    /// upnp：双方各自让路由器开洞，把映射出来的公网地址当作候选。目前**只出流程预览**。
    func onUpnp(_ target: String = "") {
        let t = target.isEmpty ? uiState.targetUsername : target
        guard !t.isEmpty else { return }
        sessionManager.previewFlow(kind: "upnp", target: t)
        appendMessage(.system, "显示 upnp 流程（真实逻辑尚未实现）：target=\(t)")
    }

    /// direct：跟服务器交换 v4/v6 地址，再做 ICMP 可达性探测（真实现，不再是预览）。
    /// 协议里只有地址、**没有端口**，所以不建 socket、不建隧道，卡片上只报「哪些地址可达」。
    func onDirect(_ target: String = "") {
        let t = target.isEmpty ? uiState.targetUsername : target
        guard !t.isEmpty else { return }
        let id = sessionManager.startDirect(t)
        appendMessage(.system, "发起 direct（交换 v4/v6 地址并探测可达性）：target=\(t) 卡片=#\(id ?? -1)")
    }

    // MARK: - 两个配置页的配置（改一次就写回 LocalPrefs）

    func onWgImplChange(_ impl: String) { updateWgConfig { $0.impl = impl } }
    func onWgExtPackageChange(_ value: String) { updateWgConfig { $0.extPackage = value } }
    func onWgExtActionChange(_ value: String) { updateWgConfig { $0.extAction = value } }

    private func updateWgConfig(_ transform: (inout WgPageConfig) -> Void) {
        var cfg = uiState.wgConfig
        transform(&cfg)
        uiState.wgConfig = cfg
        repository.setWgConfigJson(cfg.toJson())
    }

    func onSwitchCardModeChange(_ value: String) { updateSwitchConfig { $0.cardMode = value } }
    func onSwitchTunIpChange(_ value: String) { updateSwitchConfig { $0.tunIp = value } }
    func onSwitchModeChange(_ value: String) { updateSwitchConfig { $0.mode = value } }
    func onSwitchMtuChange(_ value: String) { updateSwitchConfig { $0.mtu = value } }
    func onSwitchRouteTtlChange(_ value: String) { updateSwitchConfig { $0.routeTtl = value } }
    func onSwitchDhcpEnabledChange(_ value: Bool) { updateSwitchConfig { $0.dhcpEnabled = value } }
    func onSwitchDhcpPoolChange(_ value: String) { updateSwitchConfig { $0.dhcpPool = value } }
    func onSwitchDhcpGatewayChange(_ value: String) { updateSwitchConfig { $0.dhcpGateway = value } }
    func onSwitchDhcpDnsChange(_ value: String) { updateSwitchConfig { $0.dhcpDns = value } }

    private func updateSwitchConfig(_ transform: (inout SwitchPageConfig) -> Void) {
        var cfg = uiState.switchConfig
        transform(&cfg)
        uiState.switchConfig = cfg
        repository.setSwitchConfigJson(cfg.toJson())
    }

    // ── Proxy 页（端口转发）配置 ──

    func onProxyModeChange(_ value: String) { updateProxyConfig { $0.mode = value } }
    func onProxyProtoChange(_ value: String) { updateProxyConfig { $0.proto = value } }
    func onProxyKeepaliveChange(_ value: String) { updateProxyConfig { $0.keepaliveSec = value } }
    func onProxyBindAddrChange(_ value: String) { updateProxyConfig { $0.bindAddr = value } }
    func onProxyLocalPortChange(_ value: String) { updateProxyConfig { $0.localPort = value } }
    func onProxyLListenIpChange(_ value: String) { updateProxyConfig { $0.lListenIp = value } }
    func onProxyLListenPortChange(_ value: String) { updateProxyConfig { $0.lListenPort = value } }
    func onProxyRTargetHostChange(_ value: String) { updateProxyConfig { $0.rTargetHost = value } }
    func onProxyRTargetPortChange(_ value: String) { updateProxyConfig { $0.rTargetPort = value } }

    private func updateProxyConfig(_ transform: (inout ProxyPageConfig) -> Void) {
        var cfg = uiState.proxyConfig
        transform(&cfg)
        uiState.proxyConfig = cfg
        repository.setProxyConfigJson(cfg.toJson())
    }

    /// 启动端口转发。真正的转发循环还没做，现在只改页面状态 + 把「按页面配置该起什么」写进日志。
    func onProxyStart() {
        let cfg = uiState.proxyConfig
        uiState.proxyRunning = true
        appendMessage(.system, "proxy：按页面配置启动 —— \(cfg.summary())")
        if cfg.mode == ProxyPageConfig.modeL {
            appendMessage(.system,
                "proxy：-L 会监听 \(formatHostPort(cfg.lListenIp, Int(cfg.lListenPort) ?? 0))，"
                + "accept 后与洞互转（对端要跑 -R）")
        } else if Int(cfg.rTargetPort) == nil {
            appendMessage(.system, "proxy：-R 的目标端口还没填，启动后连不上目标")
        } else {
            appendMessage(.system,
                "proxy：-R 会 connect \(formatHostPort(cfg.rTargetHost, Int(cfg.rTargetPort) ?? 0))，与洞互转")
        }
        appendMessage(.system, "proxy：转发逻辑尚未实现（TODO），当前只有配置")
    }

    func onProxyStop() {
        uiState.proxyRunning = false
        appendMessage(.system, "proxy：已停止（通道还在，socket 不受影响）")
    }

    // ── VPN 页（一对一 tun/tap）配置 ──

    func onVpnCardModeChange(_ value: String) { updateVpnConfig { $0.cardMode = value } }
    func onVpnTunIpChange(_ value: String) { updateVpnConfig { $0.tunIp = value } }
    func onVpnModeChange(_ value: String) { updateVpnConfig { $0.mode = value } }
    func onVpnMtuChange(_ value: String) { updateVpnConfig { $0.mtu = value } }
    func onVpnRouteTtlChange(_ value: String) { updateVpnConfig { $0.routeTtl = value } }
    func onVpnDhcpEnabledChange(_ value: Bool) { updateVpnConfig { $0.dhcpEnabled = value } }
    func onVpnDhcpPoolChange(_ value: String) { updateVpnConfig { $0.dhcpPool = value } }
    func onVpnDhcpGatewayChange(_ value: String) { updateVpnConfig { $0.dhcpGateway = value } }
    func onVpnDhcpDnsChange(_ value: String) { updateVpnConfig { $0.dhcpDns = value } }

    private func updateVpnConfig(_ transform: (inout VpnPageConfig) -> Void) {
        var cfg = uiState.vpnConfig
        transform(&cfg)
        uiState.vpnConfig = cfg
        repository.setVpnConfigJson(cfg.toJson())
    }

    /// 启动/停止一对一 VPN。真正的 tun/tap + 转发还没做，现在只改页面状态 + 写日志。
    func onVpnStart() {
        let cfg = uiState.vpnConfig
        let channels = uiState.udpSockets.filter { $0.handedTo == "tun" }
        uiState.vpnRunning = true
        appendMessage(.system, "vpn：按页面配置启动 —— \(cfg.summary())")
        if channels.isEmpty {
            appendMessage(.system, "vpn：还没有接通道（在主页 socket 卡片第 5 行点 tun）")
        } else {
            let list = channels.map { "\($0.target)(洞\($0.localPort))" }.joined(separator: "、")
            appendMessage(.system, "vpn：一对一通道 = \(list)")
            if channels.count > 1 {
                appendMessage(.system, "vpn：一对一只需要一条通道，现在接了 \(channels.count) 条")
            }
        }
        appendMessage(.system, "vpn：tun/tap 与协议栈尚未实现（TODO），当前只有配置")
    }

    func onVpnStop() {
        uiState.vpnRunning = false
        appendMessage(.system, "vpn：已停止（通道还在，socket 不受影响）")
    }

    // ── media 页（多媒体聊天）配置 ──
    // 我们只负责打洞；媒体流由外部聊天程序收发，所以这里只有配置 + 拉起。

    func onMediaRecvProtoChange(_ value: String) { updateMediaConfig { $0.recvProto = value } }
    func onMediaSendProtoChange(_ value: String) { updateMediaConfig { $0.sendProto = value } }
    func onMediaCaptureChange(_ value: String) { updateMediaConfig { $0.capture = value } }
    func onMediaAppPackageChange(_ value: String) { updateMediaConfig { $0.appPackage = value } }
    func onMediaAppActionChange(_ value: String) { updateMediaConfig { $0.appAction = value } }

    private func updateMediaConfig(_ transform: (inout MediaPageConfig) -> Void) {
        var cfg = uiState.mediaConfig
        transform(&cfg)
        uiState.mediaConfig = cfg
        repository.setMediaConfigJson(cfg.toJson())
    }

    /// media 页的「拉起应用」：把这条洞的参数交给外部聊天程序。
    ///
    /// iOS 用自定义 URL scheme（不改 Info.plist，也不用 canOpenURL），参数**全部取自打洞通道**
    /// （参数表和 Android `MainActivity.launchMediaApp` 的 extras 一致，一共 7 个 key）：
    /// `p2pnetmedia://start?localaddr=…&localport=…&peeraddr=…&peerport=…`
    /// `&recv_proto=…&send_proto=…&capture=…`
    ///   - `localaddr`/`localport` = 本机这一侧（洞的本机地址、本机端口）
    ///   - `peeraddr`/`peerport`  = 对方路由器公网地址、端口（对方内网地址不用管）
    /// - `appPackage` 在 iOS 侧当 URL scheme 用（留空 = `p2pnetmedia`）；
    /// - `appAction` 保留 JSON 键以便两端配置可对照，但 iOS 拼 URL 时 host 固定 `start`。
    func onMediaLaunchApp() {
        let cfg = uiState.mediaConfig
        guard let channel = sessionManager.sessionsSnapshot().first(where: { $0.handedTo == "media" }) else {
            appendMessage(.system,
                "media：还没打洞（先去主页 socket 卡片第 5 行点 media），拉起等于没有通道可用")
            return
        }
        let trimmed = cfg.appPackage.trimmingCharacters(in: .whitespaces)
        let scheme = trimmed.isEmpty ? "p2pnetmedia" : trimmed

        appendMessage(.system,
            "media[拉起应用]：scheme=\(scheme) action=\(cfg.appAction)（仅 Android 用）"
            + " localaddr=\(channel.localIp) localport=\(channel.localPort)"
            + " peeraddr=\(channel.peerPublicIp) peerport=\(channel.peerPublicPort)"
            + " recv=\(cfg.recvProto) send=\(cfg.sendProto) capture=\(cfg.capture)")

        var comps = URLComponents()
        comps.scheme = scheme
        comps.host = "start"
        comps.queryItems = [
            URLQueryItem(name: "localaddr", value: channel.localIp),
            URLQueryItem(name: "localport", value: String(channel.localPort)),
            URLQueryItem(name: "peeraddr", value: channel.peerPublicIp),
            URLQueryItem(name: "peerport", value: String(channel.peerPublicPort)),
            URLQueryItem(name: "recv_proto", value: cfg.recvProto),
            URLQueryItem(name: "send_proto", value: cfg.sendProto),
            URLQueryItem(name: "capture", value: cfg.capture),
        ]
        guard let url = comps.url else {
            appendMessage(.system, "media[拉起应用]：URL 拼不出来（scheme=\(scheme)）")
            return
        }
        appendMessage(.system, "media[拉起应用]：open \(url.absoluteString)")

        UIApplication.shared.open(url, options: [:]) { [weak self] ok in
            DispatchQueue.main.async {
                self?.appendMessage(.system, ok
                    ? "media：已拉起聊天程序（\(scheme)://start）"
                    : "media：没找到能处理 \(scheme)://start 的聊天程序（对方 app 还没装？）")
            }
        }
    }

    // MARK: - WireGuard 路由（点 socket 卡片上的 wg 之后）

    /// 先填地址并跳到 WG 页，再按 WG 页的「实现」选择决定后续动作
    /// （对齐 Android `openWireGuardTab` + `routeWgByConfig`）。
    ///
    /// 注意 `myPort` 用的是**打洞时那个本地端口**（`card.localPort`）：
    /// Android 那边填的是 `myPublicPort`，但 WG 的 listen port 必须是本机那个端口，
    /// 否则打洞出来的 NAT 映射会对不上（本页的参数预览和 URL 也都用这个口）。
    private func routeWg(_ card: UdpSessionInfo) {
        navigateTo(Page.wireGuard(
            targetUsername: card.target,
            myIp: card.myPublicIp,
            myPort: card.localPort,
            peerIp: card.peerPublicIp,
            peerPort: card.peerPublicPort
        ))

        let cfg = uiState.wgConfig
        switch cfg.impl {
        case WgPageConfig.implSelf:
            appendMessage(.system,
                "wg[自己实现]：复用已打洞 socket（本机端口 \(card.localPort)）跑自写协议栈 + 自建隧道；"
                + "协议栈尚未接入（TODO）")
        case WgPageConfig.implOfficial:
            appendMessage(.system,
                "wg[官方库]：调官方 wireguard tunnel 库 + 自建隧道（本机端口 \(card.localPort)）；"
                + "依赖尚未接入（TODO：要 SPM 依赖 + NetworkExtension）")
        default:
            startExternalVpn(card, cfg: cfg)
        }
    }

    /// impl = system：把这条洞的参数交给外部那个真正的 VPN 服务 app。
    ///
    /// iOS 用自定义 URL scheme（不改 Info.plist，也不用 canOpenURL）：
    ///   `p2pnetvpn://start?listen_port=…&peer_ip=…&peer_port=…&my_public_ip=…&my_public_port=…`
    /// - `extPackage` 在 iOS 侧当 URL scheme 用（留空 = 默认 `p2pnetvpn`）；
    /// - `extAction` 保留 JSON 键以便两端配置可对照，但 iOS 拼 URL 时 **host 固定用 `start`**，
    ///   那串 action 只在 Android 用；
    /// - 用 `open` 的回调 Bool 判断「有没有 app 接走」。
    private func startExternalVpn(_ card: UdpSessionInfo, cfg: WgPageConfig) {
        let trimmed = cfg.extPackage.trimmingCharacters(in: .whitespaces)
        let scheme = trimmed.isEmpty ? "p2pnetvpn" : trimmed

        var comps = URLComponents()
        comps.scheme = scheme
        comps.host = "start"
        comps.queryItems = [
            URLQueryItem(name: "listen_port", value: String(card.localPort)),
            URLQueryItem(name: "peer_ip", value: card.peerPublicIp),
            URLQueryItem(name: "peer_port", value: String(card.peerPublicPort)),
            URLQueryItem(name: "my_public_ip", value: card.myPublicIp),
            URLQueryItem(name: "my_public_port", value: String(card.myPublicPort)),
        ]
        guard let url = comps.url else {
            appendMessage(.system, "wg[调系统程序]：URL 拼不出来（scheme=\(scheme)）")
            return
        }

        appendMessage(.system,
            "wg[调系统程序]：scheme=\(scheme) action=\(cfg.extAction)（仅 Android 用）"
            + " listen_port=\(card.localPort)"
            + " peer=\(formatHostPort(card.peerPublicIp, card.peerPublicPort))"
            + " my_public=\(formatHostPort(card.myPublicIp, card.myPublicPort))")
        appendMessage(.system, "wg[调系统程序]：open \(url.absoluteString)")

        UIApplication.shared.open(url, options: [:]) { [weak self] ok in
            DispatchQueue.main.async {
                self?.appendMessage(.system, ok
                    ? "wg：已拉起外部 VPN 服务（\(scheme)://start）"
                    : "wg：没找到能处理 \(scheme)://start 的 VPN 应用（对方 app 还没装？）")
            }
        }
    }

    func onConnect() {
        appendMessage(.system, "点击连接")
        uiState.loading = true
        uiState.error = nil

        setupRepositoryCallbacks()
        repository.setupConnectionCallbacks()
        appendMessage(.system, "setupRepositoryCallbacks 完成")
        appendMessage(.system, "connectOnly 调用前")
        repository.connectOnly(useWss: uiState.useWss, host: uiState.serverHost, port: Int(uiState.serverPort) ?? 10000)
        appendMessage(.system, "connectOnly 已返回，等待 onConnected 回调...")
    }

    func onDisconnect() {
        repository.disconnectOnly()
        onStopService?()
        // 不清空 messages：App 内日志跨连接保留，只有日志面板里的「清空」才会清
        // —— 逐条对齐 Android `LoginViewModel.onDisconnect()`
        uiState.isConnected = false
        uiState.isLoggedIn = false
        uiState.loading = false
        uiState.myIp = ""
        uiState.myPort = 0
        uiState.peers = []
        sessionManager.closeAll()
    }

    func onLogin() {
        guard !uiState.username.isEmpty, !uiState.password.isEmpty else {
            uiState.error = "请输入用户名和密码"
            return
        }

        appendMessage(.system, "点击登录")
        uiState.loading = true
        uiState.error = nil

        setupRepositoryCallbacks()
        appendMessage(.system, "开始登录流程")


        Task {
            appendMessage(.system, "await repository.login(...)")
            let result = await repository.login(
                useWss: uiState.useWss,
                host: uiState.serverHost,
                port: Int(uiState.serverPort) ?? 10000,
                username: uiState.username,
                password: uiState.password
            )
            appendMessage(.system, "login 返回，结果=\(result)")
            switch result {
            case .success(let username):
                appendMessage(.system, "登录成功")
                uiState.loading = false
                uiState.isLoggedIn = true
                uiState.isConnected = true
                uiState.loggedInUsername = username
                uiState.error = nil
            case .error(let message):
                appendMessage(.system, "登录失败: \(message)")
                uiState.loading = false
                uiState.error = message
            }
        }
    }

    func onLogout() {
        // 只退出登录：给服务器发 `{"type":"logout"}`，但 WebSocket 连接保留
        //（isConnected 不动、不停服务、不清空已输入的密码、也不清空 App 内日志）
        // —— 逐条对齐 Android `LoginViewModel.onLogout()`
        repository.logout(keepConnection: true)
        uiState.isLoggedIn = false
        uiState.loggedInUsername = ""
        uiState.myIp = ""
        uiState.myPort = 0
        uiState.peers = []
        sessionManager.closeAll()
    }

    func clearError() {
        uiState.error = nil
    }

    func clearMessages() {
        uiState.messages = []
    }

    func clearUdpSockMessages() {
        udpSockMessages = []
    }

    // MARK: - Tab navigation

    /// 两个 Page 是不是「同一种页面」（对齐 Android `navigateTo` 里的
    /// `it.page::class == page::class`）。
    /// 不能直接比 `Page` 的相等：wireGuard / udpTest 带着地址，地址一变就不相等了，
    /// 那样每次点 wg 都会再开一个 tab —— 原来那行判重
    /// `!(page == .main || page == .wireGuard() || false)` 就是这个毛病（`|| false` 还是死代码）。
    private func samePageKind(_ a: Page, _ b: Page) -> Bool {
        switch (a, b) {
        case (.main, .main), (.udpTest, .udpTest), (.videoCall, .videoCall),
             (.chat, .chat), (.wireGuard, .wireGuard), (.vswitch, .vswitch),
             (.proxy, .proxy), (.vpn, .vpn), (.media, .media):
            return true
        default:
            return false
        }
    }

    func navigateTo(_ page: Page) {
        // 主页固定在第 0 个 tab
        if samePageKind(page, .main) {
            uiState.currentTabIndex = 0
            uiState.currentPage = .main
            return
        }

        var tabs = uiState.tabs
        if let existing = tabs.firstIndex(where: { samePageKind($0.page, page) }) {
            // 命中已有 tab：切过去，并把 page 刷新成新的一份
            // （WG 页带着对端地址，必须刷新；closable 也要原样保留，别重建时把固定页变成可关闭）
            tabs[existing] = TabItem(
                page: page,
                title: tabs[existing].title,
                closable: tabs[existing].closable
            )
            uiState.tabs = tabs
            uiState.currentTabIndex = existing
            uiState.currentPage = page
            return
        }

        // 新开 tab 时才清空 UDP 日志
        if case .udpTest = page {
            udpSockMessages = []
        }
        let title: String
        switch page {
        case .udpTest: title = "UDP"
        case .wireGuard: title = "wireguard"
        case .vswitch: title = "switch"
        case .proxy: title = "proxy"
        case .vpn: title = "vpn"
        case .media: title = "media"
        case .videoCall: title = "视频通话"
        case .chat: title = "聊天"
        case .main: title = "主页"
        }
        tabs.append(TabItem(page: page, title: title))
        uiState.tabs = tabs
        uiState.currentTabIndex = tabs.count - 1
        uiState.currentPage = page
    }

    func switchToTab(_ index: Int) {
        guard index >= 0 && index < uiState.tabs.count else { return }
        uiState.currentTabIndex = index
        uiState.currentPage = uiState.tabs[index].page
    }

    func removeTab(_ index: Int) {
        guard index > 0 && index < uiState.tabs.count else { return }
        // 固定配置页（主页 / WireGuard / Switch）不给关，界面上也不显示 ×
        guard uiState.tabs[index].closable else { return }
        let removed = uiState.tabs[index]
        var tabs = uiState.tabs
        tabs.remove(at: index)
        if case .udpTest = removed.page {
            // 关掉 UDP tab 只摘掉用法（停 ping），session 和 socket 保留
            // （对齐 Android removeTab → detachUdpUsages）
            sessionManager.detachAllUsages()
        }
        var current = uiState.currentTabIndex
        var page = uiState.currentPage
        if current >= tabs.count {
            current = tabs.count - 1
            page = tabs[current].page
        } else if current > index {
            current -= 1
            page = tabs[current].page
        }
        uiState.tabs = tabs
        uiState.currentTabIndex = current
        uiState.currentPage = page
    }

    private func appendMessage(_ dir: Direction, _ content: String) {
        let item = MessageItem(direction: dir, content: content)
        uiState.messages.append(item)
    }

    // MARK: - Repository callbacks

    private func setupRepositoryCallbacks() {
        appendMessage(.system, "setupRepositoryCallbacks")
        repository.onLogMessage = { [weak self] text in
            DispatchQueue.main.async {
                self?.appendMessage(.system, text)
            }
        }
        repository.onConnectedHandler = { [weak self] in
            DispatchQueue.main.async {
                self?.appendMessage(.system, "onConnected 回调")
                self?.uiState.loading = false
                self?.uiState.isConnected = true
            }
        }
        repository.onDisconnectedHandler = { [weak self] in
            DispatchQueue.main.async {
                self?.appendMessage(.system, "onDisconnected 回调")
                self?.uiState.isConnected = false
                self?.uiState.isLoggedIn = false
            }
        }
        repository.onError = { [weak self] message in
            DispatchQueue.main.async {
                self?.appendMessage(.system, "onError: \(message)")
                self?.uiState.loading = false
                self?.uiState.error = message
            }
        }
        repository.onUdpSend = { [weak self] text in
            DispatchQueue.main.async {
                let dir: Direction = (text.contains("burst") || text.contains("keep-alive")) ? .udpSend : .system
                self?.appendMessage(dir, text)
            }
        }
        repository.onUdpRecv = { [weak self] text in
            DispatchQueue.main.async {
                self?.appendMessage(.server, "← \(text)")
            }
        }
        repository.onHelloDone = { [weak self] info, sock, peerIp, peerPort, mode in
            DispatchQueue.main.async {
                self?.appendMessage(.system, "onHelloDone callback")
                self?.handleHelloDone(info: info, sock: sock, peerIp: peerIp, peerPort: peerPort, mode: mode)
            }
        }
        // socket 卡片：绑定完成就建卡；每一步进度按 fd 找到卡片打勾
        repository.onUdpSocketBound = { [weak self] fd, localIp, localPort in
            self?.sessionManager.beginHello(fd: fd)
            DispatchQueue.main.async {
                self?.appendMessage(.system, "socket 卡片已创建（本机绑定 \(formatHostPort(localIp, localPort))）")
            }
        }
        repository.onUdpSocketStep = { [weak self] fd, step, myIp, myPort, peerIp, peerPort in
            self?.sessionManager.markStep(
                fd: fd,
                step: step,
                myIp: myIp,
                myPort: myPort,
                peerIp: peerIp,
                peerPort: peerPort
            )
        }
        // direct 地址交换：收到就要处理（请求要回一份地址，应答只探测）
        repository.onP2pDirect = { [weak self] from, ipv4, ipv6, isReply in
            self?.sessionManager.onDirectFromPeer(from: from, ipv4: ipv4, ipv6: ipv6, isReply: isReply)
            DispatchQueue.main.async {
                self?.appendMessage(
                    .system,
                    isReply ? "收到 \(from) 的 direct 应答" : "收到 \(from) 的 direct 请求（自动回一份地址）"
                )
            }
        }
        repository.onListResult = { [weak self] users in
            DispatchQueue.main.async {
                self?.applyListResult(users)
            }
        }
        repository.onSend = { [weak self] text in
            DispatchQueue.main.async {
                self?.appendMessage(.client, "→ \(text)")
            }
        }
        repository.onRecv = { [weak self] text in
            DispatchQueue.main.async {
                self?.appendMessage(.server, "← \(text)")
            }
        }
    }

    /// list 回复解析结果 → 我的 ip/port + 其他在线用户（对齐 Android `tryParseListResult`：
    /// 用户名等于自己的那条算「我」，其余进 peers）
    private func applyListResult(_ users: [PeerEntry]) {
        // Android: loggedInUsername.ifBlank { username }
        let myName = uiState.loggedInUsername.isEmpty ? uiState.username : uiState.loggedInUsername
        let mine = users.first { $0.username == myName }
        uiState.myIp = mine?.ip ?? ""
        uiState.myPort = mine?.port ?? 0
        uiState.peers = users.filter { $0.username != myName }
        appendMessage(.system, "list: \(users.count) 人在线，我=\(uiState.myIp):\(uiState.myPort)，其他人 \(uiState.peers.count) 个")
    }

    /// hello 结束：**成功就把 fd 的所有权交给 SessionManager**（A1 定好的所有权转移），
    /// 失败的话 WsClient 已经自己把 fd 关了，这里只记日志。
    /// 注意：这里不再自动跳 tab、也不自动交给某个用法（对齐 Android：
    /// 「打洞到这里就结束了，打不打勾、交给谁由用户在 socket 卡片上选」）。
    private func handleHelloDone(info: PeerInfo?, sock: Int32?, peerIp: String, peerPort: Int, mode: String) {
        appendMessage(.system, "UDP hello 线程已退出")
        if let info = info, let fd = sock {
            sessionManager.handOver(fd: fd)
            appendMessage(.system, "P2P已建立: \(info.name)（对端 \(formatHostPort(info.peerIp, info.peerPort))）")
            appendMessage(.system, "打洞完成，在 socket 卡片第 5 行选用法（udptest / tun / switch / wg）")
        } else {
            appendMessage(.system, "onHelloDone info=null（hello 线程超时或异常）")
        }
    }

    // MARK: - socket 卡片上的操作（对齐 Android useUdpSocket / closeUdpSocket）

    /// 卡片第 5 行点了某个用法（对齐 Android `useUdpSocket`）。
    /// wg 走「按 WG 页的『实现』配置路由」，switch 走「按 Switch 页配置启动并插网口」。
    func useUdpSocket(_ id: Int64, _ usageId: String) {
        guard let card = sessionManager.sessionsSnapshot().first(where: { $0.id == id }) else { return }
        // 已经交给它了，别重复交接
        if card.handedTo == usageId { return }

        switch usageId {
        case "udptest":
            // udptest 有自己的界面：切到 UDP tab，并把本机/公网地址写进页面
            navigateTo(Page.udpTest(
                targetUsername: card.target,
                myIp: card.myPublicIp,
                myPublicPort: card.myPublicPort,
                myLocalIp: card.localIp,
                myLocalPort: card.localPort,
                peerIp: card.peerPublicIp,
                peerPort: card.peerPublicPort
            ))
        case "wg":
            // 原 wghelp 的行为挪到这里：填地址 + 跳 WG 页 + 按「实现」三档路由
            routeWg(card)
        case "switch":
            // 按 switch 页的配置启动（或复用）交换机，然后这条 session 会占第一个空网口
            if !uiState.switchRunning { onSwitchStart() }
            appendMessage(.system,
                "switch：把 \(card.target) 插到网口（对端 \(formatHostPort(card.peerPublicIp, card.peerPublicPort))）")
            navigateTo(.vswitch)
        case "proxy":
            // 按 Proxy 页的配置启动（或复用）端口转发，然后这条 session 变成那条通道
            if !uiState.proxyRunning { onProxyStart() }
            appendMessage(.system,
                "proxy：把 \(card.target) 接成通道（洞本机端口 \(card.localPort)）")
            navigateTo(.proxy)
        case "tun":
            // tun = 一对一 VPN 的隧道：按 vpn 页的配置启动/复用，然后跳到 vpn 页
            if !uiState.vpnRunning { onVpnStart() }
            appendMessage(.system,
                "vpn：把 \(card.target) 接成一对一通道（洞本机端口 \(card.localPort)）")
            navigateTo(.vpn)
        case "media":
            // media：只负责把这条洞接成通道，媒体去 media 页点「拉起应用」
            appendMessage(.system,
                "media：把 \(card.target) 接成多媒体通道（洞本机端口 \(card.localPort)），"
                + "去 media 页点「拉起应用」")
            navigateTo(.media)
        default:
            break
        }
        if !sessionManager.attachUsage(id, usageId: usageId) {
            appendMessage(.system, "socket 卡片已关闭，无法交给 \(usageId)")
        }
    }

    // MARK: - 虚拟交换机（switch 页；真 hub 留 TODO）

    /// 启动交换机：真正的一进程多路转发还没做，这里只改页面状态 + 把「按页面配置该起什么」写进日志
    func onSwitchStart() {
        let cfg = uiState.switchConfig
        uiState.switchRunning = true
        appendMessage(.system, "switch：按页面配置启动 —— \(cfg.summary())")
        appendMessage(.system, "switch：转发逻辑尚未实现（TODO），当前只有配置和网口编排")
    }

    func onSwitchStop() {
        uiState.switchRunning = false
        appendMessage(.system, "switch：已停止（插着的网口还在，socket 不受影响）")
    }

    /// Switch 页上点某个网口 = 拔线：只摘掉这条用法，不动 session/socket
    func unplugSwitchPort(_ id: Int64) {
        guard let card = sessionManager.sessionsSnapshot().first(where: { $0.id == id }) else { return }
        sessionManager.detachUsage(id)
        appendMessage(.system,
            "switch：已拔出 \(card.target)（socket \(formatHostPort(card.localIp, card.localPort)) 保留）")
    }

    /// 卡片右上角 ✕：关掉这条 session（fd 由 SessionManager 关 —— 唯一关闭点）
    func closeUdpSocket(_ id: Int64) {
        sessionManager.close(id)
    }

    // MARK: - WireGuard

    /// WireGuard 的日志不再单独存一个流：统一写进 App 内日志（右下角「日志」按钮里看）
    /// （对齐 Android：`appendMessage(Direction.SYSTEM, "wg: $text")`）
    func appendWgLog(_ text: String) {
        appendMessage(.system, "wg: \(text)")
    }

    func generateWgKeypair(callback: @escaping (String, String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let privKey = Crypto.generateRandomBase64(32)
            let pubKey = Crypto.generateRandomBase64(32)
            DispatchQueue.main.async {
                callback(pubKey, privKey)
            }
        }
    }

    func startWgTunnel(config: WgConfig, callback: @escaping (Bool, String) -> Void) {
        let iface = WgInterface(
            myIp: config.myIp,
            myPort: config.myPort,
            privateKey: config.myPrivateKey,
            peers: [WgPeer(endpoint: config.peerEndpoint, publicKey: config.peerPublicKey, presharedKey: config.peerPresharedKey, allowedIPs: config.allowedIPs)]
        )
        startWgTunnelManual(iface, callback: callback)
    }

    func startWgTunnelAuto(page: Page, callback: @escaping (Bool, String) -> Void) {
        guard case .wireGuard(_, _, let myPort, let peerIp, let peerPort) = page else {
            callback(false, "invalid page")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let _ = self?.buildWireGuardInterfaceConfig(WgInterface(
                myIp: "10.0.0.2/24",
                myPort: myPort,
                privateKey: "",
                peers: [WgPeer(endpoint: "\(peerIp):\(peerPort)", publicKey: "", presharedKey: "", allowedIPs: "0.0.0.0/0")]
            ))
            DispatchQueue.main.async {
                self?.appendWgLog("WireGuard 自动配置生成完成: \(peerIp):\(peerPort)")
                callback(true, "自动配置已生成")
            }
        }
    }

    func stopWgTunnel() {
        DispatchQueue.main.async { [weak self] in
            self?.appendWgLog("WireGuard 已断开")
        }
    }

    func startWgTunnelManual(_ wgInterface: WgInterface, callback: ((Bool, String) -> Void)? = nil) {
        DispatchQueue.main.async { [weak self] in
            let _ = self?.buildWireGuardInterfaceConfig(wgInterface)
            self?.appendWgLog("WireGuard 手动配置生成完成")
            callback?(true, "配置已生成")
        }
    }

    /// 把 WgInterface 拼成一份 wg 配置文本。
    /// `nonisolated`：它是纯字符串拼接（不碰任何界面状态），
    /// 而 `startWgTunnelAuto` 要在后台队列里调它。
    nonisolated func buildWireGuardInterfaceConfig(_ iface: WgInterface) -> String {
        var lines: [String] = []
        lines.append("[Interface]")
        lines.append("ListenPort = \(iface.myPort)")
        lines.append("PrivateKey = \(iface.privateKey)")
        if !iface.myIp.isEmpty {
            lines.append("Address = \(iface.myIp)")
        }
        lines.append("")
        for peer in iface.peers {
            lines.append("[Peer]")
            lines.append("PublicKey = \(peer.publicKey)")
            if !peer.presharedKey.isEmpty {
                lines.append("PresharedKey = \(peer.presharedKey)")
            }
            lines.append("Endpoint = \(peer.endpoint)")
            lines.append("AllowedIPs = \(peer.allowedIPs)")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}
