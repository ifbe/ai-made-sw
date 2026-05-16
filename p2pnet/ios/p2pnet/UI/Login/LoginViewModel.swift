import Foundation
import Combine

@MainActor
class LoginViewModel: ObservableObject {
    @Published var uiState: LoginUiState

    private let repository: P2pRepository
    private var messageCount: Int = 0

    // UDP P2P socket state
    private var udpSockFd: Int32 = -1
    private var udpSockRunning = false
    @Published var udpSockMessages: [String] = []

    // WireGuard log
    @Published var wgLogMessages: [String] = []

    // RTT tracking
    private var sentPings: [Int: Date] = [:]

    // Service callbacks (stub - no foreground service on iOS)
    var onStartService: (() -> Void)?
    var onStopService: (() -> Void)?

    init(repository: P2pRepository) {
        self.repository = repository
        self.uiState = LoginUiState(serverHost: repository.getServerHost())
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

    func onList() {
        repository.sendList()
    }

    func onUdp() {
        repository.sendP2pUdp(uiState.targetUsername)
    }

    func onTcp() {
        repository.sendP2pTcp(uiState.targetUsername)
    }

    func onWghelp() {
        let target = uiState.targetUsername
        if !target.isEmpty {
            repository.sendWghelp(target)
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
        uiState.isConnected = false
        uiState.isLoggedIn = false
        uiState.loading = false
        uiState.messages = []
        stopUdpPeerSocket()
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
        repository.logout()
        onStopService?()
        uiState.isConnected = false
        uiState.isLoggedIn = false
        uiState.loggedInUsername = ""
        uiState.messages = []
        uiState.password = ""
        stopUdpPeerSocket()
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

    func navigateTo(_ page: Page) {
        var tabs = uiState.tabs
        if let existing = tabs.firstIndex(where: { type(of: $0.page) == type(of: page) && !(page == .main || page == .wireGuard() || false) }) {
            uiState.currentTabIndex = existing
            uiState.currentPage = page
            return
        }
        switch page {
        case .main:
            uiState.currentTabIndex = 0
            uiState.currentPage = .main
        case .udpTest:
            udpSockMessages = []
            let title = "UDP"
            tabs.append(TabItem(page: page, title: title))
            uiState.tabs = tabs
            uiState.currentTabIndex = tabs.count - 1
            uiState.currentPage = page
        case .wireGuard:
            let wgIndex = tabs.firstIndex { if case .wireGuard = $0.page { return true } else { return false } }
            if let idx = wgIndex {
                uiState.currentTabIndex = idx
                uiState.currentPage = page
            } else {
                tabs.append(TabItem(page: page, title: "WireGuard"))
                uiState.tabs = tabs
                uiState.currentTabIndex = tabs.count - 1
                uiState.currentPage = page
            }
        default:
            let title: String = {
                if case .videoCall = page { return "视频通话" }
                if case .chat = page { return "聊天" }
                return "主页"
            }()
            tabs.append(TabItem(page: page, title: title))
            uiState.tabs = tabs
            uiState.currentTabIndex = tabs.count - 1
            uiState.currentPage = page
        }
    }

    func switchToTab(_ index: Int) {
        guard index >= 0 && index < uiState.tabs.count else { return }
        uiState.currentTabIndex = index
        uiState.currentPage = uiState.tabs[index].page
    }

    func removeTab(_ index: Int) {
        guard index > 0 && index < uiState.tabs.count else { return }
        let removed = uiState.tabs[index]
        var tabs = uiState.tabs
        tabs.remove(at: index)
        if case .udpTest = removed.page {
            stopUdpPeerSocket()
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

    private func handleHelloDone(info: PeerInfo?, sock: Int32?, peerIp: String, peerPort: Int, mode: String) {
        appendMessage(.system, "UDP hello 线程已退出")
        if let info = info, let sockFd = sock {
            appendMessage(.system, "P2P已建立: \(info.name) (\(info.peerIp):\(info.peerPort))")
            appendMessage(.system, "peer info: 本机=\(info.myIp):\(info.myPort) 对方=\(info.peerIp):\(info.peerPort)")
            if mode == "wg" {
                let wgIndex = uiState.tabs.firstIndex { if case .wireGuard = $0.page { return true } else { return false } }
                if let idx = wgIndex {
                    let updatedPage = Page.wireGuard(
                        targetUsername: info.name,
                        myIp: info.myIp,
                        myPort: info.myPort,
                        peerIp: info.peerIp,
                        peerPort: info.peerPort
                    )
                    var tabs = uiState.tabs
                    tabs[idx] = TabItem(page: updatedPage, title: "WireGuard")
                    uiState.tabs = tabs
                    uiState.currentTabIndex = idx
                    uiState.currentPage = updatedPage
                    appendMessage(.system, "已跳转到 WireGuard tab")
                } else {
                    appendMessage(.system, "WireGuard tab 未找到")
                }
            } else {
                let page = info.toPage()
                navigateTo(page)
                appendMessage(.system, "navigateTo 完成，启动 socket")
                startUdpPeerSocket(page: page, inheritedFd: sockFd)
            }
        } else {
            appendMessage(.system, "onHelloDone info=null（hello线程超时或异常）")
        }
    }

    // MARK: - UDP P2P socket

    func startUdpPeerSocket(page: Page, inheritedFd: Int32? = nil) {
        stopUdpPeerSocket()
        guard let fd = inheritedFd else {
            udpSockMessages.append("ios: 无可用 socket，无法建立 P2P 连接")
            return
        }
        udpSockFd = fd
        udpSockRunning = true

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.runUdpPeerSocket(page: page)
        }
    }

    private func runUdpPeerSocket(page: Page) {
        let peerAddr: String
        let peerPortN: Int
        if case Page.udpTest(let targetUsername, let myIp, let myPublicPort, let myLocalIp, let myLocalPort, let pAddr, let pPort) = page {
            peerAddr = pAddr
            peerPortN = pPort
        } else { return }

        DispatchQueue.main.async {
            self.udpSockMessages.append("ios: P2P socket 启动 本机=\(self.udpSockFd) 对方=\(peerAddr):\(peerPortN)")
        }

        guard let addrCStr = peerAddr.withCString({ strdup($0) }) else { return }
        defer { free(addrCStr) }

        var destAddr = sockaddr_in()
        destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_port = UInt16(peerPortN).bigEndian
        inet_pton(AF_INET, addrCStr, &destAddr.sin_addr)

        func sendToPeer(_ data: Data) {
            data.withUnsafeBytes { dataPtr in
                withUnsafePointer(to: &destAddr) { destPtr in
                    destPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                        _ = sendto(self.udpSockFd, dataPtr.baseAddress, data.count, 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        }

        var seq = 1
        let startTime = Date()

        while udpSockRunning && udpSockFd >= 0 {
            let ping: [String: Any] = [
                "type": "ping",
                "seq": seq,
                "ts": Int64(Date().timeIntervalSince1970 * 1000)
            ]
            if let data = try? JSONSerialization.data(withJSONObject: ping) {
                sentPings[seq] = Date()
                if sentPings.count > 100 {
                    if let minKey = sentPings.keys.min() {
                        sentPings.removeValue(forKey: minKey)
                    }
                }
                sendToPeer(data)
                DispatchQueue.main.async {
                    self.udpSockMessages.append("send: \(peerAddr):\(peerPortN) \(ping)")
                }
            }

            var buf = [UInt8](repeating: 0, count: 2048)
            var srcAddr = sockaddr_in()
            var srcAddrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

            let recvResult = withUnsafeMutablePointer(to: &srcAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    recvfrom(udpSockFd, &buf, buf.count, 0, sockaddrPtr, &srcAddrLen)
                }
            }

            if recvResult > 0 {
                let data = Data(bytes: buf, count: recvResult)
                if let msgStr = String(data: data, encoding: .utf8) {
                    if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let type = json["type"] as? String {
                        switch type {
                        case "pong":
                            let pongSeq = json["seq"] as? Int ?? 0
                            let rtt = Int(Date().timeIntervalSince(sentPings[pongSeq] ?? Date()) * 1000)
                            sentPings.removeValue(forKey: pongSeq)
                            DispatchQueue.main.async {
                                self.udpSockMessages.append("recv: \(peerAddr):\(peerPortN) \(msgStr) RTT=\(rtt)ms")
                            }
                        case "ping":
                            let pong: [String: Any] = [
                                "type": "pong",
                                "seq": json["seq"] as? Int ?? 0,
                                "ts": json["ts"] as? Int64 ?? 0
                            ]
                            if let pongData = try? JSONSerialization.data(withJSONObject: pong) {
                                sendToPeer(pongData)
                                DispatchQueue.main.async {
                                    self.udpSockMessages.append("recv: \(peerAddr):\(peerPortN) \(msgStr)")
                                    self.udpSockMessages.append("send: \(peerAddr):\(peerPortN) \(pong)")
                                }
                            }
                        default:
                            DispatchQueue.main.async {
                                self.udpSockMessages.append("recv: \(peerAddr):\(peerPortN) \(msgStr)")
                            }
                        }
                    } else {
                        DispatchQueue.main.async {
                            self.udpSockMessages.append("recv: \(peerAddr):\(peerPortN) [\(data.count) bytes]")
                        }
                    }
                }
            }

            Thread.sleep(forTimeInterval: 1)
            seq += 1
        }

        DispatchQueue.main.async {
            self.udpSockMessages.append("ios: P2P socket 线程结束")
        }
    }

    func stopUdpPeerSocket() {
        udpSockRunning = false
        if udpSockFd >= 0 {
            Darwin.close(udpSockFd)
            udpSockFd = -1
        }
        sentPings.removeAll()
    }

    // MARK: - WireGuard

    func appendWgLog(_ text: String) {
        wgLogMessages.append(text)
    }

    func clearWgLog() {
        wgLogMessages = []
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
        guard case .wireGuard(_, let myIp, let myPort, let peerIp, let peerPort) = page else {
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

    func buildWireGuardInterfaceConfig(_ iface: WgInterface) -> String {
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
