import Foundation

enum LoginResult {
    case success(String)
    case error(String)
}

class P2pRepository {
    private var _client: WsClient
    private var _connectionListener: WsClientListenerWrapper?
    private var _loggedInUsername: String?
    var loggedInUsername: String? { _loggedInUsername }

    // MARK: - Stored callbacks (renamed to avoid conflict with protocol methods)
    var onLogMessage: ((String) -> Void)?
    var onConnectedHandler: (() -> Void)?
    /// 自动重连成功（连接重新打开）——上层据此决定要不要用原凭据重新登录
    var onAutoReconnectedHandler: (() -> Void)?
    /// 被服务器明确踢下线（收到 `kicked`）
    var onKickedHandler: ((String) -> Void)?
    var onDisconnectedHandler: (() -> Void)?
    var onError: ((String) -> Void)?

    var onSend: ((String) -> Void)?
    var onUdpSend: ((String) -> Void)?
    var onUdpRecv: ((String) -> Void)?
    var onRecv: ((String) -> Void)?
    var onHelloDone: ((PeerInfo?, Int32?, String, Int, String) -> Void)?
    /// list 回复解析出来的在线用户（由 WsClient 的 list_result 分支回调）
    var onListResult: (([PeerEntry]) -> Void)?
    /// hello socket 刚绑定好（fd, localIp, localPort）
    var onUdpSocketBound: ((Int32, String, Int) -> Void)?
    /// UDP 打洞每一步的进度（fd, step, myIp, myPort, peerIp, peerPort）
    var onUdpSocketStep: ((Int32, UdpStep, String, Int, String, Int) -> Void)?
    /// 收到 direct 地址交换（from, ipv4, ipv6, isReply）
    var onP2pDirect: ((String, [String], [String], Bool) -> Void)?
    // Login-specific callbacks (set by login())
    private var loginSuccessHandler: ((String) -> Void)?
    private var loginFailedHandler: ((String) -> Void)?
    private var loginDisconnectedHandler: (() -> Void)?



    private let localPrefs: LocalPrefs

    init(localPrefs: LocalPrefs) {
        self.localPrefs = localPrefs
        _client = WsClient()
    }

    func useClient(_ client: WsClient?) {
        _client = client ?? WsClient()
    }

    func getClient() -> WsClient {
        return _client
    }

    func setupConnectionCallbacks() {
        let wrapper = WsClientListenerWrapper(
            onMessage: { [weak self] in self?.onLogMessage?($0) },
            onRecv: { [weak self] in self?.onRecv?($0) },
            onSend: { [weak self] in self?.onSend?($0) },
            onUdpSend: { [weak self] in self?.onUdpSend?($0) },
            onUdpRecv: { [weak self] in self?.onUdpRecv?($0) },
            onHelloDone: { [weak self] in self?.onHelloDone?($0, $1, $2, $3, $4) },
            onListResult: { [weak self] in self?.onListResult?($0) },
            onUdpSocketBound: { [weak self] in self?.onUdpSocketBound?($0, $1, $2) },
            onUdpSocketStep: { [weak self] in self?.onUdpSocketStep?($0, $1, $2, $3, $4, $5) },
            onP2pDirect: { [weak self] in self?.onP2pDirect?($0, $1, $2, $3) },
            onLoginSuccess: { [weak self] in self?.loginSuccessHandler?($0) },
            onLoginFailed: { [weak self] in self?.loginFailedHandler?($0) },
            onError: { _ in },
            onDisconnected: { [weak self] in self?.onDisconnectedHandler?() },
            onConnected: { [weak self] in self?.onConnectedHandler?() },
            onAutoReconnected: { [weak self] in self?.onAutoReconnectedHandler?() },
            onKicked: { [weak self] in self?.onKickedHandler?($0) }
        )
        print("[P2pRepo] setupConnectionCallbacks: wrapper created, stored callbacks registered")
        _connectionListener = wrapper
        print("[P2pRepo] setupConnectionCallbacks: wrapper=\(String(format: "%p", unsafeBitCast(wrapper, to: Int.self))) _client.listener will be set")
        _client.listener = wrapper
        print("[P2pRepo] setupConnectionCallbacks: done")
    }

    func login(useWss: Bool, host: String, port: Int, username: String, password: String) async -> LoginResult {
        _loggedInUsername = username
        localPrefs.serverHost = host
        localPrefs.serverPort = port
        localPrefs.username = username
        localPrefs.loggedIn = true

        return await withCheckedContinuation { cont in
            self.loginSuccessHandler = { username in
                self._loggedInUsername = username
                self.localPrefs.loggedIn = true
                cont.resume(returning: .success(username))
            }
            self.loginFailedHandler = { message in
                self.localPrefs.clearSession()
                self._loggedInUsername = nil
                cont.resume(returning: .error(message))
            }
            // Do NOT replace _client.listener - keep the connection callbacks
            _client.login(useWss: useWss, serverHost: host, serverPort: port, username: username, password: password)
        }
    }

    /// 退出登录。
    /// keepConnection = true：只给服务器发 `{"type":"logout"}`，WebSocket 保持连接；
    /// keepConnection = false（默认）：直接断开连接。
    /// （签名与行为对齐 Android `P2pRepository.logout(keepConnection)`）
    func logout(keepConnection: Bool = false) {
        if keepConnection {
            _client.sendLogout()
        } else {
            _client.disconnectOnly()
        }
        localPrefs.clearSession()
        _loggedInUsername = nil
    }

    func connectOnly(useWss: Bool, host: String, port: Int) {
        _client.connect(useWss: useWss, host: host, port: port)
    }

    func disconnectOnly() {
        _client.disconnectOnly()
    }

    func resetUdpState() {
        _client.resetUdpState()
    }

    func sendList() { _client.sendList() }

    /// 应用层 ping（`{"type":"ping","seq":N}`）；服务端回 `{"type":"pong","seq":N}`
    func sendAppPing(seq: Int) { _client.sendAppPing(seq: seq) }
    func sendP2pUdp(_ target: String) { _client.sendP2pUdp(target) }
    func sendP2pTcp(_ target: String) { _client.sendP2pTcp(target) }
    func sendP2pDirect(_ target: String, ipv4: [String], ipv6: [String]) {
        _client.sendP2pDirect(target, ipv4: ipv4, ipv6: ipv6)
    }
    func sendP2pDirectReply(_ target: String, ipv4: [String], ipv6: [String]) {
        _client.sendP2pDirectReply(target, ipv4: ipv4, ipv6: ipv6)
    }
    func getServerHost() -> String { localPrefs.serverHost }
    func getServerPort() -> Int { localPrefs.serverPort }
    func isLoggedIn() -> Bool { localPrefs.loggedIn }
    func getSavedUsername() -> String? { localPrefs.username }

    // 两个配置页的配置（JSON 原文）—— ViewModel 不直接持有 LocalPrefs，这里透传
    func getWgConfigJson() -> String? { localPrefs.wgConfigJson }
    func setWgConfigJson(_ json: String?) { localPrefs.wgConfigJson = json }
    func getSwitchConfigJson() -> String? { localPrefs.switchConfigJson }
    func setSwitchConfigJson(_ json: String?) { localPrefs.switchConfigJson = json }
    func getProxyConfigJson() -> String? { localPrefs.proxyConfigJson }
    func setProxyConfigJson(_ json: String?) { localPrefs.proxyConfigJson = json }
    func getVpnConfigJson() -> String? { localPrefs.vpnConfigJson }
    func setVpnConfigJson(_ json: String?) { localPrefs.vpnConfigJson = json }
    func getMediaConfigJson() -> String? { localPrefs.mediaConfigJson }
    func setMediaConfigJson(_ json: String?) { localPrefs.mediaConfigJson = json }
}

// MARK: - WsClientListenerWrapper

class WsClientListenerWrapper: WsClientListener {
    let onMessage: (String) -> Void
    let onRecv: (String) -> Void
    let onSend: (String) -> Void
    let onUdpSend: (String) -> Void
    let onUdpRecv: (String) -> Void
    let onHelloDone: (PeerInfo?, Int32?, String, Int, String) -> Void
    let onListResult: ([PeerEntry]) -> Void
    let onUdpSocketBound: (Int32, String, Int) -> Void
    let onUdpSocketStep: (Int32, UdpStep, String, Int, String, Int) -> Void
    let onP2pDirect: (String, [String], [String], Bool) -> Void
    let onLoginSuccess: (String) -> Void
    let onLoginFailed: (String) -> Void
    let onError: (String) -> Void
    let onDisconnectedHandler: () -> Void
    let onConnectedHandler: (() -> Void)?   // 新增
    let onAutoReconnectedHandler: () -> Void
    let onKickedHandler: ((String) -> Void)?

    init(
        onMessage: @escaping (String) -> Void,
        onRecv: @escaping (String) -> Void,
        onSend: @escaping (String) -> Void,
        onUdpSend: @escaping (String) -> Void,
        onUdpRecv: @escaping (String) -> Void,
        onHelloDone: @escaping (PeerInfo?, Int32?, String, Int, String) -> Void,
        onListResult: @escaping ([PeerEntry]) -> Void,
        onUdpSocketBound: @escaping (Int32, String, Int) -> Void,
        onUdpSocketStep: @escaping (Int32, UdpStep, String, Int, String, Int) -> Void,
        onP2pDirect: @escaping (String, [String], [String], Bool) -> Void,
        onLoginSuccess: @escaping (String) -> Void,
        onLoginFailed: @escaping (String) -> Void,
        onError: @escaping (String) -> Void,
        onDisconnected: @escaping () -> Void,
        onConnected: (() -> Void)? = nil,    // 新增参数，默认为 nil
        onAutoReconnected: @escaping () -> Void = {},
        onKicked: ((String) -> Void)? = nil
    ) {
        self.onMessage = onMessage
        self.onRecv = onRecv
        self.onSend = onSend
        self.onUdpSend = onUdpSend
        self.onUdpRecv = onUdpRecv
        self.onHelloDone = onHelloDone
        self.onListResult = onListResult
        self.onUdpSocketBound = onUdpSocketBound
        self.onUdpSocketStep = onUdpSocketStep
        self.onP2pDirect = onP2pDirect
        self.onLoginSuccess = onLoginSuccess
        self.onLoginFailed = onLoginFailed
        self.onError = onError
        self.onDisconnectedHandler = onDisconnected
        self.onConnectedHandler = onConnected  // 保存回调
        self.onAutoReconnectedHandler = onAutoReconnected
        self.onKickedHandler = onKicked
    }
    func onMessage(_ text: String) { onMessage(text) }

    func onAutoReconnected() { onAutoReconnectedHandler() }

    func onKicked(_ message: String) { onKickedHandler?(message) }
    func onConnected() { onConnectedHandler?() }
    func onDisconnected() { onDisconnectedHandler() }
    func onRecv(_ text: String) { onRecv(text) }
    func onSend(_ text: String) { onSend(text) }
    func onLoginSuccess(_ username: String) { onLoginSuccess(username) }
    func onLoginFailed(_ message: String) { onLoginFailed(message) }
    func onError(_ message: String) { onError(message) }
    func onUdpSend(_ text: String) { onUdpSend(text) }
    func onUdpRecv(_ text: String) { onUdpRecv(text) }
    func onHelloDone(_ info: PeerInfo?, _ sock: Int32?, _ peerIp: String, _ peerPort: Int, _ mode: String) { onHelloDone(info, sock, peerIp, peerPort, mode) }
    func onListResult(_ users: [PeerEntry]) { onListResult(users) }
    func onUdpSocketBound(_ fd: Int32, _ localIp: String, _ localPort: Int) { onUdpSocketBound(fd, localIp, localPort) }
    func onUdpSocketStep(_ fd: Int32, _ step: UdpStep, _ myIp: String, _ myPort: Int, _ peerIp: String, _ peerPort: Int) {
        onUdpSocketStep(fd, step, myIp, myPort, peerIp, peerPort)
    }
    func onP2pDirect(_ from: String, _ ipv4: [String], _ ipv6: [String], _ isReply: Bool) {
        onP2pDirect(from, ipv4, ipv6, isReply)
    }
}
