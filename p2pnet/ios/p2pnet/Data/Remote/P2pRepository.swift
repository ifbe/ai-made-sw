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
    var onDisconnectedHandler: (() -> Void)?
    var onError: ((String) -> Void)?

    var onSend: ((String) -> Void)?
    var onUdpSend: ((String) -> Void)?
    var onUdpRecv: ((String) -> Void)?
    var onRecv: ((String) -> Void)?
    var onHelloDone: ((PeerInfo?, Int32?, String, Int, String) -> Void)?
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
            onLoginSuccess: { [weak self] in self?.loginSuccessHandler?($0) },
            onLoginFailed: { [weak self] in self?.loginFailedHandler?($0) },
            onError: { _ in },
            onDisconnected: { [weak self] in self?.onDisconnectedHandler?() },
            onConnected: { [weak self] in self?.onConnectedHandler?() }
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

    func logout() {
        _client.disconnectOnly()
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
    func sendWghelp(_ target: String) { _client.sendWghelp(target) }
    func sendP2pUdp(_ target: String) { _client.sendP2pUdp(target) }
    func sendP2pTcp(_ target: String) { _client.sendP2pTcp(target) }
    func getServerHost() -> String { localPrefs.serverHost }
    func getServerPort() -> Int { localPrefs.serverPort }
    func isLoggedIn() -> Bool { localPrefs.loggedIn }
    func getSavedUsername() -> String? { localPrefs.username }
}

// MARK: - WsClientListenerWrapper

class WsClientListenerWrapper: WsClientListener {
    let onMessage: (String) -> Void
    let onRecv: (String) -> Void
    let onSend: (String) -> Void
    let onUdpSend: (String) -> Void
    let onUdpRecv: (String) -> Void
    let onHelloDone: (PeerInfo?, Int32?, String, Int, String) -> Void
    let onLoginSuccess: (String) -> Void
    let onLoginFailed: (String) -> Void
    let onError: (String) -> Void
    let onDisconnectedHandler: () -> Void
    let onConnectedHandler: (() -> Void)?   // 新增

    init(
        onMessage: @escaping (String) -> Void,
        onRecv: @escaping (String) -> Void,
        onSend: @escaping (String) -> Void,
        onUdpSend: @escaping (String) -> Void,
        onUdpRecv: @escaping (String) -> Void,
        onHelloDone: @escaping (PeerInfo?, Int32?, String, Int, String) -> Void,
        onLoginSuccess: @escaping (String) -> Void,
        onLoginFailed: @escaping (String) -> Void,
        onError: @escaping (String) -> Void,
        onDisconnected: @escaping () -> Void,
        onConnected: (() -> Void)? = nil    // 新增参数，默认为 nil
    ) {
        self.onMessage = onMessage
        self.onRecv = onRecv
        self.onSend = onSend
        self.onUdpSend = onUdpSend
        self.onUdpRecv = onUdpRecv
        self.onHelloDone = onHelloDone
        self.onLoginSuccess = onLoginSuccess
        self.onLoginFailed = onLoginFailed
        self.onError = onError
        self.onDisconnectedHandler = onDisconnected
        self.onConnectedHandler = onConnected  // 保存回调
    }
    func onMessage(_ text: String) { onMessage(text) }
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
}
