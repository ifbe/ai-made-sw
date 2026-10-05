import Foundation

// MARK: - PeerInfo

struct PeerInfo: Equatable {
    let name: String
    let peerIp: String
    let peerPort: Int
    let myIp: String
    let myPort: Int
    var myLocalPort: Int
}

// MARK: - WsClientListener

/// UDP socket 卡片的五个步骤（对齐 Android `WsClient.UdpStep`）
enum UdpStep {
    case sentToServer
    case serverReplied
    case sentToPeer
    case peerReplied
    case handedTo
}

protocol WsClientListener: AnyObject {
    func onMessage(_ text: String)
    func onConnected()
    func onDisconnected()
    func onRecv(_ text: String)
    func onSend(_ text: String)
    func onLoginSuccess(_ username: String)
    func onLoginFailed(_ message: String)
    func onError(_ message: String)
    func onUdpSend(_ text: String)
    func onUdpRecv(_ text: String)
    func onHelloDone(_ info: PeerInfo?, _ sock: Int32?, _ peerIp: String, _ peerPort: Int, _ mode: String)

    /// list 回复解析出来的在线用户（username / ip / port）。
    /// 对齐 Android `WsClient` / `LoginViewModel.tryParseListResult` 的解析结果。
    func onListResult(_ users: [PeerEntry])

    /// hello socket 刚绑定好（界面据此生成 socket 卡片）
    func onUdpSocketBound(_ fd: Int32, _ localIp: String, _ localPort: Int)

    /// UDP 打洞流程的每一步进度（socket 卡片用来打勾）
    func onUdpSocketStep(
        _ fd: Int32,
        _ step: UdpStep,
        _ myIp: String,
        _ myPort: Int,
        _ peerIp: String,
        _ peerPort: Int
    )

    /// 收到服务器转来的 direct 地址交换（p2pdirect / p2pdirect_reply）。
    ///
    /// isReply = false → 对方来要地址（请求里就带着他的地址表，我们没发过就得回一份 reply）
    /// isReply = true  → 对方对我方请求的应答，只探测、不再回
    ///
    /// 协议里**只有 IP 列表、没有端口**，所以 direct 只能判断「可达」，不建 socket、不建隧道。
    func onP2pDirect(_ from: String, _ ipv4: [String], _ ipv6: [String], _ isReply: Bool)
}

// MARK: - WsClient using URLSessionWebSocketTask (Foundation)

class WsClient: NSObject, URLSessionWebSocketDelegate {
    private var session: URLSession?
    private var wsTask: URLSessionWebSocketTask?
    weak var listener: WsClientListener?

    private var serverHost = ""
    private var serverPort = 0
    private var useWss = false

    private var loginUsername = ""
    private var loginPassword = ""
    var confirmedUsername = ""
    private var sessionKey: Data?
    private var pendingSalt = ""
    private var pendingChallenge = ""
    private var pendingPwHash = ""

    private var _pendingPeerInfo: PeerInfo?
    private var _helloMode = "udp"
    private var _helloPeerIp = ""
    private var _helloPeerPort = 0
    private var stopFlag = false
    private var helloQueue: DispatchQueue?

    // UDP socket fd (for P2P hello)
    private var udpSockFd: Int32 = -1

    /// 服务器 UDP 端口对应的 IP。
    /// ⚠️ 服务端 `send_udp_to_server` **从不发 `server_ip`**（只发 `udpport`），所以这里默认是空的，
    /// 必须在 `startUdpHello()` 里用 `UdpSocket.resolveHost(serverHost)` 解析出来；
    /// 否则目标不是 IP 字面量，hello 一个都发不出去。
    private var serverIp = ""
    private var serverUdpPort = 0

    // Track connection state
    private var isReceiving = false
    private var isConnected = false

    // Pending messages to send after connection opens
    private var pendingMessages: [String] = []

    /// WS 协议级心跳定时器（`sendPing`）：连接被中间设备静默回收时，
    /// `receive()` 不返回也不报错，只有心跳失败能给信号（见 `startHeartbeat()`）
    private var heartbeatTimer: DispatchSourceTimer?
    /// 心跳周期（秒）：三端统一 **20s**
    private let heartbeatIntervalSec = 20
    /// 协议级 ping 的序号：每次**真的发**才 +1（跳过的那轮不加），随连接重置
    private var heartbeatSeq = 0
    /// 单次心跳的等待上限（秒）：必须**小于**心跳周期，且要覆盖一次正常 RTT
    private let heartbeatWatchdogTimeoutSec: TimeInterval = 10
    /// 心跳看门狗：`sendPing` 的回调只在"收到 pong / 出错"时触发，
    /// 对端不回 pong 时永远不触发 —— 靠它兜底判死
    private lazy var heartbeatWatchdog = HeartbeatWatchdog(timeout: heartbeatWatchdogTimeoutSec) { [weak self] reason in
        self?.handleHeartbeatFailure(reason)
    }

    deinit {
        heartbeatTimer?.cancel()
    }

    override init() {
        super.init()
    }

    func connect(useWss: Bool, host: String, port: Int) {
        self.serverHost = host
        self.serverPort = port
        self.useWss = useWss
        self.isConnected = false
        self.pendingMessages = []

        let proto = useWss ? "wss" : "ws"
        let urlStr = "\(proto)://\(host):\(port)/"
        print("[WsClient] connect() listener=\(String(format: "%p", unsafeBitCast(listener as AnyObject, to: Int.self))) listener?.onMessage: \(listener != nil ? "YES" : "NO")")
        listener?.onMessage("连接 \(urlStr)")
        print("[WsClient] connect() url=\(urlStr)")

        guard let url = URL(string: urlStr) else {
            print("[WsClient] connect() FAIL: invalid url")
            listener?.onMessage("无效的 URL: \(urlStr)")
            return
        }

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 0

        session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        wsTask = session?.webSocketTask(with: url)
        wsTask?.resume()
        listener?.onMessage("URLSession 已创建，wsTask.resume() 已调用")
    }

    // MARK: - URLSessionWebSocketDelegate

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol proto: String?) {
        print("[WsClient] didOpenWithProtocol: \(proto ?? "nil")")
        isConnected = true
        listener?.onMessage("WebSocket 连接已打开，协议: \(proto ?? "nil")")
        listener?.onConnected()

        // Flush pending messages
        for text in pendingMessages {
            print("[WsClient] didOpen flush pending: \(text)")
            doSend(text)
        }
        pendingMessages = []

        startReceiveLoop()
        startHeartbeat()
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        print("[WsClient] didCloseWith closeCode=\(closeCode.rawValue)")
        stopHeartbeat()
        isConnected = false
        isReceiving = false
        listener?.onMessage("WebSocket 连接关闭 closeCode=\(closeCode.rawValue)")
        listener?.onDisconnected()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        print("[WsClient] didCompleteWithError: \(error?.localizedDescription ?? "nil")")
        stopHeartbeat()
        isConnected = false
        isReceiving = false
        if let error = error {
            let nsErr = error as NSError
            // ATS / NSURLErrorDomain errors
            if nsErr.domain == "NSURLErrorDomain" {
                let msg: String
                switch nsErr.code {
                case -1022:
                    msg = "ATS拒绝: App Transport Security 阻止非安全连接 (ws://). 需在 Info.plist 添加 NSAppTransportSecurity 配置，或使用 wss://"
                case -1001:
                    msg = "连接超时"
                case -1003:
                    msg = "找不到服务器: \(serverHost):\(serverPort)"
                case -1004:
                    msg = "无法连接服务器"
                case -1005:
                    msg = "网络连接丢失"
                case -1200:
                    msg = "TLS/SSL错误"
                default:
                    msg = "连接错误 [\(nsErr.code)]: \(error.localizedDescription)"
                }
                listener?.onMessage(msg)
            } else {
                print("[WsClient] didCompleteWithError listener?.onMessage was NOT called (no error)")
                listener?.onMessage(error.localizedDescription)
            }
        }
    }

    private func startReceiveLoop() {
        guard !isReceiving else {
            listener?.onMessage("startReceiveLoop: 已在接收中，跳过")
            return
        }
        isReceiving = true

        wsTask?.receive { [weak self] result in
            guard let self = self else { return }
            self.isReceiving = false

            switch result {
            case .success(let msg):
                print("[WsClient] receive success: \(msg)")
                switch msg {
                case .string(let text):
                    listener?.onRecv(text)
                    self.handleMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        listener?.onRecv(text)
                        self.handleMessage(text)
                    }
                @unknown default:
                    break
                }
                if self.wsTask != nil && self.isConnected {
                    self.startReceiveLoop()
                }

            case .failure(let err):
                let nsErr = err as NSError
                print("[WsClient] receive failure: code=\(nsErr.code) msg=\(err.localizedDescription)")
                if nsErr.code == 57 || nsErr.code == 1 {
                    self.listener?.onDisconnected()
                } else if nsErr.code == -1001 {
                    self.listener?.onMessage("接收超时")
                } else if nsErr.code == -1005 {
                    self.listener?.onMessage("网络连接丢失")
                } else {
                    self.listener?.onMessage("接收错误 [\(nsErr.code)]: \(err.localizedDescription)")
                }
            }
        }
    }

    func disconnectOnly() {
        print("[WsClient] disconnectOnly()")
        stopHeartbeat()
        resetUdpState()
        isReceiving = false
        isConnected = false
        wsTask?.cancel(with: .goingAway, reason: nil)
        wsTask = nil
        session?.invalidateAndCancel()
        session = nil
        listener?.onMessage("已断开连接")
        listener?.onDisconnected()
    }

    private func handleMessage(_ text: String) {
        print("[WsClient] handleMessage: \(text)")

        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = obj["type"] as? String else { return }

        print("[WsClient] handleMessage type=\(type)")

        switch type {
        case "login_failed":
            listener?.onLoginFailed(obj["message"] as? String ?? "")

        case "send_udp_to_server":
            // 服务端实际上**不发 `server_ip`**（见 server/server.py），读这个字段只是为了兼容别的实现；
            // 真正的目标 IP 由 startUdpHello() 解析 serverHost 兜底
            serverIp = obj["server_ip"] as? String ?? ""
            serverUdpPort = obj["udpport"] as? Int ?? 0
            listener?.onSend("send_udp_to_server")
            startUdpHello()

        case "thisisyourpeer_udp":
            let info = PeerInfo(
                name: obj["name"] as? String ?? "",
                peerIp: obj["ip"] as? String ?? "",
                peerPort: obj["port"] as? Int ?? 0,
                myIp: obj["my_ip"] as? String ?? "",
                myPort: obj["my_port"] as? Int ?? 0,
                myLocalPort: 0
            )
            _pendingPeerInfo = info
            _helloPeerIp = info.peerIp
            _helloPeerPort = info.peerPort
            stopFlag = true
            listener?.onUdpRecv("收到 thisisyourpeer_udp，设置停止标志")
            // 服务器回复：socket 卡片打第 2 个勾，并显示公网 ip/port
            listener?.onUdpSocketStep(
                udpSockFd,
                .serverReplied,
                info.myIp,
                info.myPort,
                info.peerIp,
                info.peerPort
            )

        case "list_result":
            // 对齐 Android `LoginViewModel.tryParseListResult`：只取 username / ip / port，
            // 用户名为空的那条丢掉
            let rawUsers = obj["users"] as? [[String: Any]] ?? []
            let users: [PeerEntry] = rawUsers.compactMap { u in
                let name = u["username"] as? String ?? ""
                guard !name.isEmpty else { return nil }
                return PeerEntry(
                    username: name,
                    ip: u["ip"] as? String ?? "",
                    port: u["port"] as? Int ?? 0
                )
            }
            listener?.onListResult(users)

        case "p2pdirect", "p2pdirect_reply":
            // direct 地址交换：服务器只做中转，from 由服务器填。
            // 请求（p2pdirect）→ 该回一份地址；应答（p2pdirect_reply）→ 只探测，不再回。
            listener?.onP2pDirect(
                obj["from"] as? String ?? "",
                stringArray(obj, "ipv4"),
                stringArray(obj, "ipv6"),
                type == "p2pdirect_reply"
            )

        case "challenge":
            print("[WsClient] got challenge, computing response")
            pendingChallenge = obj["challenge"] as? String ?? ""
            pendingSalt = obj["salt"] as? String ?? ""
            let pwHash = Crypto.sha256(loginPassword + pendingSalt)
            pendingPwHash = pwHash
            let response = Crypto.computeAuthResponse(password: loginPassword, salt: pendingSalt, challenge: pendingChallenge)
            sendJson(["type": "login", "username": loginUsername, "response": response])
            loginPassword = ""

        case "login_ok":
            confirmedUsername = obj["username"] as? String ?? ""
            // 派生 session_key：和上面 `challenge` 里算 response 用的是同一个 pw_hash（hex 字符串），
            // 这里要按服务端/安卓的做法 hexDecode 成字节再喂给 HKDF，**别把字符串字节直接喂进去**
            // session_key = HKDF-SHA256(ikm = pw_hash, salt = pw_hash, info = challenge)
            sessionKey = Crypto.hkdfSHA256(
                ikm: Crypto.hexToBytes(pendingPwHash),
                salt: Crypto.hexToBytes(pendingPwHash),
                info: Crypto.hexToBytes(pendingChallenge)
            )
            if let key = sessionKey {
                // 只打长度 + 前 4 字节，别把密钥打全
                let prefix = key.prefix(4).map { String(format: "%02x", $0) }.joined()
                print("[WsClient] session_key derived: \(key.count) bytes, prefix=\(prefix)…")
            }
            print("[WsClient] login_ok username=\(confirmedUsername)")
            listener?.onLoginSuccess(confirmedUsername)

        default:
            break
        }
    }

    private func startUdpHello() {
        print("[WsClient] startUdpHello ENTRY serverIp=\(serverIp) serverUdpPort=\(serverUdpPort) mode=\(_helloMode)")
        // 服务端只发 `udpport`、不发 `server_ip`，所以这里必须自己把 serverHost（可能是域名）
        // 解析成 IP 字面量：`sendto` 喂域名会直接失败（实测 -1 errno=22 EINVAL），
        // 表现就是"给服务器 UDP 端口发消息那一步 udp 根本没发出去"。
        // 兜底逻辑与措辞对齐安卓 `WsClient.kt`。
        if serverIp.isEmpty && !serverHost.isEmpty {
            if let resolved = UdpSocket.resolveHost(serverHost) {
                serverIp = resolved
                listener?.onUdpSend("serverIp fallback resolved: \(resolved) from \(serverHost)")
            } else {
                listener?.onUdpSend("serverIp fallback failed: \(serverHost)")
            }
        }
        if serverIp.isEmpty || serverUdpPort == 0 {
            listener?.onUdpSend("startUdpHello EARLY RETURN! serverIp=\(serverIp) serverUdpPort=\(serverUdpPort)")
            return
        }

        let sockFd = createHelloSocket()
        if sockFd < 0 {
            listener?.onMessage("UDP socket 创建/绑定失败")
            return
        }
        udpSockFd = sockFd

        // 通知界面：socket 已创建，把本机实际绑定的地址/端口显示出来
        let localPort = UdpSocket.localPort(of: sockFd)
        let localIp = UdpSocket.localIp(of: sockFd)
        listener?.onMessage("UDP hello socket 绑定=\(formatHostPort(localIp, localPort)) 目标=\(formatHostPort(serverIp, serverUdpPort))")
        listener?.onUdpSocketBound(sockFd, localIp.isEmpty ? "::" : localIp, localPort)

        stopFlag = false
        _pendingPeerInfo = nil

        helloQueue = DispatchQueue(label: "p2pnet.udp.hello", qos: .userInitiated)
        helloQueue?.async { [weak self] in
            guard let self = self else { return }
            let lp = self.getLocalUdpPort(sockFd)
            self.runHello(sockFd, lp)
        }
    }

    /// 建一个 v4/v6 都能用的 hello socket（对齐 Android `WsClient.createHelloSocket()`）：
    /// 首选绑 `::` 的双栈 socket，任何一步失败就退回原来的 `0.0.0.0`。
    /// 注意：绑 `::` 之后往 v4 目的地发数据必须写成 v4-mapped，这一步在 `UdpSocket.send` 里处理。
    private func createHelloSocket() -> Int32 {
        let dual = UdpSocket.openBound("::")
        if dual >= 0 {
            listener?.onMessage("UDP socket 创建成功（双栈 ::）fd=\(dual)")
            return dual
        }
        listener?.onMessage("双栈绑定(::)失败，退回 v4 0.0.0.0")
        let v4 = UdpSocket.openBound("0.0.0.0")
        if v4 >= 0 {
            listener?.onMessage("UDP socket 创建成功（v4）fd=\(v4)")
        }
        return v4
    }

    private func runHello(_ sockFd: Int32, _ localPort: Int) {
        // 目的地可能是 v4 也可能是 v6，socket 可能是双栈：地址族转换都在 UdpSocket.send 里做
        func sendToPeer(_ data: Data) {
            let sent = UdpSocket.send(fd: sockFd, data: data, ip: serverIp, port: serverUdpPort)
            if sent < 0 {
                listener?.onMessage("UDP sendto 失败 errno=\(errno)")
            }
        }

        listener?.onMessage("UDP hello 开始，发送 15 个 burst")
        for i in 0..<15 {
            let payload = buildP2pUdpPayload()
            if let data = payload.data(using: .utf8) {
                sendToPeer(data)
            }
            listener?.onUdpSend("UDP burst[\(i)] → \(payload)")
            // 第一个包发出去就算「发给服务器」这一步完成
            if i == 0 { listener?.onUdpSocketStep(sockFd, .sentToServer, "", 0, "", 0) }
            Thread.sleep(forTimeInterval: 0.03)
        }
        listener?.onUdpSend("burst 15个发完，进入维持阶段")

        var seq = 0
        let startTime = Date()
        while !stopFlag {
            if Date().timeIntervalSince(startTime) > 10 {
                listener?.onUdpSend("UDP hello 维持 10s 无响应，主动放弃")
                cleanupSocket(sockFd)
                listener?.onMessage("UDP hello 超时")
                notifyHelloDone(nil, nil)
                return
            }
            Thread.sleep(forTimeInterval: 1)
            if stopFlag { break }
            seq += 1

            let payload = buildP2pUdpPayload()
            if let data = payload.data(using: .utf8) {
                sendToPeer(data)
            }
            listener?.onUdpSend("UDP keep-alive[\(seq)] → \(payload)")
        }

        if var updatedInfo = _pendingPeerInfo {
            updatedInfo = PeerInfo(
                name: updatedInfo.name,
                peerIp: updatedInfo.peerIp,
                peerPort: updatedInfo.peerPort,
                myIp: updatedInfo.myIp,
                myPort: updatedInfo.myPort,
                myLocalPort: localPort
            )
            listener?.onUdpSend("hello 线程被中断，收到 peer info: \(updatedInfo.peerIp):\(updatedInfo.peerPort)")
            // A1：成功路径是**所有权转移** —— 这条 fd 交给上层继续用（P2P ping/pong），
            // 这里绝不能 close，只把 WsClient 这边的引用摘掉。
            releaseSocketOwnership(sockFd)
            notifyHelloDone(updatedInfo, sockFd)
        } else {
            cleanupSocket(sockFd)
            listener?.onMessage("UDP hello 未找到 peer 信息")
            notifyHelloDone(nil, nil)
        }
    }

    private func getLocalUdpPort(_ sockFd: Int32) -> Int {
        // A2：sin_port / sin6_port 是网络字节序，转换（UInt16(bigEndian:)）和地址族判断
        // 都在 UdpSocket.localPort 里做。原来写成 Int(localAddr.sin_port).bigEndian 是错的。
        return UdpSocket.localPort(of: sockFd)
    }

    private func cleanupSocket(_ sockFd: Int32) {
        Darwin.close(sockFd)
        listener?.onMessage("UDP socket 已关闭 fd=\(sockFd)")
        if udpSockFd == sockFd {
            udpSockFd = -1
        }
    }

    /// A1：把 fd 的所有权交给上层 —— **不 close**，只摘掉 WsClient 这边的引用。
    /// 唯一关闭点是 `LoginViewModel.stopUdpPeerSocket()`（它也负责把 fd 置 -1）。
    private func releaseSocketOwnership(_ sockFd: Int32) {
        if udpSockFd == sockFd {
            udpSockFd = -1
        }
        listener?.onMessage("UDP socket fd=\(sockFd) 所有权已转移给上层（WsClient 不再关闭它）")
    }

    private func notifyHelloDone(_ info: PeerInfo?, _ sockFd: Int32?) {
        if let info = info {
            listener?.onMessage("UDP hello 成功，peer=\(info.peerIp):\(info.peerPort)")
        }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.listener?.onHelloDone(info, sockFd, self._helloPeerIp, self._helloPeerPort, self._helloMode)
        }
    }

    private func buildP2pUdpPayload() -> String {
        var payload: [String: Any] = [
            "type": "p2pudp_hello",
            "username": confirmedUsername
        ]
        if let key = sessionKey {
            let sig = Crypto.hmacSHA256Hex(key: key, data: Data("ping".utf8))
            payload["signature"] = sig
        }
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let str = String(data: data, encoding: .utf8) {
            return str
        }
        return "{\"type\":\"p2pudp_hello\",\"username\":\"\(confirmedUsername)\"}"
    }

    func resetUdpState() {
        stopFlag = true
        helloQueue?.async { [weak self] in
            if let fd = self?.udpSockFd, fd >= 0 {
                Darwin.close(fd)
                self?.udpSockFd = -1
            }
        }
        helloQueue = nil
    }

    func sendP2pUdp(_ target: String) {
        _helloMode = "udp"
        sendJson(["type": "p2pudp", "target": target])
    }

    func sendP2pTcp(_ target: String) {
        sendJson(["type": "p2ptcp", "target": target])
    }

    /// direct：把自己的 v4/v6 地址列表交给服务器转给对方。
    /// 服务器只做中转（校验 target 在线、填 from、每族最多 32 条并过滤非法地址），
    /// **协议里没有端口** —— direct 只回答「哪些地址 ICMP 可达」。
    func sendP2pDirect(_ target: String, ipv4: [String], ipv6: [String]) {
        sendJson(["type": "p2pdirect", "target": target, "ipv4": ipv4, "ipv6": ipv6])
    }

    /// direct 应答：对方来要地址时回一份（type 不同，免得两边「收到就回」无限来回）
    func sendP2pDirectReply(_ target: String, ipv4: [String], ipv6: [String]) {
        sendJson(["type": "p2pdirect_reply", "target": target, "ipv4": ipv4, "ipv6": ipv6])
    }

    /// 读形如 {"ipv4":["1.2.3.4", ...]} 的字符串数组，顺手丢掉空串
    private func stringArray(_ obj: [String: Any], _ key: String) -> [String] {
        guard let raw = obj[key] as? [Any] else { return [] }
        return raw.compactMap { $0 as? String }
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // A3：`sendWghelp` 已删除 —— 服务端 `handle_wghelp` 早就注释掉了，
    // 发 `wghelp` 只会收到 `{"type":"error","message":"unknown type: wghelp"}`。
    // wg 入口改成 socket 卡片上的 `wg` 按钮（阶段 3 落）。

    /// 退出登录：只通知服务器结束登录会话（`{"type":"logout"}`），
    /// **不断开 WebSocket、不动 socket**（对照 Android `WsClient.sendLogout()`）
    func sendLogout() {
        sendJson(["type": "logout"])
    }

    func sendList() {
        sendJson(["type": "list"])
    }

    func login(useWss: Bool, serverHost: String, serverPort: Int, username: String, password: String) {
        self.serverHost = serverHost
        loginUsername = username
        loginPassword = password
        print("[WsClient] login() username=\(username) useWss=\(useWss) host=\(serverHost):\(serverPort)")
        if isConnected {
            print("[WsClient] login() already connected, sending login message")
            let msg = "{\"type\":\"login\",\"username\":\"\(username)\"}"
            listener?.onSend(msg)
            doSend(msg)
            return
        }
        listener?.onMessage("请先点击连接")
        return
    }

    // MARK: - 心跳（WS 协议级 ping/pong）

    /// 起一个 25s 的重复定时器，用 `URLSessionWebSocketTask.sendPing` 做 **WS 协议级** 心跳。
    ///
    /// 为什么必须有它：连接被中间设备（NAT/防火墙）静默回收后，`receive()` **永远不返回、
    /// 也不报错**（`timeoutIntervalForRequest` 对 WS 的 receive 不生效），所以
    /// `startReceiveLoop()` 的 `.failure` 分支永远不会走 → 界面一直显示"已连接"。
    /// 只有 `sendPing` 的回调能给出信号：`error != nil` 就是没等到 pong（或连接已坏）。
    private func startHeartbeat() {
        stopHeartbeat()
        heartbeatSeq = 0          // 跟连接同生命周期：断开/重连后从第 1 次重新数
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(
            deadline: .now() + .seconds(heartbeatIntervalSec),
            repeating: .seconds(heartbeatIntervalSec),
            leeway: .seconds(3)
        )
        timer.setEventHandler { [weak self] in
            self?.sendHeartbeat()
        }
        heartbeatTimer = timer
        timer.resume()
    }

    private func stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        // 连心跳一起把看门狗停掉：正常断开时不该再判死一次
        heartbeatWatchdog.cancel()
    }

    /// 发一次协议级 ping；**只有失败才打日志**（成功的心跳不刷屏）。
    ///
    /// ⚠️ 关键：`sendPing` 的回调**只在收到 pong 或出错时才触发** —— 对端不回 pong 时
    /// （例如服务端还是老代码、不支持 WS 协议级 ping）回调**永远不触发**，
    /// 既不判死也不打日志（本机实测：不回 pong 时回调 12s 内从未触发）。所以每次都
    /// `arm()` 一个 10s 看门狗兜底。
    private func sendHeartbeat() {
        // 定时器在后台队列上；这里回主线程再碰 isConnected/wsTask/watchdog
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isConnected, let task = self.wsTask else { return }
            // 防重入：上一轮还在等回调就跳过（看门狗 10s < 心跳周期 20s，正常不会撞上）
            guard self.heartbeatWatchdog.arm() else { return }

            // 日志**只在真的调了 sendPing 时**打：放在 arm() 之后、sendPing 之前，
            // 所以上面被跳过的那一轮不会留下"发了"的假日志。
            // 文案三端逐字一致（`ios:` 前缀由日志管线按 Direction.system 加）
            self.heartbeatSeq += 1
            self.listener?.onMessage(
                "WS 心跳：发出协议级 ping（第 \(self.heartbeatSeq) 次，间隔 \(self.heartbeatIntervalSec)s）"
            )

            task.sendPing { [weak self] error in
                guard let self = self else { return }
                // nil = 收到 pong（取消看门狗、不打日志）；非 nil = 出错（取消看门狗并立即判死）
                self.heartbeatWatchdog.complete(error)
            }
        }
    }

    /// 心跳判定失败（看门狗超时，或 `sendPing` 报了错）：统一在这里收尾
    private func handleHeartbeatFailure(_ reason: String) {
        // 回调可能来自看门狗的定时器线程 / URLSession 队列：统一回主线程再收尾
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isConnected else { return }   // 已经断了就别重复处理
            self.listener?.onMessage("ios: WS 心跳失败，连接已断开（\(reason)）")
            // 走和"连接被关闭"同一套收尾：停心跳 + 清连接状态 + 让上层把界面改成未连接
            self.stopHeartbeat()
            self.isConnected = false
            self.isReceiving = false
            self.wsTask?.cancel(with: .goingAway, reason: nil)
            self.wsTask = nil
            self.session?.invalidateAndCancel()
            self.session = nil
            self.listener?.onDisconnected()
        }
    }

    /// **应用层** ping：`{"type":"ping","seq":N}` → 服务端原样回 `{"type":"pong","seq":N}`
    /// （不需要登录）。和上面的协议级心跳是两回事：这个走正常消息通道，出/入都会进 App 内日志。
    ///
    /// 报文**手工拼**而不是走 `sendJson` 的字典：`JSONSerialization` 的键序不稳定
    /// （实测同一个字典，`seq=1` 会输出 `{"seq":1,"type":"ping"}`、`seq=12` 又是 `{"type":"ping","seq":12}`），
    /// 手工拼能保证 App 内日志里的报文和安卓/协议文档一字不差，方便两端对着看。
    func sendAppPing(seq: Int) {
        let text = "{\"type\":\"ping\",\"seq\":\(seq)}"
        print("[WsClient] sendAppPing: \(text)")
        sendThrough(text, queuedTag: "sendAppPing")
    }

    private func sendJson(_ obj: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return }
        print("[WsClient] sendJson: \(text)")
        sendThrough(text, queuedTag: "sendJson")
    }

    /// 共用的发送路径：先记日志（`onSend` → App 内日志的 `client:` 行），未连接就排队
    private func sendThrough(_ text: String, queuedTag: String) {
        listener?.onSend(text)

        if isConnected {
            doSend(text)
        } else {
            print("[WsClient] \(queuedTag) QUEUED (not connected yet): \(text)")
            pendingMessages.append(text)
        }
    }

    private func doSend(_ text: String) {
        let msg = URLSessionWebSocketTask.Message.string(text)
        wsTask?.send(msg) { [weak self] error in
            if let error = error {
                let nsErr = error as NSError
                if nsErr.code == -1001 {
                    self?.listener?.onMessage("发送超时")
                } else if nsErr.code == -1004 {
                    self?.listener?.onMessage("无法发送: 连接已断开")
                } else {
                    self?.listener?.onMessage("发送错误: \(error.localizedDescription)")
                }
            } else {
                print("[WsClient] doSend SUCCESS: \(text)")
            }
        }
    }
}
