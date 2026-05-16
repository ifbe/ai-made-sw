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
    private var serverIp = ""
    private var serverUdpPort = 0

    // Track connection state
    private var isReceiving = false
    private var isConnected = false

    // Pending messages to send after connection opens
    private var pendingMessages: [String] = []

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
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: Int, reason: Data?) {
        print("[WsClient] didCloseWith closeCode=\(closeCode)")
        isConnected = false
        isReceiving = false
        listener?.onMessage("WebSocket 连接关闭 closeCode=\(closeCode)")
        listener?.onDisconnected()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        print("[WsClient] didCompleteWithError: \(error?.localizedDescription ?? "nil")")
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
            print("[WsClient] login_ok username=\(confirmedUsername)")
            listener?.onLoginSuccess(confirmedUsername)

        default:
            break
        }
    }

    private func startUdpHello() {
        print("[WsClient] startUdpHello ENTRY serverIp=\(serverIp) serverUdpPort=\(serverUdpPort) mode=\(_helloMode)")
        if serverIp.isEmpty || serverUdpPort == 0 {
            listener?.onUdpSend("startUdpHello EARLY RETURN! serverIp=\(serverIp) serverUdpPort=\(serverUdpPort)")
            return
        }

        let sockFd = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        if sockFd < 0 {
            listener?.onMessage("UDP socket 创建失败")
            return
        }
        listener?.onMessage("UDP socket 创建成功 fd=\(sockFd)")
        udpSockFd = sockFd

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = 0
        addr.sin_port = 0

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.bind(sockFd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if bindResult < 0 {
            listener?.onMessage("UDP bind 失败")
            Darwin.close(sockFd)
            udpSockFd = -1
            return
        }

        listener?.onMessage("UDP bind 成功")
        stopFlag = false
        _pendingPeerInfo = nil

        helloQueue = DispatchQueue(label: "p2pnet.udp.hello", qos: .userInitiated)
        helloQueue?.async { [weak self] in
            guard let self = self else { return }
            let lp = self.getLocalUdpPort(sockFd)
            self.runHello(sockFd, lp)
        }
    }

    private func runHello(_ sockFd: Int32, _ localPort: Int) {
        guard let addrCStr = serverIp.withCString({ strdup($0) }) else { return }
        defer { free(addrCStr) }

        var destAddr = sockaddr_in()
        destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_port = UInt16(serverUdpPort).bigEndian
        inet_pton(AF_INET, addrCStr, &destAddr.sin_addr)

        func sendToPeer(_ data: Data) {
            data.withUnsafeBytes { dataPtr in
                withUnsafePointer(to: &destAddr) { destPtr in
                    destPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                        let sent = sendto(sockFd, dataPtr.baseAddress, data.count, 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                        if sent < 0 {
                            listener?.onMessage("UDP sendto 失败 errno=\(errno)")
                        }
                    }
                }
            }
        }

        listener?.onMessage("UDP hello 开始，发送 15 个 burst")
        for i in 0..<15 {
            let payload = buildP2pUdpPayload()
            if let data = payload.data(using: .utf8) {
                sendToPeer(data)
            }
            listener?.onUdpSend("UDP burst[\(i)] → \(payload)")
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
            cleanupSocket(sockFd)
            notifyHelloDone(updatedInfo, sockFd)
        } else {
            cleanupSocket(sockFd)
            listener?.onMessage("UDP hello 未找到 peer 信息")
            notifyHelloDone(nil, nil)
        }
    }

    private func getLocalUdpPort(_ sockFd: Int32) -> Int {
        var localAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &localAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                getsockname(sockFd, sockaddrPtr, &len)
            }
        }
        return Int(localAddr.sin_port).bigEndian
    }

    private func cleanupSocket(_ sockFd: Int32) {
        Darwin.close(sockFd)
        listener?.onMessage("UDP socket 已关闭 fd=\(sockFd)")
        if udpSockFd == sockFd {
            udpSockFd = -1
        }
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

    func sendWghelp(_ target: String) {
        _helloMode = "wg"
        sendJson(["type": "wghelp", "target": target])
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

    private func sendJson(_ obj: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return }
        print("[WsClient] sendJson: \(text)")
        listener?.onSend(text)

        if isConnected {
            doSend(text)
        } else {
            print("[WsClient] sendJson QUEUED (not connected yet): \(text)")
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
