import Foundation
import Network

enum SocketType: String {
    case tcp = "TCP"
    case udp = "UDP"
}

/// Socket 参与者：TCP 或 UDP 客户端（使用 NWConnection）
final class SocketParticipant: Participant {

    let type: ParticipantType = .socket
    let displayName: String

    var onMessage: ((Message) -> Void)?

    /// 链路状态回调（主线程）：连上 = true，连不上 / 掉线 = false。
    /// **主动 disconnect() 不会回调 false**——否则旧实例的迟到回调会把刚重连好的会话标成断开。
    /// 对应 Android `SocketParticipant.onStateChange`。
    var onStateChange: ((Bool) -> Void)?

    private let sessionId: String
    private let ip: String
    private let port: Int
    private let sockType: SocketType

    // TCP
    private var tcpConnection: NWConnection?
    private var tcpQueue: DispatchQueue?

    // UDP
    private var udpConnection: NWConnection?

    /// 线程安全：`running` 会被 connect / disconnect（主线程）和 NWConnection 回调（queue）同时读写，
    /// 用 NSLock 而不是裸 var（Android 那边是 @Volatile，Swift 没有等价关键字）
    private let stateLock = NSLock()
    private var _running = false
    private var running: Bool {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _running
        }
        set {
            stateLock.lock()
            _running = newValue
            stateLock.unlock()
        }
    }

    private let queue = DispatchQueue(label: "SocketParticipant", qos: .userInitiated)

    init(sessionId: String, ip: String, port: Int, sockType: SocketType) {
        self.sessionId = sessionId
        self.ip = ip
        self.port = port
        self.sockType = sockType
        self.displayName = sockType == .udp ? "UDP" : "TCP"
        self.tcpQueue = DispatchQueue(label: "SocketParticipant.tcp", qos: .userInitiated)
    }

    func connect() {
        running = true
        switch sockType {
        case .tcp: connectTcp()
        case .udp: connectUdp()
        }
    }

    private func connectTcp() {
        postInfo("🔗 TCP 正在连接 \(ip):\(port)...", true)

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(ip),
            port: NWEndpoint.Port(integerLiteral: UInt16(port))
        )
        // TCP keep-alive（OS 层 socket option，不是 app 层心跳字节）——
        // 让系统代发 TCP keep-alive probe，跟 Android `socket.keepAlive=true` 等价。
        // 不污染数据流（用户明确拒绝过 \n / OOB 心跳）。
        // iOS 上对非 Background Modes app 这可能被 OS 覆盖，但设上不亏。
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.keepaliveIdle = 30       // 30s 空闲后开始发 keep-alive probe
        tcpOptions.keepaliveCount = 3       // 3 个未应答 probe 后放弃
        tcpOptions.keepaliveInterval = 10   // probe 间隔 10s
        let parameters = NWParameters(tls: nil, tcp: tcpOptions)
        tcpConnection = NWConnection(to: endpoint, using: parameters)

        tcpConnection?.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.postInfo("🔗 TCP 已连接 \(self.ip):\(self.port)", true)
                // 已主动 disconnect 的老实例（running=false）不再上报：否则迟到回调会把
                // 刚重连好的会话标成断开
                if self.running { self.reportState(true) }
                self.startTcpReader()
            case .failed(let error):
                let errMsg = String(describing: error)
                self.postInfo("❌ TCP 连接失败: \(errMsg)", true)
                if self.running { self.reportState(false) }
            case .cancelled:
                self.postInfo("⚠️ TCP 连接已取消", true)
                // 主动 disconnect()（running=false）导致的 cancelled 不上报，避免污染重连后的状态
                if self.running { self.reportState(false) }
            default:
                break
            }
        }

        tcpConnection?.start(queue: queue)
    }

    private func startTcpReader() {
        guard let conn = tcpConnection else { return }
        readLoopTcp(conn)
    }

    private func readLoopTcp(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                let text = String(data: data, encoding: .utf8) ?? ""
                let lines = text.components(separatedBy: "\n")
                for line in lines where !line.isEmpty {
                    let clean = line.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
                    DispatchQueue.main.async {
                        self.dispatchLine(clean)
                    }
                }
            }
            if let error = error {
                DispatchQueue.main.async {
                    self.postInfo("❌ TCP 读取错误: \(error)", true)
                    // 非主动断开（对端 RST / 网络切换）→ 链路已断
                    if self.running { self.reportState(false) }
                }
                return
            }
            if isComplete {
                DispatchQueue.main.async {
                    self.postInfo("⚠️ TCP 连接已关闭", true)
                    if self.running { self.reportState(false) }
                }
                return
            }
            self.readLoopTcp(conn)
        }
    }

    private func connectUdp() {
        postInfo("📡 UDP 正在连接 \(ip):\(port)...", true)

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(ip),
            port: NWEndpoint.Port(integerLiteral: UInt16(port))
        )
        udpConnection = NWConnection(to: endpoint, using: .udp)

        udpConnection?.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.postInfo("📡 UDP 已连接 \(self.ip):\(self.port)", true)
                if self.running { self.reportState(true) }
                self.startUdpReader()
            case .failed(let error):
                let errMsg = String(describing: error)
                self.postInfo("❌ UDP 连接失败: \(errMsg)", true)
                if self.running { self.reportState(false) }
            case .cancelled:
                self.postInfo("⚠️ UDP 连接已取消", true)
                if self.running { self.reportState(false) }
            default:
                break
            }
        }

        udpConnection?.start(queue: queue)
    }

    private func startUdpReader() {
        guard let conn = udpConnection else { return }
        readLoopUdp(conn)
    }

    private func readLoopUdp(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                let text = String(data: data, encoding: .utf8) ?? ""
                let lines = text.components(separatedBy: "\n")
                for line in lines where !line.isEmpty {
                    let clean = line.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
                    DispatchQueue.main.async {
                        self.dispatchLine(clean)
                    }
                }
            }
            if let error = error {
                DispatchQueue.main.async {
                    self.postInfo("❌ UDP 读取错误: \(error)", true)
                    if self.running { self.reportState(false) }
                }
                return
            }
            self.readLoopUdp(conn)
        }
    }

    func sendInput(_ text: String) {
        guard running else { return }
        queue.async { [weak self] in
            guard let self = self else { return }
            switch self.sockType {
            case .tcp:
                self.sendTcp(text)
            case .udp:
                self.sendUdp(text)
            }
        }
    }

    private func sendTcp(_ text: String) {
        guard let conn = tcpConnection else {
            postInfo("❌ TCP 未连接", true)
            return
        }
        let data = (text + "\n").data(using: .utf8)!
        conn.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error = error {
                DispatchQueue.main.async {
                    self?.postInfo("❌ TCP 发送失败: \(error)", true)
                }
            }
        })
    }

    private func sendUdp(_ text: String) {
        guard let conn = udpConnection else {
            postInfo("❌ UDP 未连接", true)
            return
        }
        let data = (text + "\n").data(using: .utf8)!
        conn.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error = error {
                DispatchQueue.main.async {
                    self?.postInfo("❌ UDP 发送失败: \(error)", true)
                }
            }
        })
    }

    func disconnect() {
        // 先置 running=false：后面 NWConnection 回调里的 cancelled 才不会上报 false
        running = false
        tcpConnection?.cancel()
        tcpConnection = nil
        udpConnection?.cancel()
        udpConnection = nil
    }

    /// 上报链路状态（统一回主线程，SessionManager 是 @MainActor）
    private func reportState(_ up: Bool) {
        DispatchQueue.main.async { [weak self] in
            self?.onStateChange?(up)
        }
    }

    private func postInfo(_ content: String, _ isInfo: Bool) {
        let msg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: content,
            isInfo: isInfo
        )
        DispatchQueue.main.async {
            self.onMessage?(msg)
        }
    }

    private func dispatchLine(_ content: String) {
        let bytes = Array(content.utf8)
        let len = bytes.count
        let hex = bytes.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")

        let infoMsg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: "📥 接收 len=\(len) hex=\(hex)",
            isInfo: true
        )
        let msg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: content
        )
        onMessage?(infoMsg)
        onMessage?(msg)
    }
}