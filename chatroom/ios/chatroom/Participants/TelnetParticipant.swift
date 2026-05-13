import Foundation

/// Telnet 参与者：TCP 连接 + 自动登录（等 login: / password: 提示）
final class TelnetParticipant: Participant {

    let type: ParticipantType = .telnet
    let displayName: String = "TELNET"

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    private let ip: String
    private let port: Int
    private let username: String
    private let password: String

    private var sock: Int32 = -1
    private var readerThread: Thread?
    private var running = false
    private let queue = DispatchQueue(label: "TelnetParticipant", qos: .userInitiated)

    init(sessionId: String, ip: String, port: Int, username: String, password: String) {
        self.sessionId = sessionId
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
    }

    func connect() {
        running = true
        postInfo("🔗 TELNET 正在连接 \(ip):\(port)...", true)
        queue.async { [weak self] in
            self?.doConnect()
        }
    }

    private func doConnect() {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        self.sock = sock
        guard sock >= 0 else {
            postInfo("❌ TELNET socket 创建失败", true)
            return
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(self.port).bigEndian
        inet_pton(AF_INET, self.ip, &addr.sin_addr)

            let addrSize = socklen_t(MemoryLayout<sockaddr_in>.size)
            let result = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    Darwin.connect(sock, sockaddrPtr, addrSize)
                }
            }

        if result < 0 {
            postInfo("❌ TELNET 连接失败: \(String(cString: strerror(errno)))", true)
            close(sock)
            self.sock = -1
            return
        }

        postInfo("🔗 TELNET 已连接 \(ip):\(port)，等待登录...", true)

        readerThread = Thread { [weak self] in
            self?.readLoop()
        }
        readerThread?.start()
    }

    private func readLoop() {
        var buffer = [UInt8](repeating: 0, count: 4096)
        let prompt = NSMutableString()
        var stage = 0  // 0=wait login, 1=wait password, 2=connected

        while running {
            let n = read(sock, &buffer, 4096)
            if n <= 0 {
                if running { postInfo("⚠️ TELNET 连接已断开", true) }
                break
            }

            for i in 0..<n {
                let c = Character(UnicodeScalar(buffer[i]))
                prompt.append(String(c))
            }

            // 每次 buffer读完处理累积的行
            let content = prompt as String
            let lines = content.components(separatedBy: "\n")
            prompt.setString("")

            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty { continue }

                dispatchLine(trimmed)

                // 自动登录
                switch stage {
                case 0:
                    if trimmed.lowercased().contains("login:") {
                        sendText(username)
                        postInfo("📤 发送用户名: \(username)", true)
                        stage = 1
                    }
                case 1:
                    if trimmed.lowercased().contains("password:") {
                        sendText(password)
                        postInfo("📤 发送密码: ****", true)
                        stage = 2
                        postInfo("🔗 TELNET 登录完成", true)
                    }
                default:
                    break
                }
            }

            Thread.sleep(forTimeInterval: 0.05)
        }

        running = false
    }

    private func sendText(_ text: String) {
        guard sock >= 0 else { return }
        var data = (text + "\n").data(using: .utf8)!
        let dataCount = data.count
        _ = data.withUnsafeMutableBytes { write(sock, $0.baseAddress!, dataCount) }
    }

    func sendInput(_ text: String) {
        guard running && sock >= 0 else { return }
        queue.async { [weak self] in
            self?.sendText(text)
        }
    }

    func disconnect() {
        running = false
        readerThread?.cancel()
        if sock >= 0 { close(sock); sock = -1 }
    }

    private func postInfo(_ content: String, _ isInfo: Bool) {
        let msg = Message(
            senderId: "telnet",
            senderType: .telnet,
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
            senderId: "telnet",
            senderType: .telnet,
            senderName: displayName,
            content: "📥 接收 len=\(len) hex=\(hex)",
            isInfo: true
        )
        let msg = Message(
            senderId: "telnet",
            senderType: .telnet,
            senderName: displayName,
            content: content
        )
        DispatchQueue.main.async {
            self.onMessage?(infoMsg)
            self.onMessage?(msg)
        }
    }
}
