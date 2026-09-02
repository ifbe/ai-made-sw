import Foundation

/// WebSocket sub-type of SOCKET participant.
/// 用 URLSessionWebSocketTask（iOS 13+）实现。
///
/// 接收规则（按 chatroom 现状）：
///  - text frame  → info msg ("📥 接收 type=text len=N hex=...") + content msg (bubble)
///  - binary blob → info msg ("📥 接收 type=blob len=N hex=...") + (if image/*) image bubble
///
/// 连接握手：HTTP/1.1 GET Upgrade + 101 Switching Protocols，
///          走 URLSessionWebSocketDelegate 的 didOpenWithProtocol 回调（仅 protocol，无 HTTP status line）。
///
/// 发送：单条 `send(text)` 一帧，不追加 \n（WS 帧边界自带分隔）。
final class WsParticipant: Participant {

    let type: ParticipantType = .socket
    let displayName: String = "WS"

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    private let ip: String
    private let port: Int
    private let path: String

    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private var running = false

    init(sessionId: String, ip: String, port: Int, path: String = "/") {
        self.sessionId = sessionId
        self.ip = ip
        self.port = port
        self.path = path
    }

    func connect() {
        let url = buildURL()
        postInfo("🔌 WS 正在连接 \(url)")
        postInfo("🔌 WS 握手请求: GET \(url) HTTP/1.1")

        let delegate = WsDelegate()
        session = URLSession(configuration: .default, delegate: delegate, delegateQueue: OperationQueue())
        delegate.onOpen = { [weak self] proto in
            DispatchQueue.main.async {
                self?.handleOpen(protocol: proto)
            }
        }
        delegate.onClose = { [weak self] code, reason in
            DispatchQueue.main.async {
                self?.handleClose(code: code, reason: reason)
            }
        }
        task = session?.webSocketTask(with: url)
        running = true
        task?.resume()
        receiveLoop()
    }

    func sendInput(_ text: String) {
        guard running, let task = task else {
            postInfo("❌ WS 未连接")
            return
        }
        // WS 帧边界自带消息分隔，不追加 \n
        task.send(.string(text)) { [weak self] error in
            if let error = error {
                DispatchQueue.main.async {
                    self?.postInfo("❌ WS 发送失败: \(error)")
                }
            }
        }
    }

    func sendBinary(_ data: Data) {
        guard running, let task = task else {
            postInfo("❌ WS 未连接")
            return
        }
        task.send(.data(data)) { [weak self] error in
            if let error = error {
                DispatchQueue.main.async {
                    self?.postInfo("❌ WS 发送二进制失败: \(error)")
                }
            }
        }
    }

    func disconnect() {
        running = false
        task?.cancel(with: .normalClosure, reason: nil)
        session?.invalidateAndCancel()
        task = nil
        session = nil
    }

    private func buildURL() -> URL {
        let scheme = port == 443 ? "wss" : "ws"
        var components = URLComponents()
        components.scheme = scheme
        components.host = ip
        components.port = port
        // path 原样透传：用户输入 `/test` → `ws://ip:port/test`，输入 `?test` → `ws://ip:port?test`
        // 不自动补 `/`，让用户自己控制是 path 还是 query
        components.path = path
        return components.url ?? URL(string: "\(scheme)://\(ip):\(port)\(path)")!
    }

    private func receiveLoop() {
        task?.receive { [weak self] result in
            guard let self = self, self.running else { return }
            switch result {
            case .success(let message):
                DispatchQueue.main.async {
                    switch message {
                    case .string(let text):
                        self.dispatchText(text)
                    case .data(let data):
                        self.dispatchBinary(data)
                    @unknown default:
                        break
                    }
                }
                self.receiveLoop()
            case .failure(let error):
                DispatchQueue.main.async {
                    self.postInfo("❌ WS 接收错误: \(error)")
                }
            }
        }
    }

    private func handleOpen(protocol proto: String?) {
        // URLSessionWebSocketDelegate 只给 protocol（如 "websocket"），不给完整 HTTP status line。
        // 这里打印 protocol 即可，跟 Android 的 `Response.protocol` 对齐。
        postInfo("🔌 WS 握手响应: \(proto ?? "") 101 Switching Protocols")
        postInfo("🔌 WS 已连接")
    }

    private func handleClose(code: Int, reason: String?) {
        running = false
        postInfo("🔌 WS 已断开 code=\(code) reason=\(reason ?? "")")
    }

    private func dispatchText(_ content: String) {
        let bytes = Array(content.utf8)
        let len = bytes.count
        let hex = bytes.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")

        let infoMsg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: "📥 接收 type=text len=\(len) hex=\(hex)",
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

    private func dispatchBinary(_ data: Data) {
        let len = data.count
        let previewBytes = [UInt8](data.prefix(8))
        let hex = previewBytes.map { String(format: "%02X", $0) }.joined(separator: " ")

        let infoMsg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: "📥 接收 type=blob len=\(len) hex=\(hex)",
            isInfo: true
        )
        onMessage?(infoMsg)

        let detected = BlobSniffer.detectType(data)
        let isImage = detected.hasPrefix("image/")
        let isAudio = detected.hasPrefix("audio/")

        let typeContent: String
        if isImage {
            if let size = BlobSniffer.decodeImageSize(data) {
                typeContent = "🔍 检测 type=\(detected) size=\(size.width)x\(size.height)"
            } else {
                typeContent = "🔍 检测 type=\(detected) size=?"
            }
        } else {
            typeContent = "🔍 检测 type=\(detected)"
        }
        let typeMsg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: typeContent,
            isInfo: true
        )
        onMessage?(typeMsg)

        // image/* 和 audio/* 都额外发一条气泡消息（imageBytes 走内存版，后续加 disk cache 后再切换）
        // - image/... → MessageRowView 走 Image 分支，点击全屏
        // - audio/... → MessageRowView 走 AudioBubbleView 分支，点击播放
        // TODO: 内存压力 —— 现阶段每张图 / 每段音频都全量 Data 驻在 messages 里，
        //   大文件 / 连续接收会快速推高堆。
        //   后续方案：1) NSCache + 缩略图优先；2) 原图 / 原音写入 cacheDir，内存仅保留 path。
        if isImage || isAudio {
            let mediaMsg = Message(
                senderId: "socket",
                senderType: .socket,
                senderName: displayName,
                content: "",
                imageBytes: data
            )
            onMessage?(mediaMsg)
        }
    }

    private func postInfo(_ content: String) {
        let msg = Message(
            senderId: "socket",
            senderType: .socket,
            senderName: displayName,
            content: content,
            isInfo: true
        )
        onMessage?(msg)
    }
}

// MARK: - URLSessionWebSocketDelegate

private final class WsDelegate: NSObject, URLSessionWebSocketDelegate {
    var onOpen: ((String?) -> Void)?
    var onClose: ((Int, String?) -> Void)?

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol proto: String?) {
        onOpen?(proto)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        let reasonString = reason.flatMap { String(data: $0, encoding: .utf8) }
        onClose?(closeCode.rawValue, reasonString)
    }
}