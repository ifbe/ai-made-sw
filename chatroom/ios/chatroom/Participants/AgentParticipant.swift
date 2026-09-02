import Foundation

/// Agent 参与者（AGENT 类型）。
///
/// 设计（与 Android `AgentParticipant` 对齐）：
/// - ChatView.sendMessage 是**正常 broadcast**——text 一视同仁发给所有参与者
/// - AgentParticipant 自己看 subType 决定怎么响应
///
/// 当前 subType-specific 行为：
/// - "openclaw"：sendInput 收到以 `/` 开头的 text 时，把 `/<text>` 当作 API 路径，
///   GET http://addr:port/<text>，回复以本 participant 名义贴 chat
///   非 / 开头的 text 不响应（openclaw 是 command-driven，不是 chat-driven）
/// - "codex" / "claude" / "gemini" / "copilot"：暂 no-op
///
/// 未来加 subType-specific 行为时，按 subType switch 在 sendInput 里分发。
final class AgentParticipant: Participant {

    let type: ParticipantType = .agent
    let displayName: String

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    private let name: String
    private let addr: String
    private let port: String
    private let username: String
    private let password: String
    private let subType: String
    private let baseUrl: String

    init(
        sessionId: String,
        name: String,
        addr: String,
        port: String,
        username: String,
        password: String,
        subType: String
    ) {
        self.sessionId = sessionId
        self.name = name
        self.addr = addr
        self.port = port
        self.username = username
        self.password = password
        self.subType = subType
        self.baseUrl = "http://\(addr):\(port)"
        self.displayName = name
    }

    func connect() {
        postMessage("🦞 \(name) (\(subType)) 已连接", isInfo: true)
    }

    /**
     * 收到 text（普通 broadcast 过来的，**不**做任何拦截）。
     * subType-specific 分发在内部完成。
     */
    func sendInput(_ text: String) {
        if subType == "openclaw" {
            // openclaw: / 开头当 API 调用；非 / 开头不响应
            if text.hasPrefix("/") {
                let path = String(text.dropFirst())
                callApi(path: path)
            }
        }
        // 其它 subType（codex / claude / gemini / copilot）暂 no-op
    }

    func disconnect() {
        // 无持久连接
    }

    // MARK: - openclaw API

    /**
     * 调 openclaw 的 HTTP API（GET）。路径来自 sendInput 剥掉前导 `/` 的部分。
     * - 2xx → 以本 participant 名义贴气泡
     * - 非 2xx / 异常 → 贴 info 灰字
     * UI 操作走 DispatchQueue.main.async 切回主线程
     */
    private func callApi(path: String) {
        let urlStr = "\(baseUrl)/\(path)"
        guard let url = URL(string: urlStr) else {
            postMessage("❌ URL 构建失败: \(urlStr)", isInfo: true)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 10

        let task = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else { return }

            if let error = error {
                self.postMessage("❌ \(urlStr) 异常: \(error.localizedDescription)", isInfo: true)
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.postMessage("❌ \(urlStr) 响应解析失败", isInfo: true)
                return
            }

            let code = httpResponse.statusCode
            let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""

            self.postMessage("📤 GET \(urlStr) → \(code)", isInfo: true)

            if (200..<300).contains(code) {
                // 2xx：贴本 participant 名义气泡（非 info）
                self.postMessage(body, isInfo: false)
            } else {
                self.postMessage("❌ \(urlStr) → HTTP \(code): \(body)", isInfo: true)
            }
        }

        task.resume()
    }

    // MARK: - helpers

    private func postMessage(_ content: String, isInfo: Bool) {
        let msg = Message(
            senderId: "agent",
            senderType: .agent,
            senderName: name,
            content: content,
            isInfo: isInfo
        )
        DispatchQueue.main.async {
            self.onMessage?(msg)
        }
    }
}
