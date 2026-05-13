import Foundation

/// AI 参与者：OpenAI 兼容 API
final class AiParticipant: Participant {

    let type: ParticipantType = .ai
    let displayName: String = "AI"

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    private let ip: String
    private let port: String
    private let apiKey: String
    private let model: String
    private let baseUrl: String

    init(sessionId: String, ip: String, port: String, apiKey: String, model: String) {
        self.sessionId = sessionId
        self.ip = ip
        self.port = port
        self.apiKey = apiKey
        self.model = model
        self.baseUrl = "http://\(ip):\(port)"
    }

    func connect() {
        postInfo("🤖 AI 已连接（\(baseUrl)）", true)
    }

    func sendInput(_ text: String) {
        Thread { [weak self] in
            self?.doRequest(text)
        }.start()
    }

    private func doRequest(_ userText: String) {
        guard let url = URL(string: "\(baseUrl)/v1/chat/completions") else {
            postInfo("❌ URL 构建失败", true)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey.isEmpty ? "dummy" : apiKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 60

        let body: [String: Any] = [
            "model": model.isEmpty ? "gpt-3.5-turbo" : model,
            "stream": false,
            "messages": [
                ["role": "user", "content": userText]
            ]
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            postInfo("❌ 请求体构建失败: \(error)", true)
            return
        }

        let task = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else { return }

            if let error = error {
                self.postInfo("❌ AI 请求异常: \(error.localizedDescription)", true)
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.postInfo("❌ 响应解析失败", true)
                return
            }

            guard httpResponse.statusCode == 200 else {
                let errorBody = data.flatMap { String(data: $0, encoding: .utf8) } ?? "(无内容)"
                self.postInfo("❌ AI 请求失败（\(httpResponse.statusCode)）: \(errorBody)", true)
                return
            }

            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let choices = json["choices"] as? [[String: Any]],
                  let firstChoice = choices.first,
                  let message = firstChoice["message"] as? [String: Any],
                  var content = message["content"] as? String else {
                self.postInfo("❌ AI 返回格式异常", true)
                return
            }

            content = content.trimmingCharacters(in: .whitespacesAndNewlines)
            let bytes = Array(content.utf8)
            let len = bytes.count
            let hex = bytes.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")

            let infoMsg = Message(
                senderId: "ai",
                senderType: .ai,
                senderName: self.displayName,
                content: "📥 接收 len=\(len) hex=\(hex)",
                isInfo: true
            )
            let replyMsg = Message(
                senderId: "ai",
                senderType: .ai,
                senderName: self.displayName,
                content: content
            )

            DispatchQueue.main.async {
                self.onMessage?(infoMsg)
                self.onMessage?(replyMsg)
            }
        }

        task.resume()
    }

    func disconnect() {
        // 无持久连接
    }

    private func postInfo(_ content: String, _ isInfo: Bool) {
        let msg = Message(
            senderId: "ai",
            senderType: .ai,
            senderName: displayName,
            content: content,
            isInfo: isInfo
        )
        DispatchQueue.main.async {
            self.onMessage?(msg)
        }
    }
}
