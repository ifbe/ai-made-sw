import Foundation

/// AI 模型查询错误
enum ModelQueryError: LocalizedError {
    case invalidURL
    case nonHTTPResponse
    case http(Int)
    case network(String)
    case parseFailed

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "URL 非法"
        case .nonHTTPResponse: return "响应非 HTTP"
        case .http(let code): return "HTTP \(code)"
        case .network(let msg): return "网络错误：\(msg)"
        case .parseFailed: return "返回数据格式不对"
        }
    }
}

/// AI 参与者：OpenAI 兼容 API
///
/// - subType="text"（默认）：走 `/v1/chat/completions`，sendInput(text) 走 chat
/// - subType="stt"：走 `/v1/audio/transcriptions`，sendVoice(wavData) 走 ASR
/// - subType="tts"：走 `/v1/audio/speech`，sendInput(text) 走 TTS，返回音频字节
///
/// 共用同一组 ip/port/apiKey/model/voice 配置：
/// - model 字段填对应模型（text → chat / stt → ASR / tts → TTS）
/// - apiKey 字段填对应服务的 Bearer token
/// - tts 模式的 voice 字段（默认 "alloy"）
final class AiParticipant: Participant {

    let type: ParticipantType = .ai
    let displayName: String = "AI"

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    private let ip: String
    private let port: String
    private let apiKey: String
    private let model: String
    private let subType: String
    private let voice: String
    private let baseUrl: String

    init(sessionId: String, ip: String, port: String, apiKey: String, model: String, subType: String = "text", voice: String = "alloy") {
        self.sessionId = sessionId
        self.ip = ip
        self.port = port
        self.apiKey = apiKey
        self.model = model
        self.subType = subType
        self.voice = voice
        self.baseUrl = "http://\(ip):\(port)"
    }

    func connect() {
        postInfo("🤖 AI 已连接（\(baseUrl)）", true)
    }

    /// 发送文本。根据 subType 走不同 endpoint：
    /// - "text"（默认）→ POST `/v1/chat/completions`，走 chat
    /// - "tts" → POST `/v1/audio/speech`，走 TTS，返回音频字节
    /// - "stt" → 本方法 no-op（stt 走 sendVoice）
    func sendInput(_ text: String) {
        switch subType {
        case "tts":
            Task { [weak self] in
                await self?.doTtsRequest(text)
            }
            return
        case "stt":
            return  // stt 是音频进文本出，sendInput 不处理
        default:
            Thread { [weak self] in
                self?.doRequest(text)
            }.start()
        }
    }

    /// 发送 WAV bytes 给 STT AI。仅在 subType="stt" 时生效，text 模式 no-op。
    /// POST `/v1/audio/transcriptions`，multipart/form-data，stream=true（SSE）。
    /// 流式响应：每行 `data: {"text": "..."}` 解析 chunk → 贴 info，全部收完后贴 AI reply。
    func sendVoice(_ wavData: Data) {
        guard subType == "stt" else { return }
        Task { [weak self] in
            await self?.doSttRequest(wavData)
        }
    }

    func disconnect() {
        // 无持久连接
    }

    // MARK: - chat（subType="text"）

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

    // MARK: - stt（subType="stt"）

    private func doSttRequest(_ wavData: Data) async {
        guard let url = URL(string: "\(baseUrl)/v1/audio/transcriptions") else {
            postInfo("❌ STT URL 构建失败", true)
            return
        }

        let boundary = "Boundary-\(UUID().uuidString)"
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey.isEmpty ? "dummy" : apiKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 60

        // 构造 multipart/form-data body（URLSession 没有 OkHttp 的 MultipartBody，手写）
        var body = Data()
        let crlf = "\r\n"
        let modelName = model.isEmpty ? "Qwen3-ASR-0.6B-4bit" : model

        // model 字段
        body.append("--\(boundary)\(crlf)".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"model\"\(crlf)\(crlf)".data(using: .utf8)!)
        body.append("\(modelName)\(crlf)".data(using: .utf8)!)

        // stream 字段
        body.append("--\(boundary)\(crlf)".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"stream\"\(crlf)\(crlf)".data(using: .utf8)!)
        body.append("true\(crlf)".data(using: .utf8)!)

        // file 字段（WAV）
        body.append("--\(boundary)\(crlf)".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"voice.wav\"\(crlf)".data(using: .utf8)!)
        body.append("Content-Type: audio/wav\(crlf)\(crlf)".data(using: .utf8)!)
        body.append(wavData)
        body.append("\(crlf)--\(boundary)--\(crlf)".data(using: .utf8)!)

        request.httpBody = body

        do {
            let (asyncBytes, response) = try await URLSession.shared.bytes(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                postInfo("❌ STT 响应解析失败", true)
                return
            }

            guard httpResponse.statusCode == 200 else {
                let statusCode = httpResponse.statusCode
                // 读错误响应 body（最多 500 字符）
                var errorBody = ""
                for try await line in asyncBytes.lines {
                    errorBody += line + "\n"
                    if errorBody.count > 500 { break }
                }
                postInfo("❌ STT 请求失败（\(statusCode)）: \(errorBody)", true)
                return
            }

            // 流式解析 SSE：每行 `data: {"text": "..."}` → 贴 info + 累加
            var accumulated = ""
            for try await line in asyncBytes.lines {
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard trimmed.hasPrefix("data:") else { continue }
                let data = trimmed
                    .replacingOccurrences(of: "data:", with: "", options: .anchored)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if data == "[DONE]" { break }
                if data.isEmpty { continue }
                guard let chunkData = data.data(using: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: chunkData) as? [String: Any],
                      let chunk = json["text"] as? String,
                      !chunk.isEmpty else {
                    continue
                }
                accumulated += chunk
                postInfo("📥 STT: \(chunk)", true)
            }

            let final = accumulated.trimmingCharacters(in: .whitespacesAndNewlines)
            if !final.isEmpty {
                let reply = Message(
                    senderId: "ai",
                    senderType: .ai,
                    senderName: displayName,
                    content: final
                )
                DispatchQueue.main.async {
                    self.onMessage?(reply)
                }
            } else {
                postInfo("⚠️ STT 返回为空", true)
            }
        } catch {
            postInfo("❌ STT 请求异常: \(error.localizedDescription)", true)
        }
    }

    // MARK: - helpers

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

    // MARK: - tts（subType="tts"）

    /// TTS：文本 → 语音（subType="tts" 时使用）。
    /// POST `/v1/audio/speech`，body = {model, input, voice}，返回原始音频字节。
    /// 把字节塞进 Message.imageBytes，adapter 靠 BlobSniffer 嗅探成 audio/... → 音频气泡。
    private func doTtsRequest(_ text: String) async {
        // 立即贴一条“合成中”提示
        postInfo("🔄 TTS 合成中...", true)

        guard let url = URL(string: "\(baseUrl)/v1/audio/speech") else {
            postInfo("❌ TTS URL 构建失败", true)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey.isEmpty ? "dummy" : apiKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 60

        let modelName = model.isEmpty ? "Qwen3-TTS-12Hz-0.6B-Base-4bit" : model
        let voiceName = voice.isEmpty ? "alloy" : voice

        let body: [String: Any] = [
            "model": modelName,
            "input": text,
            "voice": voiceName
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            postInfo("❌ TTS 请求体构建失败: \(error.localizedDescription)", true)
            return
        }

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                postInfo("❌ TTS 响应解析失败", true)
                return
            }

            guard httpResponse.statusCode == 200 else {
                let statusCode = httpResponse.statusCode
                let errorBody = String(data: data, encoding: .utf8) ?? "(no body)"
                postInfo("❌ TTS 请求失败（\(statusCode)）: \(errorBody)", true)
                return
            }

            let len = data.count
            let previewBytes = [UInt8](data.prefix(8))
            let hex = previewBytes.map { String(format: "%02X", $0) }.joined(separator: " ")
            let detected = BlobSniffer.detectType(data)
            let infoMsg = Message(
                senderId: "ai",
                senderType: .ai,
                senderName: displayName,
                content: "📥 TTS 接收 type=\(detected) len=\(len) hex=\(hex)",
                isInfo: true
            )
            let audioMsg = Message(
                senderId: "ai",
                senderType: .ai,
                senderName: displayName,
                content: "",
                imageBytes: data
            )
            await MainActor.run {
                self.onMessage?(infoMsg)
                self.onMessage?(audioMsg)
            }
        } catch {
            postInfo("❌ TTS 请求异常: \(error.localizedDescription)", true)
        }
    }

    // MARK: - 模型查询（无状态，供主页编辑卡片调用）

    /// 拉取 `/v1/models` 列表（OpenAI 兼容协议）。无状态，不依赖 participant 实例。
    /// 协议：GET http://ip:port/v1/models，Bearer Token = apiKey。
    /// 解析：`{"data":[{"id":"model-name"}, ...]}`，返回 id 列表。
    ///
    /// - Returns: success（列表可能为空 = 200 但没模型）/ failure（错误描述）
    static func queryModels(ip: String, port: String, apiKey: String) async -> Result<[String], ModelQueryError> {
        guard let url = URL(string: "http://\(ip):\(port)/v1/models") else {
            return .failure(.invalidURL)
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        if !apiKey.isEmpty {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                return .failure(.nonHTTPResponse)
            }
            guard http.statusCode == 200 else {
                return .failure(.http(http.statusCode))
            }
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return .failure(.parseFailed)
            }
            // 200 但没有 data 字段，按"没模型"处理（与 Android AiParticipant.fetchModels 一致）
            guard let dataArr = json["data"] as? [[String: Any]] else {
                return .success([])
            }
            let models = dataArr.compactMap { $0["id"] as? String }.filter { !$0.isEmpty }
            return .success(models)
        } catch {
            return .failure(.network(error.localizedDescription))
        }
    }
}