import Foundation

/// Echo participant — 自测用的"复读机"。
///
/// 行为：
///  - 文本输入（sendInput）：原样回一条文本消息
///  - 二进制输入（sendBinary）：原样回一条带 imageBytes 的消息，
///    adapter 靠 BlobSniffer 嗅探 — image/... 渲染图片气泡（可点全屏），
///    audio/... 渲染音频气泡（点按钮播放），其他 binary 渲染为文本回退
///
/// 纯客户端、无网络 / 无 fd / 无需任何配置。用来测试 chat 页面 + 消息广播链路时不用起真实服务。
final class EchoParticipant: Participant {

    let type: ParticipantType = .echo
    let displayName: String = "ECHO"

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    /// 延迟（秒），默认 0.5；可设 0 即时回吐。用于自测时控制发送 / 接收节奏
    private let delaySeconds: Float

    init(sessionId: String, delaySeconds: Float = 0.5) {
        self.sessionId = sessionId
        self.delaySeconds = delaySeconds
    }

    func connect() {
        let delayLabel: String
        if delaySeconds == 0.5 {
            delayLabel = "默认 0.5s"
        } else {
            delayLabel = String(format: "%gs", delaySeconds)
        }
        postInfo("🔁 Echo 已连接（自测模式 · 延迟 \(delayLabel)）")
    }

    /// 收到 sendInput(text)：原样回一条 ECHO 类型的文本消息，渲染为"对方"气泡。
    /// 走 DispatchQueue.main.asyncAfter（毫秒 = delaySeconds * 1000）。
    func sendInput(_ text: String) {
        let delayMs = Int((delaySeconds * 1000).rounded())
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(delayMs)) { [weak self] in
            self?.postReply(text)
        }
    }

    /// 收到 sendBinary(data)：原样回一条带 imageBytes 的消息。
    /// 跟 WsParticipant.dispatchBinary 那条路径一致 —— 贴两条 info（接收 hex / 检测 mime），
    /// 再贴一条 imageBytes 消息；adapter 自动按 mime 走 image/audio/text 分支渲染。
    /// 不管 mime 是什么都返 — "其他"（PDF / ZIP / 任意 binary）也能跑通 self-test。
    func sendBinary(_ data: Data) {
        let delayMs = Int((delaySeconds * 1000).rounded())
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(delayMs)) { [weak self] in
            guard let self = self else { return }
            let len = data.count
            let previewBytes = [UInt8](data.prefix(8))
            let hex = previewBytes.map { String(format: "%02X", $0) }.joined(separator: " ")
            self.postInfo("📥 Echo 接收 type=blob len=\(len) hex=\(hex)")

            let detected = BlobSniffer.detectType(data)
            let isImage = detected.hasPrefix("image/")
            let typeContent: String
            if isImage {
                if let size = BlobSniffer.decodeImageSize(data) {
                    typeContent = "🔍 Echo 检测 type=\(detected) size=\(size.width)x\(size.height)"
                } else {
                    typeContent = "🔍 Echo 检测 type=\(detected) size=?"
                }
            } else {
                typeContent = "🔍 Echo 检测 type=\(detected)"
            }
            self.postInfo(typeContent)

            // 原样回：imageBytes 复用字段，adapter 按 mime 决渲染分支
            let msg = Message(
                senderId: "echo",
                senderType: .echo,
                senderName: displayName,
                content: "",
                imageBytes: data
            )
            self.onMessage?(msg)
        }
    }

    func disconnect() {
        // no-op: echo 不持有任何资源（无 fd / 无 socket / 无后台线程）
    }

    private func postReply(_ content: String) {
        let msg = Message(
            senderId: "echo",
            senderType: .echo,
            senderName: displayName,
            content: content
        )
        onMessage?(msg)
    }

    private func postInfo(_ content: String) {
        let msg = Message(
            senderId: "echo",
            senderType: .echo,
            senderName: displayName,
            content: content,
            isInfo: true
        )
        onMessage?(msg)
    }
}