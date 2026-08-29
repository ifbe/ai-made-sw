package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType

/**
 * Echo participant — 自测用的"复读机"。
 *
 * 行为：
 *  - 文本输入（sendInput）：原样回一条文本消息
 *  - 二进制输入（sendBinary）：原样回一条带 imageBytes 的消息，
 *    adapter 靠 BlobSniffer 嗅探 — image/... 渲染图片气泡（可点全屏），
 *    audio/... 渲染音频气泡（点按钮播放），其他 binary 渲染为文本回退
 *
 * 纯客户端、无网络 / 无 fd / 无需任何配置。用来测试 chat 页面 + 消息广播链路时不用起真实服务。
 */
class EchoParticipant(
    private val sessionId: String,
    /** 延迟（秒），默认 0.5；可设 0 即时回吐。用于自测时控制发送 / 接收节奏 */
    private val delaySeconds: Float = 0.5f,
    private val onMessage: (Message) -> Unit
) {
    val type: ParticipantType = ParticipantType.ECHO
    val displayName: String = "ECHO"

    fun connect() {
        val delayLabel = if (delaySeconds == 0.5f) "默认 0.5s" else "${delaySeconds}s"
        mainHandler.post {
            postInfo("🔁 Echo 已连接（自测模式 · 延迟 $delayLabel）")
        }
    }

    /**
     * 收到 sendInput(text)：原样回一条 ECHO 类型的文本消息，渲染为"对方"气泡。
     * postDelayed 的 delay 毫秒 = delaySeconds * 1000。
     */
    fun sendInput(text: String) {
        mainHandler.postDelayed({
            postReply(text)
        }, (delaySeconds * 1000).toLong().coerceAtLeast(0L))
    }

    /**
     * 收到 sendBinary(bytes)：原样回一条带 imageBytes 的消息。
     * 跟 WS dispatchBinary 那条路径一致 —— 贴两条 info（接收 hex / 检测 mime），
     * 再贴一条 imageBytes 消息；adapter 自动按 mime  拖 image/audio/text 分支渲染。
     * 不管 mime 是什么都返 — “其他”（PDF / ZIP / 任意 binary）也能跑通 self-test。
     */
    fun sendBinary(bytes: ByteArray) {
        mainHandler.postDelayed({
            val len = bytes.size
            val hex = bytes.take(8).joinToString(" ") { "%02X".format(it) }
            postInfo("📥 Echo 接收 type=blob len=$len hex=$hex")

            val mime = com.example.chatroom.core.BlobSniffer.detectType(bytes)
            val isImage = mime.startsWith("image/")
            val typeContent = if (isImage) {
                val size = com.example.chatroom.core.BlobSniffer.decodeImageSize(bytes)
                if (size != null) "🔍 Echo 检测 type=$mime size=${size.first}x${size.second}"
                else "🔍 Echo 检测 type=$mime size=?"
            } else {
                "🔍 Echo 检测 type=$mime"
            }
            postInfo(typeContent)

            // 原样回：imageBytes 复用字段，adapter 按 mime 决渲染分支
            val msg = Message(
                senderId = "echo",
                senderType = ParticipantType.ECHO,
                senderName = displayName,
                content = "",
                imageBytes = bytes
            )
            onMessage(msg)
        }, (delaySeconds * 1000).toLong().coerceAtLeast(0L))
    }

    fun disconnect() {
        // no-op: echo 不持有任何资源（无 fd / 无 socket / 无后台线程）
    }

    private fun postReply(content: String) {
        val msg = Message(
            senderId = "echo",
            senderType = ParticipantType.ECHO,
            senderName = displayName,
            content = content
        )
        onMessage(msg)
    }

    private fun postInfo(content: String) {
        val msg = Message(
            senderId = "echo",
            senderType = ParticipantType.ECHO,
            senderName = displayName,
            content = content,
            isInfo = true
        )
        onMessage(msg)
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}