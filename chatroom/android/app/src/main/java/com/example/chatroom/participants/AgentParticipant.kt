package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Agent participant（AGENT 类型）。
 *
 * 设计：
 * - ChatFragment.sendMessage 是**正常 broadcast**——text 一视同仁发给所有参与者（PTY/AI/WS/Agent 等都收到）
 * - AgentParticipant 自己看 subType 决定怎么响应
 *
 * 当前 subType-specific 行为：
 * - "openclaw"：sendInput 收到以 `/` 开头的 text 时，把 `/<text>` 当作 API 路径，
 *   GET http://addr:port/<text>，回复以本 participant 名义贴 chat
 *   非 / 开头的 text 不响应（openclaw 是 command-driven，不是 chat-driven）
 * - "codex" / "claude" / "gemini" / "copilot"：暂 no-op（等有具体行为再实现）
 *
 * 未来加 subType-specific 行为时，按 subType switch 在 sendInput 里分发。
 */
class AgentParticipant(
    private val sessionId: String,
    private val name: String,
    private val addr: String,
    private val port: String,
    private val username: String,
    private val password: String,
    private val subType: String,
    private val onMessage: (Message) -> Unit
) {
    val type: ParticipantType = ParticipantType.AGENT
    val displayName: String = name

    fun connect() {
        mainHandler.post {
            onMessage(
                Message(
                    senderId = "agent",
                    senderType = ParticipantType.AGENT,
                    senderName = name,
                    content = "🦞 $name ($subType) 已连接",
                    isInfo = true
                )
            )
        }
    }

    /**
     * 收到 text（普通 broadcast 过来的，**不**做任何拦截）。
     * subType-specific 分发在内部完成。
     */
    fun sendInput(text: String) {
        when (subType) {
            "openclaw" -> {
                // openclaw: / 开头当 API 调用；非 / 开头不响应
                if (text.startsWith("/")) {
                    val path = text.removePrefix("/")
                    callApi(path)
                }
            }
            // 其它 subType（codex / claude / gemini / copilot）暂 no-op
        }
    }

    fun disconnect() {
        // no persistent connection
    }

    /**
     * 调 openclaw 的 HTTP API（GET）。路径来自 sendInput 剥掉前导 `/` 的部分。
     * - 2xx → 以本 participant 名义贴气泡
     * - 非 2xx / 异常 → 贴 info 灰字
     * UI 操作走 mainHandler 切回主线程
     */
    private fun callApi(path: String) {
        val urlStr = "http://$addr:$port/$path"
        Thread({
            try {
                val client = OkHttpClient.Builder()
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.SECONDS)
                    .build()
                val request = Request.Builder().url(urlStr).get().build()
                val response = client.newCall(request).execute()
                val code = response.code
                val body = response.body?.string() ?: ""
                response.close()

                mainHandler.post {
                    onMessage(
                        Message(
                            senderId = "agent",
                            senderType = ParticipantType.AGENT,
                            senderName = name,
                            content = "📤 GET $urlStr → $code",
                            isInfo = true
                        )
                    )
                    if (code in 200..299) {
                        onMessage(
                            Message(
                                senderId = "agent",
                                senderType = ParticipantType.AGENT,
                                senderName = name,
                                content = body,
                                isInfo = false
                            )
                        )
                    } else {
                        onMessage(
                            Message(
                                senderId = "system",
                                senderType = ParticipantType.AGENT,
                                senderName = "系统",
                                content = "❌ $urlStr → HTTP $code: $body",
                                isInfo = true
                            )
                        )
                    }
                }
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post {
                    onMessage(
                        Message(
                            senderId = "system",
                            senderType = ParticipantType.AGENT,
                            senderName = "系统",
                            content = "❌ $urlStr 异常: $detail",
                            isInfo = true
                        )
                    )
                }
            }
        }, "AgentApiCaller").start()
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}
