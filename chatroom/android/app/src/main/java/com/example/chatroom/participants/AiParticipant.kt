package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * AI participant using OpenAI-compatible API.
 * Params: ip + port -> http://ip:port/v1/chat/completions
 */
class AiParticipant(
    private val sessionId: String,
    private val ip: String,
    private val port: String,
    private val apiKey: String,
    private val model: String,
    private val onMessage: (Message) -> Unit
) {
    val type: ParticipantType = ParticipantType.AI
    val displayName: String = "AI"

    private val baseUrl: String by lazy {
        "http://$ip:$port"
    }

    fun connect() {
        mainHandler.post {
            postMessage("🤖 AI 已连接（$baseUrl）", true)
        }
    }

    fun sendInput(text: String) {
        Thread({
            try {
                val url = URL("$baseUrl/v1/chat/completions")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Authorization", "Bearer ${apiKey.ifBlank { "dummy" }}")
                conn.doOutput = true
                conn.connectTimeout = 10000
                conn.readTimeout = 60_000

                val body = JSONObject().apply {
                    put("model", model.ifBlank { "gpt-3.5-turbo" })
                    put("stream", false)
                    put("messages", JSONArray().apply {
                        put(JSONObject().apply {
                            put("role", "user")
                            put("content", text)
                        })
                    })
                }

                OutputStreamWriter(conn.outputStream).use { w ->
                    w.write(body.toString())
                    w.flush()
                }

                val responseCode = conn.responseCode
                if (responseCode != 200) {
                    val errorBody = BufferedReader(InputStreamReader(conn.errorStream)).use { it.readText() }
                    mainHandler.post {
                        postMessage("❌ AI 请求失败（$responseCode）: $errorBody", true)
                    }
                    return@Thread
                }

                val response = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                val json = JSONObject(response)
                val choices = json.optJSONArray("choices")
                if (choices != null && choices.length() > 0) {
                    val content = choices.getJSONObject(0)
                        .optJSONObject("message")
                        ?.optString("content")
                        ?: "(无内容)"

                    val replyMsg = Message(
                        senderId = "ai",
                        senderType = ParticipantType.AI,
                        senderName = displayName,
                        content = content.trim()
                    )
                    mainHandler.post { onMessage(replyMsg) }
                } else {
                    mainHandler.post {
                        postMessage("❌ AI 返回格式异常: $response", true)
                    }
                }

                conn.disconnect()
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post {
                    postMessage("❌ AI 请求异常: $detail", true)
                }
            }
        }, "AiRequester").start()
    }

    fun disconnect() {
        // no persistent connection
    }

    private fun postMessage(content: String, isInfo: Boolean = false) {
        val msg = Message(
            senderId = "ai",
            senderType = ParticipantType.AI,
            senderName = displayName,
            content = content,
            isInfo = isInfo
        )
        onMessage(msg)
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}
