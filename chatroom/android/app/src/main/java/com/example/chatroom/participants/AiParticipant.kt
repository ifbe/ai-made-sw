package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * AI participant using OpenAI-compatible API.
 *
 * Params: ip + port -> http://ip:port
 *  - subType="text"（默认）：走 `/v1/chat/completions`，sendInput(text) 走 chat
 *  - subType="stt"：走 `/v1/audio/transcriptions`，sendVoice(wavBytes) 走 ASR
 *  - subType="tts"：走 `/v1/audio/speech`，sendInput(text) 走 TTS，返回音频字节
 *
 * 三个 subType 共用同一组 ip/port/apiKey/model 配置：
 * - model 字段填对应模型（text → chat / stt → ASR / tts → TTS）
 * - apiKey 字段填对应服务的 Bearer token
 * - tts 模式的 voice 字段暂硬编码 "alloy"（用户测过的 Qwen3-TTS 默认值）
 */
class AiParticipant(
    private val sessionId: String,
    private val ip: String,
    private val port: String,
    private val apiKey: String,
    private val model: String,
    private val subType: String = "text",
    private val voice: String = "alloy",
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

    /**
     * 发送文本。根据 subType 走不同 endpoint：
     *  - "text"（默认）→ POST `/v1/chat/completions`，走 chat
     *  - "tts" → POST `/v1/audio/speech`，走 TTS，返回音频字节
     *  - "stt" → 本方法 no-op（stt 走 sendVoice）
     */
    fun sendInput(text: String) {
        when (subType) {
            "tts" -> {
                sendTextToSpeech(text)
                return
            }
            "stt" -> {
                // stt 是音频进文本出，sendInput 不处理
                return
            }
            // "text" 及其他走 chat completions
        }
        sendChatCompletion(text)
    }

    /**
     * TTS：文本 → 语音（subType="tts" 时使用）。
     * POST `/v1/audio/speech`，body = {model, input, voice}，返回原始音频字节流。
     * 把字节塞进 Message.imageBytes，adapter 靠 BlobSniffer 嗅探成 audio/... → 音频气泡。
     *
     * voice 走构造参数（从 config.params["voice"] 读，默认 "alloy"），
     * 让用户在首页 AI 卡片上填值，连接会话时传到这儿。
     */
    private fun sendTextToSpeech(text: String) {
        // 立即贴一条"合成中"提示
        mainHandler.post {
            postMessage("🔄 TTS 合成中...", true)
        }
        Thread({
            try {
                val url = URL("$baseUrl/v1/audio/speech")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Authorization", "Bearer ${apiKey.ifBlank { "dummy" }}")
                conn.doOutput = true
                conn.connectTimeout = 10_000
                conn.readTimeout = 60_000

                val body = JSONObject().apply {
                    put("model", model.ifBlank { "Qwen3-TTS-12Hz-0.6B-Base-4bit" })
                    put("input", text)
                    put("voice", voice.ifBlank { "alloy" })
                }

                OutputStreamWriter(conn.outputStream).use { w ->
                    w.write(body.toString())
                    w.flush()
                }

                val responseCode = conn.responseCode
                if (responseCode != 200) {
                    val errorBody = BufferedReader(InputStreamReader(conn.errorStream)).use { it.readText() }
                    mainHandler.post {
                        postMessage("❌ TTS 请求失败（$responseCode）: $errorBody", true)
                    }
                    return@Thread
                }

                val bytes = conn.inputStream.readBytes()
                conn.disconnect()

                val mime = com.example.chatroom.core.BlobSniffer.detectType(bytes)
                val len = bytes.size
                val hex = bytes.take(8).joinToString(" ") { "%02X".format(it) }

                // info 行：type + len + hex（跟 WS / STT 那边的接收 info 一致）
                val infoMsg = Message(
                    senderId = "ai",
                    senderType = ParticipantType.AI,
                    senderName = displayName,
                    content = "📥 TTS 接收 type=$mime len=$len hex=$hex",
                    isInfo = true
                )
                // 音频气泡：imageBytes 复用字段，adapter 嗅探 audio/* 走音频气泡
                val audioMsg = Message(
                    senderId = "ai",
                    senderType = ParticipantType.AI,
                    senderName = displayName,
                    content = "",
                    imageBytes = bytes
                )
                mainHandler.post { onMessage(infoMsg) }
                mainHandler.post { onMessage(audioMsg) }
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post {
                    postMessage("❌ TTS 请求异常: $detail", true)
                }
            }
        }, "AiTtsRequester").start()
    }

    /**
     * Chat completions（subType="text" 时使用）。
     * POST `/v1/chat/completions`，stream=false，OpenAI chat completions 协议。
     */
    private fun sendChatCompletion(text: String) {
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

                    val text = content.trim()
                    val bytes = text.toByteArray()
                    val len = bytes.size
                    val hex = bytes.take(8).joinToString(" ") { "%02X".format(it) }
                    val infoMsg = Message(
                        senderId = "ai",
                        senderType = ParticipantType.AI,
                        senderName = displayName,
                        content = "📥 接收 len=$len hex=$hex",
                        isInfo = true
                    )
                    val replyMsg = Message(
                        senderId = "ai",
                        senderType = ParticipantType.AI,
                        senderName = displayName,
                        content = text
                    )
                    mainHandler.post { onMessage(infoMsg) }
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

    /**
     * 发送 WAV 给 STT AI（subType="stt" 时使用）。其他 subtype 直接 no-op。
     *
     * POST `/v1/audio/transcriptions`，multipart/form-data，OpenAI audio transcriptions 协议。
     * 表单字段：model + stream=true + file=voice.wav（audio/wav）。
     * 流式响应：每收到一段 `data: {"text": "..."}` 就贴一条 info，全部收完后贴一条 AI 回复。
     */
    fun sendVoice(wavBytes: ByteArray) {
        if (subType != "stt") return

        Thread({
            try {
                val urlStr = "$baseUrl/v1/audio/transcriptions"
                val fileBody = wavBytes.toRequestBody("audio/wav".toMediaType())

                val multipart = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart("model", model.ifBlank { "Qwen3-ASR-0.6B-4bit" })
                    .addFormDataPart("stream", "true")
                    .addFormDataPart("file", "voice.wav", fileBody)
                    .build()

                val request = Request.Builder()
                    .url(urlStr)
                    .header("Authorization", "Bearer ${apiKey.ifBlank { "dummy" }}")
                    .post(multipart)
                    .build()

                val client = OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(60, TimeUnit.SECONDS)
                    .build()

                val response = client.newCall(request).execute()
                if (!response.isSuccessful) {
                    val code = response.code
                    val errBody = response.body?.string() ?: "(no body)"
                    response.close()
                    mainHandler.post {
                        postMessage("❌ STT 请求失败（$code）: $errBody", true)
                    }
                    return@Thread
                }

                val source = response.body?.source()
                val accumulated = StringBuilder()

                if (source != null) {
                    while (!source.exhausted()) {
                        val line = source.readUtf8Line() ?: break
                        val trimmed = line.trim()
                        if (trimmed.startsWith("data:")) {
                            val data = trimmed.removePrefix("data:").trim()
                            if (data == "[DONE]") break
                            if (data.isBlank()) continue
                            try {
                                val json = JSONObject(data)
                                val chunk = json.optString("text", "")
                                if (chunk.isNotEmpty()) {
                                    accumulated.append(chunk)
                                    mainHandler.post {
                                        postMessage("📥 STT: $chunk", true)
                                    }
                                }
                            } catch (_: Exception) {
                                // 跳过格式异常的 chunk
                            }
                        }
                    }
                    response.close()
                }

                val finalText = accumulated.toString().trim()
                if (finalText.isNotEmpty()) {
                    mainHandler.post {
                        val replyMsg = Message(
                            senderId = "ai",
                            senderType = ParticipantType.AI,
                            senderName = displayName,
                            content = finalText
                        )
                        onMessage(replyMsg)
                    }
                } else {
                    mainHandler.post {
                        postMessage("⚠️ STT 返回为空", true)
                    }
                }
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post {
                    postMessage("❌ STT 请求异常: $detail", true)
                }
            }
        }, "AiSttRequester").start()
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

        /**
         * 拉取 `/v1/models` 列表（OpenAI 兼容协议），供主页编辑卡片查询模型时使用。
         * 网络调用在 background thread，结果通过 callback 在 main thread 回调。
         *
         * @param callback (httpCode, models, errorMsg)
         *  - errorMsg != null → 网络/IO 异常，httpCode = -1
         *  - errorMsg == null && httpCode != 200 → HTTP 错误
         *  - errorMsg == null && httpCode == 200 → 成功（models 可能为空 = 200 但没模型）
         */
        fun fetchModels(
            ip: String,
            port: String,
            apiKey: String,
            callback: (httpCode: Int, models: List<String>, errorMsg: String?) -> Unit
        ) {
            Thread({
                try {
                    val url = URL("http://$ip:$port/v1/models")
                    val conn = url.openConnection() as HttpURLConnection
                    conn.requestMethod = "GET"
                    conn.setRequestProperty("Authorization", "Bearer $apiKey")
                    conn.connectTimeout = 5000
                    conn.readTimeout = 10000
                    val code = conn.responseCode
                    val body = if (code == 200) BufferedReader(InputStreamReader(conn.inputStream)).readText() else ""
                    conn.disconnect()

                    val models = mutableListOf<String>()
                    if (code == 200) {
                        val json = JSONObject(body)
                        val data = json.optJSONArray("data")
                        if (data != null) {
                            for (i in 0 until data.length()) {
                                val m = data.getJSONObject(i).optString("id", "")
                                if (m.isNotBlank()) models.add(m)
                            }
                        }
                    }

                    mainHandler.post {
                        callback(code, models, null)
                    }
                } catch (e: Exception) {
                    mainHandler.post {
                        callback(-1, emptyList(), e.message)
                    }
                }
            }, "AiParticipant-FetchModels").start()
        }
    }
}