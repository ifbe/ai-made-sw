package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.TimeUnit

/**
 * WebSocket sub-type of SOCKET participant.
 *
 * 接收规则（按 chatroom 现状）：
 *  - text frame  → info msg ("📥 WS TEXT len=N hex=...") + content msg (bubble)
 *  - binary blob → info msg only ("📥 WS BLOB len=N")
 *  - ping/pong   → OkHttp 内部 autopong（不发应用字节，不出现在 UI）
 *
 * 连接握手：HTTP/1.1 GET Upgrade + 101 Switching Protocols，
 *          请求和响应都走 info msg 显示到小灰字。
 *
 * 发送：单条 `send(text)` 一帧，不追加 \n（WS 帧边界自带分隔）。
 */
class WsParticipant(
    private val sessionId: String,
    private val ip: String,
    private val port: Int,
    private val path: String = "/",
    private val onMessage: (Message) -> Unit,
    /** 链路状态变化：true=连上了 / false=连接失败或断开。service 用它维护会话的 tab 状态 */
    private val onStateChange: ((Boolean) -> Unit)? = null
) {
    private var ws: WebSocket? = null

    // disconnect() 与 OkHttp 回调在不同线程 → @Volatile 保证可见性
    @Volatile
    private var running = false

    /** 我方主动 disconnect：close 回调不算掉线，避免老实例的迟到回调用坏新连接的状态 */
    private var intentionalClose = false

    val type: ParticipantType = ParticipantType.SOCKET
    val displayName: String = "WS"

    fun connect() {
        intentionalClose = false
        val url = buildUrl()
        val scheme = if (port == 443) "wss" else "ws"

        post("🔌 WS 正在连接 $url", isInfo = true)
        // 握手首包：HTTP/1.1 GET，Upgrade: websocket
        post("🔌 WS 握手请求: GET $url HTTP/1.1", isInfo = true)

        val request = Request.Builder().url(url).build()
        ws = sharedClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                running = true
                val statusLine = "${response.protocol} ${response.code} ${response.message}"
                post("🔌 WS 握手响应: $statusLine", isInfo = true)
                post("🔌 WS 已连接", isInfo = true)
                onStateChange?.invoke(true)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                dispatchText(text)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                dispatchBinary(bytes)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                running = false
                post("🔌 WS 已断开 code=$code reason=$reason", isInfo = true)
                if (!intentionalClose) onStateChange?.invoke(false)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                running = false
                val detail = "${t.javaClass.simpleName}: ${t.message ?: "no message"}"
                post("❌ WS 失败: $detail", isInfo = true)
                if (!intentionalClose) onStateChange?.invoke(false)
            }
        })
    }

    fun sendInput(text: String) {
        val w = ws ?: run {
            post("❌ WS 未连接", isInfo = true)
            return
        }
        // WS 帧边界自带消息分隔，不追加 \n
        val ok = w.send(text)
        if (!ok) {
            post("❌ WS 发送失败（队列满或已关闭）", isInfo = true)
        }
    }

    /**
     * 发送二进制帧（图片等）。bytearray 版本方便从 Uri / File / Bitmap 压缩后直接喂过来。
     * 注意：OkHttp WebSocket.send(ByteString) 走 binary frame，对端按 binary frame 接收。
     */
    fun sendBinary(bytes: ByteArray) {
        val w = ws ?: run {
            post("❌ WS 未连接", isInfo = true)
            return
        }
        val ok = w.send(ByteString.of(*bytes))
        if (!ok) {
            post("❌ WS 发送二进制失败（队列满或已关闭）", isInfo = true)
        }
    }

    fun disconnect() {
        intentionalClose = true
        running = false
        ws?.close(1000, "client close")
        ws = null
    }

    private fun buildUrl(): String {
        val scheme = if (port == 443) "wss" else "ws"
        // path 原样透传：用户输入 `/test` → `ws://ip:port/test`，输入 `?test` → `ws://ip:port?test`
        // 不自动补 `/`，让用户自己控制是 path 还是 query
        return "$scheme://$ip:$port$path"
    }

    private fun dispatchText(content: String) {
        val bytes = content.toByteArray(Charsets.UTF_8)
        val len = bytes.size
        val hex = bytes.take(8).joinToString(" ") { "%02X".format(it) }
        val infoMsg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = "📥 接收 type=text len=$len hex=$hex",
            isInfo = true
        )
        val msg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = content
        )
        mainHandler.post { onMessage(infoMsg) }
        mainHandler.post { onMessage(msg) }
    }

    private fun dispatchBinary(bytes: ByteString) {
        val len = bytes.size
        val arr = bytes.toByteArray()
        val hex = arr.take(8).joinToString(" ") { "%02X".format(it) }
        val infoMsg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = "📥 接收 type=blob len=$len hex=$hex",
            isInfo = true
        )
        mainHandler.post { onMessage(infoMsg) }

        // magic byte 嗅探：识别 jpg / png / wav / mp3 / pdf 等，并在下一行打印识别结果
        val detected = com.example.chatroom.core.BlobSniffer.detectType(arr)
        val isImage = detected.startsWith("image/")
        val isAudio = detected.startsWith("audio/")

        // image/* 多出 size= W x H （用 BitmapFactory inJustDecodeBounds 取 metadata，不解码像素）
        val typeContent = if (isImage) {
            val size = com.example.chatroom.core.BlobSniffer.decodeImageSize(arr)
            if (size != null) "🔍 检测 type=$detected size=${size.first}x${size.second}"
            else "🔍 检测 type=$detected size=?"
        } else {
            "🔍 检测 type=$detected"
        }
        val typeMsg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = typeContent,
            isInfo = true
        )
        mainHandler.post { onMessage(typeMsg) }

        // image/* 和 audio/* 都额外发一条气泡消息（imageBytes 走内存版，后续加 disk cache 后再切换）
        // - image/* → MessageAdapter 走 ImageView 分支，点击全屏
        // - audio/* → MessageAdapter 走音频气泡分支，点击播放
        // TODO: 内存压力 — 现阶段每张图 / 每段音频都全量 ByteArray 驻在 messageList 里，
        //   大文件 / 连续接收会快速推高堆。
        //   后续方案：1) LruCache + 缩略图优先；2) 原图 / 原音写入 cacheDir，内存仅保留 path。
        if (isImage || isAudio) {
            val mediaMsg = Message(
                senderId = "socket",
                senderType = ParticipantType.SOCKET,
                senderName = displayName,
                content = "",
                imageBytes = arr
            )
            mainHandler.post { onMessage(mediaMsg) }
        }
    }

    private fun post(content: String, isInfo: Boolean = false) {
        val msg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = content,
            isInfo = isInfo
        )
        mainHandler.post { onMessage(msg) }
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())

        /**
         * 共享 OkHttpClient（连接池/线程池复用）。
         *
         * `pingInterval(30s)`：OkHttp 每 30s 发一个 **WebSocket 协议级 ping 帧**（不是应用数据，
         * 对端由 WS 库自动 pong，不污染业务流）。作用：
         *  - 让 NAT / 运营商侧的空闲连接不被回收（没有流量时中间设备常 1~5 分钟就静默断）
         *  - 对端真的死了的话，ping 失败会触发 onFailure，能及时知道断线
         * 之前注释写的"后续按需再加 pingInterval"，现在按需加上了。
         */
        private val sharedClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .pingInterval(30, TimeUnit.SECONDS)
                .build()
        }
    }
}
