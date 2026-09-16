package com.example.sport.net.ws

import com.example.sport.log.AppLog
import com.example.sport.net.LinkState
import com.example.sport.net.Session
import com.example.sport.sport.share.protocol.DragMoved
import com.example.sport.sport.share.protocol.SportCodec
import com.example.sport.sport.share.protocol.SportEvent
import com.example.sport.sport.share.protocol.SportKind
import com.example.sport.sport.share.protocol.StateChanged
import org.java_websocket.WebSocket
import org.java_websocket.client.WebSocketClient
import org.java_websocket.drafts.Draft
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.handshake.ServerHandshake
import org.java_websocket.handshake.ServerHandshakeBuilder
import org.java_websocket.server.WebSocketServer
import java.net.InetSocketAddress
import java.net.URI
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * 一个 WebSocket 房间，既能当服务端也能当客户端（同一个类的两种用法，协议完全一样）。
 * 结构照搬象棋那套：
 *
 *  - **服务端**：收到的事件转发给**其它**客户端（不回给发送者），并缓存每种球
 *    最后一包全量状态 —— 新加入 / 重连的人一连上就先把这些发给他；
 *  - **客户端**：本地事件发给服务端；
 *  - **高频位置流**（[DragMoved]）只留最新一条、按 30Hz 发送；发关键事件前先 flush，
 *    保证「先动、后落」。
 *
 * 注意：Android 16+ 访问局域网需要 `ACCESS_LOCAL_NETWORK` 权限（见 AndroidManifest），
 * 否则连出去 / 被连进来都会被系统拦掉。
 *
 * [onState] 会在网络线程上回调，UI 记得自己切主线程。
 */
class WsSession(
    private val onState: (LinkState, String) -> Unit,
) : Session {

    companion object {
        /** 位置流的发送间隔：30Hz 足够跟手，再快只是浪费带宽。 */
        private const val DRAG_INTERVAL_MS = 33L

        /** 显式绑 IPv4 通配地址（我们发给对端的也是 192.168.x.x）。 */
        private const val BIND_HOST = "0.0.0.0"
    }

    private var server: RoomServer? = null
    private var client: RoomClient? = null
    private var listener: ((SportEvent) -> Unit)? = null

    /** 用户主动关闭时，不再把 onClose/onError 报成故障。 */
    @Volatile
    private var closing = false

    /** 每种球最后一包全量状态：给新加入的人做同步。 */
    private val lastState = HashMap<SportKind, String>()

    private val dragLock = Any()
    private var pendingDrag: SportEvent? = null
    private var scheduler: ScheduledExecutorService? = null

    /** 服务端绑定的端口（测试里用 0 让它自己挑一个空闲端口）。 */
    val boundPort: Int get() = server?.port ?: -1

    // ------------------------------------------------------------------ 启动

    fun startServer(port: Int) {
        closing = false
        AppLog.log("启动服务：监听 $BIND_HOST:$port（仅 IPv4）")
        onState(LinkState.STARTING, "启动中…")

        val created = RoomServer(port)
        server = created
        // 之前那些连接会在端口上留下 TIME_WAIT，不打开 reuseAddr 就会
        // 「Address already in use」——哪怕没有别的程序监听这个端口。
        runCatching { created.isReuseAddr = true }
        created.start() // Java-WebSocket 自己起线程
    }

    fun startClient(uri: URI) {
        closing = false
        val created = RoomClient(uri)
        client = created
        AppLog.log("开始连接：$uri")
        onState(LinkState.STARTING, "连接中…")
        created.connect() // 异步连接
    }

    override fun listen(listener: (SportEvent) -> Unit) {
        this.listener = listener
    }

    // ------------------------------------------------------------------ 发送

    override fun send(events: List<SportEvent>) {
        for (event in events) {
            if (event is DragMoved) {
                // 位置流：只留最新一条，交给定时器按 30Hz 发
                synchronized(dragLock) { pendingDrag = event }
                ensureScheduler()
                continue
            }
            // 关键事件之前先把攒着的位置发掉，保证「先动、后落」
            flushPendingDrag()
            val line = SportCodec.encode(event)
            if (event is StateChanged) {
                // 自己这一手也要记下来，新加入的人才能同步到最新状态
                synchronized(lastState) { lastState[event.sport] = line }
            }
            sendNow(line)
        }
    }

    private fun sendNow(line: String) {
        server?.let { s ->
            for (conn in s.connections) {
                if (conn.isOpen) runCatching { conn.send(line) }
            }
            return
        }
        client?.let { c ->
            if (c.isOpen) runCatching { c.send(line) }
        }
    }

    private fun ensureScheduler() {
        if (scheduler != null) return
        scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "ws-drag").apply { isDaemon = true }
        }.also { pool ->
            pool.scheduleAtFixedRate(
                { flushPendingDrag() },
                DRAG_INTERVAL_MS,
                DRAG_INTERVAL_MS,
                TimeUnit.MILLISECONDS,
            )
        }
    }

    private fun flushPendingDrag() {
        val event = synchronized(dragLock) {
            val pending = pendingDrag
            pendingDrag = null
            pending
        } ?: return
        sendNow(SportCodec.encode(event))
    }

    // ------------------------------------------------------------------ 关闭

    override fun close() {
        val wasServer = server != null
        closing = true

        scheduler?.shutdownNow()
        scheduler = null
        synchronized(dragLock) { pendingDrag = null }

        server?.let { s ->
            server = null
            // stop(超时) 会关掉 selector 并停掉监听线程；万一它抛异常也兜一下
            runCatching { s.stop(1000) }
        }
        client?.let { c ->
            client = null
            runCatching { if (c.isOpen) c.close() else c.closeBlocking() }
        }

        AppLog.log(if (wasServer) "已关闭服务" else "已断开连接")
        onState(LinkState.IDLE, "已关闭")
    }

    // ------------------------------------------------------------------ 收报

    private fun handleMessage(text: String) {
        val event = SportCodec.decode(text) ?: return
        if (event is StateChanged) {
            synchronized(lastState) { lastState[event.sport] = text }
        }
        listener?.invoke(event)
    }

    /** 服务端当前连着的客户端数量。 */
    private fun clientCount(): Int = server?.connections?.count { it.isOpen } ?: 0

    // ------------------------------------------------------------------ 服务端

    private inner class RoomServer(port: Int) :
        WebSocketServer(InetSocketAddress(BIND_HOST, port)) {

        override fun onStart() {
            val bound = address
            AppLog.log("服务已启动，实际监听 ${bound?.hostString ?: "?"}:${bound?.port ?: port}")
            onState(LinkState.ONLINE, "服务中·0")
        }

        /**
         * 收到 HTTP 升级请求（握手的第一步）。这里先记一行日志：
         * 用 nc / curl 之类不是 WebSocket 的客户端试探时，也能看出「服务端确实收到了东西」。
         */
        override fun onWebsocketHandshakeReceivedAsServer(
            conn: WebSocket,
            draft: Draft,
            request: ClientHandshake,
        ): ServerHandshakeBuilder {
            AppLog.log(
                "收到握手请求 ${conn.remoteSocketAddress}：" +
                    "${request.resourceDescriptor}，UA=${request.getFieldValue("User-Agent").orEmpty()}",
            )
            return super.onWebsocketHandshakeReceivedAsServer(conn, draft, request)
        }

        override fun onOpen(conn: WebSocket, handshake: ClientHandshake) {
            if (closing) return
            // 新人加入：先把每种球最后一包全量状态发给他
            synchronized(lastState) {
                lastState.values.forEach { line -> runCatching { conn.send(line) } }
            }
            AppLog.log(
                "客户端接入 ${conn.remoteSocketAddress}，当前 ${clientCount()} 个；" +
                    "已推送 ${lastState.size} 个球种的状态",
            )
            onState(LinkState.ONLINE, "服务中·${clientCount()}")
        }

        override fun onClose(conn: WebSocket, code: Int, reason: String, remote: Boolean) {
            if (closing) return
            AppLog.log("客户端断开 ${conn.remoteSocketAddress}（code=$code $reason），当前 ${clientCount()} 个")
            onState(LinkState.ONLINE, "服务中·${clientCount()}")
        }

        override fun onMessage(conn: WebSocket, message: String) {
            if (closing) return
            handleMessage(message)
            // 转发给其它客户端（不回给发送者，避免他自己收到回放）
            for (other in connections) {
                if (other !== conn && other.isOpen) runCatching { other.send(message) }
            }
        }

        override fun onError(conn: WebSocket?, ex: Exception) {
            if (closing) return
            AppLog.log("服务出错：${ex.javaClass.simpleName} ${ex.message.orEmpty()}")
            onState(LinkState.FAILED, ex.message ?: "服务出错")
        }
    }

    // ------------------------------------------------------------------ 客户端

    private inner class RoomClient(uri: URI) : WebSocketClient(uri) {

        override fun onOpen(handshake: ServerHandshake) {
            if (closing) {
                runCatching { close() }
                return
            }
            AppLog.log("已连接：${uri.host}:${uri.port}")
            onState(LinkState.ONLINE, "已连接")
        }

        override fun onMessage(message: String) {
            if (!closing) handleMessage(message)
        }

        override fun onClose(code: Int, reason: String, remote: Boolean) {
            if (closing) return
            AppLog.log("连接断开（code=$code，reason=$reason，remote=$remote）")
            onState(LinkState.FAILED, "连接已断开")
        }

        override fun onError(ex: Exception) {
            if (closing) return
            AppLog.log("连接失败：${ex.javaClass.simpleName} ${ex.message.orEmpty()}")
            onState(LinkState.FAILED, ex.message ?: "连接失败")
        }
    }
}
