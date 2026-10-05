package com.example.p2pnet.data.remote

import android.os.Handler
import android.os.Looper
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.net.hostForUrl
import okhttp3.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class WsClient(
    private val localPrefs: LocalPrefs? = null
) {
    companion object {
        /**
         * WS 协议级心跳间隔（秒）—— OkHttp 按它自动发 0x9 ping 帧（服务器原样回 0xA pong）。
         *
         * ⚠️ OkHttp **没有**任何"ping 已发出 / 收到 pong"的回调（ping 是库内部按 interval 发的），
         * 所以"WS 心跳：发出协议级 ping（第 N 次…）"那行日志由**应用侧同节奏计时器**打出
         * （见 `LoginViewModel.startWsPingLog`），节奏相同但**不是严格同一瞬间**，
         * 与真实发帧可能相差不到 1 个周期。
         */
        const val PING_INTERVAL_SECONDS = 20
    }

    interface Listener {
        fun onConnected()
        fun onDisconnected()
        fun onRawMessage(text: String)
        fun onSend(text: String)
        fun onLoginSuccess(username: String)
        fun onLoginFailed(message: String)
        fun onError(message: String)
        fun onUdpSend(text: String)
        fun onUdpRecv(text: String)
        fun onHelloDone(info: PeerInfo?, sock: DatagramSocket?, peerIp: String, peerPort: Int, mode: String)

        /** hello socket 刚创建好（绑定完成）时回调，用于在界面上生成 socket 卡片 */
        fun onUdpSocketBound(sock: DatagramSocket, localIp: String, localPort: Int) {}

        /**
         * UDP 打洞流程的每一步进度（界面上的 socket 卡片用来打勾）：
         * SENT_TO_SERVER  已把 hello 包发给服务器
         * SERVER_REPLIED  收到服务器回复（带服务器眼里我的公网 ip/port 和对方 ip/port）
         * SENT_TO_PEER    已开始给对端发包
         * PEER_REPLIED    已收到对端回包
         */
        fun onUdpSocketStep(
            sock: DatagramSocket,
            step: UdpStep,
            myIp: String = "",
            myPort: Int = 0,
            peerIp: String = "",
            peerPort: Int = 0
        ) {}

        /**
         * 收到服务器转来的 direct 地址交换（p2pdirect / p2pdirect_reply）。
         *
         * isReply = false → 对方来要地址（`p2pdirect` 请求里就带着他的地址表，
         *                    我们这边没发过地址就得回一份 `p2pdirect_reply`）
         * isReply = true  → 对方对我方请求的应答，只探测、不再回
         *
         * 协议里**只有 IP 列表、没有端口**，所以 direct 只能判断「可达」，
         * 不建 socket、不建隧道。
         */
        fun onP2pDirect(from: String, ipv4: List<String>, ipv6: List<String>, isReply: Boolean) {}
    }

    /** UDP socket 卡片的五个步骤 */
    enum class UdpStep { SENT_TO_SERVER, SERVER_REPLIED, SENT_TO_PEER, PEER_REPLIED, HANDED_TO }

    data class PeerInfo(
        val name: String,
        val peerIp: String,
        val peerPort: Int,
        val myIp: String,
        val myPort: Int,
        val myLocalPort: Int
    )

    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        // WS 协议级心跳：每 PING_INTERVAL_SECONDS 秒自动发一个 0x9 ping 帧（服务器原样回 0xA pong）。
        // 连续收不到 pong 时 OkHttp 会把这条连接判死并回调 onFailure（见下面的处理）。
        .pingInterval(PING_INTERVAL_SECONDS.toLong(), TimeUnit.SECONDS)
        .build()

    private var ws: WebSocket? = null
    private var wsOpen = false
    var listener: Listener? = null
    /** 当前 hello 用的 socket（服务器回复要按它定位到界面上的那张卡片） */
    private var helloSocket: DatagramSocket? = null
    private var serverIp = ""
    private var serverUdpPort = 0
    private var serverHost = ""

    // Login state
    private var loginUsername: String = ""
    private var loginPassword: String = ""
    var confirmedUsername: String = ""
    private var sessionKey: ByteArray? = null
    private var pendingSalt: String = ""
    private var pendingChallenge: String = ""
    private var pendingPwHash: String = ""

    // UDP hello 共享状态（主线程创建socket，hello线程写，主线程读）
    private var _pendingPeerInfo: PeerInfo? = null
    // "udp" or "wg"：标识当前 hello 线程是为 UDP tab 还是 WireGuard tab
    private var _helloMode: String = "udp"
    private var _helloPeerIp: String = ""
    private var _helloPeerPort: Int = 0
    // 中断标志：服务器发 thisisyourpeer 时置 true，hello 线程检查到这个标志就立即停止发包并退出
    private val stopFlag = AtomicBoolean(false)
    private var helloThread: Thread? = null

    fun connect(url: String) {
        val request = Request.Builder().url(url).build()
        ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                wsOpen = true
                listener?.onConnected()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                wsOpen = false
                // 心跳（pingInterval 20s）收不到 pong 时，OkHttp 就是用 SocketTimeoutException 把连接判死的；
                // 连接已经死了，状态必须一起收回「未连接」，否则界面还显示"已连接"（旧 bug）。
                val reason = if (t is SocketTimeoutException) {
                    "WS 心跳失败（20s 没收到 pong），连接已断开"
                } else {
                    "WS 连接失败：${t.message ?: "connection failed"}"
                }
                listener?.onError(reason)
                listener?.onDisconnected()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                wsOpen = false
                listener?.onDisconnected()
            }
        })
    }

    private fun handleMessage(text: String) {
        try {
            val obj = JSONObject(text)
            val type = obj.optString("type")
            listener?.onRawMessage(text)

            when (type) {
                "login_failed" -> {
                    listener?.onLoginFailed(obj.optString("message"))
                }
                "send_udp_to_server" -> {
                    serverIp = obj.optString("server_ip", "")
                    serverUdpPort = obj.optInt("udpport", 0)
                    listener?.onSend("send_udp_to_server")
                    android.util.Log.e("UDP", "send_udp_to_server received! serverIp=$serverIp serverUdpPort=$serverUdpPort")
                    startUdpHello()
                }
                "thisisyourpeer_udp" -> {
                    val info = PeerInfo(
                        name = obj.optString("name", ""),
                        peerIp = obj.optString("ip", ""),
                        peerPort = obj.optInt("port", 0),
                        myIp = obj.optString("my_ip", ""),
                        myPort = obj.optInt("my_port", 0),
                        myLocalPort = 0  // 待 hello 线程填入
                    )
                    _pendingPeerInfo = info
                    _helloPeerIp = info.peerIp
                    _helloPeerPort = info.peerPort
                    listener?.onUdpRecv("收到 thisisyourpeer_udp，设置停止标志")
                    // 服务器回复：界面上的 socket 卡片打第 2 个勾，并显示公网 ip/port
                    helloSocket?.let { s ->
                        listener?.onUdpSocketStep(
                            sock = s,
                            step = UdpStep.SERVER_REPLIED,
                            myIp = info.myIp,
                            myPort = info.myPort,
                            peerIp = info.peerIp,
                            peerPort = info.peerPort
                        )
                    }
                    stopFlag.set(true)
                }
                "p2pdirect", "p2pdirect_reply" -> {
                    // direct 地址交换：服务器只做中转，from 由服务器填。
                    // 请求（p2pdirect）→ 该回一份地址；应答（p2pdirect_reply）→ 只探测，不再回。
                    listener?.onP2pDirect(
                        from = obj.optString("from", ""),
                        ipv4 = obj.optStringList("ipv4"),
                        ipv6 = obj.optStringList("ipv6"),
                        isReply = type == "p2pdirect_reply"
                    )
                }
                "challenge" -> {
                    val challenge = obj.optString("challenge", "")
                    val salt = obj.optString("salt", "")
                    pendingSalt = salt
                    pendingChallenge = challenge
                    val pwHash = sha256(loginPassword + salt)
                    pendingPwHash = pwHash
                    val response = hmacSha256(hexDecode(pwHash), hexDecode(challenge))
                    sendJson(JSONObject().apply {
                        put("type", "login")
                        put("username", loginUsername)
                        put("response", response)
                    })
                    loginPassword = ""
                }
                "login_ok" -> {
                    confirmedUsername = obj.optString("username", "")
                    val skIkm = hexDecode(pendingPwHash)
                    sessionKey = hkdfSha256(skIkm, skIkm, hexDecode(pendingChallenge))
                    android.util.Log.e("UDP", "session_key derived: ${sessionKey?.let { binasciiHexlify(it) }}")
                    listener?.onLoginSuccess(confirmedUsername)
                }
            }
        } catch (e: Exception) {
            listener?.onError("parse error: ${e.message}")
        }
    }

    private fun startUdpHello() {
        // 捕获当前 mode（现在只有 udp 打洞会设置它），hello 线程结束时随结果一起回调
        val mode = _helloMode
        listener?.onUdpSend("startUdpHello ENTRY serverIp=$serverIp serverUdpPort=$serverUdpPort mode=$mode")
        if (serverIp.isEmpty() && serverHost.isNotEmpty()) {
            try {
                serverIp = InetAddress.getByName(serverHost).hostAddress ?: ""
                listener?.onUdpSend("serverIp fallback resolved: $serverIp from $serverHost")
            } catch (e: Exception) {
                listener?.onUdpSend("serverIp fallback failed: ${e.message}")
            }
        }
        if (serverIp.isEmpty() || serverUdpPort == 0) {
            listener?.onUdpSend("startUdpHello EARLY RETURN! serverIp=$serverIp serverUdpPort=$serverUdpPort")
            return
        }

        // 主线程创建 socket，然后直接返回，不阻塞 WebSocket 线程
        var sock: DatagramSocket? = null
        try {
            val boundSock: DatagramSocket = createHelloSocket()
            sock = boundSock
            helloSocket = boundSock
            val isV6 = boundSock.localAddress is Inet6Address
            listener?.onUdpSend(
                "UDP hello socket 绑定=${formatHostPort(boundSock.localAddress?.hostAddress ?: "", boundSock.localPort)}" +
                    " 地址族=${if (isV6) "v6 双栈（可收发 v4/v6）" else "v4"}" +
                    " 目标=${formatHostPort(serverIp, serverUdpPort)}"
            )
            // 通知界面：socket 已创建，把本机实际绑定的地址/端口显示出来
            listener?.onUdpSocketBound(
                boundSock,
                boundSock.localAddress?.hostAddress ?: if (isV6) "::" else "0.0.0.0",
                boundSock.localPort
            )
            val localPort = boundSock.localPort
            // 重置共享状态
            stopFlag.set(false)
            _pendingPeerInfo = null

            // 启动 hello 临时线程，不 join，让 WebSocket 线程立即返回
            helloThread = Thread {
                try {
                    runHello(sock!!, localPort)
                } catch (e: Exception) {
                    listener?.onError("hello thread error: ${e.message}")
                } finally {
                    // hello 线程结束后，根据结果决定关 socket 还是传给新 tab
                    val info = _pendingPeerInfo
                    Handler(Looper.getMainLooper()).post {
                        if (info != null) {
                            listener?.onUdpSend("hello 线程结束，收到 peer info，拉起新 tab")
                            listener?.onHelloDone(info, sock, _helloPeerIp, _helloPeerPort, mode)
                        } else {
                            listener?.onUdpSend("hello 线程结束，未收到 peer info，关闭 socket")
                            try { sock.close() } catch (_: Exception) {}
                            listener?.onHelloDone(null, null, "", 0, mode)
                        }
                    }
                }
            }
            helloThread?.start()
        } catch (e: Exception) {
            listener?.onError("startUdpHello error: ${e.message}")
            try { sock?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Hello 临时线程：只发包，不创建也不关闭 socket。
     * 通过 stopFlag AtomicBoolean 被 thisisyourpeer_udp 中断。
     */
    private fun runHello(sock: DatagramSocket, localPort: Int) {
        val addr = InetAddress.getByName(serverIp)

        // Phase 1: burst 15 个，30ms 间隔
        for (i in 0 until 15) {
            val payload = buildP2pUdpPayload()
            val data = payload.toString().toByteArray()
            val pkt = DatagramPacket(data, data.size, addr, serverUdpPort)
            sock.send(pkt)
            listener?.onUdpSend("UDP burst[$i] → $payload")
            // 第一个包发出去就算「发给服务器」这一步完成
            if (i == 0) listener?.onUdpSocketStep(sock, UdpStep.SENT_TO_SERVER)
            Thread.sleep(30)
        }
        listener?.onUdpSend("burst 15个发完，进入维持阶段")

        // Phase 2: 每秒发1个维持包，可被 stopFlag 中断
        var seq = 0
        val startTime = System.currentTimeMillis()
        while (!stopFlag.get()) {
            if (System.currentTimeMillis() - startTime > 10_000) {
                listener?.onUdpSend("UDP hello 维持 10s 无响应，主动放弃")
                return
            }
            Thread.sleep(1000)
            if (stopFlag.get()) break
            seq++

            val payload = buildP2pUdpPayload()
            val data = payload.toString().toByteArray()
            val pkt = DatagramPacket(data, data.size, addr, serverUdpPort)
            sock.send(pkt)
            listener?.onUdpSend("UDP keep-alive[$seq] → $payload")
        }

        // stopFlag 被设置（收到了 thisisyourpeer）
        if (_pendingPeerInfo != null) {
            _pendingPeerInfo = _pendingPeerInfo!!.copy(myLocalPort = localPort)
            listener?.onUdpSend("hello 线程退出，收到 peer info: ${_pendingPeerInfo?.peerIp}:${_pendingPeerInfo?.peerPort}")
        }

        // 被 stopFlag 停止（收到了 thisisyourpeer）
        if (_pendingPeerInfo != null) {
            // 填入本地端口
            _pendingPeerInfo = _pendingPeerInfo!!.copy(myLocalPort = localPort)
            listener?.onUdpSend("hello 线程被中断，收到 peer info: ${_pendingPeerInfo?.peerIp}:${_pendingPeerInfo?.peerPort}")
        }
    }

    private fun buildP2pUdpPayload(): JSONObject {
        val sig = sessionKey?.let { hmacSha256Hex(it, "ping".toByteArray()) }
        return JSONObject().apply {
            put("type", "p2pudp_hello")
            put("username", confirmedUsername)
            sig?.let { put("signature", it) }
        }
    }

    fun resetUdpState() {
        stopFlag.set(true)
        helloThread?.interrupt()
        helloThread = null
    }

    /**
     * 建一个 v4/v6 都能用的 hello socket。
     *
     * 首选绑 `::`（Linux/Android 默认 `net.ipv6.bindv6only=0`，双栈 socket 既能发给 v6 目的地，
     * 也能发给 v4 目的地——Java 会自动走 v4-mapped 地址）；只有双栈不可用时才退回绑 `0.0.0.0`。
     *
     * 注意：这里只解决「本机能不能收发两个地址族」。真正走 v6 还要服务端也监听 v6
     * （现在 server.py 是 `HOST='0.0.0.0'` 纯 v4），以及 DNS 能解析出 AAAA。
     */
    private fun createHelloSocket(): DatagramSocket {
        try {
            val dual = DatagramSocket(null as java.net.InetSocketAddress?)
            dual.bind(java.net.InetSocketAddress(Inet6Address.getByName("::"), 0))
            return dual
        } catch (t: Throwable) {
            android.util.Log.w("UDP", "双栈绑定(::)失败，退回 v4: ${t.javaClass.simpleName}: ${t.message}")
        }
        val v4 = DatagramSocket(null as java.net.InetSocketAddress?)
        v4.bind(java.net.InetSocketAddress(Inet4Address.getByName("0.0.0.0"), 0))
        return v4
    }

    fun sendP2pUdp(target: String) {
        _helloMode = "udp"
        sendJson(JSONObject().put("type", "p2pudp").put("target", target))
    }

    fun sendP2pTcp(target: String) {
        sendJson(JSONObject().put("type", "p2ptcp").put("target", target))
    }

    /**
     * direct：把自己的 v4/v6 地址列表交给服务器转给对方。
     * 服务器只做中转（校验 target 在线、填 from、每族最多 32 条并过滤非法地址），
     * **协议里没有端口**——direct 只回答「哪些地址 ICMP 可达」。
     */
    fun sendP2pDirect(target: String, ipv4: List<String>, ipv6: List<String>) {
        sendJson(JSONObject().apply {
            put("type", "p2pdirect")
            put("target", target)
            put("ipv4", JSONArray(ipv4))
            put("ipv6", JSONArray(ipv6))
        })
    }

    /** direct 应答：对方来要地址时回一份（type 不同，免得两边「收到就回」无限来回） */
    fun sendP2pDirectReply(target: String, ipv4: List<String>, ipv6: List<String>) {
        sendJson(JSONObject().apply {
            put("type", "p2pdirect_reply")
            put("target", target)
            put("ipv4", JSONArray(ipv4))
            put("ipv6", JSONArray(ipv6))
        })
    }

    fun sendList() {
        sendJson(JSONObject().put("type", "list"))
    }

    /**
     * 应用层 ping（和协议级 0x9 ping 帧是两回事）：
     * 发 `{"type":"ping","seq":N}`，服务器回 `{"type":"pong","seq":N}`（**不需要登录**）。
     * 走 [sendJson] 所以发出时会先经 `onSend` 进 App 内日志（渲染成 `client: {...}`）。
     */
    fun sendAppPing(seq: Int) {
        sendJson(JSONObject().put("type", "ping").put("seq", seq))
    }

    /** 退出登录：只通知服务器结束登录会话，不断开 WebSocket */
    fun sendLogout() {
        sendJson(JSONObject().put("type", "logout"))
    }

    fun disconnectOnly() {
        resetUdpState()
        wsOpen = false
        helloSocket = null
        ws?.close(1000, "bye")
        ws = null
    }

    fun login(useWss: Boolean, serverHost: String, serverPort: Int, username: String, password: String) {
        this.serverHost = serverHost
        loginUsername = username
        loginPassword = password

        val loginMsg = JSONObject().apply {
            put("type", "login")
            put("username", username)
        }

        // 已经连着（例如刚退出登录但没断连接）就直接复用这条连接登录，不再新开一条
        if (ws != null && wsOpen) {
            sendJson(loginMsg)
            return
        }

        val proto = if (useWss) "wss" else "ws"
        // serverHost 可能是裸 v6 字面量，拼 URL 要加方括号
        connect("$proto://${hostForUrl(serverHost)}:$serverPort/")
        sendJson(loginMsg)
    }

    private fun sendJson(obj: JSONObject) {
        listener?.onSend(obj.toString())
        ws?.send(obj.toString())
    }

    /** 读形如 {"ipv4":["1.2.3.4", ...]} 的字符串数组，顺便丢掉空串 */
    private fun JSONObject.optStringList(key: String): List<String> {
        val arr = optJSONArray(key) ?: return emptyList()
        val out = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.optString(i, "").trim()
            if (s.isNotEmpty()) out.add(s)
        }
        return out
    }

    // ---- Python-compatible crypto utils ----
    private fun sha256(data: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): String {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data).joinToString("") { "%02x".format(it) }
    }

    private fun hmacSha256Hex(key: ByteArray, data: ByteArray): String {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data).joinToString("") { "%02x".format(it) }
    }

    private fun hexDecode(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            result[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
        }
        return result
    }

    private fun binasciiHexlify(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val prkMac = javax.crypto.Mac.getInstance("HmacSHA256")
        prkMac.init(javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"))
        val prk = prkMac.doFinal(ikm)
        val n = 32 / 32
        var t = ByteArray(0)
        var okm = ByteArray(0)
        var i = 1
        while (okm.size < 32) {
            val input = t + info + byteArrayOf(i.toByte())
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
            t = mac.doFinal(input)
            okm += t
            i++
        }
        return okm.copyOf(32)
    }
}
