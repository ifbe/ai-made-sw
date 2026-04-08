package com.example.p2pnet.data.remote

import android.os.Handler
import android.os.Looper
import com.example.p2pnet.data.local.LocalPrefs
import okhttp3.*
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class WsClient(
    private val localPrefs: LocalPrefs? = null
) {
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
    }

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
        .build()

    private var ws: WebSocket? = null
    var listener: Listener? = null
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
                listener?.onConnected()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                listener?.onError(t.message ?: "connection failed")
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
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
                    stopFlag.set(true)
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
        // 捕获当前 mode（sendP2pUdp 或 sendWghelp 设置的），hello 线程结束时用它决定路由
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
            val ipv4Addr = Inet4Address.getByName("0.0.0.0")
            sock = DatagramSocket(null as java.net.InetSocketAddress?)
            sock.bind(java.net.InetSocketAddress(ipv4Addr, 0))
            listener?.onUdpSend("UDP hello socket 绑定类型=${sock.localAddress.javaClass.name} 本地端口=${sock.localPort} 目标=$serverIp:$serverUdpPort")
            val localPort = sock.localPort
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

    fun sendP2pUdp(target: String) {
        _helloMode = "udp"
        sendJson(JSONObject().put("type", "p2pudp").put("target", target))
    }

    fun sendP2pTcp(target: String) {
        sendJson(JSONObject().put("type", "p2ptcp").put("target", target))
    }

    fun sendWghelp(target: String) {
        _helloMode = "wg"
        sendJson(JSONObject().put("type", "wghelp").put("target", target))
    }

    fun sendList() {
        sendJson(JSONObject().put("type", "list"))
    }

    fun disconnectOnly() {
        resetUdpState()
        ws?.close(1000, "bye")
        ws = null
    }

    fun login(useWss: Boolean, serverHost: String, serverPort: Int, username: String, password: String) {
        val proto = if (useWss) "wss" else "ws"
        connect("$proto://$serverHost:$serverPort/")
        this.serverHost = serverHost
        loginUsername = username
        loginPassword = password
        sendJson(JSONObject().apply {
            put("type", "login")
            put("username", username)
        })
    }

    private fun sendJson(obj: JSONObject) {
        listener?.onSend(obj.toString())
        ws?.send(obj.toString())
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
