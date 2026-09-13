package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

enum class SocketType { TCP, UDP, WS }

/**
 * Socket participant: TCP or UDP client.
 * sockType = TCP -> connects to (ip, port) as TCP client (nc style)
 * sockType = UDP -> sends/receives datagrams to (ip, port)
 */
class SocketParticipant(
    private val sessionId: String,
    private val ip: String,
    private val port: Int,
    private val sockType: SocketType,
    private val onMessage: (Message) -> Unit,
    /** 链路状态变化：true=连上了 / false=连接失败或断开。service 用它维护会话的 tab 状态 */
    private val onStateChange: ((Boolean) -> Unit)? = null
) {
    // TCP
    private var socket: Socket? = null
    private var reader: BufferedReader? = null
    private var writer: OutputStreamWriter? = null
    private var readerThread: Thread? = null

    // UDP
    private var datagramSocket: DatagramSocket? = null
    private var udpThread: Thread? = null

    // disconnect() 由别的线程改它、读循环线程读它 → 加 @Volatile 保证可见性，
    // 否则主动断开会被误判成「异常掉线」并回调 onStateChange(false)
    @Volatile
    private var running = false

    val type: ParticipantType = ParticipantType.SOCKET
    val displayName: String = if (sockType == SocketType.UDP) "UDP" else "TCP"

    fun connect() {
        Thread({
            when (sockType) {
                SocketType.TCP -> connectTcp()
                SocketType.UDP -> connectUdp()
                SocketType.WS -> { /* WS 走 WsParticipant，不会到这里 */ }
            }
        }, "SocketConnector").start()
    }

    private fun connectTcp() {
        try {
            mainHandler.post { postMessage("🔗 TCP 正在连接 $ip:$port...", true) }
            socket = Socket(ip, port).apply {
                soTimeout = 0
                keepAlive = true       // OS 层 keepalive，零污染（不发任何数据，靠 OS 探针）
                tcpNoDelay = true      // 关 Nagle
            }
            reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))
            writer = OutputStreamWriter(socket!!.getOutputStream())
            writer!!.flush()

            running = true
            mainHandler.post { postMessage("🔗 TCP 已连接 $ip:$port", true) }
            onStateChange?.invoke(true)
            readerThread = Thread({ readLoopTcp() }, "TcpReader")
            readerThread!!.start()
        } catch (e: Exception) {
            val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            mainHandler.post { postMessage("❌ TCP 连接失败: $detail", true) }
            onStateChange?.invoke(false)
        }
    }

    private fun connectUdp() {
        try {
            mainHandler.post { postMessage("📡 UDP 正在连接 $ip:$port...", true) }
            datagramSocket = DatagramSocket()  // 绑定到随机可用端口
            val localPort = datagramSocket!!.localPort
            running = true
            mainHandler.post { postMessage("📡 UDP 已绑定 本地端口=$localPort（让对方发到这个端口）远端=$ip:$port", true) }
            onStateChange?.invoke(true)
            udpThread = Thread({ readLoopUdp() }, "UdpReader")
            udpThread!!.start()
        } catch (e: Exception) {
            val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            mainHandler.post { postMessage("❌ UDP 连接失败: $detail", true) }
            onStateChange?.invoke(false)
        }
    }

    private fun readLoopTcp() {
        // abnormal = 非我方主动 disconnect 导致的结束（对端关了 / 读异常）→ 才算链路掉线。
        // 主动 disconnect（重连 / 关会话）时 running 已被置 false，不上报 false，
        // 避免老实例的迟到回调把刚建好的新连接标成断开。
        var abnormal = false
        try {
            val buffer = CharArray(4096)
            while (running) {
                val n = reader!!.read(buffer)
                if (n <= 0) {
                    if (running) {
                        postMessage("⚠️ TCP 连接已断开", true)
                        abnormal = true
                    }
                    break
                }
                val text = String(buffer, 0, n)
                dispatchLine(text)
            }
        } catch (e: Exception) {
            if (running) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                postMessage("⚠️ TCP 读取异常: $detail", true)
                abnormal = true
            }
        }

        running = false
        if (abnormal) onStateChange?.invoke(false)
    }

    private fun readLoopUdp() {
        val buffer = ByteArray(4096)
        var abnormal = false

        while (running) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                datagramSocket!!.soTimeout = 1000  // 1秒超时
                datagramSocket!!.receive(packet)
                val senderIp = packet.address?.hostAddress ?: "?"
                val senderPort = packet.port
                val received = String(packet.data, 0, packet.length)
                mainHandler.post { postMessage("📥 UDP 收到 from $senderIp:$senderPort", true) }
                dispatchLine(received)
            } catch (e: java.net.SocketTimeoutException) {
                if (!running) break
            } catch (e: Exception) {
                if (running) {
                    val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                    mainHandler.post { postMessage("⚠️ UDP 读取异常: $detail", true) }
                    abnormal = true
                }
                break
            }
        }

        running = false
        if (abnormal) onStateChange?.invoke(false)
    }

    fun sendInput(text: String) {
        Thread({
            try {
                when (sockType) {
                    SocketType.TCP -> sendTcp(text)
                    SocketType.UDP -> sendUdp(text)
                    SocketType.WS -> { /* WS 走 WsParticipant，不会到这里 */ }
                }
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ 发送失败: $detail", true) }
            }
        }, "SocketSender").start()
    }

    private fun sendTcp(text: String) {
        if (writer == null) {
            mainHandler.post { postMessage("❌ TCP 未连接", true) }
            return
        }
        writer!!.write(text)
        writer!!.write("\n")
        writer!!.flush()
    }

    private fun sendUdp(text: String) {
        if (datagramSocket == null) {
            mainHandler.post { postMessage("❌ UDP 未连接", true) }
            return
        }
        val bytes = (text + "\n").toByteArray()
        val packet = DatagramPacket(bytes, bytes.size, InetAddress.getByName(ip), port)
        datagramSocket!!.send(packet)
    }

    fun disconnect() {
        running = false
        try {
            readerThread?.interrupt()
            udpThread?.interrupt()
            socket?.close()
            datagramSocket?.close()
            socket = null
            datagramSocket = null
            reader = null
            writer = null
        } catch (e: Exception) {
            // ignore
        }
    }

    private fun postMessage(content: String, isInfo: Boolean = false) {
        val msg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = content,
            isInfo = isInfo
        )
        mainHandler.post { onMessage(msg) }
    }

    private fun dispatchLine(content: String) {
        val bytes = content.toByteArray()
        val len = bytes.size
        val hex = bytes.take(8).joinToString(" ") { "%02X".format(it) }
        val infoMsg = Message(
            senderId = "socket",
            senderType = ParticipantType.SOCKET,
            senderName = displayName,
            content = "📥 接收 len=$len hex=$hex",
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

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}
