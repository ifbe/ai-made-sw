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

enum class SocketType { TCP, UDP }

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
    private val onMessage: (Message) -> Unit
) {
    // TCP
    private var socket: Socket? = null
    private var reader: BufferedReader? = null
    private var writer: OutputStreamWriter? = null
    private var readerThread: Thread? = null

    // UDP
    private var datagramSocket: DatagramSocket? = null
    private var udpThread: Thread? = null

    private var running = false

    val type: ParticipantType = ParticipantType.SOCKET
    val displayName: String = if (sockType == SocketType.UDP) "UDP" else "TCP"

    fun connect() {
        Thread({
            when (sockType) {
                SocketType.TCP -> connectTcp()
                SocketType.UDP -> connectUdp()
            }
        }, "SocketConnector").start()
    }

    private fun connectTcp() {
        try {
            mainHandler.post { postMessage("🔗 TCP 正在连接 $ip:$port...", true) }
            socket = Socket(ip, port)
            socket!!.soTimeout = 0
            reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))
            writer = OutputStreamWriter(socket!!.getOutputStream())
            writer!!.flush()

            running = true
            mainHandler.post { postMessage("🔗 TCP 已连接 $ip:$port", true) }
            readerThread = Thread({ readLoopTcp() }, "TcpReader")
            readerThread!!.start()
        } catch (e: Exception) {
            val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            mainHandler.post { postMessage("❌ TCP 连接失败: $detail", true) }
        }
    }

    private fun connectUdp() {
        try {
            mainHandler.post { postMessage("📡 UDP 正在连接 $ip:$port...", true) }
            datagramSocket = DatagramSocket()  // 绑定到随机可用端口
            val localPort = datagramSocket!!.localPort
            running = true
            mainHandler.post { postMessage("📡 UDP 已绑定 本地端口=$localPort（让对方发到这个端口）远端=$ip:$port", true) }
            udpThread = Thread({ readLoopUdp() }, "UdpReader")
            udpThread!!.start()
        } catch (e: Exception) {
            val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            mainHandler.post { postMessage("❌ UDP 连接失败: $detail", true) }
        }
    }

    private fun readLoopTcp() {
        try {
            val buffer = CharArray(4096)
            while (running) {
                val n = reader!!.read(buffer)
                if (n <= 0) {
                    if (running) postMessage("⚠️ TCP 连接已断开", true)
                    break
                }
                val text = String(buffer, 0, n)
                dispatchLine(text)
            }
        } catch (e: Exception) {
            if (running) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                postMessage("⚠️ TCP 读取异常: $detail", true)
            }
        }

        running = false
    }

    private fun readLoopUdp() {
        val buffer = ByteArray(4096)

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
                }
                break
            }
        }

        running = false
    }

    fun sendInput(text: String) {
        Thread({
            try {
                when (sockType) {
                    SocketType.TCP -> sendTcp(text)
                    SocketType.UDP -> sendUdp(text)
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
