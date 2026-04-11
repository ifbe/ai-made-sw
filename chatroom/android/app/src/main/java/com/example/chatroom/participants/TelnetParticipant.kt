package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket

/**
 * Telnet participant: connects to ip:port, handles login prompt,
 * sends username and password automatically.
 */
class TelnetParticipant(
    private val sessionId: String,
    private val ip: String,
    private val port: Int,
    private val username: String,
    private val password: String,
    private val onMessage: (Message) -> Unit
) {
    private var socket: Socket? = null
    private var reader: BufferedReader? = null
    private var writer: OutputStreamWriter? = null
    private var readerThread: Thread? = null
    private var running = false

    val type: ParticipantType = ParticipantType.TELNET
    val displayName: String = "TELNET"

    fun connect() {
        Thread({
            try {
                mainHandler.post { postMessage("🔗 TELNET 正在连接 $ip:$port...", true) }
                socket = Socket(ip, port)
                socket!!.soTimeout = 0
                reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))
                writer = OutputStreamWriter(socket!!.getOutputStream())
                writer!!.flush()

                running = true
                mainHandler.post { postMessage("🔗 TELNET 已连接 $ip:$port，等待登录...", true) }
                readerThread = Thread({ readLoop() }, "TelnetReader")
                readerThread!!.start()
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ TELNET 连接失败: $detail", true) }
            }
        }, "TelnetConnector").start()
    }

    private fun readLoop() {
        try {
            val buffer = CharArray(4096)
            val prompt = StringBuilder()
            var stage = 0 // 0=wait login, 1=wait password, 2=connected

            while (running) {
                val n = reader!!.read(buffer)
                if (n <= 0) {
                    if (running) postMessage("⚠️ TELNET 连接已断开", true)
                    break
                }

                for (i in 0 until n) {
                    val c = buffer[i].toChar()
                    prompt.append(c)
                }

                // 读到换行就处理一行
                val lines = prompt.toString().split("\r\n", "\n")
                prompt.clear()
                val last = if (prompt.isNotEmpty()) prompt.toString() else lines.lastOrNull() ?: ""

                for (line in lines) {
                    if (line.isBlank()) continue

                    // 调试：打印原始行
                    dispatchLine(line)

                    // 自动登录
                    when (stage) {
                        0 -> {
                            // 等 login: 或 login 字样
                            if (line.contains("login:", ignoreCase = true)) {
                                mainHandler.post { postMessage("📤 发送用户名: $username", true) }
                                writer!!.write("$username\n")
                                writer!!.flush()
                                stage = 1
                            }
                        }
                        1 -> {
                            // 等 password: 字样
                            if (line.contains("password:", ignoreCase = true)) {
                                mainHandler.post { postMessage("📤 发送密码: ****", true) }
                                writer!!.write("$password\n")
                                writer!!.flush()
                                stage = 2
                                mainHandler.post { postMessage("🔗 TELNET 登录完成", true) }
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            if (running) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("⚠️ TELNET 读取异常: $detail", true) }
            }
        }

        running = false
    }

    fun sendInput(text: String) {
        Thread({
            try {
                writer!!.write(text)
                writer!!.write("\n")
                writer!!.flush()
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ 发送失败: $detail", true) }
            }
        }, "TelnetSender").start()
    }

    fun disconnect() {
        running = false
        try {
            readerThread?.interrupt()
            socket?.close()
            socket = null
            reader = null
            writer = null
        } catch (e: Exception) {
            // ignore
        }
    }

    private fun postMessage(content: String, isInfo: Boolean = false) {
        val msg = Message(
            senderId = "telnet",
            senderType = ParticipantType.TELNET,
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
            senderId = "telnet",
            senderType = ParticipantType.TELNET,
            senderName = displayName,
            content = "📥 接收 len=$len hex=$hex",
            isInfo = true
        )
        val msg = Message(
            senderId = "telnet",
            senderType = ParticipantType.TELNET,
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
