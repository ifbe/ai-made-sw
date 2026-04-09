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
 * TCP participant: connects to (ip, port) as a TCP client.
 * Treats nc -l ip port on the other end as the server.
 */
class TcpParticipant(
    private val sessionId: String,
    private val ip: String,
    private val port: Int,
    private val onMessage: (Message) -> Unit
) {
    private var socket: Socket? = null
    private var reader: BufferedReader? = null
    private var writer: OutputStreamWriter? = null
    private var readerThread: Thread? = null
    private var running = false

    val type: ParticipantType = ParticipantType.HUMAN
    val displayName: String = "HUMAN"

    fun connect() {
        Thread({
            try {
                mainHandler.post { postMessage("🔗 TCP 正在连接 $ip:$port...", true) }
                socket = Socket(ip, port)
                socket!!.soTimeout = 0
                reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))
                writer = OutputStreamWriter(socket!!.getOutputStream())
                writer!!.flush()

                running = true
                mainHandler.post { postMessage("🔗 TCP 已连接 $ip:$port", true) }
                readerThread = Thread({ readLoop() }, "TcpReader")
                readerThread!!.start()
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ TCP 连接失败: $detail", true) }
            }
        }, "TcpConnector").start()
    }

    private fun readLoop() {
        try {
            val buffer = CharArray(4096)
            val lineBuilder = StringBuilder()

            while (running) {
                val c = reader!!.read().toChar()
                lineBuilder.append(c)

                if (c == '\n') {
                    val line = lineBuilder.toString()
                    lineBuilder.clear()
                    if (line.isNotEmpty()) {
                        dispatchLine(line.trimEnd())
                    }
                }
            }
        } catch (e: Exception) {
            if (running) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                postMessage("⚠️ TCP 读取异常: $detail", true)
            }
        }

        postMessage("⚠️ TCP 连接已断开", true)
        running = false
    }

    fun sendInput(text: String) {
        if (writer == null) {
            postMessage("❌ TCP 未连接", true)
            return
        }
        Thread({
            try {
                writer!!.write(text)
                writer!!.write("\n")
                writer!!.flush()
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ 发送失败: $detail", true) }
            }
        }, "TcpSender").start()
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
            senderId = "tcp",
            senderType = ParticipantType.HUMAN,
            senderName = displayName,
            content = content,
            isInfo = isInfo
        )
        mainHandler.post { onMessage(msg) }
    }

    private fun dispatchLine(line: String) {
        val msg = Message(
            senderId = "tcp",
            senderType = ParticipantType.HUMAN,
            senderName = displayName,
            content = line
        )
        mainHandler.post { onMessage(msg) }
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}
