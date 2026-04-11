package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import java.nio.charset.Charset

/**
 * Serial participant using JNI /dev/ttyS* with termios.
 */
class SerialParticipant(
    private val sessionId: String,
    private val device: String,
    private val baud: Int,
    private val onMessage: (Message) -> Unit
) {
    private var fd: Int = -1
    private var readerThread: Thread? = null
    private val serial = SerialNative()
    private var running = false

    val type: ParticipantType = ParticipantType.SERIAL
    val displayName: String = "SERIAL"

    fun connect() {
        Thread({
            try {
                mainHandler.post { postMessage("🔌 串口正在连接 $device @ $baud...", true) }
                fd = serial.openSerial(device, baud)
                if (fd < 0) {
                    mainHandler.post { postMessage("❌ 串口连接失败: openSerial returned $fd", true) }
                    return@Thread
                }
                running = true
                mainHandler.post { postMessage("🔌 串口已连接 $device @ $baud", true) }
                readerThread = Thread({ readLoop() }, "SerialReader")
                readerThread!!.start()
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ 串口连接失败: $detail", true) }
            }
        }, "SerialConnector").start()
    }

    private fun readLoop() {
        val buffer = ByteArray(4096)
        val lineBuilder = StringBuilder()

        while (running) {
            val n = serial.readSerial(fd, buffer, 300)

            if (n < 0) {
                if (running) {
                    mainHandler.post { postMessage("⚠️ 串口读取错误（n=$n）", true) }
                }
                break
            }

            if (n == 0) {
                if (lineBuilder.isNotEmpty()) {
                    val out = lineBuilder.toString().trimEnd()
                    if (out.isNotEmpty()) dispatchLine(out)
                    lineBuilder.clear()
                }
                Thread.sleep(50)
                continue
            }

            // 用 UTF-8 解码后按行处理
            val text = String(buffer, 0, n, Charset.forName("UTF-8"))
            for (c in text) {
                when (c) {
                    '\n' -> {
                        val line = lineBuilder.toString()
                        lineBuilder.clear()
                        if (line.isNotEmpty()) dispatchLine(line)
                    }
                    '\r' -> {
                        // ignore CR, NL will dispatch
                    }
                    else -> lineBuilder.append(c)
                }
            }
        }

        running = false
    }

    fun sendInput(text: String) {
        if (fd < 0) {
            mainHandler.post { postMessage("❌ 串口未连接", true) }
            return
        }
        Thread({
            try {
                serial.writeSerial(fd, text)
                serial.writeSerial(fd, "\n")
            } catch (e: Exception) {
                val detail = "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                mainHandler.post { postMessage("❌ 发送失败: $detail", true) }
            }
        }, "SerialSender").start()
    }

    fun disconnect() {
        running = false
        try {
            readerThread?.interrupt()
            if (fd >= 0) {
                serial.closeSerial(fd)
                fd = -1
            }
        } catch (e: Exception) {
            // ignore
        }
    }

    private fun postMessage(content: String, isInfo: Boolean = false) {
        val msg = Message(
            senderId = "serial",
            senderType = ParticipantType.SERIAL,
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
            senderId = "serial",
            senderType = ParticipantType.SERIAL,
            senderName = displayName,
            content = "📥 接收 len=$len hex=$hex",
            isInfo = true
        )
        val msg = Message(
            senderId = "serial",
            senderType = ParticipantType.SERIAL,
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
