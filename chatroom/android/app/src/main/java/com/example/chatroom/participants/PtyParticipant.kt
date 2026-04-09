package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType
import com.example.chatroom.core.Vt100Style

/**
 * PTY participant using JNI /dev/ptmx.
 * Uses PtyNative.readPty() with select() for non-blocking read.
 * All output accumulated until EOF/empty → one message per command.
 */
class PtyParticipant(
    private val sessionId: String,
    private val onMessage: (Message) -> Unit
) {
    private var masterFd: Int = -1
    private var readerThread: Thread? = null
    private val pty = PtyNative()
    private var running = false

    val type: ParticipantType = ParticipantType.PTY
    val displayName: String = "PTY"

    fun connect(device: String = "/dev/ptmx", shell: String = "/system/bin/sh") {
        try {
            postMessage("🖥️ PTY 正在连接 device=$device shell=$shell...", true)
            masterFd = pty.createPty(device, shell)
            if (masterFd < 0) {
                postMessage("❌ PTY 连接失败: createPty returned $masterFd", true)
                return
            }
            running = true
            readerThread = Thread({ readLoop() }, "PtyReader")
            readerThread!!.start()
            postMessage("🖥️ PTY 已连接", true)
        } catch (e: Exception) {
            postMessage("❌ PTY 连接失败: ${e.message}", true)
        }
    }

    private fun readLoop() {
        val buffer = ByteArray(4096)
        val output = StringBuilder()

        while (running) {
            // select 300ms：超时返回0表示本批读完
            val n = pty.readPty(masterFd, buffer, 300)

            if (n < 0) {
                // 错误或EOF
                if (output.isNotEmpty()) {
                    dispatchLine(output.toString())
                    output.clear()
                }
                postMessage("⚠️ PTY 读取结束", true)
                break
            }

            if (n == 0) {
                // 本批读完，把累积的输出发出去
                if (output.isNotEmpty()) {
                    dispatchLine(output.toString())
                    output.clear()
                }
                Thread.sleep(50)
                continue
            }

            // 正常读取，追加到 buffer
            for (i in 0 until n) {
                val c = buffer[i].toInt().toChar()
                output.append(c)
            }
        }

        running = false
    }

    fun sendInput(text: String) {
        if (masterFd < 0) return
        try {
            pty.writePty(masterFd, "$text\n")
        } catch (e: Exception) {
            postMessage("❌ 发送失败: ${e.message}", true)
        }
    }

    fun disconnect() {
        running = false
        try {
            if (masterFd >= 0) {
                pty.closePty(masterFd)
                masterFd = -1
            }
        } catch (e: Exception) {
            // ignore
        }
    }

    private fun postMessage(content: String, isInfo: Boolean = false) {
        val msg = Message(
            senderId = "pty",
            senderType = ParticipantType.PTY,
            senderName = displayName,
            content = content,
            isInfo = isInfo
        )
        mainHandler.post { onMessage(msg) }
    }

    private fun dispatchLine(content: String) {
        val msg = Message(
            senderId = "pty",
            senderType = ParticipantType.PTY,
            senderName = displayName,
            content = content
        )
        mainHandler.post { onMessage(msg) }
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}
