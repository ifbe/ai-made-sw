package com.example.chatroom.participants

import android.os.Handler
import android.os.Looper
import com.example.chatroom.core.Message
import com.example.chatroom.core.ParticipantType

/**
 * Bluetooth participant stub.
 * Full implementation TBD.
 */
class BluetoothParticipant(
    private val sessionId: String,
    private val deviceName: String,
    private val protocol: String, // "SPP" or "RFCOMM"
    private val onMessage: (Message) -> Unit
) {
    val type: ParticipantType = ParticipantType.BLUETOOTH
    val displayName: String = deviceName.ifBlank { "BLUETOOTH" }

    fun connect() {
        mainHandler.post {
            onMessage(Message(
                senderId = "bluetooth",
                senderType = ParticipantType.BLUETOOTH,
                senderName = displayName,
                content = "📱 BLUETOOTH 暂未实现 ($protocol)",
                isInfo = true
            ))
        }
    }

    fun sendInput(text: String) {
        // TBD
    }

    fun disconnect() {
        // TBD
    }

    companion object {
        private val mainHandler = Handler(Looper.getMainLooper())
    }
}
