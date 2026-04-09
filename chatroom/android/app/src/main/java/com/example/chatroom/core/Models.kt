package com.example.chatroom.core

import android.graphics.Color

/** 参与者类型 */
enum class ParticipantType(val icon: String) {
    PTY("🖥️"),
    SSH("🖥️"),
    AI("🤖"),
    SERIAL("🔌"),
    SMART_DEVICE("💡"),
    SOCKET("👤")
}

/** 样式（VT100 SGR） */
data class Vt100Style(
    val fgColor: Int = Color.BLACK,
    val bgColor: Int = Color.TRANSPARENT,
    val bold: Boolean = false,
    val underline: Boolean = false,
    val reverse: Boolean = false
)

/** 单条消息 */
data class Message(
    val id: String = java.util.UUID.randomUUID().toString(),
    val senderId: String,
    val senderType: ParticipantType,
    val senderName: String,
    val content: String,
    val style: Vt100Style = Vt100Style(),
    val imageUri: String? = null,   // 图片消息
    val timestamp: Long = System.currentTimeMillis(),
    val isInfo: Boolean = false    // true = 小灰字居中，不显示气泡
)

/** 参与者（尚未连接，只保存配置） */
data class ParticipantConfig(
    val id: String = java.util.UUID.randomUUID().toString(),
    val type: ParticipantType,
    val name: String,
    val params: Map<String, String> = emptyMap()
)

/** 输入模式 */
enum class InputMode {
    TEXT,
    FILE,
    CONTROL_PAD
}
