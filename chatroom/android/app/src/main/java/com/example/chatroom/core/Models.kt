package com.example.chatroom.core

import android.graphics.Color

/** 参与者类型 */
enum class ParticipantType(val icon: String) {
    /** 自测用的复读机，发什么回什么 */
    ECHO("🔁"),
    SERIAL("🔌"),
    PTY("🖥️"),
    SSH("🔐"),
    TELNET("📡"),
    SOCKET("🌐"),
    BBS("💬"),
    AI("🤖"),
    AGENT("🦞"),
    BLUETOOTH("📱"),
    INFRARED("💡"),
    SMART_DEVICE("🏠")
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
    val imageUri: String? = null,       // 图片消息（文件路径；预留给以后存盘版）
    val imageBytes: ByteArray? = null,  // 图片消息（内存版）。TODO: 后续加磁盘缓存后，优先读 cache file，bytes 只做 transient 过渡
    val timestamp: Long = System.currentTimeMillis(),
    val isInfo: Boolean = false         // true = 小灰字居中，不显示气泡
) {
    // data class 默认 equals/hashCode 会用 ByteArray 的引用比较导致 false negative，
    // 这里 override 让它按内容比较，避免 DiffUtil 误判同内容但不同实例的图片消息为不同。
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as Message
        if (id != other.id) return false
        if (senderId != other.senderId) return false
        if (senderType != other.senderType) return false
        if (senderName != other.senderName) return false
        if (content != other.content) return false
        if (style != other.style) return false
        if (imageUri != other.imageUri) return false
        if (imageBytes != null) {
            if (other.imageBytes == null) return false
            if (imageBytes.size != other.imageBytes.size) return false
            if (!imageBytes.contentEquals(other.imageBytes)) return false
        } else if (other.imageBytes != null) return false
        if (timestamp != other.timestamp) return false
        if (isInfo != other.isInfo) return false
        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + senderId.hashCode()
        result = 31 * result + senderType.hashCode()
        result = 31 * result + senderName.hashCode()
        result = 31 * result + content.hashCode()
        result = 31 * result + style.hashCode()
        result = 31 * result + (imageUri?.hashCode() ?: 0)
        result = 31 * result + (imageBytes?.contentHashCode() ?: 0)
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + isInfo.hashCode()
        return result
    }
}

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
