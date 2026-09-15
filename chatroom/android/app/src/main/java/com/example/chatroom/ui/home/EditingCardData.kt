package com.example.chatroom.ui.home

import com.example.chatroom.core.ParticipantConfig
import com.example.chatroom.core.ParticipantType

/**
 * 菜单页里「二级卡片」的表单数据。
 *
 * 两种存在形态：
 * - **草稿参与者**（`sessionId == null`）：还没保存到任何会话，值只在内存里，等卡片上的「创建」按钮落盘
 * - **已保存参与者**（`sessionId != null`）：对应 `SessionManager` 里某个 [ParticipantConfig]，
 *   表单任何改动都即时回写（`id` 就是 config 的 id，所以能精确定位）
 */
data class EditingCardData(
    val id: String = java.util.UUID.randomUUID().toString(),
    /** 非空 = 已保存到该会话（编辑即改即存）；null = 草稿 */
    var sessionId: String? = null,
    var type: ParticipantType = ParticipantType.SOCKET,
    var name: String = "",
    var params: String = "",
    var socketIp: String = "",
    var socketPort: String = "",
    var socketPath: String = "/",
    var sockType: String = "TCP",
    var ptyDevice: String = "/dev/ptmx",
    var ptyShell: String = "/system/bin/sh",
    var serialDevice: String = "/dev/ttyS0",
    var serialBaud: String = "115200",
    var sshIp: String = "",
    var sshPort: String = "22",
    var sshUser: String = "",
    var sshPassword: String = "",
    var telnetIp: String = "",
    var telnetPort: String = "23",
    var telnetUser: String = "",
    var telnetPassword: String = "",
    var aiIp: String = "",
    var aiPort: String = "",
    var aiApiKey: String = "",
    var aiModel: String = "",
    /** "text"（默认，OpenAI chat completions）/ "stt"（OpenAI audio transcriptions） / "tts"（OpenAI audio speech） */
    var aiSubType: String = "text",
    /** TTS 专用的 voice 字段，仅 subType=tts 时使用，默认 "alloy" */
    var aiVoice: String = "alloy",
    /** "openclaw"（默认）/ "codex" / "claude" / "gemini" / "copilot" */
    var agentSubType: String = "openclaw",
    var agentAddr: String = "",
    var agentPort: String = "",
    var agentUsername: String = "",
    var agentPassword: String = "",
    /** ECHO 专用：延迟秒数（默认 0.5，可输入浮点） */
    var echoDelay: Float = 0.5f,
    var bluetoothDevice: String = "",
    var bluetoothProtocol: String = "SPP"
)

/** 表单 → `ParticipantConfig` 的参数映射（原来散在已删除的 HomeFragment.btnCreate 里） */
fun EditingCardData.toConfig(): ParticipantConfig = ParticipantConfig(
    // id 保持不变：已保存的参与者靠它做「编辑即改即存」的精确定位
    id = id,
    type = type,
    name = name.ifBlank { type.name },
    params = toParams()
)

fun EditingCardData.toParams(): Map<String, String> = when (type) {
    ParticipantType.SOCKET -> mutableMapOf<String, String>().apply {
        if (socketIp.isNotBlank()) put("ip", socketIp)
        if (socketPort.isNotBlank()) put("port", socketPort)
        if (socketPath.isNotBlank()) put("path", socketPath)
        if (sockType.isNotBlank()) put("sockType", sockType)
    }
    ParticipantType.PTY -> mutableMapOf<String, String>().apply {
        if (ptyDevice.isNotBlank()) put("device", ptyDevice)
        if (ptyShell.isNotBlank()) put("shell", ptyShell)
    }
    ParticipantType.SERIAL ->
        if (serialDevice.isNotBlank() && serialBaud.isNotBlank()) {
            mapOf("device" to serialDevice, "baud" to serialBaud)
        } else emptyMap()
    ParticipantType.SSH -> mutableMapOf<String, String>().apply {
        if (sshIp.isNotBlank()) put("ip", sshIp)
        if (sshPort.isNotBlank()) put("port", sshPort)
        if (sshUser.isNotBlank()) put("user", sshUser)
        if (sshPassword.isNotBlank()) put("password", sshPassword)
    }
    ParticipantType.TELNET -> mutableMapOf<String, String>().apply {
        if (telnetIp.isNotBlank()) put("ip", telnetIp)
        if (telnetPort.isNotBlank()) put("port", telnetPort)
        if (telnetUser.isNotBlank()) put("user", telnetUser)
        if (telnetPassword.isNotBlank()) put("password", telnetPassword)
    }
    ParticipantType.AI -> mutableMapOf<String, String>().apply {
        if (aiIp.isNotBlank()) put("ip", aiIp)
        if (aiPort.isNotBlank()) put("port", aiPort)
        if (aiApiKey.isNotBlank()) put("apiKey", aiApiKey)
        if (aiModel.isNotBlank()) put("model", aiModel)
        // subType 为默认值 "text" 时不写入（保持与旧 config 兼容）
        if (aiSubType.isNotBlank() && aiSubType != "text") put("subType", aiSubType)
        // voice 仅在 tts 子类型且非默认值时写入（不写默认 "alloy" 避免冗余）
        if (aiSubType == "tts" && aiVoice.isNotBlank() && aiVoice != "alloy") put("voice", aiVoice)
    }
    ParticipantType.AGENT -> mutableMapOf<String, String>().apply {
        if (agentAddr.isNotBlank()) put("addr", agentAddr)
        if (agentPort.isNotBlank()) put("port", agentPort)
        if (agentUsername.isNotBlank()) put("username", agentUsername)
        if (agentPassword.isNotBlank()) put("password", agentPassword)
        // subType 为默认值 "openclaw" 时不写入
        if (agentSubType.isNotBlank() && agentSubType != "openclaw") put("subType", agentSubType)
    }
    ParticipantType.BLUETOOTH -> mutableMapOf<String, String>().apply {
        if (bluetoothDevice.isNotBlank()) put("device", bluetoothDevice)
        if (bluetoothProtocol.isNotBlank()) put("protocol", bluetoothProtocol)
    }
    ParticipantType.ECHO -> mutableMapOf<String, String>().apply {
        // 仅在用户改过默认 0.5 才写入，保持 params 简洁
        if (echoDelay != 0.5f && echoDelay >= 0f) put("delay", echoDelay.toString())
    }
    else -> parseParams(params)
}

/** 已保存的 config → 表单（菜单页把已有参与者渲染成可编辑表单） */
fun editingCardFromConfig(config: ParticipantConfig, sessionId: String): EditingCardData {
    val p = config.params
    return EditingCardData(
        id = config.id,
        sessionId = sessionId,
        type = config.type,
        name = if (config.name == config.type.name) "" else config.name,
        socketIp = p["ip"].orEmpty(),
        socketPort = p["port"].orEmpty(),
        socketPath = p["path"] ?: "/",
        sockType = p["sockType"] ?: "TCP",
        ptyDevice = p["device"] ?: "/dev/ptmx",
        ptyShell = p["shell"] ?: "/system/bin/sh",
        serialDevice = if (config.type == ParticipantType.SERIAL) p["device"].orEmpty() else "/dev/ttyS0",
        serialBaud = if (config.type == ParticipantType.SERIAL) p["baud"].orEmpty() else "115200",
        sshIp = if (config.type == ParticipantType.SSH) p["ip"].orEmpty() else "",
        sshPort = if (config.type == ParticipantType.SSH) p["port"].orEmpty() else "22",
        sshUser = if (config.type == ParticipantType.SSH) p["user"].orEmpty() else "",
        sshPassword = if (config.type == ParticipantType.SSH) p["password"].orEmpty() else "",
        telnetIp = if (config.type == ParticipantType.TELNET) p["ip"].orEmpty() else "",
        telnetPort = if (config.type == ParticipantType.TELNET) p["port"].orEmpty() else "23",
        telnetUser = if (config.type == ParticipantType.TELNET) p["user"].orEmpty() else "",
        telnetPassword = if (config.type == ParticipantType.TELNET) p["password"].orEmpty() else "",
        aiIp = if (config.type == ParticipantType.AI) p["ip"].orEmpty() else "",
        aiPort = if (config.type == ParticipantType.AI) p["port"].orEmpty() else "",
        aiApiKey = if (config.type == ParticipantType.AI) p["apiKey"].orEmpty() else "",
        aiModel = if (config.type == ParticipantType.AI) p["model"].orEmpty() else "",
        aiSubType = if (config.type == ParticipantType.AI) (p["subType"] ?: "text") else "text",
        aiVoice = p["voice"] ?: "alloy",
        agentSubType = if (config.type == ParticipantType.AGENT) (p["subType"] ?: "openclaw") else "openclaw",
        agentAddr = if (config.type == ParticipantType.AGENT) p["addr"].orEmpty() else "",
        agentPort = if (config.type == ParticipantType.AGENT) p["port"].orEmpty() else "",
        agentUsername = if (config.type == ParticipantType.AGENT) p["username"].orEmpty() else "",
        agentPassword = if (config.type == ParticipantType.AGENT) p["password"].orEmpty() else "",
        echoDelay = p["delay"]?.toFloatOrNull() ?: 0.5f,
        bluetoothDevice = if (config.type == ParticipantType.BLUETOOTH) p["device"].orEmpty() else "",
        bluetoothProtocol = if (config.type == ParticipantType.BLUETOOTH) (p["protocol"] ?: "SPP") else "SPP"
    )
}

private fun parseParams(raw: String): Map<String, String> {
    if (raw.isBlank()) return emptyMap()
    return raw.split(" ").mapNotNull {
        val parts = it.split(":")
        if (parts.isEmpty()) null else parts[0] to (parts.getOrNull(1) ?: "")
    }.toMap()
}
