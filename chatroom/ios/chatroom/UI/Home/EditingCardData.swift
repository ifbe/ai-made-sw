import SwiftUI
import Combine

/// 首页编辑卡片数据
final class EditingCardData: ObservableObject, Identifiable {
    let id: String
    @Published var type: ParticipantType = .socket
    @Published var name: String = ""

    // SOCKET
    @Published var socketIp: String = ""
    @Published var socketPort: String = ""
    @Published var sockType: String = "TCP"
    @Published var socketPath: String = "/"  // 仅 WS 使用，path 原样透传（Android 端约定一致）

    // PTY
    @Published var ptyDevice: String = "/dev/ptmx"
    @Published var ptyShell: String = "/bin/bash"

    // SERIAL
    @Published var serialDevice: String = "/dev/ttyS0"
    @Published var serialBaud: String = "115200"

    // SSH
    @Published var sshIp: String = ""
    @Published var sshPort: String = "22"
    @Published var sshUser: String = ""
    @Published var sshPassword: String = ""

    // TELNET
    @Published var telnetIp: String = ""
    @Published var telnetPort: String = "23"
    @Published var telnetUser: String = ""
    @Published var telnetPassword: String = ""

    // AI
    @Published var aiIp: String = ""
    @Published var aiPort: String = ""
    @Published var aiApiKey: String = ""
    @Published var aiModel: String = ""
    /// "text"（默认，OpenAI chat completions）/ "stt"（OpenAI audio transcriptions）/ "tts"（OpenAI audio speech）
    @Published var aiSubType: String = "text"
    /// TTS 专用的 voice 字段，仅 subType=tts 时使用，默认 "alloy"
    @Published var aiVoice: String = "alloy"

    // ECHO
    /// ECHO 专用：延迟秒数（默认 0.5，可输入浮点）
    @Published var echoDelay: Float = 0.5

    // AGENT
    /// "openclaw"（默认）/ "codex" / "claude" / "gemini" / "copilot"
    @Published var agentSubType: String = "openclaw"
    @Published var agentAddr: String = ""
    @Published var agentPort: String = ""
    @Published var agentUsername: String = ""
    @Published var agentPassword: String = ""

    // BLUETOOTH
    @Published var bluetoothDevice: String = ""
    @Published var bluetoothProtocol: String = "SPP"

    // 通用 params
    var params: String = ""

    init(id: String = UUID().uuidString) {
        self.id = id
    }

    /// 转为 ParticipantConfig
    func toConfig() -> ParticipantConfig {
        let name = self.name.isEmpty ? type.displayName : self.name
        var paramsMap: [String: String] = [:]

        switch type {
        case .socket:
            if !socketIp.isEmpty { paramsMap["ip"] = socketIp }
            if !socketPort.isEmpty { paramsMap["port"] = socketPort }
            if !sockType.isEmpty { paramsMap["sockType"] = sockType }
            // path 仅 WS 才需要写入（TCP/UDP 不消费这个字段）
            if sockType == "WS" && !socketPath.isEmpty { paramsMap["path"] = socketPath }
        case .pty:
            if !ptyDevice.isEmpty { paramsMap["device"] = ptyDevice }
            if !ptyShell.isEmpty { paramsMap["shell"] = ptyShell }
        case .serial:
            if !serialDevice.isEmpty { paramsMap["device"] = serialDevice }
            if !serialBaud.isEmpty { paramsMap["baud"] = serialBaud }
        case .ssh:
            if !sshIp.isEmpty { paramsMap["ip"] = sshIp }
            if !sshPort.isEmpty { paramsMap["port"] = sshPort }
            if !sshUser.isEmpty { paramsMap["user"] = sshUser }
            if !sshPassword.isEmpty { paramsMap["password"] = sshPassword }
        case .telnet:
            if !telnetIp.isEmpty { paramsMap["ip"] = telnetIp }
            if !telnetPort.isEmpty { paramsMap["port"] = telnetPort }
            if !telnetUser.isEmpty { paramsMap["user"] = telnetUser }
            if !telnetPassword.isEmpty { paramsMap["password"] = telnetPassword }
        case .ai:
            if !aiIp.isEmpty { paramsMap["ip"] = aiIp }
            if !aiPort.isEmpty { paramsMap["port"] = aiPort }
            if !aiApiKey.isEmpty { paramsMap["apiKey"] = aiApiKey }
            if !aiModel.isEmpty { paramsMap["model"] = aiModel }
            // subType 为默认值 "text" 时不写入（保持与旧 config 兼容）
            if !aiSubType.isEmpty && aiSubType != "text" { paramsMap["subType"] = aiSubType }
            // voice 仅在 tts 子类型且非默认值时写入（不写默认 "alloy" 避免冗余）
            if aiSubType == "tts" && !aiVoice.isEmpty && aiVoice != "alloy" {
                paramsMap["voice"] = aiVoice
            }
        case .echo:
            // 仅在用户改过默认 0.5 才写入，保持 params 简洁
            if echoDelay != 0.5 && echoDelay >= 0 {
                paramsMap["delay"] = String(echoDelay)
            }
        case .agent:
            if !agentAddr.isEmpty { paramsMap["addr"] = agentAddr }
            if !agentPort.isEmpty { paramsMap["port"] = agentPort }
            if !agentUsername.isEmpty { paramsMap["username"] = agentUsername }
            if !agentPassword.isEmpty { paramsMap["password"] = agentPassword }
            // subType 为默认值 "openclaw" 时不写入
            if !agentSubType.isEmpty && agentSubType != "openclaw" { paramsMap["subType"] = agentSubType }
        case .bluetooth:
            if !bluetoothDevice.isEmpty { paramsMap["device"] = bluetoothDevice }
            if !bluetoothProtocol.isEmpty { paramsMap["protocol"] = bluetoothProtocol }
        default:
            if !params.isEmpty {
                let pairs: [(String, String)] = params.split(separator: " ").compactMap { pair in
                    let parts = pair.split(separator: ":")
                    guard parts.count >= 2 else { return nil }
                    return (String(parts[0]), String(parts[1]))
                }
                for (k, v) in pairs { paramsMap[k] = v }
            }
        }

        return ParticipantConfig(type: type, name: name, params: paramsMap)
    }
}
