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
