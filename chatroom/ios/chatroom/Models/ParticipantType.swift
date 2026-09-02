import Foundation

/// 参与者类型
enum ParticipantType: String, CaseIterable, Identifiable {
    /// 自测用的复读机，发什么回什么
    case echo = "ECHO"
    case serial = "SERIAL"
    case pty = "PTY"
    case ssh = "SSH"
    case telnet = "TELNET"
    case socket = "SOCKET"
    case bbs = "BBS"
    case ai = "AI"
    case agent = "AGENT"
    case bluetooth = "BLUETOOTH"
    case infrared = "INFRARED"
    case smartDevice = "SMART_DEVICE"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .echo: return "🔁"
        case .serial: return "🔌"
        case .pty: return "🖥️"
        case .ssh: return "🔐"
        case .telnet: return "📡"
        case .socket: return "🌐"
        case .bbs: return "💬"
        case .ai: return "🤖"
        case .agent: return "🦞"
        case .bluetooth: return "📱"
        case .infrared: return "💡"
        case .smartDevice: return "🏠"
        }
    }

    var displayName: String {
        switch self {
        case .echo: return "ECHO"
        case .serial: return "SERIAL"
        case .pty: return "PTY"
        case .ssh: return "SSH"
        case .telnet: return "TELNET"
        case .socket: return "SOCKET"
        case .bbs: return "BBS"
        case .ai: return "AI"
        case .agent: return "AGENT"
        case .bluetooth: return "BLUETOOTH"
        case .infrared: return "INFRARED"
        case .smartDevice: return "SMART_DEVICE"
        }
    }

    /// UI 上可选的类型列表（保留 selectableCases 名字让 HomeView 不动；之前过滤掉了 .user，现 .user 已删，直接返回全枚举）
    static var selectableCases: [ParticipantType] {
        allCases
    }
}