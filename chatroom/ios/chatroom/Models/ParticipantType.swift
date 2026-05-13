import Foundation

/// 参与者类型
enum ParticipantType: String, CaseIterable, Identifiable {
    case serial = "SERIAL"
    case pty = "PTY"
    case ssh = "SSH"
    case telnet = "TELNET"
    case socket = "SOCKET"
    case bbs = "BBS"
    case ai = "AI"
    case openclaw = "OPENCLAW"
    case bluetooth = "BLUETOOTH"
    case infrared = "INFRARED"
    case smartDevice = "SMART_DEVICE"
    case user = "USER"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .serial: return "🔌"
        case .pty: return "🖥️"
        case .ssh: return "🔐"
        case .telnet: return "📡"
        case .socket: return "🌐"
        case .bbs: return "💬"
        case .ai: return "🤖"
        case .openclaw: return "🦞"
        case .bluetooth: return "📱"
        case .infrared: return "💡"
        case .smartDevice: return "🏠"
        case .user: return "👤"
        }
    }

    var displayName: String {
        switch self {
        case .serial: return "SERIAL"
        case .pty: return "PTY"
        case .ssh: return "SSH"
        case .telnet: return "TELNET"
        case .socket: return "SOCKET"
        case .bbs: return "BBS"
        case .ai: return "AI"
        case .openclaw: return "OPENCLAW"
        case .bluetooth: return "BLUETOOTH"
        case .infrared: return "INFRARED"
        case .smartDevice: return "SMART_DEVICE"
        case .user: return "USER"
        }
    }

    /// 不显示在类型选择列表的类型
    static var selectableCases: [ParticipantType] {
        allCases.filter { $0 != .user }
    }
}
