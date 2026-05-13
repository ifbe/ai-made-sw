import Foundation

/// 单条消息
struct Message: Identifiable, Equatable {
    let id: String
    let senderId: String
    let senderType: ParticipantType
    let senderName: String
    let content: String
    let style: Vt100Style
    let imageUri: String?
    let timestamp: TimeInterval
    let isInfo: Bool

    init(
        id: String = UUID().uuidString,
        senderId: String,
        senderType: ParticipantType,
        senderName: String,
        content: String,
        style: Vt100Style = Vt100Style(),
        imageUri: String? = nil,
        timestamp: TimeInterval = Date().timeIntervalSince1970,
        isInfo: Bool = false
    ) {
        self.id = id
        self.senderId = senderId
        self.senderType = senderType
        self.senderName = senderName
        self.content = content
        self.style = style
        self.imageUri = imageUri
        self.timestamp = timestamp
        self.isInfo = isInfo
    }

    static func == (lhs: Message, rhs: Message) -> Bool {
        lhs.id == rhs.id
    }
}

/// 输入模式
enum ChatInputMode: Int, CaseIterable, Identifiable {
    case text = 0
    case remote = 1
    case dim3 = 2
    case voice = 3
    case file = 4

    var id: Int { rawValue }

    var icon: String {
        switch self {
        case .text: return "📝"
        case .remote: return "🎮"
        case .dim3: return "📐"
        case .voice: return "🎤"
        case .file: return "📁"
        }
    }

    var label: String {
        switch self {
        case .text: return "文字"
        case .remote: return "遥控"
        case .dim3: return "三维"
        case .voice: return "语音"
        case .file: return "文件"
        }
    }

    var displayName: String {
        "\(icon)\(label)"
    }
}
