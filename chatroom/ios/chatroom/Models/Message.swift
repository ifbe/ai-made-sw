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
    /// 内存版图片数据。TODO: 后续加磁盘缓存后，优先读 cache file，本字段仅做 transient 过渡
    let imageBytes: Data?
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
        imageBytes: Data? = nil,
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
        self.imageBytes = imageBytes
        self.timestamp = timestamp
        self.isInfo = isInfo
    }

    static func == (lhs: Message, rhs: Message) -> Bool {
        lhs.id == rhs.id
    }
}

/// 输入模式（顺序与 Android ChatFragment.kt 保持一致）
enum ChatInputMode: Int, CaseIterable, Identifiable {
    case empty = 0
    case text = 1
    case remote = 2
    case dim3 = 3
    case voice = 4
    case file = 5

    var id: Int { rawValue }

    /// spinner / 菜单里的 emoji
    var icon: String {
        switch self {
        case .empty: return "⬜"
        case .text: return "📝"
        case .remote: return "🎮"
        case .dim3: return "📐"
        case .voice: return "🎤"
        case .file: return "📁"
        }
    }

    /// emoji 后跟的 2 字 label（统一 2 字显示：⬜空白 / 📝文字 / 🎮遥控 / 📐三维 / 🎤语音 / 📁文件）
    var label: String {
        switch self {
        case .empty: return "空白"
        case .text: return "文字"
        case .remote: return "遥控"
        case .dim3: return "三维"
        case .voice: return "语音"
        case .file: return "文件"
        }
    }

    /// 菜单触发器的全显示 = icon + label
    var displayName: String {
        "\(icon)\(label)"
    }
}
