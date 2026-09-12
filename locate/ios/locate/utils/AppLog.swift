import Foundation
import Combine

/// 应用内日志缓冲（对应 Android 的 AppLog）。
///
/// 只记录「本程序自己想在界面上告诉用户」的消息，不是系统日志的镜像。
/// 由地图页左下角的日志矩形渲染；缓冲区是进程级的单例，所以准备页写的日志
/// 进地图页也能看到。
final class AppLog: ObservableObject {

    enum Level {
        case info, warn, error
    }

    struct Entry: Identifiable {
        let id = UUID()
        let time: String
        let level: Level
        let text: String
    }

    static let shared = AppLog()

    private static let maxEntries = 200

    /// 日志矩形的展开状态和用户拖出来的尺寸。放在单例里，视图重建/旋转后保持原样。
    @Published var panelExpanded = false
    @Published var panelRows = 10
    @Published var panelWidth: CGFloat = 0   // 0 = 用默认宽度

    @Published private(set) var entries: [Entry] = []

    private let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    private init() {}

    // MARK: - 写入

    static func i(_ text: String) { shared.append(.info, text) }
    static func w(_ text: String) { shared.append(.warn, text) }
    static func e(_ text: String) { shared.append(.error, text) }

    static func clear() {
        DispatchQueue.main.async {
            shared.entries.removeAll()
        }
    }

    private func append(_ level: Level, _ text: String) {
        // 同时打到 Xcode 控制台，方便排查；界面只显示应用自己写的消息
        print("[AppLog] \(text)")

        // 调用方可能来自任意线程（CoreLocation / URLSession），统一回到主线程再改 @Published
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let time = self.timeFormatter.string(from: Date())
            self.entries.append(Entry(time: time, level: level, text: text))
            if self.entries.count > AppLog.maxEntries {
                self.entries.removeFirst(self.entries.count - AppLog.maxEntries)
            }
        }
    }
}
