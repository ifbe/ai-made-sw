import Foundation

/// 落盘用的会话快照。
///
/// **连接状态不存**——进程重启后连接必然已经断了，恢复出来一律按「未连接」处理，
/// 等用户点 `ⓘ` 展开重连面板手动重连。
struct PersistedSession {
    let id: String
    let createdAt: Int64
    let participants: [ParticipantConfig]
}

/// 会话持久化（对应 Android `SessionStore`，底层用原子写文件代替 SharedPreferences）。
///
/// 解决的问题：`SessionManager` 是纯内存单例，App 被系统回收 / 用户上滑杀掉后重建时，
/// 所有会话 + 参与者配置全没了，用户之前的会话再也找不回来。
///
/// 方案：每次会话 / 参与者变更时把「会话 id + 参与者配置」写进 Application Support 下的
/// JSON 文件，下次启动由 `SessionManager.restoreFromStore()` 读回来。
///
/// 不落盘的内容（跟 Android 一致）：
/// - 聊天消息（`imageBytes` 体积不可控，等以后有磁盘缓存再说）
/// - 连接状态（重启后必然断开）
/// - 输入模式 / 拖拽出来的输入区高度等 UI 状态
final class SessionStore {

    static let shared = SessionStore()

    private let fileName = "chatroom_sessions.json"
    private let createdAtKey = "createdAt"

    private init() {}

    /// JSON 文件位置：`Application Support/chatroom_sessions.json`
    /// （不放 Documents：不希望被 iTunes / 文件 App 暴露；不放 Caches：不能被系统清掉）
    private var fileURL: URL? {
        let fm = FileManager.default
        guard let dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        if !fm.fileExists(atPath: dir.path) {
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir.appendingPathComponent(fileName)
    }

    /// 按传入顺序覆盖保存全部会话（顺序 = tab 顺序）
    func save(_ sessions: [PersistedSession]) {
        guard let url = fileURL else { return }

        let array: [[String: Any]] = sessions.map { session in
            [
                "id": session.id,
                createdAtKey: session.createdAt,
                "participants": session.participants.map { participant -> [String: Any] in
                    [
                        "id": participant.id,
                        "type": participant.type.rawValue,
                        "name": participant.name,
                        "params": participant.params
                    ]
                }
            ]
        }

        guard let data = try? JSONSerialization.data(withJSONObject: array) else { return }
        // .atomic = 先写临时文件再 rename：会话刚建完进程就被杀也不会留下半截 JSON
        try? data.write(to: url, options: .atomic)
    }

    func load() -> [PersistedSession] {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return [] }
        return parse(data)
    }

    /// 清空历史（调试 / 未来「清空历史会话」入口用）
    func clear() {
        guard let url = fileURL else { return }
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - Private

    private func parse(_ data: Data) -> [PersistedSession] {
        // 数据损坏 / 格式升级时不要让 App 起不来：当作没有历史会话
        guard let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return []
        }

        var out: [PersistedSession] = []
        for obj in raw {
            guard let id = obj["id"] as? String, !id.isEmpty else { continue }

            var participants: [ParticipantConfig] = []
            let rawParticipants = obj["participants"] as? [[String: Any]] ?? []
            for pObj in rawParticipants {
                let typeName = pObj["type"] as? String ?? ""
                // 未知类型（旧版本写过 / 枚举改名）直接跳过，不让整条会话丢
                guard let type = ParticipantType(rawValue: typeName) else { continue }
                let name = (pObj["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? type.rawValue
                let params = pObj["params"] as? [String: String] ?? [:]
                let pid = (pObj["id"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? UUID().uuidString
                participants.append(ParticipantConfig(id: pid, type: type, name: name, params: params))
            }

            out.append(
                PersistedSession(
                    id: id,
                    createdAt: (obj[createdAtKey] as? NSNumber)?.int64Value ?? 0,
                    participants: participants
                )
            )
        }
        return out
    }
}
