import Foundation
import Combine

/// 全局 Session 管理器（对应 Android `SessionManager`）
///
/// 内存态 + 落盘（`SessionStore`）：
/// - `sessions` / `messages` / `inputModes` 是会话数据
/// - `sessionOrder` 决定 tab 顺序（= 创建顺序）
/// - `connected` 记录「本进程里被激活过」（新建 / 点过重连）。**恢复出来的会话一律 false**
/// - `linkUp` 记录网络参与者的链路聚合状态（nil = 没有网络参与者 / 还没上报 → 视为正常）。
///   只存在内存里，不落盘：进程重启后连接必然断了
@MainActor
final class SessionManager: ObservableObject {

    static let shared = SessionManager()

    // sessionId -> participants 配置列表
    @Published private(set) var sessions: [String: [ParticipantConfig]] = [:]

    // sessionId -> 聊天消息
    @Published private(set) var messages: [String: [Message]] = [:]

    // sessionId -> 当前输入模式
    @Published private(set) var inputModes: [String: ChatInputMode] = [:]

    /// 会话创建顺序（= tab 顺序）
    @Published private(set) var sessionOrder: [String] = []

    /// sessionId -> 是否已激活（本进程新建 / 点过重连）
    @Published private(set) var connected: [String: Bool] = [:]

    /// sessionId -> 网络链路是否正常（nil = 无网络参与者 / 未上报，按正常算）
    @Published private(set) var linkUp: [String: Bool] = [:]

    /// 启动恢复只做一次
    private var didRestore = false

    private init() {}

    // MARK: - 会话生命周期

    func createSession() -> String {
        let id = "session_\(Int(Date().timeIntervalSince1970 * 1000))"
        sessions[id] = []
        messages[id] = []
        inputModes[id] = .text
        sessionOrder.append(id)
        connected[id] = true          // 本进程新建 = 已激活，会立刻连
        persist()
        return id
    }

    /// 进程启动时读回上次落盘的会话（一律未连接，参与者信息保留）。
    ///
    /// 幂等：App 进程还活着（只是 View 重建）时内存里已经有这些会话，`restoreFromStore` 会跳过，
    /// 不会把 `connected=true` 的活跃会话打回未连接。
    func restoreFromStore() {
        guard !didRestore else { return }
        didRestore = true

        for persisted in SessionStore.shared.load() {
            if sessions[persisted.id] != nil {
                // 已经在内存里（View 重建），只保证 order 里有它
                if !sessionOrder.contains(persisted.id) {
                    sessionOrder.append(persisted.id)
                }
                continue
            }
            sessions[persisted.id] = persisted.participants
            messages[persisted.id] = []
            inputModes[persisted.id] = .text
            sessionOrder.append(persisted.id)
            connected[persisted.id] = false   // 恢复出来一律未连接，等用户点重连
        }
    }

    func removeSession(_ sessionId: String) {
        sessions.removeValue(forKey: sessionId)
        messages.removeValue(forKey: sessionId)
        inputModes.removeValue(forKey: sessionId)
        sessionOrder.removeAll { $0 == sessionId }
        connected.removeValue(forKey: sessionId)
        linkUp.removeValue(forKey: sessionId)
        persist()
    }

    // MARK: - 参与者

    func addParticipant(_ sessionId: String, config: ParticipantConfig) {
        sessions[sessionId, default: []].append(config)
        persist()
    }

    func removeParticipant(_ sessionId: String, participantId: String) {
        sessions[sessionId]?.removeAll { $0.id == participantId }
        persist()
    }

    // MARK: - 连接状态

    func isSessionConnected(_ sessionId: String) -> Bool {
        connected[sessionId] ?? false
    }

    func setSessionConnected(_ sessionId: String, _ value: Bool) {
        connected[sessionId] = value
    }

    /// 网络参与者聚合出来的链路状态。只有「确实有网络参与者」的会话才应该调这个方法；
    /// 纯 ECHO / PTY 这类会话没有链路可报，保持 nil（= 正常）。
    func setSessionLinkUp(_ sessionId: String, _ up: Bool) {
        if linkUp[sessionId] == up { return }
        linkUp[sessionId] = up
    }

    /// 断开 / 移除参与者后清掉链路状态，回到「未上报 = 正常」的缺省
    func clearSessionLinkUp(_ sessionId: String) {
        linkUp.removeValue(forKey: sessionId)
    }

    /// tab 显示用的「会话是否正常」：已激活 **且** 链路没报断开。
    /// nil 的 linkUp 视为 true（无网络参与者，例如纯 ECHO）。
    func isSessionUp(_ sessionId: String) -> Bool {
        isSessionConnected(sessionId) && (linkUp[sessionId] ?? true)
    }

    // MARK: - 消息 / 输入模式

    func addMessage(_ sessionId: String, message: Message) {
        messages[sessionId, default: []].append(message)
    }

    func getMessages(_ sessionId: String) -> [Message] {
        messages[sessionId] ?? []
    }

    func getParticipants(_ sessionId: String) -> [ParticipantConfig] {
        sessions[sessionId] ?? []
    }

    func getSessionOrder() -> [String] {
        sessionOrder
    }

    func setInputMode(_ sessionId: String, mode: ChatInputMode) {
        inputModes[sessionId] = mode
    }

    func getInputMode(_ sessionId: String) -> ChatInputMode {
        inputModes[sessionId] ?? .text
    }

    // MARK: - 落盘

    /// 把当前全部会话按 tab 顺序写盘（不存连接状态 / 消息）
    private func persist() {
        let snapshot: [PersistedSession] = sessionOrder.compactMap { id in
            guard let participants = sessions[id] else { return nil }
            return PersistedSession(
                id: id,
                createdAt: Self.createdAt(fromSessionId: id),
                participants: participants
            )
        }
        SessionStore.shared.save(snapshot)
    }

    /// 从 sessionId 里解出创建时间（`session_<epochMillis>`，跟 Android 同一个约定）
    static func createdAt(fromSessionId sessionId: String) -> Int64 {
        Int64(sessionId.replacingOccurrences(of: "session_", with: "")) ?? 0
    }
}
