import Foundation
import Combine

/// 全局 Session 管理器
@MainActor
final class SessionManager: ObservableObject {

    static let shared = SessionManager()

    // sessionId -> participants 配置列表
    @Published private(set) var sessions: [String: [ParticipantConfig]] = [:]

    // sessionId -> 聊天消息
    @Published private(set) var messages: [String: [Message]] = [:]

    // sessionId -> 当前输入模式
    @Published private(set) var inputModes: [String: ChatInputMode] = [:]

    private init() {}

    func createSession() -> String {
        let id = "session_\(Int(Date().timeIntervalSince1970 * 1000))"
        sessions[id] = []
        messages[id] = []
        inputModes[id] = .text
        return id
    }

    func removeSession(_ sessionId: String) {
        sessions.removeValue(forKey: sessionId)
        messages.removeValue(forKey: sessionId)
        inputModes.removeValue(forKey: sessionId)
    }

    func addParticipant(_ sessionId: String, config: ParticipantConfig) {
        sessions[sessionId, default: []].append(config)
    }

    func removeParticipant(_ sessionId: String, participantId: String) {
        sessions[sessionId]?.removeAll { $0.id == participantId }
    }

    func addMessage(_ sessionId: String, message: Message) {
        messages[sessionId, default: []].append(message)
    }

    func getMessages(_ sessionId: String) -> [Message] {
        messages[sessionId] ?? []
    }

    func getParticipants(_ sessionId: String) -> [ParticipantConfig] {
        sessions[sessionId] ?? []
    }

    func setInputMode(_ sessionId: String, mode: ChatInputMode) {
        inputModes[sessionId] = mode
    }

    func getInputMode(_ sessionId: String) -> ChatInputMode {
        inputModes[sessionId] ?? .text
    }
}
