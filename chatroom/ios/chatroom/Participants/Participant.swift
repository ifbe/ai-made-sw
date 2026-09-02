import Foundation

/// 参与者协议，所有参与者类型都实现这个
protocol Participant: AnyObject {
    var type: ParticipantType { get }
    var displayName: String { get }

    func connect()
    func sendInput(_ text: String)
    func sendBinary(_ data: Data)
    func disconnect()

    var onMessage: ((Message) -> Void)? { get set }
}

/// 默认不提供二进制发送能力的 participant（如 TCP/UDP/SERIAL/AI/PTY）走这里：no-op。
/// 只有 WsParticipant / EchoParticipant override 给真实实现。调用方不需要先做类型判断。
///
/// 注意：sendBinary 必须是 protocol requirement，不能只放在 extension 里——
/// Swift 对 extension method 是静态分派，participant?.sendBinary(data) 会永远调到 Participant.sendBinary (no-op)，
/// 调不到 EchoParticipant.sendBinary / WsParticipant.sendBinary 的 override。
extension Participant {
    func sendBinary(_ data: Data) {
        // no-op
    }
}
