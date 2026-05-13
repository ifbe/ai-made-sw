import Foundation

/// 参与者协议，所有参与者类型都实现这个
protocol Participant: AnyObject {
    var type: ParticipantType { get }
    var displayName: String { get }

    func connect()
    func sendInput(_ text: String)
    func disconnect()

    var onMessage: ((Message) -> Void)? { get set }
}
