import Foundation

/// 蓝牙参与者（stub，iOS CoreBluetooth 实现）
final class BluetoothParticipant: Participant {

    let type: ParticipantType = .bluetooth
    let displayName: String

    var onMessage: ((Message) -> Void)?

    private let sessionId: String
    private let deviceName: String
    private let protocol_: String

    init(sessionId: String, deviceName: String, protocol_: String) {
        self.sessionId = sessionId
        self.deviceName = deviceName
        self.protocol_ = protocol_
        self.displayName = deviceName.isEmpty ? "BLUETOOTH" : deviceName
    }

    func connect() {
        let msg = Message(
            senderId: "bluetooth",
            senderType: .bluetooth,
            senderName: displayName,
            content: "📱 BLUETOOTH 暂未实现 (\(protocol_))",
            isInfo: true
        )
        DispatchQueue.main.async {
            self.onMessage?(msg)
        }
    }

    func sendInput(_ text: String) {
        // TBD
    }

    func disconnect() {
        // TBD
    }
}
