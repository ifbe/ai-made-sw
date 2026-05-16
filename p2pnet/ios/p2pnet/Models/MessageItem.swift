import Foundation

enum Direction: String, Codable {
    case client = "CLIENT"
    case server = "SERVER"
    case system = "SYSTEM"
    case udpSend = "UDP_SEND"
    case udpRecv = "UDP_RECV"
}

struct MessageItem: Identifiable, Equatable {
    let id: Int64
    let direction: Direction
    let content: String
    let time: String

    init(id: Int64 = Int64(Date().timeIntervalSince1970 * 1000), direction: Direction, content: String, time: String? = nil) {
        self.id = id
        self.direction = direction
        self.content = content
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        self.time = time ?? formatter.string(from: Date())
    }
}