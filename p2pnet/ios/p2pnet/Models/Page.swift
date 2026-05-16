import Foundation

// MARK: - Page

enum Page: Equatable {
    case main
    case udpTest(targetUsername: String, myIp: String = "", myPublicPort: Int = 0, myLocalIp: String = "", myLocalPort: Int = 0, peerIp: String = "", peerPort: Int = 0)
    case videoCall(targetUsername: String)
    case chat(targetUsername: String)
    case wireGuard(targetUsername: String = "", myIp: String = "", myPort: Int = 0, peerIp: String = "", peerPort: Int = 0)
}

// MARK: - TabItem

struct TabItem: Equatable {
    let page: Page
    let title: String

    static func main() -> TabItem { TabItem(page: .main, title: "主页") }
    static func wireGuard() -> TabItem { TabItem(page: .wireGuard(), title: "WireGuard") }
}

extension PeerInfo {
    func toPage() -> Page {
        return .udpTest(
            targetUsername: name,
            myIp: myIp,
            myPublicPort: myPort,
            myLocalIp: "",
            myLocalPort: myLocalPort,
            peerIp: peerIp,
            peerPort: peerPort
        )
    }
}