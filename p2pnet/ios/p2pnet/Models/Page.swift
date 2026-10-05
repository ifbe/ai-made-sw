import Foundation

// MARK: - Page

enum Page: Equatable {
    case main
    case udpTest(targetUsername: String, myIp: String = "", myPublicPort: Int = 0, myLocalIp: String = "", myLocalPort: Int = 0, peerIp: String = "", peerPort: Int = 0)
    case videoCall(targetUsername: String)
    case chat(targetUsername: String)
    case wireGuard(targetUsername: String = "", myIp: String = "", myPort: Int = 0, peerIp: String = "", peerPort: Int = 0)
    /// 虚拟交换机（配置页，对应 python 端 client/app/switch.py）。
    /// 参数不走 page，配置在 `SwitchPageConfig`。
    /// 名字用 `vswitch` 而不是 `switch`（后者是 Swift 关键字），tab 标题是 "switch"。
    case vswitch
    /// 端口转发（配置页，对应 python 端 client/app/proxy.py）。配置在 `ProxyPageConfig`。
    case proxy
    /// 一对一 VPN（配置页，对应 python 端 client/app/vpn.py：一个洞 ↔ 一块 tun/tap）。
    /// 和 `vswitch` 的区别：vpn 是**一对一**（没有网口那排），switch 是 **m 对 n**。
    case vpn
    /// 多媒体聊天（配置页，对应 python 端 client/app/media.py + app/ffmpeg.sh）。
    /// 我们只负责打洞，打好了把洞的参数交给聊天程序去收发流。配置在 `MediaPageConfig`。
    case media
}

// MARK: - TabItem

struct TabItem: Equatable {
    let page: Page
    let title: String
    /// false = 固定配置页（主页 / media / proxy / wireguard / vpn / switch），底部 tab 不给 ×
    var closable: Bool = true

    static func main() -> TabItem { TabItem(page: .main, title: "主页", closable: false) }
    static func mediaTab() -> TabItem { TabItem(page: .media, title: "media", closable: false) }
    static func proxyTab() -> TabItem { TabItem(page: .proxy, title: "proxy", closable: false) }
    static func wireGuard() -> TabItem { TabItem(page: .wireGuard(), title: "wireguard", closable: false) }
    static func vpnTab() -> TabItem { TabItem(page: .vpn, title: "vpn", closable: false) }
    static func switchTab() -> TabItem { TabItem(page: .vswitch, title: "switch", closable: false) }
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