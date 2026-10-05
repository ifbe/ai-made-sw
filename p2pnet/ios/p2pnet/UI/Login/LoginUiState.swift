import Foundation
import Combine

struct LoginUiState: Equatable {
    var useWss: Bool = false
    var serverHost: String = "deepstack.tech"
    var serverPort: String = "10000"
    var username: String = "test"
    var password: String = "test"
    var targetUsername: String = ""
    var loading: Bool = false
    var isConnected: Bool = false
    var isLoggedIn: Bool = false
    var loggedInUsername: String = ""
    var error: String? = nil
    var messages: [MessageItem] = []
    /// 自己的 ip / port（由 list 回复解析而来）
    var myIp: String = ""
    var myPort: Int = 0
    /// list 回复里除自己以外的其他在线用户
    var peers: [PeerEntry] = []
    /// 已创建的 socket 卡片（SessionManager 的快照，ViewModel 只观察）
    var udpSockets: [UdpSessionInfo] = []
    /// WireGuard 页的配置（「实现」三档等），持久化在 LocalPrefs
    var wgConfig: WgPageConfig = WgPageConfig()
    /// Switch 页的配置（card / 交换模式 / MTU / DHCP 开关…），持久化在 LocalPrefs
    var switchConfig: SwitchPageConfig = SwitchPageConfig()
    /// 交换机是否「已启动」（目前只是页面状态：真正的 hub 还没做）
    var switchRunning: Bool = false
    /// Proxy 页（端口转发）的配置，持久化在 LocalPrefs
    var proxyConfig: ProxyPageConfig = ProxyPageConfig()
    /// 端口转发是否「已启动」（目前只是页面状态：真正的转发还没做）
    var proxyRunning: Bool = false
    /// VPN 页（一对一 tun/tap）的配置，持久化在 LocalPrefs
    var vpnConfig: VpnPageConfig = VpnPageConfig()
    /// VPN 是否「已启动」（目前只是页面状态）
    var vpnRunning: Bool = false
    /// media 页（多媒体聊天）的配置，持久化在 LocalPrefs
    var mediaConfig: MediaPageConfig = MediaPageConfig()
    /// 固定页顺序：主页 / media / proxy / wireguard / vpn / switch（和 Android 一致）
    var tabs: [TabItem] = [
        TabItem.main(),
        TabItem.mediaTab(),
        TabItem.proxyTab(),
        TabItem.wireGuard(),
        TabItem.vpnTab(),
        TabItem.switchTab(),
    ]
    var currentTabIndex: Int = 0
    var currentPage: Page = .main
}