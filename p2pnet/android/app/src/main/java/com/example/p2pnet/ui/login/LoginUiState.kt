package com.example.p2pnet.ui.login

import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.ui.MediaPageConfig
import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.ProxyPageConfig
import com.example.p2pnet.ui.SwitchPageConfig
import com.example.p2pnet.ui.TabItem
import com.example.p2pnet.ui.VpnPageConfig
import com.example.p2pnet.ui.WgPageConfig

data class LoginUiState(
    val useWss: Boolean = false,
    val serverHost: String = "deepstack.tech",
    val serverPort: String = "10000",
    val username: String = "test",
    val password: String = "test",
    val targetUsername: String = "",
    val loading: Boolean = false,
    val isConnected: Boolean = false,
    val isLoggedIn: Boolean = false,
    val loggedInUsername: String = "",
    val error: String? = null,
    val messages: List<MessageItem> = emptyList(),
    /** 自己的 ip / port（由 list 回复解析而来） */
    val myIp: String = "",
    val myPort: Int = 0,
    /** list 回复里除自己以外的其他在线用户 */
    val peers: List<PeerEntry> = emptyList(),
    /** 已创建的 UDP hello socket 卡片（点 udp 按钮时出现，点 ✕ 关闭） */
    val udpSockets: List<UdpSessionInfo> = emptyList(),
    /** WireGuard 页的配置（「实现」三档等），持久化在 LocalPrefs */
    val wgConfig: WgPageConfig = WgPageConfig(),
    /** Switch 页的配置（card / 交换模式 / MTU / DHCP 开关…），持久化在 LocalPrefs */
    val switchConfig: SwitchPageConfig = SwitchPageConfig(),
    /** 交换机是否"已启动"（目前只是页面状态：真正的 hub 还没做） */
    val switchRunning: Boolean = false,
    /** Proxy 页（端口转发）的配置，持久化在 LocalPrefs */
    val proxyConfig: ProxyPageConfig = ProxyPageConfig(),
    /** 端口转发是否"已启动"（目前只是页面状态：真正的转发还没做） */
    val proxyRunning: Boolean = false,
    /** VPN 页（一对一 tun/tap）的配置，持久化在 LocalPrefs */
    val vpnConfig: VpnPageConfig = VpnPageConfig(),
    /** VPN 是否"已启动"（目前只是页面状态） */
    val vpnRunning: Boolean = false,
    /** media 页（多媒体聊天）的配置，持久化在 LocalPrefs */
    val mediaConfig: MediaPageConfig = MediaPageConfig(),
    /** 固定页顺序：主页 / media / proxy / wireguard / vpn / switch */
    val tabs: List<TabItem> = listOf(
        TabItem.main(),
        TabItem.mediaTab(),
        TabItem.proxyTab(),
        TabItem.wireGuard(),
        TabItem.vpnTab(),
        TabItem.switchTab()
    ),
    val currentTabIndex: Int = 0,
    val currentPage: Page = Page.Main
)
