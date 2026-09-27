package com.example.p2pnet.ui.login

import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.TabItem

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
    val tabs: List<TabItem> = listOf(TabItem.main(), TabItem.wireGuard()),
    val currentTabIndex: Int = 0,
    val currentPage: Page = Page.Main
)
