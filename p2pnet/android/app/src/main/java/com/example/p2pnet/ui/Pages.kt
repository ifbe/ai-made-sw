package com.example.p2pnet.ui

import com.example.p2pnet.data.remote.WsClient

/** 页面类型 */
sealed class Page {
    object Main : Page()
    data class UdpTest(
        val targetUsername: String,
        val myIp: String = "",
        val myPublicPort: Int = 0,
        var myLocalIp: String = "",
        val myLocalPort: Int = 0,
        val peerIp: String = "",
        val peerPort: Int = 0
    ) : Page()
    data class VideoCall(val targetUsername: String) : Page()
    data class Chat(val targetUsername: String) : Page()
    data class WireGuard(
        val targetUsername: String = "",
        val myIp: String = "",
        val myPort: Int = 0,
        val peerIp: String = "",
        val peerPort: Int = 0
    ) : Page()

    /** 虚拟交换机（配置页，对应 python 端 client/app/switch.py）。参数不走 page，配置在 [SwitchPageConfig] */
    object Switch : Page()

    /** 端口转发（配置页，对应 python 端 client/app/proxy.py）。配置在 [ProxyPageConfig] */
    object Proxy : Page()

    /**
     * 一对一 VPN（配置页，对应 python 端 client/app/vpn.py：一个洞 ↔ 一块 tun/tap）。
     * 和 [Switch] 的区别：vpn 是**一对一**（没有网口那排），switch 是 **m 对 n**。
     * 配置在 [VpnPageConfig]。
     */
    object Vpn : Page()

    /**
     * 多媒体聊天（配置页，对应 python 端 client/app/media.py + app/ffmpeg.sh）。
     * 我们只负责打洞，打好了把洞的参数交给聊天程序去收发流。
     * 配置在 [MediaPageConfig]。
     */
    object Media : Page()
}

/** Tab 项 */
data class TabItem(
    val page: Page,
    val title: String,
    /** false = 固定配置页（主页 / media / proxy / wireguard / vpn / switch），底部 tab 不给 × */
    val closable: Boolean = true
) {
    companion object {
        fun main() = TabItem(Page.Main, "主页", closable = false)
        fun mediaTab() = TabItem(Page.Media, "media", closable = false)
        fun proxyTab() = TabItem(Page.Proxy, "proxy", closable = false)
        fun wireGuard() = TabItem(Page.WireGuard(), "wireguard", closable = false)
        fun vpnTab() = TabItem(Page.Vpn, "vpn", closable = false)
        fun switchTab() = TabItem(Page.Switch, "switch", closable = false)
    }
}

fun WsClient.PeerInfo.toPage(): Page.UdpTest = Page.UdpTest(
    targetUsername = name,
    myIp = myIp,
    myPublicPort = myPort,
    myLocalIp = "",
    myLocalPort = myLocalPort,
    peerIp = peerIp,
    peerPort = peerPort
)
