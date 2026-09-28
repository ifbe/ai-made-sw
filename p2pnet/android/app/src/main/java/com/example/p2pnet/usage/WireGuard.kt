package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession
import com.example.p2pnet.net.formatHostPort

/**
 * ③ 交给 WireGuard：指定本地端口，用现成的 wg 协议栈走公网直连。
 *
 * 保活用它自己的 handshake + PersistentKeepalive，不复用 udptest 的 ping。
 * 目前只做到「把已打通 socket 的对端/公网地址填进 WireGuard 页并跳过去」（原 wghelp 按钮的行为，
 * 现在入口在 socket 卡片第 5 行的 wg 按钮上），真正接入 wg 协议栈还没做。
 */
class WireGuard : Usage {
    override val id: String = "wg"
    override val title: String = "wg"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log(
            "android: wg 协议栈尚未接入；当前只是把地址交给 WireGuard 页" +
                "（公网 ${formatHostPort(session.publicIp, session.publicPort)} ↔ 对端 ${formatHostPort(session.peerIp, session.peerPort)}）"
        )
    }

    override fun detach(session: UdpSession) {}
}
