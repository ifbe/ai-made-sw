package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession

/**
 * ③ 交给 WireGuard：指定本地端口，用现成的 wg 协议栈走公网直连。
 *
 * 保活用它自己的 handshake + PersistentKeepalive，不复用 udptest 的 ping。
 */
class WireGuard : Usage {
    override val id: String = "wg"
    override val title: String = "wg"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log("android: wg（WireGuard）用法尚未实现")
    }

    override fun detach(session: UdpSession) {}
}
