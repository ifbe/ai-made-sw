package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession

/**
 * ① 交给 tun：把这条 session 的包灌进 TUN 设备，实现 p2p VPN。
 *
 * Android 上没有 /dev/net/tun，要走 [android.net.VpnService]（需要 BIND_VPN_SERVICE 权限 +
 * 用户授权），所以这个用法落地时还会带来一个新增的 Service 和 manifest 声明。
 * 保活：靠流量驱动，不自己发 ping。
 */
class Tun : Usage {
    override val id: String = "tun"
    override val title: String = "tun"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log("android: tun 用法尚未实现（需要 VpnService + 用户授权）")
    }

    override fun detach(session: UdpSession) {}
}
