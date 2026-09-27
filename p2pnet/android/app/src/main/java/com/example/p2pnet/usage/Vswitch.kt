package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession

/**
 * ② 交给虚拟交换机：把多条 session 汇成一个虚拟局域网，公网多人互联。
 *
 * 对应 python 端的 client/app/switch.py，Android 上建议进程内做（一个 hub 持有多条 session，
 * 互相转发），不再拆子进程。保活：靠流量驱动。
 */
class Vswitch : Usage {
    override val id: String = "switch"
    override val title: String = "switch"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log("android: switch（虚拟交换机）用法尚未实现")
    }

    override fun detach(session: UdpSession) {}
}
