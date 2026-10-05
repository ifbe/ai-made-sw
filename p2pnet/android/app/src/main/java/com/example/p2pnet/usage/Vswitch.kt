package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession

/**
 * ② 交给虚拟交换机：把多条 session 汇成一个虚拟局域网，公网多人互联。
 *
 * 对应 python 端的 client/app/switch.py，Android 上建议进程内做（一个 hub 持有多条 session，
 * 互相转发），不再拆子进程。保活：靠流量驱动。
 *
 * 现在挂上来的 session 会立刻出现在 Switch 页的网口上（页面按 `handedTo == "switch"` 派生，
 * 顺序就是 port1..portN），拔线 = detachUsage。真正的转发（进程内 hub + VpnService 那块 tun）
 * 还没做，配置项见 ui/PageConfig.kt 的 [com.example.p2pnet.ui.SwitchPageConfig]。
 */
class Vswitch : Usage {
    override val id: String = "switch"
    override val title: String = "switch"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log(
            "android: switch 已插成网口（${session.target}，本机端口 ${session.localPort}）；" +
                "转发逻辑尚未实现（TODO），配置见 Switch 页"
        )
    }

    override fun detach(session: UdpSession) {
        // 目前没有需要收尾的东西：转发 hub 做起来之后在这里摘掉这个网口
    }
}
