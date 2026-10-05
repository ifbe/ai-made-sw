package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession
import com.example.p2pnet.net.formatHostPort

/**
 * ④ 交给端口转发：把这条洞当一条裸通道，和某个目标 `host:port` 双向转发。
 *
 * 对应 python 端的 client/app/proxy.py（那边是 `--target host:port [--proto tcp|udp]`）：
 * 洞里收到的流量写进目标，目标的回包原路送回洞里；另外每 20s 往对端发一个空数据报保活 NAT。
 *
 * 安卓这边多一个方向（Proxy 页上的「本机监听」开关）：另开一个本地监听口，
 * 本机应用连上来就走这条洞到对端。
 *
 * 真正的转发逻辑还没做，配置项见 ui/PageConfig.kt 的 [com.example.p2pnet.ui.ProxyPageConfig]。
 */
class Proxy : Usage {
    override val id: String = "proxy"
    override val title: String = "proxy"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log(
            "android: proxy 已挂上（对端 ${formatHostPort(session.peerIp, session.peerPort)}，" +
                "洞本机端口 ${session.localPort}）；转发逻辑尚未实现（TODO），配置见 Proxy 页"
        )
    }

    override fun detach(session: UdpSession) {
        // 转发循环做起来之后在这里停掉；目前没有需要收尾的东西
    }
}
