package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession
import com.example.p2pnet.net.formatHostPort

/**
 * ⑤ 交给多媒体聊天：**我们只负责打洞**，打好了把这条洞的参数交给聊天程序，由它收发流。
 *
 * 对应 python 端的 client/app/media.py（RTMP 收/推）+ app/ffmpeg.sh（P2P 那段是 mpegts over UDP）。
 *
 * ⚠️ 经洞那一段只能是 UDP（洞本身就是 UDP 端口），rtmp/rtsp 这类需要 TCP 的协议
 * 只用在"本地这一侧"，或者改成走 TCP 洞。
 *
 * 真正的媒体收发不在我们进程里做：配置见 ui/PageConfig.kt 的
 * [com.example.p2pnet.ui.MediaPageConfig]，拉起外部程序由 Media 页的「拉起应用」负责。
 */
class Media : Usage {
    override val id: String = "media"
    override val title: String = "media"

    override fun attach(session: UdpSession, env: UsageEnv) {
        env.log(
            "android: media 已接上通道（对端 ${formatHostPort(session.peerIp, session.peerPort)}，" +
                "洞本机端口 ${session.localPort}）；去 media 页点「拉起应用」把参数交给聊天程序"
        )
    }

    override fun detach(session: UdpSession) {
        // 媒体收发在外部程序里，我们这边没有需要收尾的东西
    }
}
