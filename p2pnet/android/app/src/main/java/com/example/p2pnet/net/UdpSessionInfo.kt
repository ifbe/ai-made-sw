package com.example.p2pnet.net

/**
 * 一条 UDP session 的界面快照（SessionManager 通过 StateFlow 推给 UI）。
 * 界面上的 socket 卡片就是照它渲染的：本机绑定 + 打洞五步进度 + 选中的用法。
 */
data class UdpSessionInfo(
    val id: Long,
    /** 对端用户名 */
    val target: String = "",
    /** 本机实际绑定的地址/端口 */
    val localIp: String = "",
    val localPort: Int = 0,
    /** 1. 发给服务器 */
    val sentToServer: Boolean = false,
    /** 2. 收到服务器回复 */
    val serverReplied: Boolean = false,
    /** 服务器眼里我的公网 ip/port */
    val myPublicIp: String = "",
    val myPublicPort: Int = 0,
    /** 对端的 ip/port（服务器给的） */
    val peerPublicIp: String = "",
    val peerPublicPort: Int = 0,
    /** 3. 发给对端 */
    val sentToPeer: Boolean = false,
    /** 4. 收到对端回复 */
    val peerReplied: Boolean = false,
    /** 5. 交给哪个用法（"udptest" / "tun" / "switch" / "wg"），空 = 还没选 */
    val handedTo: String = ""
)
