package com.example.p2pnet.net

/**
 * 一条 session 的界面快照（SessionManager 通过 StateFlow 推给 UI）。
 * 界面上的 socket 卡片就是照它渲染的：本机绑定 + 打洞步骤 + 选中的用法。
 *
 * ⚠️ 名字里的 `Udp` 是历史遗留：`kind = "tcp"` 时这张卡片也被复用（TCP 的步骤和 UDP 完全不同，
 * 用 [plan] 单独描述）。`kind = "direct"` 时**没有 socket**（direct 只交换地址、不交换端口），
 * 卡片按 [plan] 渲染「枚举地址 → 交换地址 → ping 可达性」三步，末行是 [note]。
 * 等 TCP 打洞逻辑真正落地时再统一改名 / 重构。
 */
data class UdpSessionInfo(
    val id: Long,
    /** "udp" = 真的打洞出来的 session；"tcp" / "direct" 见各自的 [plan] */
    val kind: String = "udp",
    /** 对端用户名 */
    val target: String = "",
    /**
     * 自定义步骤列表。非空时卡片按它渲染步骤（tcp / direct 用），
     * 空时按下面的 UDP 五步布尔渲染。
     */
    val plan: List<SessionStep> = emptyList(),
    /**
     * true = 只画计划、没有真实逻辑（现在只剩 tcp / upnp）；
     * false + [plan] 非空 = 真实流程，步骤上的 done 是实时进度（direct）。
     */
    val isPreview: Boolean = false,
    /** 流程结束后的结果行（direct 用：可达地址列表 / 失败原因） */
    val note: String = "",
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

/** 卡片上的一步（文字 + 可选说明 + 是否已完成） */
data class SessionStep(
    val text: String,
    val detail: String = "",
    val done: Boolean = false
)
