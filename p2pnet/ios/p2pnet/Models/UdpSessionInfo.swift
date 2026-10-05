import Foundation

/// 一条 session 的界面快照（界面上的 socket 卡片就照它渲染）。
/// **字段严格对齐** Android `net/UdpSessionInfo.kt`（顺序、默认值都保持一致，方便两端对照）。
///
/// - `kind = "udp"`：真的打洞出来的 session（有 socket）；
/// - `kind = "tcp"` / `"direct"`：没有 socket 的卡片，按 `plan` 渲染步骤；
/// - `isPreview = true`：只画计划、没有真实逻辑（tcp / upnp 的流程预览）。
nonisolated struct UdpSessionInfo: Equatable, Identifiable {
    let id: Int64
    var kind: String = "udp"
    /// 对端用户名
    var target: String = ""
    /// 自定义步骤列表。非空时卡片按它渲染步骤（tcp / direct 用），空时按下面的 UDP 五步布尔渲染。
    var plan: [SessionStep] = []
    /// true = 只画计划、没有真实逻辑；false + plan 非空 = 真实流程（步骤上的 done 是实时进度）
    var isPreview: Bool = false
    /// 流程结束后的结果行（direct 用：可达地址列表 / 失败原因）
    var note: String = ""
    /// 本机实际绑定的地址/端口
    var localIp: String = ""
    var localPort: Int = 0
    /// 1. 发给服务器
    var sentToServer: Bool = false
    /// 2. 收到服务器回复
    var serverReplied: Bool = false
    /// 服务器眼里我的公网 ip/port
    var myPublicIp: String = ""
    var myPublicPort: Int = 0
    /// 对端的 ip/port（服务器给的）
    var peerPublicIp: String = ""
    var peerPublicPort: Int = 0
    /// 3. 发给对端
    var sentToPeer: Bool = false
    /// 4. 收到对端回复
    var peerReplied: Bool = false
    /// 5. 交给哪个用法（"udptest" / "tun" / "switch" / "wg"），空 = 还没选
    var handedTo: String = ""
}

/// 卡片上的一步（文字 + 可选说明 + 是否已完成）。对应 Android `SessionStep`。
nonisolated struct SessionStep: Equatable {
    var text: String
    var detail: String = ""
    var done: Bool = false
}
