import Foundation

/// 两个配置页的配置。对应 Android `ui/PageConfig.kt`，**JSON 键名完全一致**（两端配置文件可对照），
/// 解析失败/缺字段一律退回默认值。
///
/// 注意：`mtu` / `routeTtl` 在 Android 那边就是字符串（文本框直接存字符串），这里保持字符串，
/// 免得两端 JSON 出现 `"1400"` 和 `1400` 两种写法。

// MARK: - WireGuard 页

/// WireGuard 页的配置（决定 socket 卡片上点 `wg` 之后走哪条路）。
///
/// 三档和 python 端的对应关系：
///  - `self`     ：自己写协议栈（Noise IK + ChaCha20-Poly1305）＋ 自建 VpnService
///                 —— 对应 client/app/wg-python.py 那条思路（不需要 root）
///  - `official` ：调官方 wireguard tunnel 库（Go 实现，JNI）＋ 自建 VpnService
///  - `system`   ：拉起系统里另一个真正的 VPN 服务 app，把打洞参数（本地端口等）传过去
///                 —— 对应 client/app/wg-calltool.py 那条思路（自己不碰协议栈）
///
/// 三档的区别只在「谁来跑协议栈」，共同点是：**UDP 出口必须是已经打洞的那个本地端口**，
/// 否则打洞建立起来的 NAT 映射就废了。
nonisolated struct WgPageConfig: Equatable {
    /// self / official / system
    var impl: String = WgPageConfig.implSelf
    /// impl = system 时：目标 VPN 应用的 URL scheme（留空 = 不限定，只按 action 找）
    var extPackage: String = ""
    /// impl = system 时：约定的 action / URL scheme host
    var extAction: String = WgPageConfig.defaultExtAction

    static let implSelf = "self"
    static let implOfficial = "official"
    static let implSystem = "system"
    /// 和外部 VPN app 约定的 action（Android 侧是 manifest 的 <queries>，iOS 侧是 URL scheme）
    static let defaultExtAction = "com.p2pnet.action.START_VPN"

    static let implIds = [implSelf, implOfficial, implSystem]

    static func label(_ id: String) -> String {
        switch id {
        case implOfficial: return "官方库"
        case implSystem: return "调系统程序"
        default: return "自己实现"
        }
    }

    static func describe(_ id: String) -> String {
        switch id {
        case implOfficial: return "调官方 wireguard tunnel 库（Go 实现）＋ 自建 VpnService"
        case implSystem: return "拉起另一个真正的 VPN 服务 app，把已打洞的本地端口等参数传过去"
        default: return "自己写协议栈（Noise IK + ChaCha20-Poly1305）＋ 自建 VpnService"
        }
    }

    func toJson() -> String {
        let obj: [String: Any] = [
            "impl": impl,
            "extPackage": extPackage,
            "extAction": extAction,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    static func fromJson(_ json: String?) -> WgPageConfig {
        guard let json = json, !json.isEmpty,
              let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return WgPageConfig()
        }
        let impl = obj["impl"] as? String ?? implSelf
        let action = obj["extAction"] as? String ?? defaultExtAction
        return WgPageConfig(
            impl: implIds.contains(impl) ? impl : implSelf,
            extPackage: obj["extPackage"] as? String ?? "",
            extAction: action.isEmpty ? defaultExtAction : action
        )
    }
}

// MARK: - Switch 页

/// Switch 页（虚拟交换机）的配置，对应 python 端 client/app/switch.py 的命令行参数：
/// `--card` / `--tun-ip` / `--switch-mode` / `--tun-mtu` / `--route-ttl`。
///
/// DHCP 是安卓/iOS 这边新加的（python 的 switch 没有 DHCP 服务器），目前**只有开关**，
/// 真正的地址分配还没实现，所以地址池/网关/DNS 三个框先置灰。
nonisolated struct SwitchPageConfig: Equatable {
    /// none = 不开本机接口，tun = 三层，tap = 二层
    var cardMode: String = SwitchPageConfig.cardTun
    /// 配到 tun/tap 上的地址，可写 "192.168.250.55" 或 "192.168.250.55/24"
    var tunIp: String = "192.168.250.55/24"
    /// l2 = MAC 表转发，l3 = IP 表转发，auto = 看 EtherType（tap 默认 auto）
    var mode: String = SwitchPageConfig.modeL3
    /// 洞是 IP over UDP，1500 的包套上 UDP/IP 头会超网卡 MTU 分片，所以默认 1400；0 = 不改
    var mtu: String = "1400"
    /// 学到的路由/MAC 多久没再出现就老化删除（秒；0 = 不老化）
    var routeTtl: String = "300"
    var dhcpEnabled: Bool = false
    var dhcpPool: String = "192.168.250.100-192.168.250.200"
    var dhcpGateway: String = "192.168.250.55"
    var dhcpDns: String = "192.168.250.55"

    static let cardNone = "none"
    static let cardTun = "tun"
    static let cardTap = "tap"
    static let modeL2 = "l2"
    static let modeL3 = "l3"
    static let modeAuto = "auto"

    static let cardIds = [cardNone, cardTun, cardTap]
    static let modeIds = [modeL2, modeL3, modeAuto]

    /// 点 socket 卡片上 switch 时，把「按页面配置要做什么」写进日志用
    func summary() -> String {
        "card=\(cardMode) mode=\(mode) tun_ip=\(tunIp) mtu=\(mtu) route_ttl=\(routeTtl)s dhcp=\(dhcpEnabled ? "开（尚未实现）" : "关")"
    }

    func toJson() -> String {
        let obj: [String: Any] = [
            "cardMode": cardMode,
            "tunIp": tunIp,
            "mode": mode,
            "mtu": mtu,
            "routeTtl": routeTtl,
            "dhcpEnabled": dhcpEnabled,
            "dhcpPool": dhcpPool,
            "dhcpGateway": dhcpGateway,
            "dhcpDns": dhcpDns,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    static func fromJson(_ json: String?) -> SwitchPageConfig {
        guard let json = json, !json.isEmpty,
              let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return SwitchPageConfig()
        }
        let card = obj["cardMode"] as? String ?? cardTun
        let mode = obj["mode"] as? String ?? modeL3
        return SwitchPageConfig(
            cardMode: cardIds.contains(card) ? card : cardTun,
            tunIp: obj["tunIp"] as? String ?? "192.168.250.55/24",
            mode: modeIds.contains(mode) ? mode : modeL3,
            mtu: obj["mtu"] as? String ?? "1400",
            routeTtl: obj["routeTtl"] as? String ?? "300",
            dhcpEnabled: obj["dhcpEnabled"] as? Bool ?? false,
            dhcpPool: obj["dhcpPool"] as? String ?? "192.168.250.100-192.168.250.200",
            dhcpGateway: obj["dhcpGateway"] as? String ?? "192.168.250.55",
            dhcpDns: obj["dhcpDns"] as? String ?? "192.168.250.55"
        )
    }
}

// MARK: - Proxy 页（端口转发）

/// Proxy 页的配置：**一条洞 ↔ 一个固定端口**，按 ssh 的习惯分正/反向。
/// 字段名、默认值、JSON 键名都和 Android `ProxyPageConfig` 一一对应。
///
/// 两种模式各只负责**本机这一侧**：
///  - 正向 `L`（本机 listen）：监听 `lListenIp:lListenPort`，accept 后与洞互转；
///  - 反向 `R`（本机 connect）：connect `rTargetHost:rTargetPort`，与洞互转
///    —— python 端 client/app/proxy.py 就是这一半。
nonisolated struct ProxyPageConfig: Equatable {
    /// L = 正向（本机 listen）/ R = 反向（本机 connect）
    var mode: String = ProxyPageConfig.modeR
    /// tcp / udp（对齐 proxy.py 的 --proto）
    var proto: String = ProxyPageConfig.protoTcp
    /// NAT 保活间隔（秒），对齐 proxy.py 的 KEEPALIVE_INTERVAL = 20
    var keepaliveSec: String = "20"
    /// 洞 socket 的绑定地址（对齐 --localaddr）
    var bindAddr: String = "0.0.0.0"
    /// 洞的本机端口，空 = 用这条 session 实际打洞出来的端口（推荐留空）
    var localPort: String = ""
    /// 仅 -L：本机监听地址（127.0.0.1 = 只有本机应用能连；0.0.0.0 = 局域网也能连）
    var lListenIp: String = "127.0.0.1"
    /// 仅 -L：本机监听端口，0 = 让系统自动挑一个
    var lListenPort: String = "8080"
    /// 仅 -R：要 connect 的目标地址（本机视角）
    var rTargetHost: String = "127.0.0.1"
    /// 仅 -R：目标端口（必填，例如 3389 远程桌面 / 22 SSH）
    var rTargetPort: String = ""

    static let protoTcp = "tcp"
    static let protoUdp = "udp"
    static let modeL = "L"
    static let modeR = "R"

    static let protoIds = [protoTcp, protoUdp]
    static let modeIds = [modeL, modeR]

    static func modeLabel(_ id: String) -> String {
        id == modeL ? "正向 -L" : "反向 -R"
    }

    /// 点 socket 卡片上 proxy 时，把「按页面配置要做什么」写进日志用
    func summary() -> String {
        let holePort = Int(localPort) ?? 0
        let hole = holePort == 0 ? "\(bindAddr):自动" : formatHostPort(bindAddr, holePort)
        let modeText = mode == Self.modeL ? "正向 -L" : "反向 -R"
        let side: String
        if mode == Self.modeL {
            let p = Int(lListenPort) ?? 0
            side = "本机监听=" + (p == 0 ? "\(lListenIp):自动" : formatHostPort(lListenIp, p))
        } else {
            let p = Int(rTargetPort) ?? 0
            side = "本机connect=" + (p == 0 ? "\(rTargetHost):(端口未填)" : formatHostPort(rTargetHost, p))
        }
        return "mode=\(modeText) proto=\(proto) 洞=\(hole) keepalive=\(keepaliveSec)s \(side)"
    }

    func toJson() -> String {
        let obj: [String: Any] = [
            "mode": mode,
            "proto": proto,
            "keepaliveSec": keepaliveSec,
            "bindAddr": bindAddr,
            "localPort": localPort,
            "lListenIp": lListenIp,
            "lListenPort": lListenPort,
            "rTargetHost": rTargetHost,
            "rTargetPort": rTargetPort,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    static func fromJson(_ json: String?) -> ProxyPageConfig {
        guard let json = json, !json.isEmpty,
              let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ProxyPageConfig()
        }
        let proto = obj["proto"] as? String ?? protoTcp
        let mode = obj["mode"] as? String ?? modeR
        return ProxyPageConfig(
            mode: modeIds.contains(mode) ? mode : modeR,
            proto: protoIds.contains(proto) ? proto : protoTcp,
            keepaliveSec: obj["keepaliveSec"] as? String ?? "20",
            bindAddr: obj["bindAddr"] as? String ?? "0.0.0.0",
            localPort: obj["localPort"] as? String ?? "",
            lListenIp: obj["lListenIp"] as? String ?? "127.0.0.1",
            lListenPort: obj["lListenPort"] as? String ?? "8080",
            rTargetHost: obj["rTargetHost"] as? String ?? "127.0.0.1",
            rTargetPort: obj["rTargetPort"] as? String ?? ""
        )
    }
}

// MARK: - VPN 页（一对一）

/// VPN 页（一对一）的配置，对应 python 端 client/app/vpn.py：**一个洞 ↔ 一块 tun/tap**。
/// 和 `SwitchPageConfig` 同一套字段（所以两页看起来一致），但**分开存**，改 vpn 不动 switch。
/// 只有默认网段不同（`10.0.0.x`）和页面形态不同（一对一没有网口那排）。
nonisolated struct VpnPageConfig: Equatable {
    var cardMode: String = VpnPageConfig.cardTun
    var tunIp: String = "10.0.0.2/24"
    var mode: String = VpnPageConfig.modeL3
    var mtu: String = "1400"
    var routeTtl: String = "300"
    var dhcpEnabled: Bool = false
    var dhcpPool: String = "10.0.0.100-10.0.0.200"
    var dhcpGateway: String = "10.0.0.1"
    var dhcpDns: String = "10.0.0.1"

    static let cardNone = "none"
    static let cardTun = "tun"
    static let cardTap = "tap"
    static let modeL2 = "l2"
    static let modeL3 = "l3"
    static let modeAuto = "auto"

    static let cardIds = [cardNone, cardTun, cardTap]
    static let modeIds = [modeL2, modeL3, modeAuto]

    /// 点 socket 卡片上 tun 时，把「按页面配置要做什么」写进日志用
    func summary() -> String {
        "card=\(cardMode) tun_ip=\(tunIp) mode=\(mode) mtu=\(mtu) route_ttl=\(routeTtl)s dhcp=\(dhcpEnabled ? "开（尚未实现）" : "关")"
    }

    func toJson() -> String {
        let obj: [String: Any] = [
            "cardMode": cardMode,
            "tunIp": tunIp,
            "mode": mode,
            "mtu": mtu,
            "routeTtl": routeTtl,
            "dhcpEnabled": dhcpEnabled,
            "dhcpPool": dhcpPool,
            "dhcpGateway": dhcpGateway,
            "dhcpDns": dhcpDns,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    static func fromJson(_ json: String?) -> VpnPageConfig {
        guard let json = json, !json.isEmpty,
              let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return VpnPageConfig()
        }
        let card = obj["cardMode"] as? String ?? cardTun
        let mode = obj["mode"] as? String ?? modeL3
        return VpnPageConfig(
            cardMode: cardIds.contains(card) ? card : cardTun,
            tunIp: obj["tunIp"] as? String ?? "10.0.0.2/24",
            mode: modeIds.contains(mode) ? mode : modeL3,
            mtu: obj["mtu"] as? String ?? "1400",
            routeTtl: obj["routeTtl"] as? String ?? "300",
            dhcpEnabled: obj["dhcpEnabled"] as? Bool ?? false,
            dhcpPool: obj["dhcpPool"] as? String ?? "10.0.0.100-10.0.0.200",
            dhcpGateway: obj["dhcpGateway"] as? String ?? "10.0.0.1",
            dhcpDns: obj["dhcpDns"] as? String ?? "10.0.0.1"
        )
    }
}

// MARK: - media 页（多媒体聊天）

/// media 页的配置，对应 python 端 client/app/media.py + app/ffmpeg.sh。
/// **我们的程序只负责打洞**：打好了把这条洞的参数交给聊天程序，由它收发流。
///
/// ⚠️ 所以这一页**没有地址和端口可填** —— 它们是打洞结果带出来的
/// （洞的本机侧 / 对端侧 / 服务器看到的我），双方端口是打洞时定的，不一定是 1935。
///
/// iOS 侧 `appPackage` 当 URL scheme 用（Android 那边是包名，JSON 键保持一致便于对照）；
/// `appAction` 保留 JSON 键但 iOS 拼 URL 时 host 固定用 `start`，那串 action 只在 Android 用。
nonisolated struct MediaPageConfig: Equatable {
    /// 收流协议：rtmp / rtsp / srt / udp（本地这一侧怎么收）
    var recvProto: String = MediaPageConfig.protoRtmp
    /// 推流协议：rtmp / rtsp / srt / udp（本地这一侧怎么推）
    var sendProto: String = MediaPageConfig.protoRtmp
    /// mic / camera / both：本地采集什么
    var capture: String = MediaPageConfig.captureBoth
    /// 目标聊天程序（iOS：URL scheme；留空 = 用 `p2pnetmedia`）
    var appPackage: String = ""
    /// 约定的 action（iOS 只在日志里体现，不进 URL）
    var appAction: String = MediaPageConfig.defaultAction

    static let protoRtmp = "rtmp"
    static let protoRtsp = "rtsp"
    static let protoSrt = "srt"
    static let protoUdp = "udp"
    static let protoIds = [protoRtmp, protoRtsp, protoSrt, protoUdp]

    static let captureMic = "mic"
    static let captureCamera = "camera"
    static let captureBoth = "both"
    static let captureIds = [captureMic, captureCamera, captureBoth]

    /// 和外部聊天程序约定的 action（Android 走 Intent extras）
    static let defaultAction = "com.p2pnet.action.MEDIA_CHAT"

    func summary() -> String {
        "收流=\(recvProto) 推流=\(sendProto) 采集=\(capture)"
    }

    func toJson() -> String {
        let obj: [String: Any] = [
            "recvProto": recvProto,
            "sendProto": sendProto,
            "capture": capture,
            "appPackage": appPackage,
            "appAction": appAction,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    static func fromJson(_ json: String?) -> MediaPageConfig {
        guard let json = json, !json.isEmpty,
              let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return MediaPageConfig()
        }
        let rp = obj["recvProto"] as? String ?? protoRtmp
        let sp = obj["sendProto"] as? String ?? protoRtmp
        let cap = obj["capture"] as? String ?? captureBoth
        let action = obj["appAction"] as? String ?? defaultAction
        return MediaPageConfig(
            recvProto: protoIds.contains(rp) ? rp : protoRtmp,
            sendProto: protoIds.contains(sp) ? sp : protoRtmp,
            capture: captureIds.contains(cap) ? cap : captureBoth,
            appPackage: obj["appPackage"] as? String ?? "",
            appAction: action.isEmpty ? defaultAction : action
        )
    }
}
