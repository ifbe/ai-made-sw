package com.example.p2pnet.ui

import com.example.p2pnet.net.formatHostPort
import org.json.JSONObject

/**
 * WireGuard 页的配置（决定 socket 卡片上点 `wg` 之后走哪条路）。
 *
 * 三档和 python 端的对应关系：
 *  - [IMPL_SELF]     ：自己写协议栈（Noise IK + ChaCha20-Poly1305）＋ 自建 VpnService
 *                      —— 对应 client/app/wg-python.py 那条思路（不需要 root）
 *  - [IMPL_OFFICIAL] ：调官方 wireguard tunnel 库（Go 实现，JNI）＋ 自建 VpnService
 *  - [IMPL_SYSTEM]   ：拉起系统里另一个真正的 VPN 服务 app，把打洞参数（本地端口等）传过去
 *                      —— 对应 client/app/wg-calltool.py 那条思路（自己不碰协议栈）
 *
 * 三档的区别只在"谁来跑协议栈"，共同点是：**UDP 出口必须是已经打洞的那个本地端口**，
 * 否则打洞建立起来的 NAT 映射就废了（client/app/wghelp.sh 的注释里也强调了这一点）。
 */
data class WgPageConfig(
    val impl: String = IMPL_SELF,
    /** impl = system 时：目标 VPN 应用的包名（留空 = 不限定，只在 manifest 的 <queries> 里按 action 找） */
    val extPackage: String = "",
    /** impl = system 时：约定的 action，对方 app 注册这个 action 来接收参数 */
    val extAction: String = DEFAULT_EXT_ACTION
) {
    fun toJson(): String = JSONObject().apply {
        put("impl", impl)
        put("extPackage", extPackage)
        put("extAction", extAction)
    }.toString()

    companion object {
        const val IMPL_SELF = "self"
        const val IMPL_OFFICIAL = "official"
        const val IMPL_SYSTEM = "system"

        /** 和外部 VPN app 约定的 action（见 AndroidManifest 的 <queries>） */
        const val DEFAULT_EXT_ACTION = "com.p2pnet.action.START_VPN"

        val IMPL_IDS = listOf(IMPL_SELF, IMPL_OFFICIAL, IMPL_SYSTEM)

        fun label(id: String): String = when (id) {
            IMPL_OFFICIAL -> "官方库"
            IMPL_SYSTEM -> "调系统程序"
            else -> "自己实现"
        }

        fun describe(id: String): String = when (id) {
            IMPL_OFFICIAL -> "调官方 wireguard tunnel 库（Go 实现）＋ 自建 VpnService"
            IMPL_SYSTEM -> "拉起另一个真正的 VPN 服务 app，把已打洞的本地端口等参数传过去"
            else -> "自己写协议栈（Noise IK + ChaCha20-Poly1305）＋ 自建 VpnService"
        }

        fun fromJson(json: String?): WgPageConfig {
            if (json.isNullOrBlank()) return WgPageConfig()
            return try {
                val o = JSONObject(json)
                val impl = o.optString("impl", IMPL_SELF)
                WgPageConfig(
                    impl = if (impl in IMPL_IDS) impl else IMPL_SELF,
                    extPackage = o.optString("extPackage", ""),
                    extAction = o.optString("extAction", DEFAULT_EXT_ACTION)
                        .ifBlank { DEFAULT_EXT_ACTION }
                )
            } catch (_: Exception) {
                WgPageConfig()
            }
        }
    }
}

/**
 * Switch 页（虚拟交换机）的配置，对应 python 端 client/app/switch.py 的命令行参数：
 * `--card` / `--tun-ip` / `--switch-mode` / `--tun-mtu` / `--route-ttl`。
 *
 * DHCP 是安卓这边新加的（python 的 switch 没有 DHCP 服务器），目前**只有开关**，
 * 真正的地址分配还没实现，所以地址池/网关/DNS 三个框先置灰。
 */
data class SwitchPageConfig(
    /** none = 不开本机接口，tun = 三层，tap = 二层 */
    val cardMode: String = CARD_TUN,
    /** 配到 tun/tap 上的地址，可写 "192.168.250.55" 或 "192.168.250.55/24" */
    val tunIp: String = "192.168.250.55/24",
    /** l2 = MAC 表转发，l3 = IP 表转发，auto = 看 EtherType（tap 默认 auto） */
    val mode: String = MODE_L3,
    /** 洞是 IP over UDP，1500 的包套上 UDP/IP 头会超网卡 MTU 分片，所以默认 1400；0 = 不改 */
    val mtu: String = "1400",
    /** 学到的路由/MAC 多久没再出现就老化删除（秒；0 = 不老化） */
    val routeTtl: String = "300",
    val dhcpEnabled: Boolean = false,
    val dhcpPool: String = "192.168.250.100-192.168.250.200",
    val dhcpGateway: String = "192.168.250.55",
    val dhcpDns: String = "192.168.250.55"
) {
    /** 点 socket 卡片上 switch 时，把"按页面配置要做什么"写进日志用 */
    fun summary(): String =
        "card=$cardMode mode=$mode tun_ip=$tunIp mtu=$mtu route_ttl=${routeTtl}s dhcp=${if (dhcpEnabled) "开（尚未实现）" else "关"}"

    fun toJson(): String = JSONObject().apply {
        put("cardMode", cardMode)
        put("tunIp", tunIp)
        put("mode", mode)
        put("mtu", mtu)
        put("routeTtl", routeTtl)
        put("dhcpEnabled", dhcpEnabled)
        put("dhcpPool", dhcpPool)
        put("dhcpGateway", dhcpGateway)
        put("dhcpDns", dhcpDns)
    }.toString()

    companion object {
        const val CARD_NONE = "none"
        const val CARD_TUN = "tun"
        const val CARD_TAP = "tap"
        const val MODE_L2 = "l2"
        const val MODE_L3 = "l3"
        const val MODE_AUTO = "auto"

        val CARD_IDS = listOf(CARD_NONE, CARD_TUN, CARD_TAP)
        val MODE_IDS = listOf(MODE_L2, MODE_L3, MODE_AUTO)

        fun fromJson(json: String?): SwitchPageConfig {
            if (json.isNullOrBlank()) return SwitchPageConfig()
            return try {
                val o = JSONObject(json)
                val card = o.optString("cardMode", CARD_TUN)
                val mode = o.optString("mode", MODE_L3)
                SwitchPageConfig(
                    cardMode = if (card in CARD_IDS) card else CARD_TUN,
                    tunIp = o.optString("tunIp", "192.168.250.55/24"),
                    mode = if (mode in MODE_IDS) mode else MODE_L3,
                    mtu = o.optString("mtu", "1400"),
                    routeTtl = o.optString("routeTtl", "300"),
                    dhcpEnabled = o.optBoolean("dhcpEnabled", false),
                    dhcpPool = o.optString("dhcpPool", "192.168.250.100-192.168.250.200"),
                    dhcpGateway = o.optString("dhcpGateway", "192.168.250.55"),
                    dhcpDns = o.optString("dhcpDns", "192.168.250.55")
                )
            } catch (_: Exception) {
                SwitchPageConfig()
            }
        }
    }
}

/**
 * Proxy 页（端口转发）的配置：**一条洞 ↔ 一个固定端口**，按 ssh 的习惯分正/反向。
 *
 * 两种模式各只负责**本机这一侧**（另一半要靠对端配合）：
 *  - **正向 `-L`（本机 listen）**：本机监听 [lListenIp]:[lListenPort]，accept 之后
 *    收到的数据丢进洞里；来自洞里的数据回给这条连接。
 *  - **反向 `-R`（本机 connect）**：本机主动 connect [rTargetHost]:[rTargetPort]，
 *    和洞之间互转数据。**这正是 python 端 client/app/proxy.py 的行为**（它只有 connect 侧）。
 *
 * 公共参数：协议（对齐 `--proto`）、保活间隔（对齐 `KEEPALIVE_INTERVAL = 20`，
 * 每 20s 往对端发一个空包防止 NAT 映射过期）、洞的绑定地址与端口（对齐 `--localaddr` / `--localport`）。
 *
 * ⚠️ 两端要配对才有意义：一端 `-L`（listen）+ 另一端 `-R`（connect），洞在中间当管道。
 * 单端只跑 `-L` 是把本机流量灌进洞、没人接就丢了；单端只跑 `-R` 就是 proxy.py（等洞里来流量）。
 */
data class ProxyPageConfig(
    /** [MODE_L] 正向（本机 listen）/ [MODE_R] 反向（本机 connect） */
    val mode: String = MODE_R,
    /** tcp / udp（对齐 proxy.py 的 --proto） */
    val proto: String = PROTO_TCP,
    /** NAT 保活间隔（秒），对齐 proxy.py 的 KEEPALIVE_INTERVAL = 20 */
    val keepaliveSec: String = "20",
    /** 洞 socket 的绑定地址（对齐 --localaddr） */
    val bindAddr: String = "0.0.0.0",
    /** 洞的本机端口，空 = 用这条 session 实际打洞出来的端口（推荐留空） */
    val localPort: String = "",
    // ── 仅 -L 模式用：本机 listen ──
    /** 本机监听地址（127.0.0.1 = 只有本机应用能连；0.0.0.0 = 局域网也能连） */
    val lListenIp: String = "127.0.0.1",
    /** 本机监听端口，0 = 让系统自动挑一个空闲端口 */
    val lListenPort: String = "8080",
    // ── 仅 -R 模式用：本机 connect ──
    /** 要 connect 的目标地址（本机视角，通常是 127.0.0.1 上的某个服务） */
    val rTargetHost: String = "127.0.0.1",
    /** 要 connect 的目标端口（必填，例如 3389 远程桌面 / 22 SSH） */
    val rTargetPort: String = ""
) {
    /** 点 socket 卡片上 proxy 时，把"按页面配置要做什么"写进日志用 */
    fun summary(): String {
        val holePort = localPort.toIntOrNull() ?: 0
        val hole = if (holePort == 0) "$bindAddr:自动" else formatHostPort(bindAddr, holePort)
        val modeText = if (mode == MODE_L) "正向 -L" else "反向 -R"
        val side = if (mode == MODE_L) {
            val p = lListenPort.toIntOrNull() ?: 0
            "本机监听=" + (if (p == 0) "$lListenIp:自动" else formatHostPort(lListenIp, p))
        } else {
            val p = rTargetPort.toIntOrNull() ?: 0
            "本机connect=" + (if (p == 0) "$rTargetHost:(端口未填)" else formatHostPort(rTargetHost, p))
        }
        return "mode=$modeText proto=$proto 洞=$hole keepalive=${keepaliveSec}s $side"
    }

    fun toJson(): String = JSONObject().apply {
        put("mode", mode)
        put("proto", proto)
        put("keepaliveSec", keepaliveSec)
        put("bindAddr", bindAddr)
        put("localPort", localPort)
        put("lListenIp", lListenIp)
        put("lListenPort", lListenPort)
        put("rTargetHost", rTargetHost)
        put("rTargetPort", rTargetPort)
    }.toString()

    companion object {
        const val PROTO_TCP = "tcp"
        const val PROTO_UDP = "udp"
        val PROTO_IDS = listOf(PROTO_TCP, PROTO_UDP)

        /** 正向 / 本机 listen（ssh -L 的本机那一半） */
        const val MODE_L = "L"
        /** 反向 / 本机 connect（ssh -R 的本机那一半，也是 proxy.py 的行为） */
        const val MODE_R = "R"
        val MODE_IDS = listOf(MODE_L, MODE_R)

        fun modeLabel(id: String): String = if (id == MODE_L) "正向 -L" else "反向 -R"

        fun fromJson(json: String?): ProxyPageConfig {
            if (json.isNullOrBlank()) return ProxyPageConfig()
            return try {
                val o = JSONObject(json)
                val proto = o.optString("proto", PROTO_TCP)
                val mode = o.optString("mode", MODE_R)
                ProxyPageConfig(
                    mode = if (mode in MODE_IDS) mode else MODE_R,
                    proto = if (proto in PROTO_IDS) proto else PROTO_TCP,
                    keepaliveSec = o.optString("keepaliveSec", "20"),
                    bindAddr = o.optString("bindAddr", "0.0.0.0"),
                    localPort = o.optString("localPort", ""),
                    lListenIp = o.optString("lListenIp", "127.0.0.1"),
                    lListenPort = o.optString("lListenPort", "8080"),
                    rTargetHost = o.optString("rTargetHost", "127.0.0.1"),
                    rTargetPort = o.optString("rTargetPort", "")
                )
            } catch (_: Exception) {
                ProxyPageConfig()
            }
        }
    }
}

/**
 * VPN 页（一对一）的配置，对应 python 端 client/app/vpn.py：**一个洞 ↔ 一块 tun/tap**。
 *
 * 和 [SwitchPageConfig] 是同一套字段（所以两页看起来一致），但**分开存**，
 * 改 vpn 页不会动到 switch 页。区别只在页面形态：vpn 是一对一，没有网口那排。
 */
data class VpnPageConfig(
    /** none = 不开本机接口，tun = 三层，tap = 二层 */
    val cardMode: String = CARD_TUN,
    /** 配到 tun/tap 上的地址，可写 "10.0.0.2" 或 "10.0.0.2/24" */
    val tunIp: String = "10.0.0.2/24",
    /** l2 / l3 / auto（一对一其实用不到，先跟 switch 保持一致） */
    val mode: String = MODE_L3,
    /** 洞是 IP over UDP，1500 的包套上 UDP/IP 头会分片，所以默认 1400；0 = 不改 */
    val mtu: String = "1400",
    /** 路由老化（秒；0 = 不老化） */
    val routeTtl: String = "300",
    val dhcpEnabled: Boolean = false,
    val dhcpPool: String = "10.0.0.100-10.0.0.200",
    val dhcpGateway: String = "10.0.0.1",
    val dhcpDns: String = "10.0.0.1"
) {
    /** 点 socket 卡片上 tun 时，把"按页面配置要做什么"写进日志用 */
    fun summary(): String =
        "card=$cardMode tun_ip=$tunIp mode=$mode mtu=$mtu route_ttl=${routeTtl}s " +
            "dhcp=${if (dhcpEnabled) "开（尚未实现）" else "关"}"

    fun toJson(): String = JSONObject().apply {
        put("cardMode", cardMode)
        put("tunIp", tunIp)
        put("mode", mode)
        put("mtu", mtu)
        put("routeTtl", routeTtl)
        put("dhcpEnabled", dhcpEnabled)
        put("dhcpPool", dhcpPool)
        put("dhcpGateway", dhcpGateway)
        put("dhcpDns", dhcpDns)
    }.toString()

    companion object {
        const val CARD_NONE = "none"
        const val CARD_TUN = "tun"
        const val CARD_TAP = "tap"
        const val MODE_L2 = "l2"
        const val MODE_L3 = "l3"
        const val MODE_AUTO = "auto"

        val CARD_IDS = listOf(CARD_NONE, CARD_TUN, CARD_TAP)
        val MODE_IDS = listOf(MODE_L2, MODE_L3, MODE_AUTO)

        fun fromJson(json: String?): VpnPageConfig {
            if (json.isNullOrBlank()) return VpnPageConfig()
            return try {
                val o = JSONObject(json)
                val card = o.optString("cardMode", CARD_TUN)
                val mode = o.optString("mode", MODE_L3)
                VpnPageConfig(
                    cardMode = if (card in CARD_IDS) card else CARD_TUN,
                    tunIp = o.optString("tunIp", "10.0.0.2/24"),
                    mode = if (mode in MODE_IDS) mode else MODE_L3,
                    mtu = o.optString("mtu", "1400"),
                    routeTtl = o.optString("routeTtl", "300"),
                    dhcpEnabled = o.optBoolean("dhcpEnabled", false),
                    dhcpPool = o.optString("dhcpPool", "10.0.0.100-10.0.0.200"),
                    dhcpGateway = o.optString("dhcpGateway", "10.0.0.1"),
                    dhcpDns = o.optString("dhcpDns", "10.0.0.1")
                )
            } catch (_: Exception) {
                VpnPageConfig()
            }
        }
    }
}

/**
 * media 页（多媒体聊天）的配置，对应 python 端 client/app/media.py + app/ffmpeg.sh。
 *
 * 分工：**我们的程序只负责打洞**；打好了把这条洞的参数交给聊天程序，由它收发流。
 *
 * ⚠️ 所以这一页里**没有地址和端口可填** —— 它们是打洞结果带出来的（洞的本机侧 / 对端侧），
 * 双方端口是打洞时定下来的，不一定是 1935（RTMP 的默认端口在这里没有意义）：
 *   - 收流：对方推到我这里 → 本机收流地址 = 洞的本机侧；对方要推往的地址 = 服务器看到的我的地址
 *   - 推流：我推给对端     → 目标 = 洞的对端侧
 * 这一页只让人选：协议、采集来源、拉起哪个应用。
 *
 * ⚠️ 经洞那一段只能是 UDP（洞本身就是 UDP 端口），所以要封装（mpegts / RTP）——
 * python 的 ffmpeg.sh 就是这么干的：`udp://:PORT?listen=1` ↔ `udp://对端:端口@本机:端口`。
 * rtmp/rtsp 这类需要 TCP 的协议只用在"本地这一侧"（采集/播放），或者由聊天程序转封到洞上。
 */
data class MediaPageConfig(
    /** 收流协议：rtmp / rtsp / srt / udp（本地这一侧怎么收） */
    val recvProto: String = PROTO_RTMP,
    /** 推流协议：rtmp / rtsp / srt / udp（本地这一侧怎么推） */
    val sendProto: String = PROTO_RTMP,
    /** mic / camera / both：本地采集什么 */
    val capture: String = CAPTURE_BOTH,
    /** 目标聊天程序的包名（留空 = 只按 action 找） */
    val appPackage: String = "",
    /** 约定的 action（对方 app 可以注册它来接收参数） */
    val appAction: String = DEFAULT_ACTION
) {
    fun summary(): String = "收流=$recvProto 推流=$sendProto 采集=$capture"

    fun toJson(): String = JSONObject().apply {
        put("recvProto", recvProto)
        put("sendProto", sendProto)
        put("capture", capture)
        put("appPackage", appPackage)
        put("appAction", appAction)
    }.toString()

    companion object {
        const val PROTO_RTMP = "rtmp"
        const val PROTO_RTSP = "rtsp"
        const val PROTO_SRT = "srt"
        const val PROTO_UDP = "udp"
        val PROTO_IDS = listOf(PROTO_RTMP, PROTO_RTSP, PROTO_SRT, PROTO_UDP)

        const val CAPTURE_MIC = "mic"
        const val CAPTURE_CAMERA = "camera"
        const val CAPTURE_BOTH = "both"
        val CAPTURE_IDS = listOf(CAPTURE_MIC, CAPTURE_CAMERA, CAPTURE_BOTH)

        /** 和外部聊天程序约定的 action（Android 走 Intent extras，见 MainActivity） */
        const val DEFAULT_ACTION = "com.p2pnet.action.MEDIA_CHAT"

        fun fromJson(json: String?): MediaPageConfig {
            if (json.isNullOrBlank()) return MediaPageConfig()
            return try {
                val o = JSONObject(json)
                val rp = o.optString("recvProto", PROTO_RTMP)
                val sp = o.optString("sendProto", PROTO_RTMP)
                val cap = o.optString("capture", CAPTURE_BOTH)
                MediaPageConfig(
                    recvProto = if (rp in PROTO_IDS) rp else PROTO_RTMP,
                    sendProto = if (sp in PROTO_IDS) sp else PROTO_RTMP,
                    capture = if (cap in CAPTURE_IDS) cap else CAPTURE_BOTH,
                    appPackage = o.optString("appPackage", ""),
                    appAction = o.optString("appAction", DEFAULT_ACTION).ifBlank { DEFAULT_ACTION }
                )
            } catch (_: Exception) {
                MediaPageConfig()
            }
        }
    }
}
