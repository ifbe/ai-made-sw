package com.example.p2pnet.service

import com.example.p2pnet.data.remote.WsClient
import com.example.p2pnet.net.UdpSession
import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.net.SessionStep
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.usage.Tun
import com.example.p2pnet.usage.UdpTest
import com.example.p2pnet.usage.Usage
import com.example.p2pnet.usage.UsageEnv
import com.example.p2pnet.usage.Vswitch
import com.example.p2pnet.usage.WireGuard
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.net.DatagramSocket

/** 打洞完成后探测对端的超时时间 */
private const val UDP_PROBE_TIMEOUT_MS = 10_000L

/**
 * 所有 P2P session 的**唯一 owner**，活在 Service 作用域里
 * （跟 Activity / ViewModel 生命周期解耦：进后台、Activity 被回收，session 都不受影响）。
 *
 * 职责：
 * - 接管打洞产出的 socket，起唯一读循环（[UdpSession.startReading]）
 * - 五步进度记账，并通过 [sessions] StateFlow 推给界面
 * - 探测对端（发给对端 → 收到回包 = 第 3、4 步）
 * - 把 session 交给 [Usage]（udptest / tun / switch / wg）
 * - 日志出口 [onLog]，由 ViewModel 接到自己的日志列表上
 */
class SessionManager(private val scope: CoroutineScope) {

    private val _sessions = MutableStateFlow<List<UdpSessionInfo>>(emptyList())
    val sessions: StateFlow<List<UdpSessionInfo>> = _sessions

    /** 日志出口（ViewModel 接上它自己的 UDP 日志列表） */
    var onLog: ((String) -> Unit)? = null

    private val live = mutableMapOf<Long, UdpSession>()
    private val probeJobs = mutableMapOf<Long, Job>()
    private val activeUsage = mutableMapOf<Long, Usage>()
    private var seq = 0L

    private val usages: Map<String, Usage> =
        listOf(UdpTest(), Tun(), Vswitch(), WireGuard()).associateBy { it.id }

    /** 卡片第 5 行按这个顺序出按钮 */
    val usageIds: List<String> = listOf("udptest", "tun", "switch", "wg")

    private val env = UsageEnv(scope) { text -> log(text) }

    fun log(text: String) {
        onLog?.invoke(text)
    }

    fun info(id: Long): UdpSessionInfo? = _sessions.value.firstOrNull { it.id == id }

    // ── 接管 / 关闭 ──

    /** 接管一个刚打洞好的 socket：建 session、起读循环、进卡片列表 */
    fun adopt(sock: DatagramSocket, target: String, localIp: String, localPort: Int): Long {
        val id = ++seq
        val session = UdpSession(
            id = id,
            target = target,
            socket = sock,
            localIp = localIp,
            localPort = localPort
        )
        live[id] = session
        _sessions.value = _sessions.value + UdpSessionInfo(
            id = id,
            target = target,
            localIp = localIp,
            localPort = localPort
        )
        session.startReading(scope)
        log("android: 接管 socket #$id 本机=$localIp:$localPort 对端=$target")
        return id
    }

    /** 关闭一条 session（等于卡片上的 ✕）。TCP 预览卡片没有真 socket，也走这里移除 */
    fun close(id: Long) {
        probeJobs.remove(id)?.cancel()
        val snapshot = info(id)
        val session = live.remove(id)
        if (session != null) {
            activeUsage.remove(id)?.detach(session)
            session.close()
        }
        if (snapshot == null && session == null) return
        _sessions.value = _sessions.value.filterNot { it.id == id }
        snapshot?.let {
            if (it.kind == "tcp") log("android: 已关闭 TCP 流程卡片（target=${it.target}）")
            else log("android: 已关闭 socket ${formatHostPort(it.localIp, it.localPort)}")
        }
    }

    /**
     * 只做展示：登记一张流程预览卡片（tcp / direct / upnp 用）。
     * 这三种打洞的真实逻辑都还没实现，所以这里只是把计划步骤画出来：
     * 不建 socket、不发信令、不占用端口。
     */
    fun previewFlow(kind: String, target: String): Long {
        val id = ++seq
        _sessions.value = _sessions.value + UdpSessionInfo(
            id = id,
            kind = kind,
            target = target,
            plan = flowPlan(kind)
        )
        log("android: 显示 $kind 流程（真实逻辑尚未实现，仅预览）target=$target")
        return id
    }

    private fun flowPlan(kind: String): List<SessionStep> = when (kind) {
        "tcp" -> tcpFlowPlan()
        "direct" -> directFlowPlan()
        "upnp" -> upnpFlowPlan()
        else -> emptyList()
    }

    /** TCP 打洞的计划步骤（对应 python 端 client/remote/tcp.py 的做法） */
    private fun tcpFlowPlan(): List<SessionStep> = listOf(
        SessionStep(
            text = "1. 创建并绑定 3 个 socket",
            detail = "a 注册 / b listen / c connect，三个绑同一本地端口（SO_REUSEADDR + SO_REUSEPORT）"
        ),
        SessionStep(
            text = "2. 用 a 连服务器注册",
            detail = "上报 username + session_key 签名，在网关上建立 NAT 映射"
        ),
        SessionStep(
            text = "3. 服务器交换双方地址",
            detail = "拿到对端 ip:port 和我的公网 ip:port"
        ),
        SessionStep(
            text = "4. b listen 与 c connect 竞速",
            detail = "accept / connect 谁先成功用谁；超时即失败（不 relay）"
        )
    )

    /** direct 的计划步骤：v4/v6 全地址交换 + 并发探测 */
    private fun directFlowPlan(): List<SessionStep> = listOf(
        SessionStep(
            text = "1. 向服务器请求交换全部地址",
            detail = "服务器向对方索取候选表，并把我的候选表转给对方"
        ),
        SessionStep(
            text = "2. 拿到双方候选地址",
            detail = "v4 公网 / v4 本机 / 全局 v6，每条带 ip:port"
        ),
        SessionStep(
            text = "3. 对每个候选并发探测",
            detail = "按地址族各建一个 socket 发 app 层 probe（无 root 做不了 ICMP ping）"
        ),
        SessionStep(
            text = "4. 第一个回包的候选胜出",
            detail = "用胜出的 socket 建 session，再在卡片上选应用"
        )
    )

    /** upnp 的计划步骤：双方各自让网关开洞，把映射当作候选 */
    private fun upnpFlowPlan(): List<SessionStep> = listOf(
        SessionStep(
            text = "1. SSDP 发现网关 IGD",
            detail = "组播 M-SEARCH 到 239.255.255.250:1900（需要 MulticastLock）"
        ),
        SessionStep(
            text = "2. 取设备描述，定位 WANIPConnection",
            detail = "解析设备 XML，拿到 SOAP control URL"
        ),
        SessionStep(
            text = "3. AddPortMapping 申请外部端口",
            detail = "外部端口 → 本机 UDP 端口，并用 GetExternalIPAddress 取公网 IP"
        ),
        SessionStep(
            text = "4. 把映射当作候选上报",
            detail = "双方都成功后按 direct 的方式互相探测；退出时 DeletePortMapping 清理"
        )
    )

    /** 断开连接 / 退出登录时把所有 session 收掉 */
    fun closeAll() {
        probeJobs.values.forEach { it.cancel() }
        probeJobs.clear()
        live.values.forEach { session ->
            activeUsage.remove(session.id)?.detach(session)
            session.close()
        }
        live.clear()
        activeUsage.clear()
        if (_sessions.value.isNotEmpty()) {
            _sessions.value = emptyList()
            log("android: 已关闭全部 UDP socket")
        }
    }

    // ── 五步进度 ──

    /** WsClient 事件入口：按 socket 实例找到对应 session 再记账 */
    fun markStep(
        sock: DatagramSocket,
        step: WsClient.UdpStep,
        myIp: String = "",
        myPort: Int = 0,
        peerIp: String = "",
        peerPort: Int = 0,
        handedTo: String = ""
    ) {
        val id = live.entries.firstOrNull { it.value.socket === sock }?.key ?: return
        markStep(id, step, myIp, myPort, peerIp, peerPort, handedTo)
    }

    private fun markStep(
        id: Long,
        step: WsClient.UdpStep,
        myIp: String = "",
        myPort: Int = 0,
        peerIp: String = "",
        peerPort: Int = 0,
        handedTo: String = ""
    ) {
        val session = live[id]
        when (step) {
            WsClient.UdpStep.SENT_TO_SERVER -> update(id) { it.copy(sentToServer = true) }
            WsClient.UdpStep.SERVER_REPLIED -> {
                session?.apply {
                    publicIp = myIp
                    publicPort = myPort
                    this.peerIp = peerIp
                    this.peerPort = peerPort
                }
                update(id) {
                    it.copy(
                        serverReplied = true,
                        myPublicIp = myIp,
                        myPublicPort = myPort,
                        peerPublicIp = peerIp,
                        peerPublicPort = peerPort
                    )
                }
                // 知道对端地址了，开始探测（第 3、4 步）
                session?.let { startProbe(it) }
            }
            WsClient.UdpStep.SENT_TO_PEER -> update(id) { it.copy(sentToPeer = true) }
            WsClient.UdpStep.PEER_REPLIED -> update(id) { it.copy(peerReplied = true) }
            WsClient.UdpStep.HANDED_TO -> update(id) { it.copy(handedTo = handedTo) }
        }
    }

    private fun update(id: Long, transform: (UdpSessionInfo) -> UdpSessionInfo) {
        var changed = false
        val list = _sessions.value.map { info ->
            if (info.id != id) {
                info
            } else {
                transform(info).also { if (it != info) changed = true }
            }
        }
        if (changed) _sessions.value = list
    }

    // ── 探测对端 ──

    /**
     * 打洞完成后的连通性探测：反复给对端发探针，收到任意回包就算连通。
     * 打勾第 3、4 步后**不做任何业务**，等用户在卡片上选用法。
     */
    private fun startProbe(session: UdpSession) {
        if (probeJobs[session.id]?.isActive == true) return
        log("android: 开始探测对端 ${formatHostPort(session.peerIp, session.peerPort)}（${UDP_PROBE_TIMEOUT_MS / 1000}s）")
        probeJobs[session.id] = scope.launch(Dispatchers.IO) {
            var probeSeq = 1
            val deadline = System.currentTimeMillis() + UDP_PROBE_TIMEOUT_MS
            while (System.currentTimeMillis() < deadline && !session.isClosed) {
                val probe = JSONObject().apply {
                    put("type", "ping")
                    put("seq", probeSeq)
                    put("ts", System.currentTimeMillis())
                }
                if (!session.sendToPeer(probe.toString().toByteArray())) {
                    log("android: 探测发包失败，停止探测")
                    return@launch
                }
                log("send: ${formatHostPort(session.peerIp, session.peerPort)} $probe")
                markStep(session.id, WsClient.UdpStep.SENT_TO_PEER)

                val got = withTimeoutOrNull(1000) { session.incoming.first() }
                if (got != null) {
                    markStep(session.id, WsClient.UdpStep.PEER_REPLIED)
                    log("recv: ${got.fromIp}:${got.fromPort} 探测成功，等待选择用法")
                    return@launch
                }
                probeSeq++
            }
            log("android: 探测超时（${UDP_PROBE_TIMEOUT_MS / 1000}s 内没收到对端回包）")
        }
    }

    // ── 交接给 usage ──

    /**
     * 把 session 交给某个用法。一个 socket 同一时刻只交给一个用法，
     * 交接前先把上一个摘掉。返回是否成功（socket 已关/用法不存在都算失败）。
     */
    fun attachUsage(id: Long, usageId: String): Boolean {
        val session = live[id] ?: return false
        val usage = usages[usageId] ?: return false
        activeUsage.remove(id)?.detach(session)
        usage.attach(session, env)
        activeUsage[id] = usage
        update(id) { it.copy(handedTo = usage.id) }
        return true
    }

    /** 摘掉当前用法（比如关掉 UDP tab），但**保留 session 和 socket** */
    fun detachUsage(id: Long) {
        val session = live[id] ?: return
        activeUsage.remove(id)?.detach(session)
        update(id) { it.copy(handedTo = "") }
    }

    /** 摘掉所有用法（关 UDP tab 时用） */
    fun detachAllUsages() {
        live.values.forEach { session -> activeUsage.remove(session.id)?.detach(session) }
        if (_sessions.value.any { it.handedTo.isNotEmpty() }) {
            _sessions.value = _sessions.value.map { it.copy(handedTo = "") }
        }
    }
}
