package com.example.p2pnet.service

import com.example.p2pnet.data.remote.WsClient
import com.example.p2pnet.net.PingStatus
import com.example.p2pnet.net.UdpSession
import com.example.p2pnet.net.UdpSessionInfo
import com.example.p2pnet.net.SessionStep
import com.example.p2pnet.net.dedupeAddrs
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.net.localAddresses
import com.example.p2pnet.net.pingAll
import com.example.p2pnet.usage.Media
import com.example.p2pnet.usage.Proxy
import com.example.p2pnet.usage.Tun
import com.example.p2pnet.usage.UdpTest
import com.example.p2pnet.usage.Usage
import com.example.p2pnet.usage.UsageEnv
import com.example.p2pnet.usage.Vswitch
import com.example.p2pnet.usage.WireGuard
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
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

/** direct：发出 p2pdirect 后等对方回地址的时间（和 python 端 STEP_RESPONSE_TIMEOUT 一致） */
private const val DIRECT_RESPONSE_TIMEOUT_MS = 10_000L

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

    companion object {
        /** direct 卡片的"可达地址"最多显示几条；超出的用一行「…还有 N 条」收尾 */
        const val DIRECT_NOTE_MAX_ADDRS = 10

        /** 上面那行收尾的前缀（界面靠它把这一行渲染成次要色，而不是绿色地址色） */
        const val DIRECT_NOTE_MORE_PREFIX = "…还有"
    }

    private val _sessions = MutableStateFlow<List<UdpSessionInfo>>(emptyList())
    val sessions: StateFlow<List<UdpSessionInfo>> = _sessions

    /** 日志出口（ViewModel 接上它自己的 UDP 日志列表） */
    var onLog: ((String) -> Unit)? = null

    private val live = mutableMapOf<Long, UdpSession>()
    private val probeJobs = mutableMapOf<Long, Job>()
    private val activeUsage = mutableMapOf<Long, Usage>()
    private var seq = 0L

    private val usages: Map<String, Usage> =
        listOf(UdpTest(), Tun(), Vswitch(), WireGuard(), Proxy(), Media()).associateBy { it.id }

    /** 卡片第 5 行按这个顺序出按钮 */
    val usageIds: List<String> = listOf("udptest", "tun", "switch", "wg", "proxy", "media")

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

    /** 关闭一条 session（等于卡片上的 ✕）。TCP / direct 卡片没有真 socket，也走这里移除 */
    fun close(id: Long) {
        probeJobs.remove(id)?.cancel()
        val snapshot = info(id)
        val session = live.remove(id)
        if (session != null) {
            activeUsage.remove(id)?.detach(session)
            session.close()
        }
        if (snapshot == null && session == null) return
        // direct 卡片没有 socket：只有父 Job、等待器和几个标记位（先取消 Job，再放掉等待器）
        directJobs.remove(id)?.cancel()
        directScopes.remove(id)
        directWaiters.remove(id)?.cancel()
        directPinged.remove(id)
        directAddrSent.remove(id)
        directCards.entries.removeAll { it.value == id }
        _sessions.value = _sessions.value.filterNot { it.id == id }
        snapshot?.let {
            when (it.kind) {
                "tcp" -> log("android: 已关闭 TCP 流程卡片（target=${it.target}）")
                "direct" -> log("android: 已关闭 direct 卡片（target=${it.target}）")
                else -> log("android: 已关闭 socket ${formatHostPort(it.localIp, it.localPort)}")
            }
        }
    }

    /**
     * 只做展示：登记一张流程预览卡片（tcp / upnp 用）。
     * 这两种打洞的真实逻辑都还没实现，所以这里只是把计划步骤画出来：
     * 不建 socket、不发信令、不占用端口。（direct 已经是真实流程，见 [startDirect]）
     */
    fun previewFlow(kind: String, target: String): Long {
        val id = ++seq
        _sessions.value = _sessions.value + UdpSessionInfo(
            id = id,
            kind = kind,
            target = target,
            plan = flowPlan(kind),
            isPreview = true
        )
        log("android: 显示 $kind 流程（真实逻辑尚未实现，仅预览）target=$target")
        return id
    }

    private fun flowPlan(kind: String): List<SessionStep> = when (kind) {
        "tcp" -> tcpFlowPlan()
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
        directJobs.values.forEach { it.cancel() }
        directJobs.clear()
        directScopes.clear()
        directWaiters.values.forEach { if (!it.isCompleted) it.cancel() }
        directWaiters.clear()
        directPinged.clear()
        directAddrSent.clear()
        directCards.clear()
        live.values.forEach { session ->
            activeUsage.remove(session.id)?.detach(session)
            session.close()
        }
        live.clear()
        activeUsage.clear()
        if (_sessions.value.isNotEmpty()) {
            _sessions.value = emptyList()
            log("android: 已关闭全部 session（socket / direct 卡片）")
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

    // ── direct：地址交换 + ICMP 可达性探测（没有 socket、不建隧道）──

    /**
     * direct 的发送出口。SessionManager 不直接持有 WsClient，由 ViewModel 接到 repository 上
     * （和 [onLog] 一个套路）。direct 只交换**地址**、协议里没有端口，所以不建 socket、不占端口。
     */
    var sendDirect: ((target: String, ipv4: List<String>, ipv6: List<String>) -> Unit)? = null
    var sendDirectReply: ((target: String, ipv4: List<String>, ipv6: List<String>) -> Unit)? = null

    /** 对端用户名 → 卡片 id（同一个人同时只留一张卡） */
    private val directCards = mutableMapOf<String, Long>()

    /** 卡片 id → 等对方回地址的等待器（用来做 10s 超时） */
    private val directWaiters = mutableMapOf<Long, CompletableDeferred<List<String>>>()

    /** 卡片 id → 父 Job：关卡片时一次取消它下面所有 direct 协程 */
    private val directJobs = mutableMapOf<Long, Job>()
    private val directScopes = mutableMapOf<Long, CoroutineScope>()

    /** 已经 ping 过的卡片（请求/应答两条消息都带地址，防重复 ping） */
    private val directPinged = mutableSetOf<Long>()

    /** 已经把自己的地址发出去的卡片（对方来要地址时不用回第二份） */
    private val directAddrSent = mutableSetOf<Long>()

    /** 每张 direct 卡片一个作用域（父 Job 挂在 service 的 scope 下，卡片关掉就整体取消） */
    private fun directScope(id: Long): CoroutineScope {
        directScopes[id]?.let { return it }
        val job = SupervisorJob(scope.coroutineContext[Job])
        val cs = CoroutineScope(scope.coroutineContext + job + Dispatchers.IO)
        directJobs[id] = job
        directScopes[id] = cs
        return cs
    }

    /** direct 的三步计划（和 python 端 client/hole/direct.py 的 DIRECT_STEPS 对齐） */
    private fun directPlan(): List<SessionStep> = listOf(
        SessionStep(text = "1. 枚举本机地址", detail = "v4 / v6 网卡地址，过滤 loopback 和 link-local"),
        SessionStep(text = "2. 和服务器交换地址", detail = "发给服务器，等对方回地址（10s）"),
        SessionStep(text = "3. ping 对方地址", detail = "并发 ICMP，普通权限即可（不需要 root）")
    )

    private fun newDirectCard(target: String): Long {
        val id = ++seq
        _sessions.value = _sessions.value + UdpSessionInfo(
            id = id,
            kind = "direct",
            target = target,
            plan = directPlan()
        )
        log("android: [direct] 新建卡片 #$id target=$target（无 socket、不建隧道，只报可达地址）")
        return id
    }

    /** direct 卡片：打勾 / 改某一步的说明 */
    private fun markDirectStep(id: Long, index: Int, done: Boolean, detail: String = "") {
        update(id) { info ->
            if (index !in info.plan.indices) {
                info
            } else {
                info.copy(plan = info.plan.mapIndexed { i, s ->
                    if (i == index) s.copy(done = done, detail = detail) else s
                })
            }
        }
    }

    /** direct 卡片：写结果行 */
    private fun setDirectNote(id: Long, note: String) = update(id) { it.copy(note = note) }

    /**
     * 地址列表打成多行日志：先一行汇总，再一行一个地址。
     * App 内日志一行一条，这样地址好读、也好单条复制。
     */
    private fun logAddrList(header: String, v4: List<String>, v6: List<String>) {
        log("android: [direct] $header（${v4.size} 个 v4 / ${v6.size} 个 v6）")
        v4.forEach { log("android: [direct]   v4 $it") }
        v6.forEach { log("android: [direct]   v6 $it") }
    }

    /** 可达地址也一行一个（地址族直接从字符串判断） */
    private fun logReachable(header: String, reach: List<String>) {
        log("android: [direct] $header")
        reach.forEach { log("android: [direct]   ${if (it.contains(':')) "v6" else "v4"} $it") }
    }

    /**
     * 主动发起 direct：枚举本机地址 → 发给服务器 → 等对方回地址（10s）→ 并发 ping。
     * 返回卡片 id；同一个对端已经有卡片时直接复用，不重复发起。
     */
    fun startDirect(target: String): Long? {
        if (target.isEmpty()) return null
        directCards[target]?.let { existing ->
            log("android: [direct] $target 已经有卡片 #$existing，不重复发起")
            return existing
        }
        val id = newDirectCard(target)
        directCards[target] = id
        val waiter = CompletableDeferred<List<String>>()
        directWaiters[id] = waiter

        directScope(id).launch {
            val (v4, v6) = localAddresses()
            if (v4.isEmpty() && v6.isEmpty()) {
                markDirectStep(id, 0, false, "没枚举到可用的本机地址（只有 loopback / link-local）")
                setDirectNote(id, "没枚举到可用的本机地址，没发给服务器")
                log("android: [direct] 本机没枚举到可用地址，放弃")
                return@launch
            }
            logAddrList("本机地址", v4, v6)
            markDirectStep(id, 0, true, "本机 ${v4.size} 个 v4 / ${v6.size} 个 v6")

            val sender = sendDirect
            if (sender == null) {
                markDirectStep(id, 1, false, "发送通道未接好（后台服务未就绪）")
                return@launch
            }
            markDirectStep(id, 1, false, "已把地址发给服务器，等 $target 回地址…")
            // 先标记「地址已发出」再真发：对方回得比这行代码快时也不会被当成「本地没有发起记录」
            directAddrSent.add(id)
            sender.invoke(target, v4, v6)

            // 收到地址后由 onDirectFromPeer 接着 ping；这里只负责超时
            val got = withTimeoutOrNull(DIRECT_RESPONSE_TIMEOUT_MS) { waiter.await() }
            if (got == null) {
                markDirectStep(id, 1, false, "对方一直没回地址（${DIRECT_RESPONSE_TIMEOUT_MS / 1000}s）")
                setDirectNote(id, "$target 没回地址，直连探测中止")
                log("android: [direct] $target 在 ${DIRECT_RESPONSE_TIMEOUT_MS / 1000}s 内没回地址")
            }
            directWaiters.remove(id)
        }
        return id
    }

    /**
     * 收到服务器转来的 direct 消息（WsClient → ViewModel → 这里）。
     *
     * 请求（isReply=false）本身就带着对方的地址表，所以：
     * - 我这边没发过地址（对方主动来找我）→ 枚举本机地址，回一份 p2pdirect_reply
     * - 我这边已经发过（两边同时点）→ 不重复回，直接用对方这一份地址
     * 之后不管哪种情况都进入 ping 阶段。
     */
    fun onDirectFromPeer(from: String, ipv4: List<String>, ipv6: List<String>, isReply: Boolean) {
        if (from.isEmpty()) return
        // 按族分别去重，这样卡片上能写清楚「几个 v4 / 几个 v6」
        val v4 = dedupeAddrs(ipv4)
        val v6 = dedupeAddrs(ipv6)
        val addrs = v4 + v6
        val addrSummary = "${v4.size} 个 v4 / ${v6.size} 个 v6"
        val existing = directCards[from]

        if (addrs.isEmpty()) {
            log("android: [direct] $from 没给可用地址，跳过")
            existing?.let {
                markDirectStep(it, 1, false, "$from 没给可用地址")
                setDirectNote(it, "$from 没给可用地址，探测中止")
            }
            return
        }
        if (existing != null && directPinged.contains(existing)) {
            log("android: [direct] $from 的重复消息（已经 ping 过），忽略")
            return
        }
        logAddrList("收到 $from 的地址", v4, v6)

        val id = existing ?: newDirectCard(from).also { directCards[from] = it }

        when {
            !isReply && !directAddrSent.contains(id) -> {
                // 对方主动来要地址，我这边没发过 → 回一份
                val (v4, v6) = localAddresses()
                if (v4.isEmpty() && v6.isEmpty()) {
                    markDirectStep(id, 0, false, "没枚举到可用的本机地址")
                    setDirectNote(id, "没枚举到可用的本机地址，没法回给 $from")
                    return
                }
                markDirectStep(id, 0, true, "本机 ${v4.size} 个 v4 / ${v6.size} 个 v6")
                val reply = sendDirectReply
                if (reply == null) {
                    markDirectStep(id, 1, false, "发送通道未接好（后台服务未就绪）")
                } else {
                    directAddrSent.add(id)
                    reply.invoke(from, v4, v6)
                    markDirectStep(id, 1, true, "已把本机地址回给 $from")
                    log("android: [direct] 已回一份地址给 $from")
                }
            }
            directAddrSent.contains(id) -> {
                markDirectStep(
                    id, 1, true,
                    if (isReply) "收到对方 $addrSummary" else "对方也在找我（地址已发过）"
                )
            }
            else -> {
                // 只收到应答、本地没有发起记录（正常不会走到）
                markDirectStep(id, 1, true, "收到对方 $addrSummary（本地没有发起记录）")
            }
        }
        beginDirectPing(id, from, addrs)
    }

    /** 并发 ping 对方所有地址，结果写回卡片（第 3 步 + [UdpSessionInfo.note]） */
    private fun beginDirectPing(id: Long, from: String, addrs: List<String>) {
        if (!directPinged.add(id)) return
        // 唤醒还在等地址的那条协程，别再报超时
        directWaiters.remove(id)?.let { if (!it.isCompleted) it.complete(addrs) }
        markDirectStep(id, 2, false, "正在 ping ${addrs.size} 个地址…")

        directScope(id).launch {
            // 预算和 python 端一致：地址数 * 2 + 15 秒
            val budgetMs = (addrs.size * 2L + 15L) * 1000L
            val results = withTimeoutOrNull(budgetMs) {
                pingAll(addrs) { r ->
                    log(
                        "android: [direct] ping ${r.ip} → " + when (r.status) {
                            PingStatus.REACHABLE -> "通"
                            PingStatus.UNREACHABLE -> "不通"
                            PingStatus.UNAVAILABLE -> "无法执行（${r.detail}）"
                        }
                    )
                }
            }
            if (results == null) {
                markDirectStep(id, 2, false, "ping 阶段超时（${budgetMs / 1000}s）")
                setDirectNote(id, "ping 阶段超时")
                return@launch
            }
            val reach = results.filter { it.status == PingStatus.REACHABLE }.map { it.ip }
            val unavailable = results.count { it.status == PingStatus.UNAVAILABLE }
            when {
                reach.isNotEmpty() -> {
                    markDirectStep(id, 2, true, "${reach.size}/${addrs.size} 个地址可达")
                    // 展示成"一行一个地址"（不折行）：v4 一组在前、v6 一组在后，
                    // 最多 DIRECT_NOTE_MAX_ADDRS 条，超出的用一行「…还有 N 条」收尾。
                    // 只影响显示，探测仍然是 ping 全部地址（见上面的 pingAll(addrs)）。
                    val ordered = reach.filter { !it.contains(':') } + reach.filter { it.contains(':') }
                    val shown = ordered.take(DIRECT_NOTE_MAX_ADDRS)
                    val rest = ordered.size - shown.size
                    val noteLines = shown + if (rest > 0) {
                        listOf("$DIRECT_NOTE_MORE_PREFIX $rest 条")
                    } else {
                        emptyList()
                    }
                    setDirectNote(id, noteLines.joinToString("\n"))
                    logReachable("$from 可达地址（${reach.size}/${addrs.size} 个）：", reach)
                }
                unavailable == results.size && results.isNotEmpty() -> {
                    // 本机不允许发 ICMP：这不是「对方不可达」，必须分开说
                    markDirectStep(id, 2, false, "本机无法执行 ping")
                    setDirectNote(id, "本机不能发 ICMP（没有 /system/bin/ping 或权限被拒），没法判断可达性")
                    log("android: [direct] 本机 ping 不可用，无法判断 $from 是否可达")
                }
                else -> {
                    markDirectStep(id, 2, false, "${addrs.size} 个地址一个都不通（ICMP 被挡或地址不可达）")
                    setDirectNote(id, "0/${addrs.size} 个地址可达")
                    log("android: [direct] $from 的 ${addrs.size} 个地址一个都不通")
                }
            }
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
