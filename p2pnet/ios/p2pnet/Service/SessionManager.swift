import Foundation

/// 打洞产出的 socket 的**唯一 owner**（对应 Android `service/SessionManager.kt`）。
///
/// iOS 没有前台 Service，所以它由 `LoginViewModel` 持有（跟 ViewModel 同生命周期，见决策说明）。
///
/// 职责：
///  - 接管打洞好的 fd（`handOver`），起唯一的 1s ping/pong 循环；**fd 的唯一关闭点也在这里**
///  - 五步进度记账，通过 `observer` 在主线程把 `[UdpSessionInfo]` 推给界面（对应 Android 的 StateFlow）
///  - 第 5 行「用法」（udptest / tun / switch / wg）的挂上/摘下 —— 真协议栈都还没接，
///    只记状态 + 打日志（和 Android 那边的 usage 桩一致）
///
/// 线程模型：状态用锁保护，任何线程都能调；`observer` 一定在主线程回调；
/// ping/pong 循环跑在自己的串行队列上（阻塞式收包，不能占主线程）。
///
/// `nonisolated` 是必须的：工程开了 `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`，
/// 不加的话整个类会被推断成 MainActor 隔离，后台队列里就用不了。
/// `@unchecked Sendable`：所有可变状态都由 `lock` 保护，跨线程传给 DispatchQueue 是安全的
nonisolated final class SessionManager: @unchecked Sendable {

    /// 界面观察者：每次卡片列表变化就在主线程回调一次
    var observer: (([UdpSessionInfo]) -> Void)?
    /// 日志出口（ViewModel 接到 UDP 日志列表，并镜像进 App 内日志）
    var onLog: ((String) -> Void)?

    /// 卡片第 5 行按这个顺序出按钮（对齐 Android `SessionManager.usageIds`）
    let usageIds = ["udptest", "tun", "switch", "wg", "proxy", "media"]

    private let lock = NSLock()
    private let queue = DispatchQueue(label: "p2pnet.session", qos: .userInitiated)
    private var store: [UdpSessionInfo] = []
    /// 卡片 id → fd。只有 `handOver` 之后才有值：没有值 = 这条洞还没打通、或者已经被关掉
    private var fds: [Int64: Int32] = [:]
    /// fd → 卡片 id（WsClient 的进度事件是按 fd 找卡片的）
    private var fdToId: [Int32: Int64] = [:]
    private var activeUsage: [Int64: String] = [:]
    private var probeStarted: Set<Int64> = []
    private var seq: Int64 = 0
    /// 最近一次点 udp 的目标：socket 建好时用它把卡片挂到对应的人上
    /// （对齐 Android `LoginViewModel.pendingUdpTarget`；放这里是因为 WsClient 的回调在后台线程）
    private var pendingTarget = ""

    init() {}

    /// 用户点了某个人的 udp：记下目标，等 socket 建好时用
    func setPendingTarget(_ target: String) {
        lock.lock()
        pendingTarget = target
        lock.unlock()
    }

    // MARK: - 查询

    func sessionsSnapshot() -> [UdpSessionInfo] {
        lock.lock(); defer { lock.unlock() }
        return store
    }

    /// 出日志。**任意线程都可以调**：统一派发到主线程再回调。
    ///
    /// 为什么必须这样：`onLog` 在 ViewModel 里的落点是 `udpLog()` → 写
    /// `@Published var udpSockMessages`。后台线程写 `@Published` 会触发 SwiftUI 的
    /// "Publishing changes from background threads is not allowed"（未定义行为，实测会卡死界面）。
    /// 而调 `log()` 的线程很多是后台线程：
    ///   - `startDirect()` 里的 `DispatchQueue.global(...)` 块（枚举地址、等对方地址、超时）；
    ///   - `onDirectFromPeer()`（由 WsClient 的 WebSocket 接收线程回调）；
    ///   - `startProbe()` 的 ping/pong 探测循环（每秒 send/recv 各一条）。
    func log(_ text: String) {
        if Thread.isMainThread {
            onLog?(text)
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.onLog?(text)
            }
        }
    }

    /// 每次状态变化都推一份快照给界面
    private func publish() {
        let snapshot = sessionsSnapshot()
        DispatchQueue.main.async { [weak self] in
            self?.observer?(snapshot)
        }
    }

    // MARK: - 建卡片 / 接管 / 关闭

    /// hello socket 刚绑好：先把卡片建出来（本机绑定就能显示了）。
    /// 此刻**还没拿到 fd 的所有权**（hello 阶段 socket 归 WsClient 用），只记住它对应哪张卡。
    /// 本机地址/端口直接从 fd 上取（getsockname），省得调用方再传一遍。
    @discardableResult
    func beginHello(fd: Int32) -> Int64 {
        let localIp = UdpSocket.localIp(of: fd)
        let localPort = UdpSocket.localPort(of: fd)
        lock.lock()
        seq += 1
        let id = seq
        let target = pendingTarget
        store.append(UdpSessionInfo(
            id: id,
            target: target,
            localIp: localIp,
            localPort: localPort
        ))
        fdToId[fd] = id
        lock.unlock()
        log("ios: 接管 socket #\(id) 本机=\(formatHostPort(localIp, localPort)) 对端=\(target)")
        publish()
        return id
    }

    /// 洞打通、fd 的所有权移交过来了：记住 fd 并开始 ping/pong。
    /// （A1 定的规则没变：所有权转移之后才轮到我们管，`close`/`closeAll` 是唯一关闭点）
    func handOver(fd: Int32) {
        let localIp = UdpSocket.localIp(of: fd)
        let localPort = UdpSocket.localPort(of: fd)

        lock.lock()
        var id = fdToId[fd]
        if id == nil {
            // 没走过 beginHello（正常不会发生）→ 补一张卡
            seq += 1
            id = seq
            store.append(UdpSessionInfo(
                id: id!,
                target: pendingTarget,
                localIp: localIp,
                localPort: localPort
            ))
            fdToId[fd] = id
        }
        let sessionId = id!
        fds[sessionId] = fd
        let info = store.first { $0.id == sessionId }
        let shouldProbe = !probeStarted.contains(sessionId)
        if shouldProbe, let i = info, !i.peerPublicIp.isEmpty {
            probeStarted.insert(sessionId)
        }
        lock.unlock()

        log("ios: fd=\(fd) 所有权已接管（卡片 #\(sessionId)，本机 \(formatHostPort(localIp, localPort))）")
        publish()

        // 服务器回复（含对端地址）一般在 hello 阶段就到了，所以这里就能开探测
        if shouldProbe, let i = info, !i.peerPublicIp.isEmpty {
            startProbe(id: sessionId, fd: fd, peerIp: i.peerPublicIp, peerPort: i.peerPublicPort)
        }
    }

    /// hello 没成功：WsClient 自己已经把这个 fd 关掉了（它的 nil 分支），
    /// 这里只把映射摘掉，**绝不再 close 一次**。
    func abandonHello(fd: Int32) {
        lock.lock()
        let id = fdToId.removeValue(forKey: fd)
        if let id = id { fds.removeValue(forKey: id) }
        lock.unlock()
        if let id = id {
            log("ios: 卡片 #\(id) 的 hello 未成功（fd 已由 WsClient 关闭）")
        }
        publish()
    }

    /// 关闭一条 session（等于卡片上的 ✕）。**这是 fd 的唯一关闭点。**
    func close(_ id: Int64) {
        lock.lock()
        let fd = fds.removeValue(forKey: id)
        if let fd = fd { fdToId.removeValue(forKey: fd) }
        activeUsage.removeValue(forKey: id)
        probeStarted.remove(id)
        // direct 卡片没有 fd，只有探测状态要一起收掉
        if let waiter = directWaiters.removeValue(forKey: id) { waiter.signal() }
        directPinged.remove(id)
        directAddrSent.remove(id)
        directCards = directCards.filter { $0.value != id }
        let existed = store.contains { $0.id == id }
        store.removeAll { $0.id == id }
        lock.unlock()

        if let fd = fd, fd >= 0 { Darwin.close(fd) }
        guard existed else { return }
        log("ios: 已关闭 socket 卡片 #\(id)" + (fd != nil ? "（fd=\(fd!) 已关闭）" : "（没有 fd，只摘卡片）"))
        publish()
    }

    /// 断开连接 / 退出登录：把所有 session 收掉
    func closeAll() {
        lock.lock()
        let allFds = Array(fds.values)
        fds.removeAll()
        fdToId.removeAll()
        activeUsage.removeAll()
        probeStarted.removeAll()
        directWaiters.values.forEach { $0.signal() }
        directWaiters.removeAll()
        directPinged.removeAll()
        directAddrSent.removeAll()
        directCards.removeAll()
        let had = !store.isEmpty
        store.removeAll()
        lock.unlock()

        allFds.forEach { if $0 >= 0 { Darwin.close($0) } }
        if had { log("ios: 已关闭全部 socket（\(allFds.count) 个 fd）") }
        publish()
    }

    // MARK: - 五步进度

    /// WsClient 事件入口：按 fd 找到对应卡片再记账（对齐 Android `markStep(sock, ...)`）
    func markStep(
        fd: Int32,
        step: UdpStep,
        myIp: String = "",
        myPort: Int = 0,
        peerIp: String = "",
        peerPort: Int = 0
    ) {
        lock.lock()
        let id = fdToId[fd]
        lock.unlock()
        guard let id = id else { return }
        markStep(id: id, step: step, myIp: myIp, myPort: myPort, peerIp: peerIp, peerPort: peerPort)
    }

    private func markStep(
        id: Int64,
        step: UdpStep,
        myIp: String = "",
        myPort: Int = 0,
        peerIp: String = "",
        peerPort: Int = 0
    ) {
        var changed = false
        var startProbeNow: (fd: Int32, peerIp: String, peerPort: Int)?

        lock.lock()
        if let idx = store.firstIndex(where: { $0.id == id }) {
            let before = store[idx]
            switch step {
            case .sentToServer:
                store[idx].sentToServer = true
            case .serverReplied:
                store[idx].serverReplied = true
                store[idx].myPublicIp = myIp
                store[idx].myPublicPort = myPort
                store[idx].peerPublicIp = peerIp
                store[idx].peerPublicPort = peerPort
                // 知道对端地址了：fd 已经接管过就开始探测（第 3、4 步）
                if let fd = fds[id], !probeStarted.contains(id), !peerIp.isEmpty {
                    probeStarted.insert(id)
                    startProbeNow = (fd, peerIp, peerPort)
                }
            case .sentToPeer:
                store[idx].sentToPeer = true
            case .peerReplied:
                store[idx].peerReplied = true
            case .handedTo:
                break
            }
            changed = store[idx] != before
        }
        lock.unlock()

        if let p = startProbeNow {
            startProbe(id: id, fd: p.fd, peerIp: p.peerIp, peerPort: p.peerPort)
        }
        if changed { publish() }
    }

    // MARK: - 探测对端

    /// 打洞完成后的连通性探测：每秒给对端发一个 ping，收到回包就打第 3、4 步的勾。
    /// 一直跑到卡片被关掉为止 —— 这同时也是 udptest 用法的行为（iOS 不另起第二个循环）。
    private func startProbe(id: Int64, fd: Int32, peerIp: String, peerPort: Int) {
        log("ios: 开始探测对端 \(formatHostPort(peerIp, peerPort))")
        queue.async { [weak self] in
            guard let self = self else { return }
            var seq = 1
            var sent: [Int: Date] = [:]

            while self.isAlive(id) {
                let ping: [String: Any] = [
                    "type": "ping",
                    "seq": seq,
                    "ts": Int64(Date().timeIntervalSince1970 * 1000),
                ]
                if let data = try? JSONSerialization.data(withJSONObject: ping) {
                    sent[seq] = Date()
                    if sent.count > 100, let minKey = sent.keys.min() {
                        sent.removeValue(forKey: minKey)
                    }
                    _ = UdpSocket.send(fd: fd, data: data, ip: peerIp, port: peerPort)
                    self.log("send: \(formatHostPort(peerIp, peerPort)) \(ping)")
                    self.markStep(id: id, step: .sentToPeer)
                }

                if let pkt = self.recv(fd: fd, timeoutMs: 1000) {
                    let text = String(data: pkt, encoding: .utf8) ?? ""
                    if let json = try? JSONSerialization.jsonObject(with: pkt) as? [String: Any],
                       let type = json["type"] as? String {
                        switch type {
                        case "pong":
                            let pongSeq = json["seq"] as? Int ?? 0
                            let rtt = Int(Date().timeIntervalSince(sent[pongSeq] ?? Date()) * 1000)
                            sent.removeValue(forKey: pongSeq)
                            self.log("recv: \(formatHostPort(peerIp, peerPort)) \(text) RTT=\(rtt)ms")
                            self.markStep(id: id, step: .peerReplied)
                        case "ping":
                            let pong: [String: Any] = [
                                "type": "pong",
                                "seq": json["seq"] as? Int ?? 0,
                                "ts": json["ts"] as? Int64 ?? 0,
                            ]
                            if let pongData = try? JSONSerialization.data(withJSONObject: pong) {
                                _ = UdpSocket.send(fd: fd, data: pongData, ip: peerIp, port: peerPort)
                                self.log("recv: \(formatHostPort(peerIp, peerPort)) \(text)")
                                self.log("send: \(formatHostPort(peerIp, peerPort)) \(pong)")
                            }
                            self.markStep(id: id, step: .peerReplied)
                        default:
                            self.log("recv: \(formatHostPort(peerIp, peerPort)) \(text)")
                            self.markStep(id: id, step: .peerReplied)
                        }
                    } else {
                        self.log("recv: \(formatHostPort(peerIp, peerPort)) [\(pkt.count) bytes]")
                        self.markStep(id: id, step: .peerReplied)
                    }
                }
                seq += 1
            }
            self.log("ios: socket 卡片 #\(id) 的探测循环结束")
        }
    }

    /// 卡片还活着吗（关掉之后 fd 会被 close，循环据此退出）
    private func isAlive(_ id: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return fds[id] != nil
    }

    /// 带超时收一个包（用 poll，不阻塞死；关卡片时最多 1s 就退出）
    private func recv(fd: Int32, timeoutMs: Int32) -> Data? {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let n = poll(&pfd, 1, timeoutMs)
        guard n > 0, (pfd.revents & Int16(POLLIN)) != 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: 2048)
        let got = recvfrom(fd, &buf, buf.count, 0, nil, nil)
        guard got > 0 else { return nil }
        return Data(bytes: buf, count: got)
    }

    // MARK: - direct：地址交换 + ICMP 可达性探测（没有 socket、不建隧道）

    /// direct 的发送出口。SessionManager 不直接持有 WsClient，由 ViewModel 接到 repository 上
    /// （和 `onLog` 一个套路）。direct 只交换**地址**、协议里没有端口，所以不建 socket、不占端口。
    var sendDirect: ((String, [String], [String]) -> Void)?
    var sendDirectReply: ((String, [String], [String]) -> Void)?

    /// 对端用户名 → 卡片 id（同一个人同时只留一张卡）
    private var directCards: [String: Int64] = [:]
    /// 卡片 id → 等对方回地址的信号量（用来做 10s 超时）
    private var directWaiters: [Int64: DispatchSemaphore] = [:]
    /// 已经 ping 过的卡片（请求/应答两条消息都带地址，防重复 ping）
    private var directPinged: Set<Int64> = []
    /// 已经把自己的地址发出去的卡片（对方来要地址时不用回第二份）
    private var directAddrSent: Set<Int64> = []

    /// direct 的三步计划（和 Android `SessionManager.directPlan` / python `DIRECT_STEPS` 对齐）
    static func directPlan() -> [SessionStep] {
        [
            SessionStep(text: "1. 枚举本机地址", detail: "v4 / v6 网卡地址，过滤 loopback 和 link-local"),
            SessionStep(text: "2. 和服务器交换地址", detail: "发给服务器，等对方回地址（10s）"),
            SessionStep(text: "3. ping 对方地址", detail: "并发 ICMP，普通权限即可（不需要 root）"),
        ]
    }

    /// 新建一张 direct 卡片（无 socket、无用法按钮）
    @discardableResult
    private func newDirectCard(_ target: String) -> Int64 {
        lock.lock()
        seq += 1
        let id = seq
        store.append(UdpSessionInfo(
            id: id,
            kind: "direct",
            target: target,
            plan: Self.directPlan()
        ))
        lock.unlock()
        log("ios: [direct] 新建卡片 #\(id) target=\(target)（无 socket、不建隧道，只报可达地址）")
        publish()
        return id
    }

    /// 主动发起 direct：枚举本机地址 → 发给服务器 → 等对方回地址（10s）→ 并发 ping。
    /// 同一个对端已经有卡片时直接复用，不重复发起。
    @discardableResult
    func startDirect(_ target: String) -> Int64? {
        guard !target.isEmpty else { return nil }

        lock.lock()
        if let existing = directCards[target] {
            lock.unlock()
            log("ios: [direct] \(target) 已经有卡片 #\(existing)，不重复发起")
            return existing
        }
        lock.unlock()

        let id = newDirectCard(target)
        lock.lock()
        directCards[target] = id
        let waiter = DispatchSemaphore(value: 0)
        directWaiters[id] = waiter
        lock.unlock()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let (v4, v6) = LocalAddrs.localAddresses()
            if v4.isEmpty && v6.isEmpty {
                self.markDirectStep(id, index: 0, done: false,
                                    detail: "没枚举到可用的本机地址（只有 loopback / link-local）")
                self.setDirectNote(id, "没枚举到可用的本机地址，没发给服务器")
                self.log("ios: [direct] 本机没枚举到可用地址，放弃")
                return
            }
            self.logAddrList(header: "本机地址", v4: v4, v6: v6)
            self.markDirectStep(id, index: 0, done: true,
                                detail: "本机 \(v4.count) 个 v4 / \(v6.count) 个 v6")

            guard let sender = self.sendDirect else {
                self.markDirectStep(id, index: 1, done: false, detail: "发送通道未接好（后台服务未就绪）")
                return
            }
            self.markDirectStep(id, index: 1, done: false,
                                detail: "已把地址发给服务器，等 \(target) 回地址…")
            self.markDirectAddrSent(id)
            sender(target, v4, v6)

            // 收到地址后由 onDirectFromPeer 接着 ping；这里只负责超时
            let got = waiter.wait(timeout: .now() + .milliseconds(10_000)) == .success
            if !got {
                self.markDirectStep(id, index: 1, done: false, detail: "对方一直没回地址（10s）")
                self.setDirectNote(id, "\(target) 没回地址，直连探测中止")
                self.log("ios: [direct] \(target) 在 10s 内没回地址")
            }
            self.lock.lock()
            self.directWaiters.removeValue(forKey: id)
            self.lock.unlock()
        }
        return id
    }

    /// 收到服务器转来的 direct 消息（WsClient → ViewModel → 这里）。
    ///
    /// 请求（isReply = false）本身就带着对方的地址表，所以：
    /// - 我这边没发过地址（对方主动来找我）→ 枚举本机地址，回一份 p2pdirect_reply
    /// - 我这边已经发过（两边同时点）→ 不重复回，直接用对方这一份地址
    /// 之后不管哪种情况都进入 ping 阶段。
    func onDirectFromPeer(from: String, ipv4: [String], ipv6: [String], isReply: Bool) {
        guard !from.isEmpty else { return }
        let v4 = LocalAddrs.dedupeAddrs(ipv4)
        let v6 = LocalAddrs.dedupeAddrs(ipv6)
        let addrs = v4 + v6
        let summary = "\(v4.count) 个 v4 / \(v6.count) 个 v6"

        lock.lock()
        let existing = directCards[from]
        lock.unlock()

        if addrs.isEmpty {
            log("ios: [direct] \(from) 没给可用地址，跳过")
            if let e = existing {
                markDirectStep(e, index: 1, done: false, detail: "\(from) 没给可用地址")
                setDirectNote(e, "\(from) 没给可用地址，探测中止")
            }
            return
        }
        if let e = existing, isDirectPinged(e) {
            log("ios: [direct] \(from) 的重复消息（已经 ping 过），忽略")
            return
        }
        logAddrList(header: "收到 \(from) 的地址", v4: v4, v6: v6)

        var id = existing
        if id == nil {
            id = newDirectCard(from)
            lock.lock()
            directCards[from] = id
            lock.unlock()
        }
        guard let cardId = id else { return }

        if !isReply && !isDirectAddrSent(cardId) {
            // 对方主动来要地址，我这边没发过 → 回一份
            let (myV4, myV6) = LocalAddrs.localAddresses()
            if myV4.isEmpty && myV6.isEmpty {
                markDirectStep(cardId, index: 0, done: false, detail: "没枚举到可用的本机地址")
                setDirectNote(cardId, "没枚举到可用的本机地址，没法回给 \(from)")
                return
            }
            markDirectStep(cardId, index: 0, done: true,
                           detail: "本机 \(myV4.count) 个 v4 / \(myV6.count) 个 v6")
            if let reply = sendDirectReply {
                markDirectAddrSent(cardId)
                reply(from, myV4, myV6)
                markDirectStep(cardId, index: 1, done: true, detail: "已把本机地址回给 \(from)")
                log("ios: [direct] 已回一份地址给 \(from)")
            } else {
                markDirectStep(cardId, index: 1, done: false, detail: "发送通道未接好（后台服务未就绪）")
            }
        } else if isDirectAddrSent(cardId) {
            markDirectStep(cardId, index: 1, done: true,
                           detail: isReply ? "收到对方 \(summary)" : "对方也在找我（地址已发过）")
        } else {
            // 只收到应答、本地没有发起记录（正常不会走到）
            markDirectStep(cardId, index: 1, done: true, detail: "收到对方 \(summary)（本地没有发起记录）")
        }

        beginDirectPing(cardId, from: from, addrs: addrs)
    }

    /// 并发 ping 对方所有地址，结果写回卡片第 3 步 + note
    private func beginDirectPing(_ id: Int64, from: String, addrs: [String]) {
        lock.lock()
        guard !directPinged.contains(id) else {
            lock.unlock()
            return
        }
        directPinged.insert(id)
        let waiter = directWaiters.removeValue(forKey: id)
        lock.unlock()

        // 唤醒还在等地址的那条流程，别再报超时
        waiter?.signal()

        markDirectStep(id, index: 2, done: false, detail: "正在 ping \(addrs.count) 个地址…")
        log("ios: [direct] 开始 ping \(from) 的 \(addrs.count) 个地址")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            // 预算和 Android/python 一致：地址数 * 2 + 15 秒。
            // 每个地址本身有 1s 硬超时、16 路并发，所以这里按「实际耗时是否超预算」判定，
            // 不用另起超时线程（不可能真跑到这个数）。
            let budget = Double(addrs.count * 2 + 15)
            let started = Date()
            let results = IcmpPing.pingAll(addrs, onResult: { r in
                self.log("ios: [direct] ping \(r.ip) → \(self.pingStatusText(r))")
            }, onIgnore: { line in
                // 回包来源/id 不符：报出真实来源，用户一眼就能看出"其实不是它回的"
                self.log("ios: [direct] ping \(line)")
            })
            if Date().timeIntervalSince(started) > budget {
                self.markDirectStep(id, index: 2, done: false, detail: "ping 阶段超时（\(Int(budget))s）")
                self.setDirectNote(id, "ping 阶段超时")
                return
            }

            let reach = results.filter { $0.status == .reachable }.map { $0.ip }
            let unavailable = results.filter { $0.status == .unavailable }.count

            if !reach.isEmpty {
                self.markDirectStep(id, index: 2, done: true,
                                    detail: "\(reach.count)/\(addrs.count) 个地址可达")
                // 可达地址**一行一个**：v4 一组在前、v6 一组在后；最多列 10 条，
                // 多出来的收成一行「…还有 N 条」（渲染侧：地址行绿色，这行灰色）。
                // 注意：探测本身 ping 的是**全部**地址，这里只改"显示"，不缩小探测范围。
                let v4Reach = reach.filter { !$0.contains(":") }
                let v6Reach = reach.filter { $0.contains(":") }
                let ordered = v4Reach + v6Reach
                let maxShow = 10
                var noteLines = ordered.prefix(maxShow).map { $0 }
                if ordered.count > maxShow {
                    noteLines.append("…还有 \(ordered.count - maxShow) 条")
                }
                self.setDirectNote(id, noteLines.joined(separator: "\n"))
                self.logReachable(header: "\(from) 可达地址（\(reach.count)/\(addrs.count) 个）：", reach: reach)
            } else if unavailable == results.count && !results.isEmpty {
                // 本机跑不了 ICMP：这不是「对方不可达」，必须分开说
                self.markDirectStep(id, index: 2, done: false, detail: "本机无法执行 ping")
                self.setDirectNote(id, "本机不能发 ICMP（建不了 ICMP socket 或没权限），没法判断可达性")
                self.log("ios: [direct] 本机 ICMP 不可用，无法判断 \(from) 是否可达")
            } else {
                self.markDirectStep(id, index: 2, done: false,
                                    detail: "\(addrs.count) 个地址一个都不通（ICMP 被挡或地址不可达）")
                self.setDirectNote(id, "0/\(addrs.count) 个地址可达")
                self.log("ios: [direct] \(from) 的 \(addrs.count) 个地址一个都不通")
            }
        }
    }

    /// direct 卡片：打勾 / 改某一步的说明
    private func markDirectStep(_ id: Int64, index: Int, done: Bool, detail: String = "") {
        var changed = false
        lock.lock()
        if let idx = store.firstIndex(where: { $0.id == id }), index < store[idx].plan.count {
            if store[idx].plan[index].done != done || store[idx].plan[index].detail != detail {
                store[idx].plan[index].done = done
                store[idx].plan[index].detail = detail
                changed = true
            }
        }
        lock.unlock()
        if changed { publish() }
    }

    /// direct 卡片：写结果行
    private func setDirectNote(_ id: Int64, _ note: String) {
        var changed = false
        lock.lock()
        if let idx = store.firstIndex(where: { $0.id == id }), store[idx].note != note {
            store[idx].note = note
            changed = true
        }
        lock.unlock()
        if changed { publish() }
    }

    /// 地址列表逐条打日志：一行一个（App 内日志里好读）
    private func logAddrList(header: String, v4: [String], v6: [String]) {
        log("ios: [direct] \(header)（\(v4.count) 个 v4 / \(v6.count) 个 v6）")
        v4.forEach { log("ios: [direct]   v4 \($0)") }
        v6.forEach { log("ios: [direct]   v6 \($0)") }
    }

    /// 可达地址也一行一个
    private func logReachable(header: String, reach: [String]) {
        log("ios: [direct] \(header)")
        reach.forEach { log("ios: [direct]   \($0.contains(":") ? "v6" : "v4") \($0)") }
    }

    private func pingStatusText(_ r: IcmpPing.Result) -> String {
        switch r.status {
        case .reachable: return "通"
        case .unreachable: return "不通"
        case .unavailable: return "无法执行（\(r.detail)）"
        }
    }

    private func isDirectPinged(_ id: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return directPinged.contains(id)
    }

    private func isDirectAddrSent(_ id: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return directAddrSent.contains(id)
    }

    private func markDirectAddrSent(_ id: Int64) {
        lock.lock()
        directAddrSent.insert(id)
        lock.unlock()
    }

    // MARK: - 只画计划的流程预览（tcp / upnp）

    /// 只做展示：登记一张流程预览卡片（tcp / upnp 用）。
    /// 这两种打洞的真实逻辑都还没实现，所以这里只是把计划步骤画出来：
    /// 不建 socket、不发信令、不占用端口。（direct 是真实流程，走 startDirect）
    @discardableResult
    func previewFlow(kind: String, target: String) -> Int64 {
        lock.lock()
        seq += 1
        let id = seq
        store.append(UdpSessionInfo(
            id: id,
            kind: kind,
            target: target,
            plan: Self.flowPlan(kind),
            isPreview: true
        ))
        lock.unlock()
        log("ios: 显示 \(kind) 流程（真实逻辑尚未实现，仅预览）target=\(target)")
        publish()
        return id
    }

    static func flowPlan(_ kind: String) -> [SessionStep] {
        switch kind {
        case "tcp": return tcpFlowPlan()
        case "upnp": return upnpFlowPlan()
        default: return []
        }
    }

    /// TCP 打洞的计划步骤（文案照抄 Android `SessionManager.tcpFlowPlan`）
    static func tcpFlowPlan() -> [SessionStep] {
        [
            SessionStep(text: "1. 创建并绑定 3 个 socket",
                        detail: "a 注册 / b listen / c connect，三个绑同一本地端口（SO_REUSEADDR + SO_REUSEPORT）"),
            SessionStep(text: "2. 用 a 连服务器注册",
                        detail: "上报 username + session_key 签名，在网关上建立 NAT 映射"),
            SessionStep(text: "3. 服务器交换双方地址",
                        detail: "拿到对端 ip:port 和我的公网 ip:port"),
            SessionStep(text: "4. b listen 与 c connect 竞速",
                        detail: "accept / connect 谁先成功用谁；超时即失败（不 relay）"),
        ]
    }

    /// upnp 的计划步骤（文案照抄 Android `SessionManager.upnpFlowPlan`；
    /// 只有第 1 步里 Android 特有的 "MulticastLock" 换成了 iOS 的说法）
    static func upnpFlowPlan() -> [SessionStep] {
        [
            SessionStep(text: "1. SSDP 发现网关 IGD",
                        detail: "组播 M-SEARCH 到 239.255.255.250:1900（iOS 侧要 multicast entitlement）"),
            SessionStep(text: "2. 取设备描述，定位 WANIPConnection",
                        detail: "解析设备 XML，拿到 SOAP control URL"),
            SessionStep(text: "3. AddPortMapping 申请外部端口",
                        detail: "外部端口 → 本机 UDP 端口，并用 GetExternalIPAddress 取公网 IP"),
            SessionStep(text: "4. 把映射当作候选上报",
                        detail: "双方都成功后按 direct 的方式互相探测；退出时 DeletePortMapping 清理"),
        ]
    }

    // MARK: - 交接给用法

    /// 把卡片交给某个用法。真协议栈都还没接（wg 在阶段 3、switch 在阶段 4），
    /// 所以这里只记状态 + 打日志。返回是否成功（卡片没有活 fd / 不认识这个用法都算失败）。
    @discardableResult
    func attachUsage(_ id: Int64, usageId: String) -> Bool {
        guard usageIds.contains(usageId) else { return false }

        lock.lock()
        guard let idx = store.firstIndex(where: { $0.id == id }), fds[id] != nil else {
            lock.unlock()
            return false
        }
        let previous = activeUsage[id]
        activeUsage[id] = usageId
        store[idx].handedTo = usageId
        let info = store[idx]
        lock.unlock()

        if let previous = previous, previous != usageId {
            log("ios: 卡片 #\(id) 从 \(previous) 摘下来")
        }
        // 文案对齐 Android `usage/*.kt`（android: → ios:）
        switch usageId {
        case "udptest":
            log("ios: 交给 udptest（对端 \(formatHostPort(info.peerPublicIp, info.peerPublicPort))），ping/pong 循环已经在跑")
        case "tun":
            log("ios: tun（一对一 VPN）已接上通道（对端 \(info.peerPublicIp):\(info.peerPublicPort)，"
                + "洞本机端口 \(info.localPort)）；tun/tap 与协议栈尚未实现（TODO），配置见 vpn 页")
        case "switch":
            log("ios: switch 已插成网口（\(info.target)，本机端口 \(info.localPort)）；"
                + "转发逻辑尚未实现（TODO），配置见 switch 页")
        case "wg":
            log("ios: wg 协议栈尚未接入；当前只是把地址交给 wireguard 页"
                + "（公网 \(formatHostPort(info.myPublicIp, info.myPublicPort)) ↔ 对端 \(formatHostPort(info.peerPublicIp, info.peerPublicPort))）")
        case "proxy":
            log("ios: proxy 已挂上（对端 \(formatHostPort(info.peerPublicIp, info.peerPublicPort))，"
                + "洞本机端口 \(info.localPort)）；转发逻辑尚未实现（TODO），配置见 proxy 页")
        case "media":
            log("ios: media 已接上通道（对端 \(formatHostPort(info.peerPublicIp, info.peerPublicPort))，"
                + "洞本机端口 \(info.localPort)）；去 media 页点「拉起应用」把参数交给聊天程序")
        default:
            break
        }
        publish()
        return true
    }

    /// 摘掉当前用法，但**保留 session 和 socket**
    func detachUsage(_ id: Int64) {
        lock.lock()
        guard let idx = store.firstIndex(where: { $0.id == id }) else {
            lock.unlock()
            return
        }
        let previous = activeUsage.removeValue(forKey: id)
        store[idx].handedTo = ""
        lock.unlock()
        if let previous = previous {
            log("ios: 卡片 #\(id) 已从 \(previous) 摘下来")
        }
        publish()
    }

    /// 摘掉所有用法（关 UDP tab 时用）
    func detachAllUsages() {
        lock.lock()
        let any = activeUsage.isEmpty == false
        activeUsage.removeAll()
        for idx in store.indices { store[idx].handedTo = "" }
        lock.unlock()
        if any { log("ios: 已摘掉全部用法") }
        publish()
    }
}
