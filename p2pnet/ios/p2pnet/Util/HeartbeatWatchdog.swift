import Foundation

/// 心跳看门狗：`arm()` 之后如果在 `timeout` 内没有 `complete(...)`，就判定"没等到对端回包"。
///
/// **为什么必须有它**：`URLSessionWebSocketTask.sendPing` 的回调**只在两种情况下触发** ——
/// 收到 pong，或者出错。对端**不回 pong** 时（例如服务端还是老代码、不支持 WS 协议级 ping），
/// 回调**永远不触发**：既没有 `error`、也没有任何代码执行 → 既不判死也不打日志，
/// 界面就一直是"已连接"。所以必须自己拿定时器兜底（本机实测：不回 pong 时回调 12s 内从未触发）。
///
/// 用法：
/// ```swift
/// let wd = HeartbeatWatchdog(timeout: 10) { reason in /* 判死：收尾 + 日志 */ }
/// guard wd.arm() else { return }            // false = 上一轮还在等回调，本轮跳过
/// task.sendPing { error in
///     wd.complete(error)                     // nil = 收到 pong；非 nil = 出错，立即判死
/// }
/// ```
///
/// 线程安全：所有状态由 `lock` 保护，`arm/complete/cancel` 任意线程可调；
/// `onFail` 在**定时器队列或调用 `complete` 的那个线程**上回调（调用方自己决定要不要回主线程）。
nonisolated final class HeartbeatWatchdog {

    /// 超时（秒）
    let timeout: TimeInterval
    /// 判定失败时回调：超时、或 `complete(error)` 传入错误。
    /// 只会回调**一次**（超时/错误/取消之间互斥）
    private let onFail: (String) -> Void
    /// 定时器跑在哪个队列
    private let queue: DispatchQueue

    private let lock = NSLock()
    /// 一轮的定时器
    private var timer: DispatchSourceTimer?
    /// 是否还在"等这次 ping 的回调"（防重入用）
    private var pending = false
    /// 本轮是否已经判定失败过（避免重复回调）
    private var fired = false

    init(
        timeout: TimeInterval = 10,
        queue: DispatchQueue = DispatchQueue.global(qos: .utility),
        onFail: @escaping (String) -> Void
    ) {
        self.timeout = timeout
        self.queue = queue
        self.onFail = onFail
    }

    /// 发 ping 之前调用：开始计时。
    /// - Returns: `false` = 上一轮还在等回调（本轮心跳跳过，别叠加计时器）；`true` = 已开始计时
    @discardableResult
    func arm() -> Bool {
        lock.lock()
        if pending {
            lock.unlock()
            return false
        }
        pending = true
        fired = false
        let t = DispatchSource.makeTimerSource(queue: queue)
        // leeway 要小：给 1s 的话，10s 的超时可能被推到 11s 才判死（而且小超时测试会被推迟得面目全非）
        t.schedule(deadline: .now() + timeout, leeway: .milliseconds(100))
        t.setEventHandler { [weak self] in self?.fire() }
        timer?.cancel()
        timer = t
        lock.unlock()
        t.resume()
        return true
    }

    /// ping 回调里调用。
    /// - Parameter error: `nil` = 收到 pong（取消计时，什么都不做）；非 nil = 出错（取消计时并**立即**判死）
    func complete(_ error: Error?) {
        lock.lock()
        let wasPending = pending
        pending = false
        timer?.cancel()
        timer = nil
        let alreadyFired = fired
        lock.unlock()

        guard let error = error else { return }          // 收到 pong：正常
        guard wasPending, !alreadyFired else { return }   // 已经判死过 / 这轮没在等，别重复
        let nsErr = error as NSError
        onFail("sendPing 出错（\(nsErr.code): \(error.localizedDescription)）")
    }

    /// 主动取消（正常断开连接时调用）：不再计时、也不再回调
    func cancel() {
        lock.lock()
        pending = false
        fired = true
        timer?.cancel()
        timer = nil
        lock.unlock()
    }

    /// 到期：还在等回调才判死
    private func fire() {
        lock.lock()
        guard pending, !fired else {
            lock.unlock()
            return
        }
        pending = false
        fired = true
        timer?.cancel()
        timer = nil
        lock.unlock()
        onFail("看门狗超时（\(String(format: "%g", timeout))s 内没等到 pong）")
    }
}

// MARK: - WS 自动重连的熔断策略

/// WS 自动重连的「60 秒滑窗 + 最多 3 次」熔断策略（纯逻辑，Foundation-only，可单独 swiftc 编译）。
///
/// 规则（三端一致）：
///  - 重连尝试间隔 **1s → 2s → 4s**（第 4 次就直接熔断，不做）；
///  - **60 秒滑窗内最多 3 次**自动重连，超了就放弃（`beginAttempt()` 返回 nil）；
///  - 计数清零：① 用户手动点连接（`noteManualConnect()`）；② 连接稳定存活 ≥60s（`noteStable()`）；
///  - 一旦熔断（`isAbandoned`），要等上面两种清零之一才能再自动重连。
///
/// 注意：**自动重连自己不能清零**（否则熔断永远不触发）——所以重置只由手动连接 / 稳定存活触发。
nonisolated final class WsReconnectPolicy {

    /// 滑窗长度（秒）
    let window: TimeInterval
    /// 窗口内允许的最大自动重连次数
    let maxAttempts: Int
    /// 各次尝试前的等待（第 1/2/3 次）
    let delays: [TimeInterval]

    /// 一次尝试的决策
    struct Decision {
        /// 这是窗口内的第几次（从 1 起）
        let attempt: Int
        /// 等多久再发起连接
        let delay: TimeInterval
    }

    private let lock = NSLock()
    private var attemptTimes: [Date] = []
    /// 是否已熔断放弃（要等一次清零才能再试）
    private var abandoned = false
    /// 取"现在"的方式：默认系统时钟；测试里注入假时钟，才能断言 60s 滑窗
    private let now: () -> Date

    init(
        window: TimeInterval = 60,
        maxAttempts: Int = 3,
        delays: [TimeInterval] = [1, 2, 4],
        now: @escaping () -> Date = { Date() }
    ) {
        self.window = window
        self.maxAttempts = maxAttempts
        self.delays = delays
        self.now = now
    }

    /// 窗口内已记录的尝试次数
    var attemptsInWindow: Int {
        lock.lock(); defer { lock.unlock() }
        pruneLocked()
        return attemptTimes.count
    }

    /// 是否已熔断
    var isAbandoned: Bool {
        lock.lock(); defer { lock.unlock() }
        return abandoned
    }

    /// 决定"这一次能不能试"：返回 nil = 不该再试（窗口内已满 3 次 / 已熔断）
    func beginAttempt() -> Decision? {
        lock.lock(); defer { lock.unlock() }
        pruneLocked()
        if abandoned { return nil }
        if attemptTimes.count >= maxAttempts {
            abandoned = true
            return nil
        }
        attemptTimes.append(now())
        let n = attemptTimes.count
        let idx = min(max(n - 1, 0), max(delays.count - 1, 0))
        return Decision(attempt: n, delay: delays.isEmpty ? 1 : delays[idx])
    }

    /// ① 用户手动点连接 → 清零并解除熔断
    func noteManualConnect() {
        lock.lock(); defer { lock.unlock() }
        attemptTimes.removeAll()
        abandoned = false
    }

    /// ② 连接稳定存活 ≥60s → 清零并解除熔断
    func noteStable() {
        lock.lock(); defer { lock.unlock() }
        attemptTimes.removeAll()
        abandoned = false
    }

    private func pruneLocked() {
        let t = now()
        attemptTimes.removeAll { t.timeIntervalSince($0) > window }
    }
}

// MARK: - 连接/登录事件 → 是否自动重连 / 自动重登（四端统一口径）

/// 三种"会话事件"。⚠️ **被踢不是断开**：踢人只取消登录状态，连接仍然活着、仍可收发
///（服务端只发 `kicked` + 清 username + 从 `online_users` 移除，**不关 socket**）。
nonisolated enum WsSessionEvent {
    /// ① 用户主动断开（传输层被我们关掉）
    case userDisconnect
    /// ② 被服务器踢下线（**连接保持**，只是登录被取消；之后发消息会被回 `not logged in`）
    case kicked
    /// ③ 其他被动断开（心跳/看门狗判死、接收失败、被中间设备回收…）——传输层已经断了
    case passiveDrop
}

/// 四端统一的判定。
nonisolated enum WsReconnectRules {

    /// 这个事件会不会把传输层弄断？——**被踢不会**（所以收到 `kicked` 时不许关连接、
    /// 不许停心跳/看门狗；只有 ①③ 才走断开收尾）。
    static func breaksTransport(_ event: WsSessionEvent) -> Bool {
        return event != .kicked
    }

    /// 要不要排自动重连？——只有"③ 其他被动断开"需要（① 是用户自己要断，② 连接本来就没断）。
    static func shouldReconnect(_ event: WsSessionEvent) -> Bool {
        return event == .passiveDrop
    }

    /// 要不要自动重新登录？——**只看"断开前的最后状态"**：
    ///  - ① 用户主动断开 → 不重登；
    ///  - ③ 被动断开 → 断开前**已登录**才重登，断开前只是"已连接未登录"就只恢复连接。
    ///
    /// 被踢**不需要单列规则**：踢的作用就是把状态从"已登录"打回"已连接未登录"，
    /// 之后掉线自然落进"不重登"那一档 —— 状态即真相，不用额外记标记。
    static func shouldRelogin(_ event: WsSessionEvent, wasLoggedIn: Bool) -> Bool {
        return event == .passiveDrop && wasLoggedIn
    }
}
