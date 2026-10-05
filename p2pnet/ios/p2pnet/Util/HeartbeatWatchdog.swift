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
