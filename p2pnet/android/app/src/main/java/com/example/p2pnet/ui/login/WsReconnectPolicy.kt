package com.example.p2pnet.ui.login

/**
 * WS 自动重连的「60 秒滑窗 + 熔断」策略 —— **零 Android 依赖的纯逻辑**，
 * 便于用 JVM 单测钉死（见 `app/src/test/.../WsReconnectPolicyTest.kt`），三端规则一致：
 *
 * - 每次自动重连前先调 [recordAttempt]（传单调时钟毫秒）；返回的 1-based 序号就是日志里的"第 N 次"；
 * - **[WINDOW_MS] 滑窗内最多 [MAX_ATTEMPTS] 次**；窗口内已用满 → 返回 `null`，调用方据此打"已放弃"并停手；
 * - 一旦放弃（熔断）就**锁住**：即使时间滑过窗口、旧尝试被清出窗口，也**不再尝试**，
 *   只有 [onManualConnect]（用户手动点连接）或 [onStable]（连接稳定满窗口）才会解锁；
 * - 尝试间隔由 [delayBefore] 给出：1s → 2s → 4s。
 */
internal class WsReconnectPolicy(
    private val maxAttempts: Int = MAX_ATTEMPTS,
    private val windowMs: Long = WINDOW_MS,
    private val backoffMs: List<Long> = BACKOFF_MS
) {
    companion object {
        /** 滑窗内最多自动重连几次 */
        const val MAX_ATTEMPTS = 3

        /** 滑窗长度：60 秒 */
        const val WINDOW_MS = 60_000L

        /** 每次尝试前的等待：1s → 2s → 4s */
        val BACKOFF_MS = listOf(1_000L, 2_000L, 4_000L)
    }

    /** 窗口内的尝试时刻（单调时钟毫秒） */
    private val attemptTimes = mutableListOf<Long>()

    /** 是否已熔断（放弃自动重连，等手动连接 / 稳定存活来解锁） */
    private var givenUp = false

    /** 用户手动点"连接" → 计数清零、解除熔断 */
    fun onManualConnect() = reset()

    /** 连接稳定存活满一个窗口 → 计数清零、解除熔断 */
    fun onStable() = reset()

    private fun reset() {
        attemptTimes.clear()
        givenUp = false
    }

    /** 现在还能不能自动重连（false = 已熔断或窗口内已用满） */
    fun canAttempt(nowMs: Long): Boolean {
        prune(nowMs)
        return !givenUp && attemptTimes.size < maxAttempts
    }

    /**
     * 记录一次自动重连尝试。
     * @return 本次的 1-based 序号；**窗口内已满或已熔断 → `null`**（调用方应打"已放弃"并停止）
     */
    fun recordAttempt(nowMs: Long): Int? {
        prune(nowMs)
        if (givenUp || attemptTimes.size >= maxAttempts) {
            givenUp = true
            return null
        }
        attemptTimes += nowMs
        return attemptTimes.size
    }

    /** 第 [attemptIndex] 次（1-based）尝试前该等多久；越界取最后一个（4s） */
    fun delayBefore(attemptIndex: Int): Long =
        backoffMs[(attemptIndex - 1).coerceIn(0, backoffMs.lastIndex)]

    /** 窗口内已尝试次数（测试/日志用） */
    fun attemptsInWindow(nowMs: Long): Int {
        prune(nowMs)
        return attemptTimes.size
    }

    /** 是否已熔断 */
    fun isGivenUp(nowMs: Long): Boolean {
        prune(nowMs)
        return givenUp
    }

    private fun prune(nowMs: Long) {
        while (attemptTimes.isNotEmpty() && nowMs - attemptTimes.first() >= windowMs) {
            attemptTimes.removeAt(0)
        }
    }
}
