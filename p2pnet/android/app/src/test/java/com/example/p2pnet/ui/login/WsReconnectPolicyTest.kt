package com.example.p2pnet.ui.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * WS 自动重连策略（60 秒滑窗 + 熔断）的纯逻辑断言 —— JVM 单测，不需要模拟器/真机。
 *
 * 覆盖 4 条硬规则：
 *  ① 窗口内第 1/2/3 次允许，**第 4 次不允许（已放弃）**；
 *  ② 连接稳定满 60 秒 → 计数清零（可重新尝试）；
 *  ③ 用户手动连接 → 计数清零；
 *  ④ 放弃后**不再尝试**（即使时间滑过窗口也不行）。
 * 外加间隔断言：1s / 2s / 4s。
 */
class WsReconnectPolicyTest {

    @Test
    fun windowAllowsThreeAttemptsThenGivesUp() {
        val p = WsReconnectPolicy()
        // 三次尝试都允许，序号 1/2/3
        assertEquals(1, p.recordAttempt(0L))
        assertEquals(2, p.recordAttempt(1_000L))
        assertEquals(3, p.recordAttempt(3_000L))
        println("[①] 窗口内三次尝试序号 = 1/2/3 ✓")

        // 第 4 次：不允许（返回 null），并进入"已放弃"
        assertNull("第 4 次必须不允许", p.recordAttempt(4_000L))
        assertFalse("已放弃后 canAttempt 必须为 false", p.canAttempt(5_000L))
        assertTrue("应处于已放弃状态", p.isGivenUp(5_000L))
        println("[①] 第 4 次 -> null，canAttempt=false，isGivenUp=true ✓")
    }

    @Test
    fun stableConnectionResetsCounter() {
        val p = WsReconnectPolicy()
        p.recordAttempt(0L)
        p.recordAttempt(1_000L)
        p.recordAttempt(2_000L)
        assertNull(p.recordAttempt(3_000L)) // 已放弃
        assertEquals(3, p.attemptsInWindow(3_000L))

        // 连接稳定满 60 秒 → 清零 + 解锁
        p.onStable()
        assertEquals("稳定后窗口内计数清零", 0, p.attemptsInWindow(3_000L))
        assertFalse("稳定后不再处于放弃状态", p.isGivenUp(3_000L))
        assertEquals("清零后又能从第 1 次开始", 1, p.recordAttempt(60_000L))
        println("[②] onStable() 后计数=0、可重新尝试（序号重新从 1 开始）✓")
    }

    @Test
    fun manualConnectResetsCounter() {
        val p = WsReconnectPolicy()
        p.recordAttempt(0L)
        p.recordAttempt(1_000L)
        p.recordAttempt(2_000L)
        assertNull(p.recordAttempt(3_000L)) // 已放弃

        p.onManualConnect()
        assertEquals(0, p.attemptsInWindow(3_000L))
        assertFalse(p.isGivenUp(3_000L))
        assertEquals(1, p.recordAttempt(3_100L))
        println("[③] onManualConnect() 后计数=0、可重新尝试（序号重新从 1 开始）✓")
    }

    @Test
    fun afterGivingUpNeverAttemptsAgain() {
        val p = WsReconnectPolicy()
        p.recordAttempt(0L)
        p.recordAttempt(1_000L)
        p.recordAttempt(2_000L)
        assertNull(p.recordAttempt(3_000L))

        // 即使时间滑过窗口（旧尝试会被清出），也不许再尝试
        assertNull("滑过窗口后仍不许尝试", p.recordAttempt(120_000L))
        assertNull("再久也不许", p.recordAttempt(10 * 60_000L))
        assertFalse(p.canAttempt(10 * 60_000L))
        println("[④] 放弃后 now=120s / 600s 都 -> null（锁住，不再尝试）✓")
    }

    @Test
    fun backoffIsOneTwoFourSeconds() {
        val p = WsReconnectPolicy()
        assertEquals(1_000L, p.delayBefore(1))
        assertEquals(2_000L, p.delayBefore(2))
        assertEquals(4_000L, p.delayBefore(3))
        assertEquals("越界取最后一个", 4_000L, p.delayBefore(4))
        println("[间隔] delayBefore(1/2/3) = 1000/2000/4000ms ✓")
    }

    @Test
    fun windowSlidesOutOlderAttempts() {
        val p = WsReconnectPolicy()
        assertEquals(1, p.recordAttempt(0L))
        assertEquals(2, p.recordAttempt(1_000L))
        // 再过 60s：前两次已滑出窗口，所以还能再来
        assertEquals(1, p.recordAttempt(61_000L))
        assertEquals(2, p.recordAttempt(62_000L))
        assertEquals(3, p.recordAttempt(63_000L))
        assertNull(p.recordAttempt(64_000L))
        println("[窗口] 旧尝试滑出窗口后会释放名额（1/2 → 1/2/3 → null）")
    }
}
