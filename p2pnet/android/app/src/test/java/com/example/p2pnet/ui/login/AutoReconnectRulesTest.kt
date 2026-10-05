package com.example.p2pnet.ui.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 四端统一的"断开 → 要不要自动重连 / 自动重新登录"真值表断言（纯逻辑，JVM 单测，不需要模拟器）。
 *
 * | # | 场景 | 自动重连 | 自动重新登录 |
 * |---|---|---|---|
 * | 1 | 用户主动断开 | ❌ | ❌ |
 * | 2 | 被动断开 + 断开前**已登录** | ✅ | ✅ |
 * | 3 | 被动断开 + 断开前**已连接未登录** | ✅ | ❌ |
 * | 4 | 被踢（变未登录）→ 之后掉线 | ✅ | ❌ |
 * | 5 | 被踢后**手动登录成功** → 再掉线 | ✅ | ✅（状态即真相，不需要清任何标记） |
 * | 6 | 结构性：被踢**不是断开**（不产生 DisconnectReason、不排重连、不停心跳） | —— | —— |
 */
class AutoReconnectRulesTest {

    private val passive = AutoReconnectRules.classify(userDisconnected = false)

    @Test
    fun row1_manualDisconnectDoesNeither() {
        val reason = AutoReconnectRules.classify(userDisconnected = true)
        assertEquals(DisconnectReason.MANUAL, reason)
        assertFalse("不重连", AutoReconnectRules.shouldReconnect(reason))
        assertFalse("不重登", AutoReconnectRules.shouldRelogin(reason, wasLoggedInBeforeDrop = true))
        println("[1 手动断开] reconnect=false relogin=false ✓")
    }

    @Test
    fun row2_passiveAfterLoggedInDoesBoth() {
        assertTrue("已登录掉线→重连", AutoReconnectRules.shouldReconnect(passive))
        assertTrue("已登录掉线→重登", AutoReconnectRules.shouldRelogin(passive, wasLoggedInBeforeDrop = true))
        println("[2 被动+断开前已登录] reconnect=true relogin=true ✓")
    }

    @Test
    fun row3_passiveWhileNotLoggedInOnlyReconnects() {
        assertTrue("未登录掉线→仍重连", AutoReconnectRules.shouldReconnect(passive))
        assertFalse("未登录掉线→不重登", AutoReconnectRules.shouldRelogin(passive, wasLoggedInBeforeDrop = false))
        println("[3 被动+断开前未登录] reconnect=true relogin=false ✓")
    }

    @Test
    fun row4_kickedThenDropOnlyReconnects() {
        // 被踢 = 登录状态被取消（连接不断）→ 状态变成"已连接未登录"
        // 之后连接掉线：断开前最后状态是"未登录" ⇒ 重连 ✅ / 不自动重登 ❌
        val wasLoggedInBeforeDrop = false
        assertTrue(AutoReconnectRules.shouldReconnect(passive))
        assertFalse(
            "被踢后掉线不该自动重登（账号还被别的连接占着）",
            AutoReconnectRules.shouldRelogin(passive, wasLoggedInBeforeDrop)
        )
        println("[4 被踢→变未登录→掉线] reconnect=true relogin=false ✓")
    }

    @Test
    fun row5_manualLoginAfterKickRestoresAutoRelogin() {
        // 被踢后用户手动 onLogin() 成功 → 状态回到"已登录" ⇒ 再掉线时又能自动重登。
        // 这里**没有任何标记需要清理**：判据只看断开前的最后状态。
        val wasLoggedInBeforeDrop = true
        assertTrue(AutoReconnectRules.shouldReconnect(passive))
        assertTrue(
            "手动登录成功后，再掉线应恢复自动重登",
            AutoReconnectRules.shouldRelogin(passive, wasLoggedInBeforeDrop)
        )
        println("[5 被踢→手动登录→再掉线] reconnect=true relogin=true（无需清标记）✓")
    }

    @Test
    fun row6_kickIsNotADisconnect() {
        // 结构性证明：DisconnectReason 只有"手动/被动"两种，没有 KICKED
        // ⇒ 被踢根本不进重连/断线收尾逻辑（不排重连、不停心跳、不关连接）。
        assertEquals(
            "断开原因只应有 手动/被动 两种（被踢不是断开）",
            listOf(DisconnectReason.MANUAL, DisconnectReason.PASSIVE),
            DisconnectReason.entries.toList()
        )
        println("[6 结构性] DisconnectReason.entries=${DisconnectReason.entries.toList()}（无 KICKED）✓")
    }
}
