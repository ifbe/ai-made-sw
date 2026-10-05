package com.example.p2pnet.ui.login

/**
 * "断开之后要不要自动重连 / 自动重新登录"的四端统一规则 —— **零 Android 依赖的纯逻辑**，
 * 有 JVM 单测（`app/src/test/.../AutoReconnectRulesTest.kt`）。
 *
 * 判据**只看"断开前的最后状态"**，没有任何"被踢标记"：
 *
 * | 断开前最后状态 | 自动重连 | 自动重新登录 |
 * |---|---|---|
 * | 用户主动断开 | ❌ | ❌ |
 * | 已登录 | ✅ | ✅（还需要凭据还在，见调用方） |
 * | 已连接未登录 | ✅ | ❌ |
 *
 * **被踢不需要单列规则**：踢的作用就是把状态从"已登录"打回"已连接未登录"
 * （连接不断），之后掉线自然落进"已连接未登录"那一行；用户之后手动登录成功，
 * 状态又变回"已登录"，再掉线自然又会自动重登 —— **状态即真相**。
 *
 * ⚠️ 另外：**"被踢"不是断开**（服务器只取消登录状态，socket 不关、仍可收发），
 * 所以它根本不产生 [DisconnectReason]，也进不了重连逻辑（心跳/连接都不动）。
 */
internal enum class DisconnectReason { MANUAL, PASSIVE }

internal object AutoReconnectRules {

    /** 断开的两种原因：用户手动断开 → MANUAL，其余（含心跳失败/异常断开）→ PASSIVE */
    fun classify(userDisconnected: Boolean): DisconnectReason =
        if (userDisconnected) DisconnectReason.MANUAL else DisconnectReason.PASSIVE

    /** 只有"其他被动断开"才自动重连（被踢不在此列 —— 它不产生断开） */
    fun shouldReconnect(reason: DisconnectReason): Boolean = reason == DisconnectReason.PASSIVE

    /**
     * 是否自动重新登录：被动断开 **且断开前是"已登录"状态**。
     * @param wasLoggedInBeforeDrop 断开那一刻的登录状态（状态即真相，不看任何"被踢标记"）
     */
    fun shouldRelogin(reason: DisconnectReason, wasLoggedInBeforeDrop: Boolean): Boolean =
        reason == DisconnectReason.PASSIVE && wasLoggedInBeforeDrop
}
