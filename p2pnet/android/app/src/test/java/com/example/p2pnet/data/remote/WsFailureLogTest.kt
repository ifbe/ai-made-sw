package com.example.p2pnet.data.remote

import java.io.EOFException
import java.net.SocketException
import java.net.SocketTimeoutException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * `onFailure` 上报策略的纯逻辑断言（JVM，不需要模拟器）。
 *
 * 回归点（用户实测）：点「断开」后显示 `WS 连接失败：connection failed`。
 * 用 gradle 缓存里的 okhttp-4.12.0 做过 JVM 探针复刻 `disconnectOnly()` 的 `close(1000,"bye")`：
 * - 对端不回 close 帧、优雅 FIN → `onFailure(java.io.EOFException, message=<null>)`
 *   ⇒ 我们代码的兜底串正好是 `connection failed`（就是用户看到的那串）；
 * - 对端 RST → `onFailure(java.net.SocketException, "Connection reset")`；
 * - 对端正常回 close 帧 → `onClosing` → `onClosed`（没有"失败"）。
 */
class WsFailureLogTest {

    @Test
    fun userInitiatedCloseNeverReportsFailure() {
        // 探针里的两种"自己断"的收尾，都不该报错
        assertNull("自己 close 后 OkHttp 的 EOFException 不算失败", WsFailureLog.errorText(EOFException(), closedByUs = true))
        assertNull(
            "自己 close 后对端 RST 也不算失败",
            WsFailureLog.errorText(SocketException("Connection reset"), closedByUs = true)
        )
        assertNull(
            "自己 close 后即使报心跳超时也不该刷错误",
            WsFailureLog.errorText(SocketTimeoutException(), closedByUs = true)
        )
        println("[用户主动断开] EOFException / Connection reset / 心跳超时 → 全部 null（不报错）✓")
    }

    @Test
    fun eofWithoutMessagePrintsTheFallbackUserSaw() {
        // 用户看到的那串就是这么来的：EOFException 的 message 是 null
        assertNull("前提：EOFException 没有 message", EOFException().message)
        assertEquals(
            "WS 连接失败：connection failed",
            WsFailureLog.errorText(EOFException(), closedByUs = false)
        )
        println("[用户看到的那串] EOFException + 被动断开 → \"${WsFailureLog.errorText(EOFException(), false)}\" ✓")
    }

    @Test
    fun otherFailuresStillReportedHonestly() {
        assertEquals(
            "对端 RST：把真实原因带上",
            "WS 连接失败：Connection reset",
            WsFailureLog.errorText(SocketException("Connection reset"), closedByUs = false)
        )
        assertEquals(
            "心跳超时：报心跳失败整句",
            WsFailureLog.HEARTBEAT_FAILED,
            WsFailureLog.errorText(SocketTimeoutException(), closedByUs = false)
        )
        assertEquals(
            "没有 message 的其他异常：兜底串",
            "WS 连接失败：${WsFailureLog.UNKNOWN}",
            WsFailureLog.errorText(RuntimeException(), closedByUs = false)
        )
        println("[被动断开仍如实报] Connection reset / 心跳失败 / connection failed（兜底）✓")
    }
}
