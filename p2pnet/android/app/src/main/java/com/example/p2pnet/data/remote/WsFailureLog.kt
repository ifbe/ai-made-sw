package com.example.p2pnet.data.remote

import java.net.SocketTimeoutException

/**
 * `WsClient.onFailure` 该给用户报什么 —— 抽成纯函数（零 Android 依赖，可 JVM 单测）。
 *
 * 背景（用户实测）：点「断开」后日志/界面出现 `WS 连接失败：connection failed`。
 * 那是因为 `disconnectOnly()` 用了**优雅关闭** `ws.close(1000, "bye")`（等对端回 close 帧），
 * 而对端没回 close 帧就 FIN/RST 时，OkHttp 会以 **onFailure** 收尾：
 * - 对端优雅 FIN → `java.io.EOFException`（**message 为 null**）⇒ 打印兜底串 `connection failed`（就是用户看到的那串）；
 * - 对端 RST → `java.net.SocketException("Connection reset")`；
 * - 只有对端**正常回了 close 帧**才会走 `onClosing` → `onClosed`（没有"失败"）。
 *
 * 所以必须区分"这次失败是不是**我们自己 close()** 造成的"：自己断的不该报"连接失败"。
 */
internal object WsFailureLog {

    /** 协议级心跳（20s 间隔）没收到 pong 时，OkHttp 判死的整句 */
    const val HEARTBEAT_FAILED = "WS 心跳失败（20s 没收到 pong），连接已断开"

    /** 异常没有 message 时的兜底（用户实测那串 `connection failed` 就是它） */
    const val UNKNOWN = "connection failed"

    /**
     * @param t `onFailure` 给的异常
     * @param closedByUs 这次失败是不是**我们自己主动 close()** 造成的（用户点了「断开」/登出）
     * @return 要报给用户的错误文本；**`null` = 不要报错**（这是我们主动断的，不是"连接失败"；
     *         状态照旧由 `onDisconnected` 收回到"未连接"）
     */
    fun errorText(t: Throwable, closedByUs: Boolean): String? = when {
        closedByUs -> null
        t is SocketTimeoutException -> HEARTBEAT_FAILED
        else -> "WS 连接失败：${t.message ?: UNKNOWN}"
    }
}
