package com.example.p2pnet.ui.login

/**
 * WS **协议级**心跳该打哪两行日志 —— 抽成纯函数（**零 Android 依赖**），
 * 这样在没有模拟器的情况下也能用 JVM 单测把内容钉死（见 `app/src/test/.../WsHeartbeatLogTest.kt`）。
 *
 * 背景（**日志本身必须如实**）：OkHttp 的协议级 ping（`OkHttpClient.pingInterval`）
 * **既没有 ping 回调、也没有 pong 回调**，所以安卓端**根本无法观测到应答**。
 * 因此这里**不打"收到 pong"**（打了就是撒谎），而是**在同一轮里如实说明收不到**：
 *
 * ```
 * WS 心跳：发出协议级 ping（第 N 次，间隔 20s）
 * WS 心跳：okhttp不会收到pong（OkHttp 不暴露 ping/pong 回调，无法观测应答）
 * ```
 *
 * 两条补充事实（也写在 `doc/readme-android.md` §8）：
 *  - "发出"那行是应用侧**同节奏计时器**打的（`LoginViewModel.startWsPingLog`，20s），
 *    节奏与 OkHttp 的 ping 相同，但**不是严格同一瞬间**；
 *  - 连接仍会因"ping 20s 内没等到 pong"被 OkHttp 判死（`onFailure` → 状态收回未连接），
 *    只是**这个过程没有回调可挂**，所以我们只能写"无法观测应答"，不能写"收到/没收到"。
 */
internal object WsHeartbeatLog {

    /**
     * 一轮 tick 该打哪几行；连接已死（`alive == false`）时**一行都不打**。
     *
     * @param sentCount 这一轮 tick **之前**已经发出过的 ping 次数（第 1 轮 tick 传 0，用于算"第 N 次"）
     * @param alive 此刻 WS 连接是否仍存活（生产代码传 `WsClient.isOpen()`）
     * @param intervalSeconds 心跳间隔秒数（单一来源：`WsClient.PING_INTERVAL_SECONDS`）
     */
    fun linesForTick(sentCount: Int, alive: Boolean, intervalSeconds: Int): List<String> {
        if (!alive) return emptyList()

        return listOf(
            "WS 心跳：发出协议级 ping（第 ${sentCount + 1} 次，间隔 ${intervalSeconds}s）",
            "WS 心跳：okhttp不会收到pong（OkHttp 不暴露 ping/pong 回调，无法观测应答）"
        )
    }
}
