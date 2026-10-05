package com.example.p2pnet.data.repository

/**
 * 换 `WsClient` 的前提：**当前这个没有活连接**。
 *
 * 为什么要有这条：`P2pRepository.useClient()` 会把仓库切到另一个 client 实例，
 * 而"这次会话"（socket、连接状态、常驻监听器）是挂在**旧实例**上的。
 * 如果旧实例正在连接/已连接就换掉，这次会话就被丢在背后没人管了 ——
 * 后续 `send*` / `login` 会发到一个**没连接的**新 client 上（静默失效）。
 * 所以：有活连接就**保留当前 client**，并如实打一行系统日志。
 */
internal object ClientSwapPolicy {

    /** @param currentClientBusy 当前 client 是否已连上 / 仍在连接中 */
    fun canSwap(currentClientBusy: Boolean): Boolean = !currentClientBusy
}

/**
 * "常驻监听器"的登记处 —— **单槽**语义：谁最后 [install] 谁生效（旧的自然被丢弃），
 * 并且在**换 client 之后**把同一份监听器重新装到新 client 上。
 *
 * 为什么需要它（Activity 重建/旋转的 bug）：监听器是装在 **client 实例**上的，
 * 旋转后 `P2pRepository`/`LoginViewModel` 都是新实例，而服务里 client 的槽上还挂着**旧 VM** 的监听器
 * ⇒ 新界面收不到任何状态回调、永远显示"未连接"，旧 VM 还被 reference 住。
 * 用这个登记处 + [P2pRepository.useClient] 换完 client 就重装，就能让"状态来源"始终是当前 VM。
 *
 * 泛型是为了能在 JVM 单测里用假对象测（不依赖 Android / OkHttp）。
 */
internal class ClientListenerHolder<C : Any, L : Any>(
    /** 真正的安装动作：把监听器装到某个 client 上 */
    private val setListener: (C, L?) -> Unit
) {
    /** 当前登记的常驻监听器（没登记过就是 null） */
    var persistent: L? = null
        private set

    /** 记住并装到 [client]（单槽：先前那个监听器自然被丢弃） */
    fun install(client: C, listener: L) {
        persistent = listener
        setListener(client, listener)
    }

    /** 换 client 之后把常驻监听器装到新 client 上；没登记过就什么都不做 */
    fun installOn(client: C) {
        persistent?.let { setListener(client, it) }
    }
}
