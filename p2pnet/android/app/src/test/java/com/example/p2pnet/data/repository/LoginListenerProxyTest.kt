package com.example.p2pnet.data.repository

import com.example.p2pnet.data.remote.WsClient
import java.net.DatagramSocket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 登录期间"单槽 listener"回归点的 JVM 断言。
 *
 * 回归点（用户实测）：登录成功之后，`P2pRepository.login()` 装的一次性监听器把
 * `LoginViewModel` 的常驻监听器顶掉了，而它 `onConnected` 空实现、`onDisconnected`/`onError`
 * 被 `if (cont.isActive)` 挡住、`onKicked` 用默认空实现
 * ⇒ 关掉 4G+WiFi 后心跳失败，界面**永远显示"已连接"**、也不重连。
 *
 * [LoginListenerProxy] 就是修复：连接类事件转发给常驻监听器、数据类事件仍只走仓库钩子、
 * 登录一结束把常驻监听器装回单槽。
 */
class LoginListenerProxyTest {

    /** 记录被调用了哪些回调（顺序也记下来，便于断言"各走各家、不重复"） */
    private class Recorder : WsClient.Listener {
        val calls = mutableListOf<String>()
        override fun onConnected() { calls += "onConnected" }
        override fun onDisconnected() { calls += "onDisconnected" }
        override fun onError(message: String) { calls += "onError($message)" }
        override fun onKicked(message: String) { calls += "onKicked($message)" }
        override fun onLoginSuccess(username: String) { calls += "onLoginSuccess($username)" }
        override fun onLoginFailed(message: String) { calls += "onLoginFailed($message)" }
        override fun onSend(text: String) { calls += "onSend($text)" }
        override fun onRawMessage(text: String) { calls += "onRawMessage($text)" }
        override fun onUdpSend(text: String) { calls += "onUdpSend($text)" }
        override fun onUdpRecv(text: String) { calls += "onUdpRecv($text)" }
        override fun onUdpSocketBound(sock: DatagramSocket, localIp: String, localPort: Int) { calls += "onUdpSocketBound" }
        override fun onUdpSocketStep(
            sock: DatagramSocket,
            step: WsClient.UdpStep,
            myIp: String,
            myPort: Int,
            peerIp: String,
            peerPort: Int
        ) { calls += "onUdpSocketStep" }
        override fun onHelloDone(info: WsClient.PeerInfo?, sock: DatagramSocket?, peerIp: String, peerPort: Int, mode: String) { calls += "onHelloDone" }
        override fun onP2pDirect(from: String, ipv4: List<String>, ipv6: List<String>, isReply: Boolean) { calls += "onP2pDirect" }

        fun has(name: String) = calls.any { it.startsWith(name) }
    }

    private class Fixture {
        val persistent = Recorder()
        val hooks = Recorder()
        var restoreCount = 0
        val proxy = LoginListenerProxy(
            persistent = persistent,
            hooks = hooks,
            restoreSlot = { restoreCount++ }
        )
    }

    @Test
    fun heartbeatFailureReachesPersistentListener() {
        // 这就是用户实测那条：心跳失败（关 4G+WiFi）后 OkHttp 判死 → onError + onDisconnected
        val f = Fixture()
        f.proxy.onError("WS 心跳失败（20s 没收到 pong），连接已断开")
        f.proxy.onDisconnected()

        assertTrue("常驻监听器必须收到 onError（否则界面不会显示断开原因）", f.persistent.has("onError"))
        assertTrue("常驻监听器必须收到 onDisconnected（否则界面永远显示已连接）", f.persistent.has("onDisconnected"))
        assertTrue("登录协程那条老路径仍要 resume（仓库钩子照旧收到）", f.hooks.has("onDisconnected"))
        println("[心跳失败] 常驻监听器收到 = ${f.persistent.calls}；仓库钩子收到 = ${f.hooks.calls} ✓")
    }

    @Test
    fun kickedReachesPersistentListener() {
        // 被踢：只是登录被取消、连接不断 —— 之前也到不了界面（接口默认空实现）
        val f = Fixture()
        f.proxy.onKicked("re-login from another connection")

        assertTrue("常驻监听器必须收到 onKicked", f.persistent.has("onKicked"))
        assertFalse("被踢不是断开，不该触发 onDisconnected", f.persistent.has("onDisconnected"))
        assertEquals("被踢不该动登录协程（它已经结束了）", emptyList<String>(), f.hooks.calls)
        println("[被踢] 常驻监听器收到 = ${f.persistent.calls}；没触发 onDisconnected ✓")
    }

    @Test
    fun connectedIsForwardedToo() {
        val f = Fixture()
        f.proxy.onConnected()
        assertTrue("登录期间连上了也要让界面知道", f.persistent.has("onConnected"))
        println("[onConnected] 常驻监听器收到 = ${f.persistent.calls} ✓")
    }

    @Test
    fun dataEventsGoOnlyToHooks() {
        val f = Fixture()
        f.proxy.onSend("{\"type\":\"ping\"}")
        f.proxy.onRawMessage("{\"type\":\"pong\"}")
        f.proxy.onUdpSend("burst[0] → …")
        f.proxy.onUdpRecv("recv ← data")
        f.proxy.onP2pDirect("bob", listOf("1.2.3.4"), emptyList(), false)
        f.proxy.onHelloDone(null, null, "", 0, "udp")

        assertEquals(
            listOf("onSend", "onRawMessage", "onUdpSend", "onUdpRecv", "onP2pDirect", "onHelloDone"),
            f.hooks.calls.map { it.substringBefore('(') }
        )
        assertEquals("数据类事件不许再转给常驻监听器（会重复处理/重复打日志）", emptyList<String>(), f.persistent.calls)
        println("[数据类] 只走仓库钩子 = ${f.hooks.calls.map { it.substringBefore('(') }}；常驻监听器 0 次 ✓")
    }

    @Test
    fun slotIsRestoredWhenLoginSettles() {
        // 成功 / 失败 / 出错 / 断开 —— 四种"登录流程结束"都要把常驻监听器装回单槽
        val f = Fixture()
        f.proxy.onLoginSuccess("alice")
        f.proxy.onLoginFailed("bad password")
        f.proxy.onError("WS 连接失败")
        f.proxy.onDisconnected()
        assertEquals("四种结束方式各恢复一次单槽", 4, f.restoreCount)

        // 还在连接中/被踢/数据类事件时**不能**提前恢复（否则登录结果就收不到了）
        val g = Fixture()
        g.proxy.onConnected()
        g.proxy.onKicked("kicked")
        g.proxy.onRawMessage("x")
        assertEquals(0, g.restoreCount)
        println("[单槽恢复] 登录结束 4 次恢复；连接中/被踢/数据类 0 次 ✓")
    }

    @Test
    fun loginResultStillResumesAwaitingCoroutine() {
        // 老行为不能丢：login_ok / login_failed 仍要经仓库钩子 resume 那个挂起的协程
        val ok = Fixture()
        ok.proxy.onLoginSuccess("alice")
        assertTrue(ok.hooks.has("onLoginSuccess"))

        val bad = Fixture()
        bad.proxy.onLoginFailed("bad password")
        assertTrue(bad.hooks.has("onLoginFailed"))
        println("[登录结果] hooks 仍收到 onLoginSuccess / onLoginFailed ✓")
    }
}
