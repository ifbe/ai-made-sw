package com.example.p2pnet.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * (a) 换 client 的竞态策略 + (b) Activity 重建时"常驻监听器"不能丢 —— 纯逻辑断言（JVM，不需要模拟器）。
 *
 * 用假对象替代 `WsClient`/`WsClient.Listener`（真类要 Android Context / OkHttp，JVM 里造不出来），
 * 但被测的 [ClientSwapPolicy] / [ClientListenerHolder] 就是生产代码本身。
 */
class ClientListenerHolderTest {

    private class FakeClient(val name: String) {
        var listener: Any? = null
        var busy = false
    }

    /** 只记录"被装到了哪个 client 上" */
    private class InstallLog {
        val calls = mutableListOf<Pair<String, Any?>>()
    }

    @Test
    fun installRemembersAndInstallsOnCurrentClient() {
        val log = InstallLog()
        val holder = ClientListenerHolder<FakeClient, String> { c, l -> log.calls += c.name to l }
        val client = FakeClient("A")
        holder.install(client, "ui-listener-1")

        assertSame("常驻监听器要被记住", "ui-listener-1", holder.persistent)
        assertEquals(listOf("A" to "ui-listener-1"), log.calls)
        println("[install] 记住 persistent=${holder.persistent}，装到 ${log.calls} ✓")
    }

    @Test
    fun singleSlotKeepsOnlyTheNewestListener() {
        val log = InstallLog()
        val holder = ClientListenerHolder<FakeClient, String> { c, l -> log.calls += c.name to l }
        val client = FakeClient("A")
        holder.install(client, "old-vm-listener")
        holder.install(client, "new-vm-listener")   // 旋转后新 VM 装上

        assertEquals("单槽：只有最新的那个生效", "new-vm-listener", holder.persistent)
        assertEquals(listOf("A" to "old-vm-listener", "A" to "new-vm-listener"), log.calls)
        println("[单槽] 旧 VM 监听器被丢弃，只剩 ${holder.persistent} ✓")
    }

    @Test
    fun rotationScenarioNewClientGetsTheNewVmListener() {
        // 旋转：新 VM init 时先装在"仓库自己那个 client"上，随后 useClient 切到服务持有的 client
        val log = InstallLog()
        val holder = ClientListenerHolder<FakeClient, String> { c, l -> log.calls += c.name to l }
        val ownClient = FakeClient("repo-own")
        val serviceClient = FakeClient("service")

        holder.install(ownClient, "new-vm-listener")   // VM init
        holder.installOn(serviceClient)                // useClient 换完 client 后重装

        assertEquals(
            "换 client 后常驻监听器必须跟过去（否则新界面永远收不到状态）",
            listOf("repo-own" to "new-vm-listener", "service" to "new-vm-listener"),
            log.calls
        )
        println("[旋转] 新 client 上装的是同一份新 VM 监听器 = ${log.calls} ✓")
    }

    @Test
    fun installOnWithoutRegisteredListenerDoesNothing() {
        val log = InstallLog()
        val holder = ClientListenerHolder<FakeClient, String> { c, l -> log.calls += c.name to l }
        holder.installOn(FakeClient("service"))
        assertNull(holder.persistent)
        assertTrue("没登记过就什么都不做", log.calls.isEmpty())
        println("[空登记] installOn 不产生任何安装动作 ✓")
    }

    @Test
    fun swapIsRefusedWhileCurrentClientIsBusy() {
        // (a) 当前 client 正在连接/已连接 → 不许换（否则这次会话被丢在背后）
        assertFalse("有活连接时不许换", ClientSwapPolicy.canSwap(currentClientBusy = true))
        assertTrue("没活连接时允许换", ClientSwapPolicy.canSwap(currentClientBusy = false))
        println("[竞态] canSwap(busy=true)=${ClientSwapPolicy.canSwap(true)}、canSwap(busy=false)=${ClientSwapPolicy.canSwap(false)} ✓")
    }

    @Test
    fun bindRaceKeepsTheConnectedClientAndDoesNotLoseListener() {
        // 场景：bind 回得晚 —— 用户已经连上了（repo 自己的 client 在忙），这时才 useClient(服务端 client)
        val log = InstallLog()
        val holder = ClientListenerHolder<FakeClient, String> { c, l -> log.calls += c.name to l }
        val ownClient = FakeClient("repo-own").apply { busy = true }   // 正在连接/已连接
        val serviceClient = FakeClient("service")
        holder.install(ownClient, "ui-listener")

        // 模拟 useClient：先问策略，再决定换不换
        val swapped = ClientSwapPolicy.canSwap(ownClient.busy)
        if (swapped) holder.installOn(serviceClient)

        assertFalse("不许换：这次会话还在 repo 自己的 client 上", swapped)
        assertEquals("只应有过 init 那一次安装（没有把监听器装到没连接的新 client 上）", listOf("repo-own" to "ui-listener"), log.calls)
        assertEquals("常驻监听器仍然指向原来的 client", "ui-listener", holder.persistent)
        println("[bind 竞态] 拒绝切换，会话与监听器都留在原 client = ${log.calls} ✓")
    }
}
