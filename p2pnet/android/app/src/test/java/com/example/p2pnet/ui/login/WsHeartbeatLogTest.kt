package com.example.p2pnet.ui.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * WS 协议级心跳日志的**内容与边界断言**（纯函数 JVM 单测，不需要模拟器/真机）。
 *
 * 要钉死的三条：
 *  1. 每轮 tick 只打两行：`发出协议级 ping（第 N 次…）` + `okhttp不会收到pong（…）`；
 *  2. 连接已死（`alive = false`）时**一行都不打**；
 *  3. **绝不出现"收到协议级 pong"字样** —— 防止以后有人把"推断收到"加回来。
 *
 * `println` 的内容会进 Gradle 的 JUnit XML 报告（`<system-out>`），作为原始证据。
 */
class WsHeartbeatLogTest {

    /** 每轮都该有的第二行（如实说明收不到） */
    private val disclosure = "WS 心跳：okhttp不会收到pong（OkHttp 不暴露 ping/pong 回调，无法观测应答）"

    private fun tick(sent: Int, alive: Boolean) =
        WsHeartbeatLog.linesForTick(sent, alive, intervalSeconds = 20)

    @Test
    fun tick1LogsPingAndDisclosure() {
        val lines = tick(sent = 0, alive = true)
        println("[tick 1] sent=0 alive=true -> $lines")
        assertEquals(
            listOf("WS 心跳：发出协议级 ping（第 1 次，间隔 20s）", disclosure),
            lines
        )
    }

    @Test
    fun tick2LogsPingAndDisclosure() {
        val lines = tick(sent = 1, alive = true)
        println("[tick 2] sent=1 alive=true -> $lines")
        assertEquals(
            listOf("WS 心跳：发出协议级 ping（第 2 次，间隔 20s）", disclosure),
            lines
        )
    }

    @Test
    fun tick3LogsPingAndDisclosure() {
        val lines = tick(sent = 2, alive = true)
        println("[tick 3] sent=2 alive=true -> $lines")
        assertEquals(
            listOf("WS 心跳：发出协议级 ping（第 3 次，间隔 20s）", disclosure),
            lines
        )
    }

    @Test
    fun deadConnectionLogsNothing() {
        for (sent in 0..5) {
            val lines = tick(sent = sent, alive = false)
            println("[已死] sent=$sent alive=false -> $lines")
            assertTrue("连接已死时不许有任何输出", lines.isEmpty())
        }
    }

    @Test
    fun neverLogsReceivedPong() {
        // 遍历多轮：输出里绝不许出现"收到协议级 pong"（那是无法观测的，打了就是撒谎）
        for (sent in 0..5) {
            val lines = tick(sent = sent, alive = true)
            assertTrue(
                "第 ${sent + 1} 轮不许出现'收到协议级 pong'：$lines",
                lines.none { it.contains("收到协议级 pong") }
            )
        }
        println("[反向断言] 0..5 轮输出里都没有'收到协议级 pong' ✓")
    }

    @Test
    fun threeRoundsFullSequence() {
        val log = mutableListOf<String>()
        var sent = 0
        repeat(3) {
            val lines = tick(sent = sent, alive = true)
            log += lines
            if (lines.isNotEmpty()) sent++
        }
        println("[连续三轮] 累计日志：")
        log.forEach { println("  $it") }
        assertEquals(
            listOf(
                "WS 心跳：发出协议级 ping（第 1 次，间隔 20s）",
                disclosure,
                "WS 心跳：发出协议级 ping（第 2 次，间隔 20s）",
                disclosure,
                "WS 心跳：发出协议级 ping（第 3 次，间隔 20s）",
                disclosure
            ),
            log
        )
        assertTrue("整段日志里不许有'收到协议级 pong'", log.none { it.contains("收到协议级 pong") })
    }
}
