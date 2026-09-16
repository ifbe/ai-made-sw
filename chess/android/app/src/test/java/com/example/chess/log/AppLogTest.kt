package com.example.chess.log

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 日志环形缓冲 + 监听通知，纯 JVM。 */
class AppLogTest {

    @Test
    fun `keeps the newest lines and trims the oldest`() {
        AppLog.clear()
        repeat(250) { AppLog.log("第 $it 行") }

        val lines = AppLog.snapshot()
        assertEquals(200, lines.size)
        assertTrue(lines.first().endsWith("第 50 行"))
        assertTrue(lines.last().endsWith("第 249 行"))
        AppLog.clear()
    }

    @Test
    fun `listeners get every update and can be removed`() {
        AppLog.clear()
        val seen = ArrayList<List<String>>()
        val listener: (List<String>) -> Unit = { seen += it }
        AppLog.addListener(listener)

        AppLog.log("连接已建立")
        AppLog.log("连接已断开")

        assertEquals(2, seen.size)
        assertTrue(seen.last().last().endsWith("连接已断开"))

        AppLog.removeListener(listener)
        AppLog.log("不该再收到")
        assertEquals(2, seen.size)
        AppLog.clear()
    }

    @Test
    fun `a new listener immediately receives the backlog`() {
        AppLog.clear()
        AppLog.log("旧日志")
        val seen = ArrayList<List<String>>()
        AppLog.addListener { seen += it }

        assertEquals(1, seen.size)
        assertTrue(seen.first().first().endsWith("旧日志"))
        AppLog.clear()
    }
}
