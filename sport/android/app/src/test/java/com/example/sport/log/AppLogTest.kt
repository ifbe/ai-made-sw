package com.example.sport.log

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

        AppLog.log("拖起球员")
        AppLog.log("落下球员")

        assertEquals(2, seen.size)
        assertTrue(seen.last().last().endsWith("落下球员"))

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

    @Test
    fun `sinks receive the raw message without the timestamp`() {
        AppLog.clear()
        val seen = ArrayList<String>()
        val sink: (String) -> Unit = { seen += it }
        AppLog.addSink(sink)

        AppLog.log("切到足球页")
        assertEquals(listOf("切到足球页"), seen)

        AppLog.removeSink(sink)
        AppLog.log("不该再收到")
        assertEquals(1, seen.size)
        AppLog.clear()
    }
}
