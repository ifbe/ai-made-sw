package com.example.p2pnet.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 配置卡首行状态文案的纯逻辑断言 —— **两套词汇分开断言**：
 * vpn / proxy 用 [channelStatusText]（通道），switch 用 [portStatusText]（网口）。
 * 特意加一条"两套不等价"的断言：防止以后有人把其中一个改成共用另一个。
 */
class ChannelStatusTextTest {

    // ── vpn / proxy：通道 ──

    @Test
    fun channelEmptyMeansNotWired() {
        assertEquals("未接线", channelStatusText(0))
        assertEquals("负数也按没接处理", "未接线", channelStatusText(-1))
        println("[通道文案] count=0（和负数） -> 未接线 ✓")
    }

    @Test
    fun channelNonEmptyShowsCount() {
        assertEquals("已接 1 条", channelStatusText(1))
        assertEquals("已接 3 条", channelStatusText(3))
        println("[通道文案] count=1 -> ${channelStatusText(1)}；count=3 -> ${channelStatusText(3)} ✓")
    }

    // ── switch：网口 ──

    @Test
    fun portEmptyMeansNotPlugged() {
        assertEquals("未插线", portStatusText(0))
        assertEquals("负数也按没插处理", "未插线", portStatusText(-1))
        println("[网口文案] count=0（和负数） -> 未插线 ✓")
    }

    @Test
    fun portNonEmptyShowsCount() {
        assertEquals("已插 1 个", portStatusText(1))
        assertEquals("已插 3 个", portStatusText(3))
        println("[网口文案] count=1 -> ${portStatusText(1)}；count=3 -> ${portStatusText(3)} ✓")
    }

    // ── 两套词汇不许被"顺手统一" ──

    @Test
    fun theTwoVocabulariesStayDistinct() {
        assertEquals("switch 空态仍用网口语", true, portStatusText(0) != channelStatusText(0))
        assertEquals("switch 非空仍用网口语", true, portStatusText(2) != channelStatusText(2))
        println("[词汇隔离] 空态：${portStatusText(0)} ≠ ${channelStatusText(0)}；非空：${portStatusText(2)} ≠ ${channelStatusText(2)} ✓")
    }
}
