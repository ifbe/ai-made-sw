package com.example.sport.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 地址解析 / 端口提取。纯 JVM，不碰 Android。 */
class NetAddressTest {

    @Test
    fun `port comes from the text field`() {
        assertEquals(8765, NetAddress.portOf("192.168.1.7:8765"))
        assertEquals(1234, NetAddress.portOf("192.168.1.7:1234"))
        assertEquals(9999, NetAddress.portOf("  10.0.0.2:9999  "))
    }

    @Test
    fun `missing or illegal port falls back to the default`() {
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.1.7"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.1.7:abc"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf(null))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf(""))
        // 端口范围之外也算不合法
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.1.7:0"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.1.7:70000"))
    }

    @Test
    fun `ws uri gets a scheme and a port`() {
        assertEquals("ws://192.168.1.7:8765", NetAddress.toWsUri("192.168.1.7:8765").toString())
        // 不写端口 → 补默认端口
        assertEquals("ws://192.168.1.7:8765", NetAddress.toWsUri("192.168.1.7").toString())
        // 写了 scheme 就照用
        assertEquals("ws://192.168.1.7:1234", NetAddress.toWsUri("ws://192.168.1.7:1234").toString())
        // 自定义默认端口
        assertEquals("ws://192.168.1.7:9000", NetAddress.toWsUri("192.168.1.7", 9000).toString())
    }

    @Test
    fun `illegal addresses are rejected`() {
        assertNull(NetAddress.toWsUri(null))
        assertNull(NetAddress.toWsUri(""))
        assertNull(NetAddress.toWsUri("   "))
        // 没有主机名
        assertNull(NetAddress.toWsUri("ws://:8765"))
    }
}
