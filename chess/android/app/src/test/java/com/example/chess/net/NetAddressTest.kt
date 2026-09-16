package com.example.chess.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 地址解析：端口提取 + 用户输入转 ws 地址。纯 JVM。 */
class NetAddressTest {

    @Test
    fun `port comes from the text field and falls back to the default`() {
        assertEquals(8765, NetAddress.portOf("192.168.5.103:8765"))
        assertEquals(9000, NetAddress.portOf("192.168.5.103:9000"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.5.103"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf(""))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf(null))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.5.103:abc"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.5.103:0"))
        assertEquals(NetAddress.DEFAULT_PORT, NetAddress.portOf("192.168.5.103:99999"))
    }

    @Test
    fun `client address accepts bare host and bare host with port`() {
        assertEquals("ws://192.168.5.103:8765", NetAddress.toWsUri("192.168.5.103")?.toString())
        assertEquals("ws://192.168.5.103:9000", NetAddress.toWsUri("192.168.5.103:9000")?.toString())
        assertEquals("ws://192.168.5.103:8765", NetAddress.toWsUri("ws://192.168.5.103:8765")?.toString())
        assertEquals("ws://192.168.5.103:8765", NetAddress.toWsUri("  192.168.5.103  ")?.toString())
    }

    @Test
    fun `garbage addresses are rejected`() {
        assertNull(NetAddress.toWsUri(""))
        assertNull(NetAddress.toWsUri("   "))
        assertNull(NetAddress.toWsUri(null))
    }
}
