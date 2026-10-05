package com.example.p2pnet.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 「内嵌 DHCP」开关的**纯逻辑**约定（JVM 单测，不需要模拟器）：
 * 两页的 `dhcpEnabled` **默认必须是 `false`**（用户明确要求"默认关闭"），
 * 且这个字段就是 DHCP 卡是否渲染的唯一判据（页面里 `if (cfg.dhcpEnabled)`）。
 *
 * 这里只断言默认值与开/关的取值 —— 不碰 `fromJson`（它依赖 `org.json`，在 JVM 单测里是 mockable jar 的桩实现，
 * 断言它等于断言桩行为，没有意义）。
 */
class PageConfigDhcpDefaultsTest {

    @Test
    fun dhcpDefaultsToOffOnBothPages() {
        assertFalse("switch 页的 dhcpEnabled 默认必须是 false", SwitchPageConfig().dhcpEnabled)
        assertFalse("vpn 页的 dhcpEnabled 默认必须是 false", VpnPageConfig().dhcpEnabled)
        println("[默认值] SwitchPageConfig().dhcpEnabled = ${SwitchPageConfig().dhcpEnabled}")
        println("[默认值] VpnPageConfig().dhcpEnabled   = ${VpnPageConfig().dhcpEnabled}")
    }

    @Test
    fun toggleDecidesCardVisibility() {
        // 页面里的渲染判据就是这一个布尔：false → 不渲染 DHCP 卡，true → 渲染
        assertFalse("默认关 → 不渲染 DHCP 卡", SwitchPageConfig().dhcpEnabled)
        assertTrue("打开 → 渲染 DHCP 卡", SwitchPageConfig(dhcpEnabled = true).dhcpEnabled)
        assertFalse("vpn 默认关 → 不渲染 DHCP 卡", VpnPageConfig().dhcpEnabled)
        assertTrue("vpn 打开 → 渲染 DHCP 卡", VpnPageConfig(dhcpEnabled = true).dhcpEnabled)
        println("[渲染判据] if (cfg.dhcpEnabled) { DHCP 卡 } —— 默认 false，故默认不出现 ✓")
    }
}
