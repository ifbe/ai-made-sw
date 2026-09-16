package com.example.chess.net

import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.URI

/** 地址相关的小工具：找本机局域网 IP、把用户输入变成 ws:// 地址。 */
object NetAddress {

    const val DEFAULT_PORT = 8765

    /** 本机局域网 IPv4：优先 192.168.*，没有再退到其它私有网段。 */
    fun localIpv4(): String? {
        val found = ArrayList<String>()
        runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().forEach { nif ->
                if (!nif.isUp || nif.isLoopback) return@forEach
                nif.inetAddresses.toList().forEach { address ->
                    if (address is Inet4Address && !address.isLoopbackAddress && address.isSiteLocalAddress) {
                        address.hostAddress?.let { found += it }
                    }
                }
            }
        }
        return found.firstOrNull { it.startsWith("192.168.") } ?: found.firstOrNull()
    }

    /** 服务端模式下文本框里显示的地址。 */
    fun serverAddress(port: Int = DEFAULT_PORT): String = "${localIpv4() ?: "本机没连局域网"}:$port"

    /** 从「ip:端口」里取端口；没写或不合法就用默认端口。 */
    fun portOf(text: String?, defaultPort: Int = DEFAULT_PORT): Int {
        val raw = text?.trim().orEmpty()
        val colon = raw.lastIndexOf(':')
        if (colon < 0) return defaultPort
        val port = raw.substring(colon + 1).toIntOrNull() ?: return defaultPort
        return if (port in 1..65535) port else defaultPort
    }

    /**
     * 用户输入 → ws 地址。允许省略 `ws://` 前缀，也允许不写端口（补默认端口）。
     * 不合法返回 null。
     */
    fun toWsUri(text: String?, defaultPort: Int = DEFAULT_PORT): URI? {
        val raw = text?.trim().orEmpty()
        if (raw.isEmpty()) return null

        val withScheme = if (raw.startsWith("ws://") || raw.startsWith("wss://")) raw else "ws://$raw"
        val uri = runCatching { URI(withScheme) }.getOrNull() ?: return null
        val host = uri.host
        if (host.isNullOrEmpty()) return null

        return if (uri.port == -1) {
            runCatching { URI("${uri.scheme}://$host:$defaultPort") }.getOrNull()
        } else {
            uri
        }
    }
}
