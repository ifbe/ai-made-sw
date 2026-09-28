package com.example.p2pnet.net

/**
 * v4/v6 通用的地址显示与 URL 拼接工具。
 *
 * IPv6 里冒号本身就是地址的一部分，所以「地址:端口」必须写成 `[地址]:端口`，
 * 直接拼 `$ip:$port` 会变成 `2001:db8::1:4574` 这种没法读、也没法解析的字符串。
 */

/** `1.2.3.4:5678` 或 `[2001:db8::1]:5678` */
fun formatHostPort(ip: String, port: Int): String {
    val host = ip.trim()
    return when {
        host.isEmpty() -> ":$port"
        host.contains(':') && !host.startsWith("[") -> "[$host]:$port"
        else -> "$host:$port"
    }
}

/** 拼 URL 用的 host：裸的 v6 字面量要加方括号（`ws://[2001:db8::1]:10000/`） */
fun hostForUrl(host: String): String {
    val h = host.trim()
    return if (h.contains(':') && !h.startsWith("[")) "[$h]" else h
}
