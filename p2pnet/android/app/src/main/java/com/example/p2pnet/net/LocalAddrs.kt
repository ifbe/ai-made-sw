package com.example.p2pnet.net

import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * direct 用到的地址工具：枚举本机地址（发给服务器 / 回给对方）、清洗对方给过来的地址。
 *
 * 和 python 端 client/hole/direct.py 的 local_addresses() / _dedup_usable() 对齐：
 * - 过滤 loopback / link-local / 多播 / 未指定，**不过滤私有地址**
 *   （10/8、172.16/12、192.168/16 正是同局域网直连要用的）
 * - v6 必须去掉 `%wlan0` 这种 scope 后缀，否则服务端 inet_pton 会判非法直接扔掉
 * - 每族最多 32 条，和服务端 MAX_DIRECT_ADDRS 一致
 *
 * 注意 direct 交换的是**纯地址、没有端口**，所以它只能回答「哪些地址 ICMP 可达」，
 * 不建隧道。v6 的全局地址（2001:…）本身就是端到端可路由的，没有 NAT 这一层，
 * 所以 v6 场景下 direct 报出来的可达地址就是真直连。
 */

/** 每族最多报这么多条（和 server.py 的 MAX_DIRECT_ADDRS 一致） */
const val MAX_DIRECT_ADDRS = 32

/** 枚举本机所有可用网卡的地址，返回 (v4, v6)。读不到就返回两个空表。 */
fun localAddresses(): Pair<List<String>, List<String>> {
    val v4 = LinkedHashSet<String>()
    val v6 = LinkedHashSet<String>()
    try {
        val nifs = NetworkInterface.getNetworkInterfaces() ?: return emptyList<String>() to emptyList()
        for (nif in nifs) {
            try {
                if (!nif.isUp || nif.isLoopback) continue
                for (addr in nif.inetAddresses) {
                    if (addr.isLoopbackAddress || addr.isLinkLocalAddress ||
                        addr.isMulticastAddress || addr.isAnyLocalAddress
                    ) {
                        continue
                    }
                    // 不要用 isSiteLocalAddress 过滤：192.168/10/172.16 正是要用的
                    // v6 的 `%wlan0` 必须去掉，否则服务端 inet_pton 会判非法
                    val host = addr.hostAddress?.substringBefore('%')?.trim().orEmpty()
                    if (host.isEmpty()) continue
                    if (addr is Inet4Address) {
                        if (v4.size < MAX_DIRECT_ADDRS) v4.add(host)
                    } else {
                        if (v6.size < MAX_DIRECT_ADDRS) v6.add(host)
                    }
                }
            } catch (_: Exception) {
                // 单个网卡读失败不影响其它网卡
            }
        }
    } catch (_: Exception) {
        // 拿不到网卡列表就当本机没有可用地址
    }
    return v4.toList() to v6.toList()
}

/** 清洗对方给过来的地址（服务端已经过滤过一遍，这里只去空、去重、保序） */
fun dedupeAddrs(raw: List<String>): List<String> {
    val out = LinkedHashSet<String>()
    for (item in raw) {
        val s = item.trim()
        if (s.isNotEmpty()) out.add(s)
    }
    return out.toList()
}
