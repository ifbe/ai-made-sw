package com.example.p2pnet.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * direct 的可达性探测：跑系统 `ping` 发 ICMP，不建 socket、不需要 root。
 *
 * 为什么不用 [java.net.InetAddress.isReachable]：普通 App 拿不到 raw socket 权限，
 * 它按契约会退化成「对目标 7 端口做 TCP echo」，对端没开 7 端口就一律 false，
 * 和「ICMP 可达」不是一回事。所以这里和 python 端 client/hole/direct.py 一样，
 * 直接调系统 ping 子进程，**以输出里有没有 `ttl=` 判定**（比退出码可靠：
 * 网关回的 Destination Host Unreachable 退出码也可能是 0）。
 *
 * 安卓侧的平台差异：`-W` 的单位是秒（iputils），v6 用 `-6`；
 * 少数老 ROM 只有独立的 `/system/bin/ping6`，所以 v6 会退一级重试。
 * 部分 ROM/SELinux 会直接拒掉 ping（没有二进制或 Permission denied），
 * 这种情况返回 [PingStatus.UNAVAILABLE]，和「不通」区分开——否则界面会误报成对方不可达。
 */

/** ping 一次的结果 */
enum class PingStatus {
    /** 收到回包（输出里出现 ttl=） */
    REACHABLE,

    /** 命令跑起来了，但没人回：超时、目标不可达、或被防火墙挡了 ICMP */
    UNREACHABLE,

    /** 命令根本跑不起来：没有 ping 二进制，或权限被拒 */
    UNAVAILABLE,
}

data class PingResult(val ip: String, val status: PingStatus, val detail: String = "")

/** Android 自带的 ping（iputils），普通 App 权限就能跑 */
private const val PING_BIN = "/system/bin/ping"

/** 少数老 ROM 上 v6 还是独立的 ping6 */
private const val PING_BIN6 = "/system/bin/ping6"

/** `-W` 的单位是秒（和 python 端 Linux 分支一致） */
private const val PING_TIMEOUT_S = 1

/** 子进程最多等这么久（python 端是 PING_TIMEOUT_S + 3） */
private const val WAIT_TIMEOUT_MS = (PING_TIMEOUT_S + 3) * 1000L

/** 并发 ping 的协程数（和 python 端 PING_WORKERS 一致） */
const val PING_WORKERS = 16

/** ping 一个地址（v4/v6 都走这里，按 ip 里有没有冒号判断） */
suspend fun pingOnce(ip: String): PingResult = withContext(Dispatchers.IO) {
    val isV6 = ip.contains(':')
    val cmds = ArrayList<List<String>>(2)
    if (isV6) {
        cmds.add(listOf(PING_BIN, "-6", "-c", "1", "-W", PING_TIMEOUT_S.toString(), ip))
        cmds.add(listOf(PING_BIN6, "-c", "1", "-W", PING_TIMEOUT_S.toString(), ip))
    } else {
        cmds.add(listOf(PING_BIN, "-c", "1", "-W", PING_TIMEOUT_S.toString(), ip))
    }

    var lastDetail = ""
    var started = false
    for ((i, cmd) in cmds.withIndex()) {
        if (!File(cmd[0]).exists()) {
            lastDetail = "本机没有 ${cmd[0]}"
            continue
        }
        val out = runPing(cmd)
        if (out == null) {
            lastDetail = "启动 ${cmd[0]} 失败"
            continue
        }
        started = true
        lastDetail = firstLine(out)
        if (isPermissionDenied(out)) {
            return@withContext PingResult(ip, PingStatus.UNAVAILABLE, firstLine(out))
        }
        // 判定以输出里有没有 ttl= 为准（比退出码可靠）
        if (out.contains("ttl=", ignoreCase = true)) {
            return@withContext PingResult(ip, PingStatus.REACHABLE, firstLine(out))
        }
        // v6：这个 ROM 的 ping 不认 -6 时，换 ping6 再试一次
        if (i < cmds.lastIndex && isBadOption(out)) continue
        return@withContext PingResult(ip, PingStatus.UNREACHABLE, firstLine(out))
    }
    PingResult(ip, if (started) PingStatus.UNREACHABLE else PingStatus.UNAVAILABLE, lastDetail)
}

/** 并发 ping 一串地址，返回每个地址的结果（顺序和入参一致）；onResult 在每个结果出来后被调用 */
suspend fun pingAll(
    addrs: List<String>,
    onResult: (PingResult) -> Unit = {}
): List<PingResult> {
    if (addrs.isEmpty()) return emptyList()
    val sem = Semaphore(minOf(PING_WORKERS, addrs.size))
    val results = coroutineScope {
        addrs.map { ip -> async { sem.withPermit { pingOnce(ip) } } }.awaitAll()
    }
    results.forEach(onResult)
    return results
}

/** 跑一次 ping，返回合并后的输出；启动失败返回 null */
private fun runPing(cmd: List<String>): String? = try {
    val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
    try {
        p.outputStream.close()
    } catch (_: Exception) {
    }
    val finished = p.waitFor(WAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
    if (!finished) p.destroyForcibly()
    // 输出很小（一个回包的结果），先 waitFor 再读不会把管道写满
    p.inputStream.bufferedReader().use { it.readText() }
} catch (_: Throwable) {
    null
}

private fun isPermissionDenied(out: String): Boolean {
    val s = out.lowercase()
    return s.contains("permission denied") ||
        s.contains("operation not permitted") ||
        s.contains("not permitted")
}

private fun isBadOption(out: String): Boolean {
    val s = out.lowercase()
    return s.contains("invalid option") ||
        s.contains("unknown option") ||
        s.contains("unrecognized option") ||
        s.contains("unrecognised option") ||
        s.contains("usage:")
}

private fun firstLine(out: String): String =
    out.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(80) ?: ""
