package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession
import kotlinx.coroutines.CoroutineScope

/**
 * 打洞成功后的 socket 可以交给这些用法。
 *
 * 接口只描述「挂上 / 摘下」—— **不规定怎么收发，更不规定怎么保活**：
 * - [UdpTest] 自己起 1s 一次的 ping/pong
 * - [Tun] / [Vswitch] 靠流量驱动
 * - [WireGuard] 用它自己的 handshake + PersistentKeepalive
 */
interface Usage {
    /** 卡片第 5 行按钮上的名字，也是 SessionManager 里注册的 key */
    val id: String
    val title: String

    /** 挂到这条 session 上：自己决定起哪些协程/循环 */
    fun attach(session: UdpSession, env: UsageEnv)

    /** 摘下来：停掉自己起的东西，**不要关 socket**（socket 归 SessionManager） */
    fun detach(session: UdpSession)
}

/** usage 需要的外部环境：协程作用域 + 日志出口 */
class UsageEnv(
    val scope: CoroutineScope,
    val log: (String) -> Unit
)
