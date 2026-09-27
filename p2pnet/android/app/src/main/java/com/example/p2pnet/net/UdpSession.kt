package com.example.p2pnet.net

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/** 收到的一个 UDP 包（带来源地址，回包时才不用猜） */
class UdpPacket(
    val data: ByteArray,
    val fromIp: String,
    val fromPort: Int
)

/**
 * 打洞成功后产出的连接 —— 唯一被「交接」的对象。
 *
 * - socket 和它的**唯一读循环**都在这里，收到的包统一发到 [incoming]，谁想用谁 collect；
 *   这样「交给谁」永远不会变成两个读者抢同一个 socket。
 * - 生命周期（创建/关闭）归 [com.example.p2pnet.service.SessionManager]，
 *   usage 只负责 attach/detach，不负责关 socket。
 */
class UdpSession(
    val id: Long,
    /** 对端用户名（服务器 list 里的名字） */
    val target: String,
    /** 打洞时那条 socket，原样复用 */
    val socket: DatagramSocket,
    /** 本机实际绑定的地址/端口 */
    val localIp: String,
    val localPort: Int
) {
    /** 服务器眼里的我的公网地址（thisisyourpeer_udp 给的） */
    var publicIp: String = ""
    var publicPort: Int = 0

    /** 对端地址（服务器给的公网地址） */
    var peerIp: String = ""
    var peerPort: Int = 0

    private val _incoming = MutableSharedFlow<UdpPacket>(
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val incoming: SharedFlow<UdpPacket> = _incoming

    val isClosed: Boolean get() = socket.isClosed

    private var readerJob: Job? = null

    /** 起读循环（幂等）。超时 1s 一轮，方便随时感知 socket 被关闭 */
    fun startReading(scope: CoroutineScope) {
        if (readerJob?.isActive == true) return
        readerJob = scope.launch(Dispatchers.IO) {
            val buf = ByteArray(2048)
            while (isActive && !socket.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    socket.soTimeout = 1000
                    socket.receive(pkt)
                    _incoming.tryEmit(
                        UdpPacket(
                            data = pkt.data.copyOf(pkt.length),
                            fromIp = pkt.address?.hostAddress ?: "",
                            fromPort = pkt.port
                        )
                    )
                } catch (_: Exception) {
                    // 1s 收不到就是超时，正常，继续转
                }
            }
        }
    }

    /** 发给对端（用服务器给的对端地址） */
    fun sendToPeer(payload: ByteArray): Boolean = sendTo(peerIp, peerPort, payload)

    /** 发给指定地址（比如把 pong 回给包的来源） */
    fun sendTo(ip: String, port: Int, payload: ByteArray): Boolean = try {
        if (socket.isClosed || ip.isEmpty() || port <= 0) {
            false
        } else {
            socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(ip), port))
            true
        }
    } catch (_: Exception) {
        false
    }

    fun close() {
        readerJob?.cancel()
        readerJob = null
        try { socket.close() } catch (_: Exception) {}
    }
}
