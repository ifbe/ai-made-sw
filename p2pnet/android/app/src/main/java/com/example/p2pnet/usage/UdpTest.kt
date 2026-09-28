package com.example.p2pnet.usage

import com.example.p2pnet.net.UdpSession
import com.example.p2pnet.net.formatHostPort
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * 连通性测试用法：每秒一个 ping、收到 pong 算 RTT、收到 ping 回 pong
 * （包格式和 python 端 client/remote/udp.py 一致）。
 *
 * 保活方式就是它自己的 ping —— 这是唯一自带 ping 的用法。
 */
class UdpTest : Usage {

    override val id: String = "udptest"
    override val title: String = "udptest"

    /** sessionId → 自己起的协程，detach 时全部取消 */
    private val jobs = mutableMapOf<Long, MutableList<Job>>()

    override fun attach(session: UdpSession, env: UsageEnv) {
        detach(session)
        env.log("android: 交给 udptest（对端 ${formatHostPort(session.peerIp, session.peerPort)}），开始 ping/pong")

        val sentPings = mutableMapOf<Int, Long>()
        var seq = 1

        val ticker = env.scope.launch(Dispatchers.IO) {
            while (isActive && !session.isClosed) {
                val ping = JSONObject().apply {
                    put("type", "ping")
                    put("seq", seq)
                    put("ts", System.currentTimeMillis())
                }
                sentPings[seq] = System.currentTimeMillis()
                if (sentPings.size > 100) {
                    sentPings.keys.minOrNull()?.let { sentPings.remove(it) }
                }
                if (session.sendToPeer(ping.toString().toByteArray())) {
                    env.log("send: ${formatHostPort(session.peerIp, session.peerPort)} $ping")
                } else {
                    env.log("android: udptest 发包失败，循环退出")
                    break
                }
                seq++
                delay(1000)
            }
        }

        val reader = env.scope.launch(Dispatchers.IO) {
            session.incoming.collect { pkt ->
                val text = try { String(pkt.data, Charsets.UTF_8) } catch (_: Exception) { "" }
                val msg = try { JSONObject(text) } catch (_: Exception) { null }
                if (msg == null) {
                    env.log("recv: ${formatHostPort(pkt.fromIp, pkt.fromPort)} [${pkt.data.size} bytes]")
                    return@collect
                }
                when (msg.optString("type")) {
                    "pong" -> {
                        val pongSeq = msg.optInt("seq")
                        val rtt = System.currentTimeMillis() - (sentPings.remove(pongSeq) ?: 0L)
                        env.log("recv: ${formatHostPort(pkt.fromIp, pkt.fromPort)} $msg RTT=${rtt}ms")
                    }
                    "ping" -> {
                        // 回复 pong（和 udp.py 一致）
                        val pong = JSONObject().apply {
                            put("type", "pong")
                            put("seq", msg.optInt("seq"))
                            put("ts", msg.optLong("ts"))
                        }
                        session.sendTo(pkt.fromIp, pkt.fromPort, pong.toString().toByteArray())
                        env.log("recv: ${formatHostPort(pkt.fromIp, pkt.fromPort)} $msg")
                        env.log("send: ${formatHostPort(pkt.fromIp, pkt.fromPort)} $pong")
                    }
                    else -> env.log("recv: ${pkt.fromIp}:${pkt.fromPort} $msg")
                }
            }
        }

        jobs[session.id] = mutableListOf(ticker, reader)
    }

    override fun detach(session: UdpSession) {
        jobs.remove(session.id)?.forEach { it.cancel() }
    }
}
