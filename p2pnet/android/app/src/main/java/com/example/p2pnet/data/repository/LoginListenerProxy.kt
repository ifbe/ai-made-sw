package com.example.p2pnet.data.repository

import com.example.p2pnet.data.remote.WsClient
import java.net.DatagramSocket

/**
 * 登录期间临时装在 [`WsClient.listener`]（**单槽**）上的"转发代理"。
 *
 * ## 为什么需要它（用户实测 bug 的根因）
 *
 * `P2pRepository.login()` 必须临时收 `login_ok` / `login_failed` 来 resume 等待中的协程，
 * 而 `WsClient.listener` 是**单槽**。改动前它直接把 `LoginViewModel` 装的**常驻监听器整个顶掉**，
 * 而那个一次性监听器：
 * - `onConnected` 是空实现；
 * - `onDisconnected` / `onError` 被 `if (cont.isActive)` 挡住 —— 登录成功后协程已完成，`isActive` 是 `false`，
 *   于是**什么都不做**；
 * - `onKicked` 用接口的默认空实现。
 *
 * ⇒ 登录成功之后，**心跳失败 / 网络消失（关 4G+WiFi）/ 被踢** 这些回调全部到不了界面：
 * 界面永远停在"已连接"（也不会自动重连、不会打那行断开日志）。
 *
 * ## 代理的分流规则（改动后每个回调仍然各走各家，**不重复处理**）
 *
 * - **连接类** [onConnected] / [onDisconnected] / [onError] / [onKicked] /
 *   [onLoginSuccess] / [onLoginFailed] → 转发给常驻监听器 [persistent]；
 * - **数据/日志类** [onSend] / [onRawMessage] / `onUdp*` / [onHelloDone] / [onP2pDirect]
 *   → 只走仓库既有的钩子 [hooks]（与改动前一致）；
 * - 登录流程一结束（成功 / 失败 / 断开 / 出错）→ 调 [restoreSlot]，
 *   把常驻监听器**装回单槽**（这样登录之后一切照常）。
 */
internal class LoginListenerProxy(
    /** 登录之前装在槽里的常驻监听器（通常就是 `LoginViewModel` 那个 UI 监听器） */
    private val persistent: WsClient.Listener?,
    /** 仓库既有的直通钩子（`onSend` / `onRawMessage` / …）：数据类事件仍只走这里 */
    private val hooks: WsClient.Listener,
    /** 登录流程结束 → 把常驻监听器装回单槽（调用方只在"槽里还是本代理"时才会真替换） */
    private val restoreSlot: () -> Unit
) : WsClient.Listener {

    // ── 连接类：必须转给常驻监听器（改动前就是在这里被静默吞掉 = bug 根因）──

    override fun onConnected() {
        persistent?.onConnected()
    }

    override fun onKicked(message: String) {
        persistent?.onKicked(message)
    }

    override fun onDisconnected() {
        persistent?.onDisconnected()
        restoreSlot()
        hooks.onDisconnected()
    }

    override fun onError(message: String) {
        persistent?.onError(message)
        restoreSlot()
        hooks.onError(message)
    }

    override fun onLoginSuccess(username: String) {
        persistent?.onLoginSuccess(username)
        restoreSlot()
        hooks.onLoginSuccess(username)
    }

    override fun onLoginFailed(message: String) {
        persistent?.onLoginFailed(message)
        restoreSlot()
        hooks.onLoginFailed(message)
    }

    // ── 数据/日志类：原样只走仓库钩子（与改动前一致，避免同一事件被处理两遍）──

    override fun onSend(text: String) {
        hooks.onSend(text)
    }

    override fun onRawMessage(text: String) {
        hooks.onRawMessage(text)
    }

    override fun onUdpSend(text: String) {
        hooks.onUdpSend(text)
    }

    override fun onUdpRecv(text: String) {
        hooks.onUdpRecv(text)
    }

    override fun onUdpSocketBound(sock: DatagramSocket, localIp: String, localPort: Int) {
        hooks.onUdpSocketBound(sock, localIp, localPort)
    }

    override fun onUdpSocketStep(
        sock: DatagramSocket,
        step: WsClient.UdpStep,
        myIp: String,
        myPort: Int,
        peerIp: String,
        peerPort: Int
    ) {
        hooks.onUdpSocketStep(sock, step, myIp, myPort, peerIp, peerPort)
    }

    override fun onHelloDone(
        info: WsClient.PeerInfo?,
        sock: DatagramSocket?,
        peerIp: String,
        peerPort: Int,
        mode: String
    ) {
        hooks.onHelloDone(info, sock, peerIp, peerPort, mode)
    }

    override fun onP2pDirect(from: String, ipv4: List<String>, ipv6: List<String>, isReply: Boolean) {
        hooks.onP2pDirect(from, ipv4, ipv6, isReply)
    }
}
