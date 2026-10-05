package com.example.p2pnet.data.repository

import android.util.Log
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.remote.WsClient
import com.example.p2pnet.net.hostForUrl
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import kotlin.coroutines.resume

class P2pRepository(
    private val localPrefs: LocalPrefs
) {
    private var _client: WsClient = WsClient(localPrefs)
    private var _loggedInUsername: String? = null
    val loggedInUsername: String? get() = _loggedInUsername

    /** 常驻监听器的登记处：换 client 时要把同一份重新装上（单槽，见 [ClientListenerHolder]） */
    private val listenerHolder = ClientListenerHolder<WsClient, WsClient.Listener> { c, l -> c.listener = l }

    /** 系统级日志（例如"保留当前 client、拒绝切换"）：由 `LoginViewModel` 接到 App 内日志 */
    var onSystemLog: ((String) -> Unit)? = null

    sealed class LoginResult {
        data class Success(val username: String) : LoginResult()
        data class Error(val message: String) : LoginResult()
    }

    var onRawMessage: ((String) -> Unit)? = null
    var onSend: ((String) -> Unit)? = null
    var onUdpSend: ((String) -> Unit)? = null
    var onUdpRecv: ((String) -> Unit)? = null
    var onUdpSocketBound: ((java.net.DatagramSocket, String, Int) -> Unit)? = null
    var onUdpSocketStep: ((java.net.DatagramSocket, WsClient.UdpStep, String, Int, String, Int) -> Unit)? = null
    var onHelloDone: ((WsClient.PeerInfo?, java.net.DatagramSocket?, String, Int, String) -> Unit)? = null

    /** 收到服务器转来的 direct 地址交换（from, ipv4, ipv6, isReply） */
    var onP2pDirect: ((String, List<String>, List<String>, Boolean) -> Unit)? = null

    /**
     * 装上"常驻监听器"（`LoginViewModel` 的 UI 监听器）：**记住它** + 装到**当前** client。
     * 幂等，可以重复调用（`connectInternal()` 每次连接都会调一遍）。
     */
    fun installListener(listener: WsClient.Listener) {
        listenerHolder.install(_client, listener)
    }

    /**
     * 把仓库切到另一个 `WsClient`（例如绑定上后台服务持有的那个）。
     *
     * 两条硬约束：
     * - **(a) 当前 client 还在连接/已连接时不切**：这次会话（socket + 监听器）挂在旧实例上，
     *   切走就等于把它丢在背后（后续 `send*` / `login` 会发到一个没连接的 client）。如实打一行日志。
     * - **(b) 换完立刻把常驻监听器装到新 client 上**：监听器是装在 client 实例上的，
     *   不重装的话界面（尤其 Activity 重建后的新 VM）就再也收不到状态回调了。
     */
    fun useClient(client: WsClient?) {
        val next = client ?: WsClient(localPrefs)
        if (_client === next) return
        if (!ClientSwapPolicy.canSwap(_client.isBusy())) {
            onSystemLog?.invoke("当前客户端正在连接/已连接，保留它、暂不切换到新的客户端（避免会话被丢在背后）")
            return
        }
        _client = next
        listenerHolder.installOn(next)
    }

    fun getClient(): WsClient = _client

    /** LocalPrefs 里记的"上次登录过"（Activity 重建后用来尽量把登录状态同步回来） */
    fun isLoggedInSaved(): Boolean = localPrefs.loggedIn

    /** LocalPrefs 里记的上次登录用户名（密码不落盘，恢复不了） */
    fun savedUsername(): String? = localPrefs.username

    private val ws: WsClient get() = _client

    suspend fun login(useWss: Boolean, host: String, port: Int, username: String, password: String): LoginResult {
        _loggedInUsername = username
        localPrefs.serverHost = host
        localPrefs.serverPort = port
        localPrefs.username = username
        localPrefs.loggedIn = true

        return suspendCancellableCoroutine { cont ->
            // 仓库既有的直通钩子：数据/日志类事件仍按老样子走这些（onSend / onRawMessage / onUdp* / …），
            // 登录结果也在这里 resume 协程。连接类事件不走这里，由下面的转发代理负责（见 LoginListenerProxy）。
            val hooks = object : WsClient.Listener {
                override fun onConnected() {}

                override fun onSend(text: String) {
                    this@P2pRepository.onSend?.invoke(text)
                }

                override fun onRawMessage(text: String) {
                    this@P2pRepository.onRawMessage?.invoke(text)
                }

                override fun onUdpSend(text: String) {
                    this@P2pRepository.onUdpSend?.invoke(text)
                }

                override fun onUdpRecv(text: String) {
                    this@P2pRepository.onUdpRecv?.invoke(text)
                }

                override fun onUdpSocketBound(sock: java.net.DatagramSocket, localIp: String, localPort: Int) {
                    this@P2pRepository.onUdpSocketBound?.invoke(sock, localIp, localPort)
                }

                override fun onUdpSocketStep(
                    sock: java.net.DatagramSocket,
                    step: WsClient.UdpStep,
                    myIp: String,
                    myPort: Int,
                    peerIp: String,
                    peerPort: Int
                ) {
                    this@P2pRepository.onUdpSocketStep?.invoke(sock, step, myIp, myPort, peerIp, peerPort)
                }

                override fun onHelloDone(info: WsClient.PeerInfo?, sock: java.net.DatagramSocket?, peerIp: String, peerPort: Int, mode: String) {
                    this@P2pRepository.onHelloDone?.invoke(info, sock, peerIp, peerPort, mode)
                }

                override fun onP2pDirect(from: String, ipv4: List<String>, ipv6: List<String>, isReply: Boolean) {
                    this@P2pRepository.onP2pDirect?.invoke(from, ipv4, ipv6, isReply)
                }

                override fun onLoginSuccess(username: String) {
                    _loggedInUsername = username
                    localPrefs.loggedIn = true
                    cont.resume(LoginResult.Success(username))
                }

                override fun onLoginFailed(message: String) {
                    localPrefs.clearSession()
                    _loggedInUsername = null
                    cont.resume(LoginResult.Error(message))
                }

                override fun onDisconnected() {
                    if (cont.isActive) {
                        cont.resume(LoginResult.Error("连接断开"))
                    }
                }

                override fun onError(message: String) {
                    if (cont.isActive) {
                        cont.resume(LoginResult.Error(message))
                    }
                }
            }

            // ⚠️ `WsClient.listener` 是**单槽**：登录必须临时装个监听器才能收 login_ok / login_failed，
            // 但**不能**因此把常驻监听器（LoginViewModel 装的那个）挤掉 ——
            // 否则登录成功之后：心跳失败 / 网络消失（关 4G+WiFi）/ 被踢 这些回调全部到不了界面，
            // 界面会永远停在"已连接"、也不会自动重连（用户实测 bug）。
            // 所以这里包一层转发代理：连接类事件继续转给常驻监听器，登录一结束就把常驻监听器装回单槽。
            val persistent = ws.listener
            var proxy: LoginListenerProxy? = null
            val restoreSlot: () -> Unit = {
                // 只在槽里还是本代理时才替换（避免踩掉这期间别人新装的监听器）
                if (ws.listener === proxy) ws.listener = persistent
            }
            proxy = LoginListenerProxy(
                persistent = persistent,
                hooks = hooks,
                restoreSlot = restoreSlot
            )
            ws.listener = proxy
            ws.login(useWss, host, port, username, password)

            cont.invokeOnCancellation {
                ws.disconnectOnly()
            }
        }
    }

    /**
     * 退出登录。
     * keepConnection = true：只告诉服务器结束登录会话（logout），WebSocket 保持连接；
     * keepConnection = false（默认）：直接断开连接。
     */
    fun logout(keepConnection: Boolean = false) {
        if (keepConnection) {
            ws.sendLogout()
        } else {
            ws.disconnectOnly()
        }
        localPrefs.clearSession()
        _loggedInUsername = null
    }

    fun connectOnly(useWss: Boolean, host: String, port: Int) {
        val proto = if (useWss) "wss" else "ws"
        // host 可能是裸 v6 字面量，拼 URL 要加方括号
        ws.connect("$proto://${hostForUrl(host)}:$port/")
    }

    fun disconnectOnly() {
        ws.disconnectOnly()
    }

    fun resetUdpState() {
        ws.resetUdpState()
    }

    fun sendList() = ws.sendList()
    /** 应用层 ping：`{"type":"ping","seq":N}` → 服务器回 `{"type":"pong","seq":N}`（不需要登录） */
    fun sendAppPing(seq: Int) = ws.sendAppPing(seq)
    fun sendP2pUdp(target: String) = ws.sendP2pUdp(target)
    fun sendP2pTcp(target: String) = ws.sendP2pTcp(target)
    fun sendP2pDirect(target: String, ipv4: List<String>, ipv6: List<String>) =
        ws.sendP2pDirect(target, ipv4, ipv6)
    fun sendP2pDirectReply(target: String, ipv4: List<String>, ipv6: List<String>) =
        ws.sendP2pDirectReply(target, ipv4, ipv6)
    fun getServerHost(): String = localPrefs.serverHost
    fun getServerPort(): Int = localPrefs.serverPort
    fun isLoggedIn(): Boolean = localPrefs.loggedIn
    fun getSavedUsername(): String? = localPrefs.username

    // 两个配置页的配置（JSON 原文）—— ViewModel 不直接持有 LocalPrefs，这里透传
    fun getWgConfigJson(): String? = localPrefs.wgConfigJson
    fun setWgConfigJson(json: String?) { localPrefs.wgConfigJson = json }
    fun getSwitchConfigJson(): String? = localPrefs.switchConfigJson
    fun setSwitchConfigJson(json: String?) { localPrefs.switchConfigJson = json }
    fun getProxyConfigJson(): String? = localPrefs.proxyConfigJson
    fun setProxyConfigJson(json: String?) { localPrefs.proxyConfigJson = json }
    fun getVpnConfigJson(): String? = localPrefs.vpnConfigJson
    fun setVpnConfigJson(json: String?) { localPrefs.vpnConfigJson = json }
    fun getMediaConfigJson(): String? = localPrefs.mediaConfigJson
    fun setMediaConfigJson(json: String?) { localPrefs.mediaConfigJson = json }
}
