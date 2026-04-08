package com.example.p2pnet.data.repository

import android.util.Log
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.remote.WsClient
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import kotlin.coroutines.resume

class P2pRepository(
    private val localPrefs: LocalPrefs
) {
    private var _client: WsClient = WsClient(localPrefs)
    private var _loggedInUsername: String? = null
    val loggedInUsername: String? get() = _loggedInUsername

    sealed class LoginResult {
        data class Success(val username: String) : LoginResult()
        data class Error(val message: String) : LoginResult()
    }

    var onRawMessage: ((String) -> Unit)? = null
    var onSend: ((String) -> Unit)? = null
    var onUdpSend: ((String) -> Unit)? = null
    var onUdpRecv: ((String) -> Unit)? = null
    var onHelloDone: ((WsClient.PeerInfo?, java.net.DatagramSocket?, String, Int, String) -> Unit)? = null

    fun useClient(client: WsClient?) {
        _client = client ?: WsClient(localPrefs)
    }

    fun getClient(): WsClient = _client

    private val ws: WsClient get() = _client

    suspend fun login(useWss: Boolean, host: String, port: Int, username: String, password: String): LoginResult {
        _loggedInUsername = username
        localPrefs.serverHost = host
        localPrefs.serverPort = port
        localPrefs.username = username
        localPrefs.loggedIn = true

        return suspendCancellableCoroutine { cont ->
            val listener = object : WsClient.Listener {
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

                override fun onHelloDone(info: WsClient.PeerInfo?, sock: java.net.DatagramSocket?, peerIp: String, peerPort: Int, mode: String) {
                    this@P2pRepository.onHelloDone?.invoke(info, sock, peerIp, peerPort, mode)
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

            ws.listener = listener
            ws.login(useWss, host, port, username, password)

            cont.invokeOnCancellation {
                ws.disconnectOnly()
            }
        }
    }

    fun logout() {
        ws.disconnectOnly()
        localPrefs.clearSession()
        _loggedInUsername = null
    }

    fun connectOnly(useWss: Boolean, host: String, port: Int) {
        val proto = if (useWss) "wss" else "ws"
        ws.connect("$proto://$host:$port/")
    }

    fun disconnectOnly() {
        ws.disconnectOnly()
    }

    fun resetUdpState() {
        ws.resetUdpState()
    }

    fun sendList() = ws.sendList()
    fun sendWghelp(target: String) = ws.sendWghelp(target)
    fun sendP2pUdp(target: String) = ws.sendP2pUdp(target)
    fun sendP2pTcp(target: String) = ws.sendP2pTcp(target)
    fun getServerHost(): String = localPrefs.serverHost
    fun getServerPort(): Int = localPrefs.serverPort
    fun isLoggedIn(): Boolean = localPrefs.loggedIn
    fun getSavedUsername(): String? = localPrefs.username
}
