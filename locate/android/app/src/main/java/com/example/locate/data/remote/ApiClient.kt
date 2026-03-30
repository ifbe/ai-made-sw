package com.example.locate.data.remote

import com.example.locate.domain.model.ServerMessage
import com.example.locate.domain.model.User
import okhttp3.*
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * WebSocket 客户端
 * 用于：登录、位置上报、接收其他用户数据
 */
class ApiClient(private val serverUrl: String) {

    private var webSocket: WebSocket? = null
    private var token: String? = null
    private var username: String? = null

    interface ApiListener {
        fun onLoginSuccess(token: String, nickname: String)
        fun onLoginFailed(error: String)
        fun onUserList(users: List<User>)
        fun onUserJoined(username: String)
        fun onUserLeft(username: String)
        fun onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?)
        fun onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float)
        fun onError(message: String)
        fun onConnected()
        fun onDisconnected()
    }

    var listener: ApiListener? = null

    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    private val wsUrl: String
        get() = serverUrl.replace("http://", "ws://").replace("https://", "wss://")

    /**
     * 建立 WebSocket 连接并发送登录消息
     */
    fun connectAndLogin(username: String, response: String, lat: Double, lng: Double, heading: Float) {
        this.username = username

        val request = Request.Builder()
            .url("$wsUrl/")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, wsResponse: Response) {
                // 发送登录消息
                val loginMsg = JSONObject().apply {
                    put("type", "login")
                    put("username", username)
                    put("response", response)
                    put("lat", lat)
                    put("lng", lng)
                    put("heading", heading)
                }
                webSocket.send(loginMsg.toString())
                listener?.onConnected()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                listener?.onError(t.message ?: "连接失败")
                listener?.onDisconnected()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                listener?.onDisconnected()
            }
        })
    }

    private fun handleMessage(text: String) {
        val msg = ServerMessage.parse(text) ?: return

        when (msg) {
            is ServerMessage.LoginSuccess -> {
                this.token = msg.token
                listener?.onLoginSuccess(msg.token, msg.nickname)
            }
            is ServerMessage.UserList -> listener?.onUserList(msg.users)
            is ServerMessage.UserJoined -> listener?.onUserJoined(msg.username)
            is ServerMessage.UserLeft -> listener?.onUserLeft(msg.username)
            is ServerMessage.TargetUpdate -> {
                listener?.onTargetUpdate(msg.username, msg.targetLat, msg.targetLng)
            }
            is ServerMessage.PositionUpdate -> {
                android.util.Log.d("ApiClient", "Received PositionUpdate from server: username=${msg.username} lat=${msg.lat} lng=${msg.lng}")
                listener?.onPositionUpdate(msg.username, msg.lat, msg.lng, msg.heading)
            }
            is ServerMessage.Error -> listener?.onError(msg.message)
        }
    }

    /**
     * 发送位置更新
     */
    fun sendPosition(lat: Double, lng: Double, heading: Float) {
        val token = this.token ?: return
        val msg = JSONObject().apply {
            put("type", "update_position")
            put("token", token)
            put("username", username)
            put("lat", lat)
            put("lng", lng)
            put("heading", heading)
        }
        webSocket?.send(msg.toString())
    }

    /**
     * 发送目标点更新
     */
    fun sendTarget(targetLat: Double?, targetLng: Double?) {
        val token = this.token ?: return
        val msg = JSONObject().apply {
            put("type", "update_target")
            put("token", token)
            put("username", username)
            put("target_lat", targetLat)
            put("target_lng", targetLng)
        }
        webSocket?.send(msg.toString())
    }

    /**
     * 关闭连接
     */
    fun disconnect() {
        webSocket?.close(1000, "client close")
        webSocket = null
        token = null
    }
}
