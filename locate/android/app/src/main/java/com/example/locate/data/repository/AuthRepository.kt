package com.example.locate.data.repository

import com.example.locate.data.local.SecurePrefs
import com.example.locate.data.remote.ApiClient
import com.example.locate.data.remote.AuthApi
import com.example.locate.domain.model.User
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * 认证仓库
 * 负责：登录验证、凭证存储、自动登录
 */
class AuthRepository(
    private val serverUrl: String,
    private val securePrefs: SecurePrefs
) {
    private val authApi = AuthApi(serverUrl)
    private val apiClient = ApiClient(serverUrl)

    sealed class LoginState {
        data class Success(val token: String, val nickname: String) : LoginState()
        data class Error(val message: String) : LoginState()
    }

    sealed class LoginStep {
        data object Idle : LoginStep()
        data object FetchingChallenge : LoginStep()
        data object Connecting : LoginStep()
        data class WaitingResult(val nickname: String?) : LoginStep()
        data class Error(val message: String) : LoginStep()
    }

    /**
     * 登录（完整流程）
     * 1. 获取 challenge
     * 2. 计算 response
     * 3. WebSocket 登录
     */
    suspend fun login(username: String, password: String): LoginState {
        // 1. 获取 challenge
        val challengeResult = authApi.getChallenge(username)
        if (!challengeResult.success || challengeResult.challenge == null || challengeResult.salt == null) {
            return LoginState.Error(challengeResult.error ?: "获取挑战码失败")
        }

        // 2. 计算 response
        val response = authApi.computeResponse(
            password,
            challengeResult.salt,
            challengeResult.challenge
        )

        // 3. WebSocket 登录
        return suspendCancellableCoroutine { cont ->
            // 保存原有的 listener（可能是 MapActivity 设置的）
            val existingListener = apiClient.listener

            apiClient.listener = object : ApiClient.ApiListener {
                override fun onLoginSuccess(token: String, nickname: String) {
                    securePrefs.saveCredentials(username, password, token)
                    cont.resume(LoginState.Success(token, nickname))
                    // 恢复原有 listener
                    apiClient.listener = existingListener
                }

                override fun onLoginFailed(error: String) {
                    cont.resume(LoginState.Error(error))
                    // 恢复原有 listener
                    apiClient.listener = existingListener
                }

                override fun onUserList(users: List<User>) {
                    existingListener?.onUserList(users)
                }
                override fun onUserJoined(username: String) {
                    existingListener?.onUserJoined(username)
                }
                override fun onUserLeft(username: String) {
                    existingListener?.onUserLeft(username)
                }
                override fun onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?) {
                    existingListener?.onTargetUpdate(username, targetLat, targetLng)
                }
                override fun onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float) {
                    android.util.Log.d("AuthRepo", "onPositionUpdate: username=$username lat=$lat lng=$lng")
                    existingListener?.onPositionUpdate(username, lat, lng, heading)
                }
                override fun onError(message: String) {
                    if (cont.isActive) cont.resume(LoginState.Error(message))
                    apiClient.listener = existingListener
                }

                override fun onConnected() {
                    existingListener?.onConnected()
                }
                override fun onDisconnected() {
                    existingListener?.onDisconnected()
                }
            }

            apiClient.connectAndLogin(username, response, 0.0, 0.0, 0f)

            cont.invokeOnCancellation {
                apiClient.disconnect()
            }
        }
    }

    /**
     * 退出登录
     */
    fun logout() {
        securePrefs.clearCredentials()
        apiClient.disconnect()
    }

    /**
     * 获取已保存的用户名
     */
    fun getSavedUsername(): String? = securePrefs.username

    /**
     * 是否有已保存的凭证
     */
    fun hasSavedCredentials(): Boolean = securePrefs.hasCredentials()

    fun getApiClient(): ApiClient = apiClient
}
