package com.example.locate.data.remote

import com.example.locate.util.Crypto
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * HTTP 认证接口
 * 对应 server.py 的 /api/challenge 端点
 */
class AuthApi(private val serverUrl: String) {

    data class ChallengeResult(
        val success: Boolean,
        val challenge: String? = null,
        val salt: String? = null,
        val error: String? = null
    )

    data class LoginResult(
        val success: Boolean,
        val token: String? = null,
        val nickname: String? = null,
        val error: String? = null
    )

    /**
     * 获取挑战码
     * POST /api/challenge { "username": "xxx" }
     */
    suspend fun getChallenge(username: String): ChallengeResult = withContext(Dispatchers.IO) {
        try {
            val url = URL("$serverUrl/api/challenge")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000

            val body = JSONObject().put("username", username).toString()
            conn.outputStream.write(body.toByteArray())

            val responseCode = conn.responseCode
            val reader = BufferedReader(InputStreamReader(conn.inputStream))
            val response = reader.readText()
            reader.close()

            if (responseCode == 200) {
                val json = JSONObject(response)
                ChallengeResult(
                    success = json.getBoolean("success"),
                    challenge = json.optString("challenge"),
                    salt = json.optString("salt"),
                    error = json.optString("error").takeIf { it.isNotEmpty() && !json.getBoolean("success") }
                )
            } else {
                ChallengeResult(success = false, error = "HTTP $responseCode")
            }
        } catch (e: Exception) {
            ChallengeResult(success = false, error = e.message ?: "网络错误")
        }
    }

    /**
     * 计算登录响应（本地计算，不发网络请求）
     * response = HMAC-SHA256(SHA256(password + salt), challenge)
     */
    fun computeResponse(password: String, salt: String, challenge: String): String {
        return Crypto.computeAuthResponse(password, salt, challenge)
    }
}
