package com.example.locate.util

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 加密工具类
 * 对应 server.py 的 challenge-response 认证流程：
 * 1. password_hash = SHA256(password + salt)
 * 2. response = HMAC-SHA256(password_hash, challenge)
 */
object Crypto {

    private const val HMAC_SHA256 = "HmacSHA256"
    private const val SHA256 = "SHA-256"

    /**
     * 计算 SHA256 哈希
     */
    fun sha256(input: String): String {
        val digest = MessageDigest.getInstance(SHA256)
        val hashBytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hashBytes.toHexString()
    }

    /**
     * 计算 HMAC-SHA256
     * password_hash 作为 key，challenge 作为 data
     */
    fun hmacSha256(key: String, data: String): String {
        val mac = Mac.getInstance(HMAC_SHA256)
        val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), HMAC_SHA256)
        mac.init(secretKey)
        val hmacBytes = mac.doFinal(data.toByteArray(Charsets.UTF_8))
        return hmacBytes.toHexString()
    }

    /**
     * 根据服务器规则计算认证响应
     * password_hash = SHA256(password + salt)
     * response = HMAC-SHA256(password_hash, challenge)
     */
    fun computeAuthResponse(password: String, salt: String, challenge: String): String {
        val passwordHash = sha256(password + salt)
        return hmacSha256(passwordHash, challenge)
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}
