package com.example.p2pnet.util

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 加密工具类
 * p2pnet 认证流程：
 * 1. pw_hash = SHA256(password + salt)  (password+salt as UTF-8 bytes, output as hex)
 * 2. response = HMAC-SHA256(hex2bin(pw_hash), hex2bin(challenge))
 */
object Crypto {

    private const val HMAC_SHA256 = "HmacSHA256"
    private const val SHA256 = "SHA-256"

    fun sha256(input: String): String {
        return sha256Bytes(input).toHexString()
    }

    fun sha256Bytes(input: String): ByteArray {
        return MessageDigest.getInstance(SHA256).digest(input.toByteArray(Charsets.UTF_8))
    }

    fun hmacSha256(keyBytes: ByteArray, dataBytes: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_SHA256)
        val secretKey = SecretKeySpec(keyBytes, HMAC_SHA256)
        mac.init(secretKey)
        return mac.doFinal(dataBytes)
    }

    fun hmacSha256Hex(key: ByteArray, data: ByteArray): String {
        return hmacSha256(key, data).toHexString()
    }

    fun computeAuthResponse(password: String, salt: String, challenge: String): String {
        val pwHash = sha256(password + salt)
        val pwHashBytes = hexToBytes(pwHash)
        val challengeBytes = hexToBytes(challenge)
        val hmacBytes = hmacSha256(pwHashBytes, challengeBytes)
        return hmacBytes.toHexString()
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
