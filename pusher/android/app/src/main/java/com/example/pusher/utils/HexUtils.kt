package com.example.pusher.utils

object HexUtils {
    private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

    fun bytesToHex(bytes: ByteArray, maxLen: Int = bytes.size): String {
        val len = bytes.size.coerceAtMost(maxLen)
        val result = StringBuilder(len * 3)
        for (i in 0 until len) {
            val b = bytes[i].toInt() and 0xFF
            result.append(HEX_CHARS[b shr 4])
            result.append(HEX_CHARS[b and 0x0F])
            result.append(' ')
        }
        return result.toString().trim()
    }
}
