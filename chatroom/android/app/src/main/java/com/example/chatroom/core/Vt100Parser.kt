package com.example.chatroom.core

import android.graphics.Color
import androidx.core.graphics.ColorUtils

/** 解析 ANSI/VT100 SGR escape sequence，返回 (remainingText, currentStyle) */
object Vt100Parser {

    // ANSI color map
    private val ANSI_FG = mapOf(
        30 to Color.BLACK,
        31 to Color.parseColor("#D32F2F"),
        32 to Color.parseColor("#388E3C"),
        33 to Color.parseColor("#F57C00"),
        34 to Color.parseColor("#1565C0"),
        35 to Color.parseColor("#7B1FA2"),
        36 to Color.parseColor("#00838F"),
        37 to Color.WHITE,
        39 to Color.BLACK  // default
    )

    private val ANSI_BG = mapOf(
        40 to Color.BLACK,
        41 to Color.parseColor("#D32F2F"),
        42 to Color.parseColor("#388E3C"),
        43 to Color.parseColor("#F57C00"),
        44 to Color.parseColor("#1565C0"),
        45 to Color.parseColor("#7B1FA2"),
        46 to Color.parseColor("#00838F"),
        47 to Color.WHITE,
        49 to Color.TRANSPARENT
    )

    /** 解析完整字符串，返回 (纯文本, 样式列表，每段一个样式) */
    fun parse(text: String): List<Pair<String, Vt100Style>> {
        val result = mutableListOf<Pair<String, Vt100Style>>()
        var currentStyle = Vt100Style()
        var buffer = StringBuilder()
        var i = 0

        while (i < text.length) {
            if (text[i] == '\u001B' && i + 1 < text.length && text[i + 1] == '[') {
                // 保存当前buffer
                if (buffer.isNotEmpty()) {
                    result.add(buffer.toString() to currentStyle)
                    buffer.clear()
                }

                // 找到 CSI 序列
                var j = i + 2
                while (j < text.length && text[j] !in 'A'..'z') j++
                val seq = if (j < text.length) text.substring(i + 2, j + 1) else text.substring(i + 2)
                currentStyle = applySGR(seq.dropLast(1), currentStyle)
                i = j + 1
            } else {
                buffer.append(text[i])
                i++
            }
        }

        if (buffer.isNotEmpty()) {
            result.add(buffer.toString() to currentStyle)
        }

        return result
    }

    private fun applySGR(params: String, style: Vt100Style): Vt100Style {
        if (params.isEmpty() || params == "0") return Vt100Style()

        var s = style
        val codes = params.split(";").mapNotNull { it.toIntOrNull() }

        for (code in codes) {
            when {
                code == 0 -> s = Vt100Style()
                code == 1 -> s = s.copy(bold = true)
                code == 4 -> s = s.copy(underline = true)
                code == 7 -> s = s.copy(reverse = true)
                code in ANSI_FG -> s = s.copy(fgColor = ANSI_FG[code]!!)
                code in ANSI_BG -> s = s.copy(bgColor = ANSI_BG[code]!!)
            }
        }

        return s
    }
}
