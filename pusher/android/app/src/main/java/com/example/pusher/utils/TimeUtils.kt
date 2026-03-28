package com.example.pusher.utils

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TimeUtils {
    private val format = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    fun formatMillis(millis: Long): String {
        // millis 是相对时间（毫秒），不是 epoch 时间戳
        val totalSeconds = millis / 1000
        val hours = (totalSeconds / 3600) % 24
        val minutes = (totalSeconds / 60) % 60
        val seconds = totalSeconds % 60
        val ms = millis % 1000
        return String.format(Locale.US, "%02d:%02d:%02d.%03d", hours, minutes, seconds, ms)
    }
}
