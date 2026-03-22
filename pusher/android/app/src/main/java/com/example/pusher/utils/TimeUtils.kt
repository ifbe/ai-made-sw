package com.example.pusher.utils

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TimeUtils {
    private val format = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    fun formatMillis(millis: Long): String {
        return format.format(Date(millis))
    }
}
