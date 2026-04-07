package com.example.p2pnet.ui.login

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class Direction { CLIENT, SERVER, SYSTEM, UDP_SEND, UDP_RECV }

data class MessageItem(
    val id: Long = System.currentTimeMillis(),
    val direction: Direction,
    val content: String,
    val time: String = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
)
