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

/** list 回复（list_result）里的一个在线用户：名称 / ip / port */
data class PeerEntry(
    val username: String,
    val ip: String,
    val port: Int
)
