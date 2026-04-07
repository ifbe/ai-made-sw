package com.example.p2pnet.ui

import com.example.p2pnet.data.remote.WsClient

/** 页面类型 */
sealed class Page {
    object Main : Page()
    data class UdpTest(
        val targetUsername: String,
        val myIp: String = "",
        val myPublicPort: Int = 0,
        var myLocalIp: String = "",
        val myLocalPort: Int = 0,
        val peerIp: String = "",
        val peerPort: Int = 0
    ) : Page()
    data class VideoCall(val targetUsername: String) : Page()
    data class Chat(val targetUsername: String) : Page()
}

/** Tab 项 */
data class TabItem(
    val page: Page,
    val title: String
) {
    companion object {
        fun main() = TabItem(Page.Main, "主页")
    }
}

fun WsClient.PeerInfo.toPage(): Page.UdpTest = Page.UdpTest(
    targetUsername = name,
    myIp = myIp,
    myPublicPort = myPort,
    myLocalIp = "",
    myLocalPort = myLocalPort,
    peerIp = peerIp,
    peerPort = peerPort
)
