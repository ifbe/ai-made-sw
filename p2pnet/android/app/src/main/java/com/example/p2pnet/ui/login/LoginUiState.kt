package com.example.p2pnet.ui.login

import com.example.p2pnet.ui.Page
import com.example.p2pnet.ui.TabItem

data class LoginUiState(
    val useWss: Boolean = false,
    val serverHost: String = "deepstack.tech",
    val serverPort: String = "10000",
    val username: String = "test",
    val password: String = "test",
    val targetUsername: String = "",
    val loading: Boolean = false,
    val isConnected: Boolean = false,
    val isLoggedIn: Boolean = false,
    val loggedInUsername: String = "",
    val error: String? = null,
    val messages: List<MessageItem> = emptyList(),
    val tabs: List<TabItem> = listOf(TabItem.main()),
    val currentTabIndex: Int = 0,
    val currentPage: Page = Page.Main
)
