package com.example.p2pnet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.p2pnet.ui.login.MainPage
import com.example.p2pnet.ui.login.LoginViewModel

@Composable
fun MainScreen(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        bottomBar = {
            Column {
                if (uiState.tabs.size > 1) {
                    HorizontalDivider()
                }
                LazyRow(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    itemsIndexed(uiState.tabs) { index, tab ->
                        val isSelected = index == uiState.currentTabIndex
                        val bgColor = if (isSelected) {
                            MaterialTheme.colorScheme.primaryContainer
                        } else {
                            MaterialTheme.colorScheme.surface
                        }
                        val textColor = if (isSelected) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }

                        // 整个 tab 用 Surface 只做圆角背景，不处理点击
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = bgColor,
                            tonalElevation = if (isSelected) 0.dp else 2.dp
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                // 左半边文字区：点击切换 tab
                                Text(
                                    text = tab.title,
                                    modifier = Modifier
                                        .clickable { viewModel.switchToTab(index) }
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = textColor
                                )

                                // 右半边 × 按钮：点击关闭 tab（仅 index>0）
                                if (index > 0) {
                                    Text(
                                        text = "×",
                                        modifier = Modifier
                                            .clickable { viewModel.removeTab(index) }
                                            .padding(horizontal = 8.dp, vertical = 8.dp),
                                        style = MaterialTheme.typography.labelMedium,
                                        color = textColor.copy(alpha = 0.5f)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    ) { paddingValues ->
        Box(modifier = Modifier.padding(paddingValues)) {
            when (val page = uiState.currentPage) {
                is Page.Main -> MainPage(viewModel)
                is Page.UdpTest -> UdpTestPage(page, viewModel)
                is Page.VideoCall -> VideoCallPage(page.targetUsername, viewModel)
                is Page.Chat -> ChatPage(page.targetUsername, viewModel)
                is Page.WireGuard -> WireGuardPage(page, viewModel)
            }
        }
    }
}

@Composable
fun VideoCallPage(targetUsername: String, viewModel: LoginViewModel) {
    Box(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("视频通话页 - $targetUsername")
    }
}

@Composable
fun ChatPage(targetUsername: String, viewModel: LoginViewModel) {
    Box(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("聊天页 - $targetUsername")
    }
}
