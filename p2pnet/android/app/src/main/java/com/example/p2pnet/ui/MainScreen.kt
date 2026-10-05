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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.p2pnet.ui.login.MainPage
import com.example.p2pnet.ui.login.LoginViewModel

@Composable
fun MainScreen(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        // 顶部 / 底部两条"避让区"要显示纯黑：
        //   顶部 = 状态栏那条（内容吃 paddingValues，所以上面露出的就是 Scaffold 底色）
        //   底部 = 系统导航栏那条（见下面 bottomBar 的 inset 处理）
        // 不调 setDecorFitsSystemWindows：targetSdk 36 在 Android 15+ 强制 edge-to-edge，调了也无效。
        containerColor = Color.Black,
        bottomBar = {
            // ⚠️ Scaffold 只给"内容"加 inset，自绘的 bottomBar 必须自己处理 insets：
            //   外层 windowInsetsPadding(navigationBars) → 把 tab 行抬到导航栏之上（不被手势条/三键导航压住）
            //   内层 background(surfaceVariant)        → tab 行自己的色块停在上面
            // 导航栏那条露出来的就是 Scaffold 的纯黑底色（= 避让区），里面不放任何可交互控件。
            Column(
                modifier = Modifier
                    .windowInsetsPadding(WindowInsets.navigationBars)
                    .background(MaterialTheme.colorScheme.surfaceVariant)
            ) {
                if (uiState.tabs.size > 1) {
                    HorizontalDivider()
                }
                LazyRow(
                    modifier = Modifier
                        .fillMaxWidth()
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

                                // 右半边 × 按钮：点击关闭 tab
                                // 固定配置页（主页 / WireGuard / Switch）不给 ×，免得关掉找不回来
                                if (tab.closable) {
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
        Box(modifier = Modifier.padding(paddingValues).fillMaxSize()) {
            when (val page = uiState.currentPage) {
                is Page.Main -> MainPage(viewModel)
                is Page.UdpTest -> UdpTestPage(page, viewModel)
                is Page.VideoCall -> VideoCallPage(page.targetUsername, viewModel)
                is Page.Chat -> ChatPage(page.targetUsername, viewModel)
                is Page.WireGuard -> WireGuardPage(page, viewModel)
                is Page.Switch -> SwitchPage(viewModel)
                is Page.Proxy -> ProxyPage(viewModel)
                is Page.Vpn -> VpnPage(viewModel)
                is Page.Media -> MediaPage(viewModel)
            }

            // App 内日志浮层：**应用级**，悬浮在所有页面之上（不属于主页），切到任何 tab 都在
            AppLogOverlay(
                messages = uiState.messages,
                onClear = { viewModel.clearMessages() }
            )
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
