package com.example.p2pnet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
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
                        val containerColor = if (isSelected) {
                            MaterialTheme.colorScheme.primaryContainer
                        } else {
                            MaterialTheme.colorScheme.surface
                        }
                        val contentColor = if (isSelected) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Surface(
                                onClick = { viewModel.switchToTab(index) },
                                shape = RoundedCornerShape(8.dp),
                                color = containerColor,
                                contentColor = contentColor,
                                tonalElevation = if (isSelected) 0.dp else 2.dp
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Text(
                                        text = tab.title,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = contentColor
                                    )
                                }
                            }
                            if (index > 0) {
                                IconButton(
                                    onClick = { viewModel.removeTab(index) },
                                    modifier = Modifier.size(24.dp)
                                ) {
                                    Text(
                                        "×",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
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
