package com.example.p2pnet.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.ui.login.LoginViewModel

@Composable
fun UdpTestPage(page: Page.UdpTest, viewModel: LoginViewModel) {
    val messages by viewModel.udpSockMessages.collectAsState()
    val listState = rememberLazyListState()

    // 自动滚动到底部（仅当用户已在底部时才滚动，否则保持当前位置）
    LaunchedEffect(messages.size) {
        if (messages.isEmpty()) return@LaunchedEffect
        val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()
        val atBottom = lastVisible != null && lastVisible.index >= messages.size - 1
        if (atBottom) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 4.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── 地址块 ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    text = "UDP - ${page.targetUsername}",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))
                Text(
                    text = "mylocaladdr  ${page.myLocalIp}:${page.myLocalPort}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "mypublicaddr ${page.myIp}:${page.myPublicPort}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "peerpublicaddr ${page.peerIp}:${page.peerPort}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }
        }

        // ── 日志块 ──
        Card(
            modifier = Modifier.fillMaxWidth().weight(1f),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "消息历史",
                        style = MaterialTheme.typography.titleSmall
                    )
                    val clipboardManager = LocalClipboardManager.current
                    var snackbarVisible by remember { mutableStateOf(false) }
                    TextButton(
                        onClick = {
                            val text = messages.joinToString("\n")
                            clipboardManager.setText(AnnotatedString(text))
                            snackbarVisible = true
                        },
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text("📋复制", fontSize = 10.sp)
                    }
                    if (snackbarVisible) {
                        LaunchedEffect(Unit) {
                            kotlinx.coroutines.delay(1500)
                            snackbarVisible = false
                        }
                        Text(
                            text = "已复制",
                            fontSize = 10.sp,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(start = 4.dp)
                        )
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize()
                    ) {
                        itemsIndexed(messages, key = { index, _ -> index }) { _, msg ->
                            Text(
                                text = msg,
                                fontSize = 7.sp,
                                lineHeight = 8.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}
