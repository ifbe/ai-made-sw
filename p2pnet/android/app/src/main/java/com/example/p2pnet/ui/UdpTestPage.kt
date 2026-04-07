package com.example.p2pnet.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
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

    // 自动滚动到底部
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text("UDP - ${page.targetUsername}", style = MaterialTheme.typography.titleMedium)
        HorizontalDivider()

        // 头部：3 行地址信息
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

        HorizontalDivider()

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "消息历史",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
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

        SelectionContainer {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxWidth().weight(1f)
            ) {
                itemsIndexed(messages, key = { index, _ -> index }) { _, msg ->
                    Text(
                        text = msg,
                        fontSize = 8.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}
