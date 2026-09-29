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

    // 是否跟着最新一条走：用户往上翻历史就暂停，滑回最底下再自动恢复
    var followTail by remember { mutableStateOf(true) }
    // 首次进入直接跳到底（不 animate），免得先看到从顶部一路滚下来
    var didInitialJump by remember { mutableStateOf(false) }

    // 只在「一轮手动滚动停下来」这一刻重新判断要不要跟随。
    // 不能用 messages.size 判断有没有贴底：新消息一进来，最后一条就暂时跑到视口外，
    // 「是否贴底」瞬间变 false，跟随会再也回不来。
    LaunchedEffect(listState) {
        snapshotFlow { listState.isScrollInProgress }.collect { scrolling ->
            if (!scrolling) followTail = !listState.canScrollForward
        }
    }

    LaunchedEffect(messages.size) {
        if (messages.isEmpty() || !followTail) return@LaunchedEffect
        if (!didInitialJump) {
            listState.scrollToItem(messages.lastIndex)
            didInitialJump = true
        } else {
            listState.animateScrollToItem(messages.lastIndex)
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
            // 注意：这一层 Column 不再统一加 padding——消息内容要左右间距 0，紧贴卡片边缘。
            // 标题行和分割线各自补 padding，所以只有消息列表是贴边的。
            Column {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 12.dp, end = 12.dp, top = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "消息历史",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (messages.isNotEmpty()) {
                            TextButton(
                                onClick = { viewModel.clearUdpSockMessages() },
                                modifier = Modifier.height(28.dp),
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                            ) {
                                Text("清空", fontSize = 10.sp)
                            }
                        }
                        val clipboardManager = LocalClipboardManager.current
                        var snackbarVisible by remember { mutableStateOf(false) }
                        TextButton(
                            onClick = {
                                // 复制的是原始日志（不带下面为了排版插入的零宽字符）
                                val text = messages.joinToString("\n")
                                clipboardManager.setText(AnnotatedString(text))
                                snackbarVisible = true
                            },
                            modifier = Modifier.height(28.dp),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
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
                }

                HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))

                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize()
                    ) {
                        itemsIndexed(messages, key = { index, _ -> index }) { _, msg ->
                            Text(
                                text = logDisplayText(msg),
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

/**
 * 日志里的 JSON 是一整块没有空格的字符，安卓的行断开是按「词」来的：
 * 这一块整体放不下时会被整个挪到下一行，看起来就像凭空空了一行。
 *
 * 这里在 `{...}` 里面每个字符后面插一个零宽空格（U+200B）：
 * 它只增加换行点、本身不占宽度也不显示，于是 JSON 会正常接在前面文字后面、
 * 排到行尾再折行；JSON 之外的普通文字（带空格的中文/英文）换行规则不受影响。
 *
 * 只认 `{`，不认 `[`：`[12:00:00.123]`、`[direct]` 这种方括号在普通日志里太常见，
 * 不当作 JSON 起点（JSON 数组都嵌在对象里，外层 `{` 已经把 depth 打开了）。
 *
 * 只用于显示：📋复制 用的是原始 messages，不含这些零宽字符。
 */
private fun logDisplayText(line: String): String {
    // 不含 JSON 对象的日志原样返回，不做多余处理
    if (!line.contains('{')) return line
    val sb = StringBuilder(line.length + 32)
    var depth = 0
    for (ch in line) {
        sb.append(ch)
        when (ch) {
            '{' -> {
                depth++
                sb.append('\u200B')
            }
            '}' -> {
                if (depth > 0) depth--
                // 闭合回到顶层就不必再加换行点了
                if (depth > 0) sb.append('\u200B')
            }
            else -> if (depth > 0) sb.append('\u200B')
        }
    }
    return sb.toString()
}
