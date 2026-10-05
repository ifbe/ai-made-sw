package com.example.p2pnet.ui

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.ui.login.Direction
import com.example.p2pnet.ui.login.MessageItem
import kotlinx.coroutines.delay

/**
 * App 内日志浮层：**应用级**，悬浮在所有页面之上（不属于某一个页面）。
 *
 * 折叠时只剩右下角一颗「日志」按钮；点开是一个 90% 的矩形，
 * 以右下角为原点从按钮放大 / 缩回（[TransformOrigin] + [graphicsLayer] 缩放 + 遮罩淡入）。
 *
 * 放在 `MainScreen` 的页面内容之上，所以切到任何 tab 都能看到、都能点开；
 * 折叠时这一层不吞触摸事件（只有展开时才铺遮罩拦事件），底下的页面照常可以操作。
 */
@Composable
fun AppLogOverlay(
    messages: List<MessageItem>,
    onClear: () -> Unit,
    modifier: Modifier = Modifier
) {
    // false = 折叠（只剩右下角按钮），true = 展开（90% 屏幕）
    var expanded by remember { mutableStateOf(false) }
    val progress by animateFloatAsState(
        targetValue = if (expanded) 1f else 0f,
        animationSpec = tween(durationMillis = 260, easing = FastOutSlowInEasing)
    )

    Box(modifier = modifier.fillMaxSize()) {
        // ── 展开时的日志面板 + 遮罩（折叠时整块不组合，保证不吞事件）──
        if (progress > 0.001f) {
            // 背景遮罩，随折叠一起淡出；同时吞掉所有触摸，
            // 避免日志展开时误点到/拖到下面的卡片（日志面板本身在遮罩之上，不受影响）
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = 0.55f * progress))
                    .pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                awaitPointerEvent().changes.forEach { it.consume() }
                            }
                        }
                    }
            )

            AppLogPanel(
                messages = messages,
                onClear = onClear,
                onClose = { expanded = false },
                modifier = Modifier
                    .align(Alignment.Center)
                    .fillMaxSize(0.9f)
                    .graphicsLayer {
                        val p = progress
                        alpha = p
                        // 以面板右下角（≈ 屏幕右下角按钮）为原点缩放，形成从按钮放大 / 缩回按钮的动画
                        transformOrigin = TransformOrigin(1f, 1f)
                        scaleX = 0.08f + 0.92f * p
                        scaleY = 0.08f + 0.92f * p
                    }
            )
        }

        // ── 右下角「日志」按钮：折叠或展开时始终显示 ──
        Box(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(16.dp)
                .shadow(8.dp, RoundedCornerShape(24.dp))
                .clip(RoundedCornerShape(24.dp))
                .background(
                    if (expanded) MaterialTheme.colorScheme.tertiaryContainer
                    else MaterialTheme.colorScheme.primaryContainer
                )
                .clickable { expanded = !expanded }
                .padding(horizontal = 20.dp, vertical = 12.dp)
        ) {
            Text(
                text = "日志",
                style = MaterialTheme.typography.labelLarge,
                color = if (expanded) MaterialTheme.colorScheme.onTertiaryContainer
                else MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

/** 展开后的日志面板本体（90% 矩形） */
@Composable
private fun AppLogPanel(
    messages: List<MessageItem>,
    onClear: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboardManager = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    // 新日志到达时自动滚到底部
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    LaunchedEffect(copied) {
        if (copied) {
            delay(1500)
            copied = false
        }
    }

    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        shadowElevation = 16.dp
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "App 内日志",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (messages.isNotEmpty()) {
                        TextButton(
                            onClick = onClear,
                            modifier = Modifier.height(28.dp),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                        ) {
                            Text("清空", fontSize = 10.sp)
                        }
                    }
                    TextButton(
                        onClick = {
                            val text = messages.joinToString("\n") { "${it.direction.name}: ${it.content}" }
                            clipboardManager.setText(AnnotatedString(text))
                            copied = true
                        },
                        enabled = messages.isNotEmpty(),
                        modifier = Modifier.height(28.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                    ) {
                        Text("📋复制", fontSize = 10.sp)
                    }
                    if (copied) {
                        Text(
                            text = "已复制",
                            fontSize = 10.sp,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(start = 4.dp)
                        )
                    }
                    TextButton(
                        onClick = onClose,
                        modifier = Modifier.height(28.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                    ) {
                        Text("✕", fontSize = 12.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(6.dp))

            if (messages.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        text = "暂无日志",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        // 底部留白，避免日志被右下角「日志」按钮挡住
                        contentPadding = PaddingValues(bottom = 56.dp),
                        modifier = Modifier.fillMaxSize()
                    ) {
                        itemsIndexed(messages, key = { index, _ -> index }) { _, item ->
                            AppLogRow(item)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppLogRow(item: MessageItem) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Start
    ) {
        Text(
            text = when (item.direction) {
                Direction.CLIENT -> "client:"
                Direction.SERVER -> "server:"
                Direction.SYSTEM -> "android:"
                Direction.UDP_SEND -> "→ "
                Direction.UDP_RECV -> "← "
            },
            fontSize = 10.sp,
            lineHeight = 13.sp,
            fontFamily = FontFamily.Monospace,
            color = when (item.direction) {
                Direction.CLIENT -> MaterialTheme.colorScheme.primary
                Direction.SERVER -> MaterialTheme.colorScheme.tertiary
                Direction.SYSTEM -> MaterialTheme.colorScheme.error
                Direction.UDP_SEND -> MaterialTheme.colorScheme.primary
                Direction.UDP_RECV -> MaterialTheme.colorScheme.tertiary
            },
            modifier = Modifier.width(52.dp)
        )
        Text(
            text = item.content,
            fontSize = 10.sp,
            lineHeight = 13.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
