package com.example.p2pnet.ui.login

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.ui.Page

@Composable
fun MainPage(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val focusManager = LocalFocusManager.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 4.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        // ── Block 1: connection ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text("ws", style = MaterialTheme.typography.bodyMedium)
                        Switch(
                            checked = uiState.useWss,
                            onCheckedChange = viewModel::onUseWssChange,
                            modifier = Modifier.height(24.dp)
                        )
                        Text("wss", style = MaterialTheme.typography.bodyMedium)
                    }
                    OutlinedTextField(
                        value = uiState.serverHost,
                        onValueChange = viewModel::onServerHostChange,
                        label = { Text("服务器") },
                        singleLine = true,
                        enabled = !uiState.loading,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Uri,
                            imeAction = ImeAction.Next
                        ),
                        keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Right) }),
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = uiState.serverPort,
                        onValueChange = viewModel::onServerPortChange,
                        label = { Text("端口") },
                        singleLine = true,
                        enabled = !uiState.loading,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Number,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(onDone = {
                            focusManager.clearFocus()
                            if (!uiState.isConnected) viewModel.onConnect()
                        }),
                        modifier = Modifier.width(80.dp)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        if (uiState.isConnected) {
                            viewModel.onDisconnect()
                        } else {
                            viewModel.onConnect()
                        }
                    },
                    enabled = !uiState.loading,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        if (uiState.isConnected) "已连接，点我断开"
                        else "未连接，点我连接"
                    )
                }
            }
        }

        // ── Block 2: login ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = uiState.username,
                        onValueChange = viewModel::onUsernameChange,
                        label = { Text("用户名") },
                        singleLine = true,
                        enabled = !uiState.loading,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                        keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Down) }),
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = uiState.password,
                        onValueChange = viewModel::onPasswordChange,
                        label = { Text("密码") },
                        singleLine = true,
                        enabled = !uiState.loading,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(onDone = {
                            focusManager.clearFocus()
                            viewModel.onLogin()
                        }),
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                uiState.error?.let { error ->
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }

                Button(
                    onClick = {
                        if (uiState.isLoggedIn) {
                            viewModel.onLogout()
                        } else {
                            viewModel.onLogin()
                        }
                    },
                    enabled = !uiState.loading && (
                        uiState.isLoggedIn ||
                            (uiState.isConnected && uiState.username.isNotBlank() && uiState.password.isNotBlank())
                        ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (uiState.loading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text(
                        if (uiState.isLoggedIn) "已登录，点我退出"
                        else "未登录，点我登录"
                    )
                }
            }
        }

        // ── Block 3: peer ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                OutlinedTextField(
                    value = uiState.targetUsername,
                    onValueChange = viewModel::onTargetUsernameChange,
                    label = { Text("对方用户名") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { viewModel.onList() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.primary
                        )
                    ) {
                        Text("list")
                    }
                    OutlinedButton(
                        onClick = { viewModel.onWghelp() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.secondary
                        )
                    ) {
                        Text("wghelp")
                    }
                    OutlinedButton(
                        onClick = { viewModel.onUdp() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.tertiary
                        )
                    ) {
                        Text("udp")
                    }
                    OutlinedButton(
                        onClick = { viewModel.navigateTo(Page.Chat(uiState.targetUsername)) },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text("tcp")
                    }
                }
            }
        }

        // ── Block 4: message history ──
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
                        text = "收发历史",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (uiState.messages.isNotEmpty()) {
                            TextButton(
                                onClick = { viewModel.clearMessages() },
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
                                val text = uiState.messages.joinToString("\n") { "${it.direction.name}: ${it.content}" }
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

                Spacer(modifier = Modifier.height(8.dp))

                val listState = rememberLazyListState()
                LaunchedEffect(uiState.messages.size) {
                    if (uiState.messages.isNotEmpty()) {
                        listState.animateScrollToItem(uiState.messages.size - 1)
                    }
                }

                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        itemsIndexed(uiState.messages, key = { index, _ -> index }) { _, item ->
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
                                    fontSize = 7.sp,
                                    lineHeight = 8.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = when (item.direction) {
                                        Direction.CLIENT -> MaterialTheme.colorScheme.primary
                                        Direction.SERVER -> MaterialTheme.colorScheme.tertiary
                                        Direction.SYSTEM -> MaterialTheme.colorScheme.error
                                        Direction.UDP_SEND -> MaterialTheme.colorScheme.primary
                                        Direction.UDP_RECV -> MaterialTheme.colorScheme.tertiary
                                    },
                                    modifier = Modifier.wrapContentWidth()
                                )
                                Text(
                                    text = item.content,
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
}
