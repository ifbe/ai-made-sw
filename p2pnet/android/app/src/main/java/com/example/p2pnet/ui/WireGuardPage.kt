package com.example.p2pnet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.ui.login.LoginViewModel
import java.util.UUID

// WireGuard 配置（兼容旧接口，单 peer 场景）
data class WgConfig(
    val myIp: String = "10.0.0.2/24",
    val myPort: Int = 51820,
    val myPrivateKey: String = "",
    val peerEndpoint: String = "",
    val peerPublicKey: String = "",
    val peerPresharedKey: String = "",
    val allowedIPs: String = "0.0.0.0/0",
    val dns: String = "8.8.8.8",
    val mtu: Int = 1420
)

// WireGuard Interface 配置
data class WgInterface(
    val myIp: String = "10.0.0.2/24",
    val myPort: Int = 51820,
    val privateKey: String = "",
    val peers: List<WgPeer> = emptyList()
)

// WireGuard Peer 配置
data class WgPeer(
    val id: String = UUID.randomUUID().toString(),
    val endpoint: String = "",
    val publicKey: String = "",
    val presharedKey: String = "",
    val allowedIPs: String = "0.0.0.0/0",
    val status: TunnelStatus = TunnelStatus.DISCONNECTED
)

enum class TunnelStatus {
    DISCONNECTED, CONNECTING, CONNECTED, FAILED
}

private val labelWidth = 72.dp
private val fieldHeight = 32.dp
private val rowSpacer = 4.dp

@Composable
fun WireGuardPage(page: Page.WireGuard, viewModel: LoginViewModel) {
    val wgLogs by viewModel.wgLogMessages.collectAsState()
    val logListState = rememberLazyListState()
    var tunnelStatus by remember { mutableStateOf(TunnelStatus.DISCONNECTED) }
    val wgInterface = remember {
        mutableStateOf(
            WgInterface(
                myPort = page.myPort,
                privateKey = "GHH4S==XXo89xk2k3n5jV8Q==",
                peers = listOf(
                    WgPeer(endpoint = "10.0.0.1:51820", publicKey = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc=", allowedIPs = "0.0.0.0/0")
                )
            )
        )
    }
    val showPrivateKey = remember { mutableStateOf(false) }

    val isAutoMode = page.peerIp.isNotEmpty()

    // 自动滚动日志
    LaunchedEffect(wgLogs.size) {
        if (wgLogs.isEmpty()) return@LaunchedEffect
        val lastVisible = logListState.layoutInfo.visibleItemsInfo.lastOrNull()
        val atBottom = lastVisible != null && lastVisible.index >= wgLogs.size - 1
        if (atBottom) logListState.animateScrollToItem(wgLogs.size - 1)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        // ── 连接按钮 ──
        Box(modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = {
                    if (tunnelStatus == TunnelStatus.DISCONNECTED) {
                        viewModel.appendWgLog("正在启动 WireGuard...")
                        tunnelStatus = TunnelStatus.CONNECTING
                        if (isAutoMode) {
                            viewModel.startWgTunnelAuto(page) { success, msg ->
                                tunnelStatus = if (success) TunnelStatus.CONNECTED else TunnelStatus.DISCONNECTED
                                viewModel.appendWgLog(if (success) "WireGuard 已连接" else "启动失败: $msg")
                            }
                        } else {
                            viewModel.startWgTunnelManual(wgInterface.value) { success, msg ->
                                tunnelStatus = if (success) TunnelStatus.CONNECTED else TunnelStatus.DISCONNECTED
                                viewModel.appendWgLog(if (success) "WireGuard 已连接" else "启动失败: $msg")
                            }
                        }
                    } else {
                        viewModel.stopWgTunnel()
                        tunnelStatus = TunnelStatus.DISCONNECTED
                        viewModel.appendWgLog("WireGuard 已断开")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (tunnelStatus == TunnelStatus.CONNECTED)
                        MaterialTheme.colorScheme.error
                    else
                        MaterialTheme.colorScheme.primary
                )
            ) {
                Text(
                    text = when (tunnelStatus) {
                        TunnelStatus.CONNECTED -> "已连接 — 点击断开"
                        TunnelStatus.CONNECTING -> "连接中..."
                        TunnelStatus.FAILED -> "连接失败 — 重试"
                        TunnelStatus.DISCONNECTED -> if (isAutoMode) "启动 WireGuard" else "启动 WireGuard"
                    },
                    fontSize = 12.sp
                )
            }
        }

        // ── My Interface ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp)
        ) {
            Column(modifier = Modifier.padding(8.dp)) {
                Text(
                    text = "My Interface",
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(bottom = rowSpacer)
                )

                // IP/掩码 + 端口
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("IP/掩码", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                    OutlinedTextField(
                        value = wgInterface.value.myIp,
                        onValueChange = { wgInterface.value = wgInterface.value.copy(myIp = it) },
                        modifier = Modifier.weight(1f).height(fieldHeight),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                    )
                    Text("端口", fontSize = 11.sp, modifier = Modifier.width(32.dp))
                    OutlinedTextField(
                        value = wgInterface.value.myPort.toString(),
                        onValueChange = { wgInterface.value = wgInterface.value.copy(myPort = it.toIntOrNull() ?: 51820) },
                        modifier = Modifier.width(64.dp).height(fieldHeight),
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                    )
                }

                Spacer(modifier = Modifier.height(rowSpacer))

                // 私钥 + 生成按钮
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("私钥", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                    OutlinedTextField(
                        value = wgInterface.value.privateKey,
                        onValueChange = { wgInterface.value = wgInterface.value.copy(privateKey = it) },
                        modifier = Modifier.weight(1f).height(fieldHeight),
                        singleLine = true,
                        visualTransformation = if (showPrivateKey.value) VisualTransformation.None else PasswordVisualTransformation(),
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                    )
                    IconButton(
                        onClick = { showPrivateKey.value = !showPrivateKey.value },
                        modifier = Modifier.size(fieldHeight)
                    ) {
                        Text(if (showPrivateKey.value) "🙈" else "👁", fontSize = 12.sp)
                    }
                    Button(
                        onClick = {
                            viewModel.generateWgKeypair { _, privkey ->
                                wgInterface.value = wgInterface.value.copy(privateKey = privkey)
                                viewModel.appendWgLog("密钥对已生成")
                            }
                        },
                        modifier = Modifier.height(fieldHeight),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                    ) {
                        Text("生成", fontSize = 11.sp)
                    }
                }
            }
        }

        // ── Peer 列表 ──
        wgInterface.value.peers.forEachIndexed { index, peer ->
            PeerCard(
                peer = peer,
                peerIndex = index,
                isAutoMode = isAutoMode,
                onUpdate = { updated ->
                    val newPeers = wgInterface.value.peers.toMutableList()
                    newPeers[index] = updated
                    wgInterface.value = wgInterface.value.copy(peers = newPeers)
                },
                onDelete = {
                    val newPeers = wgInterface.value.peers.toMutableList()
                    newPeers.removeAt(index)
                    wgInterface.value = wgInterface.value.copy(peers = newPeers)
                }
            )
        }

        OutlinedButton(
            onClick = {
                wgInterface.value = wgInterface.value.copy(
                    peers = wgInterface.value.peers + WgPeer()
                )
            },
            modifier = Modifier.fillMaxWidth().height(32.dp),
            contentPadding = PaddingValues(vertical = 0.dp)
        ) {
            Text("+ 添加 Peer", fontSize = 11.sp)
        }

        // ── 消息历史 ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp)
        ) {
            Column(modifier = Modifier.padding(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("消息历史", style = MaterialTheme.typography.labelMedium)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (wgLogs.isNotEmpty()) {
                            TextButton(
                                onClick = { viewModel.clearWgLog() },
                                modifier = Modifier.height(24.dp),
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                            ) {
                                Text("清空", fontSize = 10.sp)
                            }
                        }
                        val clipboardManager = LocalClipboardManager.current
                        var copiedVisible by remember { mutableStateOf(false) }
                        TextButton(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(wgLogs.joinToString("\n")))
                                copiedVisible = true
                            },
                            modifier = Modifier.height(24.dp),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                        ) {
                            Text("📋复制", fontSize = 10.sp)
                        }
                        if (copiedVisible) {
                            LaunchedEffect(Unit) {
                                kotlinx.coroutines.delay(1500)
                                copiedVisible = false
                            }
                            Text("已复制", fontSize = 10.sp, color = MaterialTheme.colorScheme.primary)
                        }
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

                LazyColumn(
                    state = logListState,
                    modifier = Modifier.height(120.dp)
                ) {
                    itemsIndexed(wgLogs, key = { index, _ -> index }) { _, msg ->
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

@Composable
private fun PeerCard(
    peer: WgPeer,
    peerIndex: Int,
    isAutoMode: Boolean,
    onUpdate: (WgPeer) -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(8.dp)) {
            // 标题行
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Peer ${peerIndex + 1}", style = MaterialTheme.typography.labelMedium)
                if (!isAutoMode) {
                    IconButton(
                        onClick = onDelete,
                        modifier = Modifier.size(20.dp)
                    ) {
                        Text("×", fontSize = 16.sp, color = MaterialTheme.colorScheme.error)
                    }
                }
            }

            // Endpoint
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text("Endpoint", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                OutlinedTextField(
                    value = peer.endpoint,
                    onValueChange = { onUpdate(peer.copy(endpoint = it)) },
                    modifier = Modifier.weight(1f).height(fieldHeight),
                    singleLine = true,
                    enabled = !isAutoMode,
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                )
            }

            Spacer(modifier = Modifier.height(rowSpacer))

            // Peer 公钥
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text("Peer公钥", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                OutlinedTextField(
                    value = peer.publicKey,
                    onValueChange = { onUpdate(peer.copy(publicKey = it)) },
                    modifier = Modifier.weight(1f).height(fieldHeight),
                    singleLine = true,
                    enabled = !isAutoMode,
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                )
            }

            Spacer(modifier = Modifier.height(rowSpacer))

            // Preshared Key
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text("Preshared", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                OutlinedTextField(
                    value = peer.presharedKey,
                    onValueChange = { onUpdate(peer.copy(presharedKey = it)) },
                    modifier = Modifier.weight(1f).height(fieldHeight),
                    singleLine = true,
                    enabled = !isAutoMode,
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                )
            }

            Spacer(modifier = Modifier.height(rowSpacer))

            // Allowed IPs
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text("AllowedIPs", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                OutlinedTextField(
                    value = peer.allowedIPs,
                    onValueChange = { onUpdate(peer.copy(allowedIPs = it)) },
                    modifier = Modifier.weight(1f).height(fieldHeight),
                    singleLine = true,
                    enabled = !isAutoMode,
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                )
            }
        }
    }
}
