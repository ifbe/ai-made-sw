package com.example.p2pnet.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.net.formatHostPort
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

/**
 * WireGuard 页顶部的「实现」配置：三档 + （选「调系统程序」时的）外部 VPN 应用。
 *
 * 三档只决定"谁来跑协议栈"：
 *  自己实现 / 官方库 → 我们自建 VpnService，UDP 出口用已打洞的本地端口；
 *  调系统程序        → 把参数（listen_port 等）交给外部那个 VPN 服务 app。
 * 共同点：**UDP 出口必须是打洞时那个本地端口**，否则 NAT 映射就废了。
 */
@Composable
private fun WgImplCard(
    cfg: WgPageConfig,
    page: Page.WireGuard,
    onImplChange: (String) -> Unit,
    onExtPackageChange: (String) -> Unit,
    onExtActionChange: (String) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
        Column(
            modifier = Modifier.padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text("实现", style = MaterialTheme.typography.labelMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                WgPageConfig.IMPL_IDS.forEach { id ->
                    val on = id == cfg.impl
                    OutlinedButton(
                        onClick = { onImplChange(id) },
                        shape = RoundedCornerShape(6.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                        border = BorderStroke(
                            1.dp,
                            if (on) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                        ),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = if (on) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant
                        ),
                        modifier = Modifier.height(26.dp)
                    ) { Text(WgPageConfig.label(id), fontSize = 10.sp) }
                }
            }
            Text(
                text = WgPageConfig.describe(cfg.impl),
                fontSize = 9.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (cfg.impl == WgPageConfig.IMPL_SYSTEM) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 2.dp))
                Text("外部 VPN 应用", style = MaterialTheme.typography.labelMedium)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("包名", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                    OutlinedTextField(
                        value = cfg.extPackage,
                        onValueChange = onExtPackageChange,
                        singleLine = true,
                        placeholder = { Text("留空 = 只按 action 找", fontSize = 10.sp) },
                        modifier = Modifier.weight(1f).height(fieldHeight),
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("Action", fontSize = 11.sp, modifier = Modifier.width(labelWidth))
                    OutlinedTextField(
                        value = cfg.extAction,
                        onValueChange = onExtActionChange,
                        singleLine = true,
                        modifier = Modifier.weight(1f).height(fieldHeight),
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp)
                    )
                }
                Text(
                    text = "将传给对方：listen_port=" +
                        (if (page.myPort > 0) page.myPort.toString() else "(还没通路)") +
                        "  peer=" +
                        (if (page.peerIp.isNotEmpty()) formatHostPort(page.peerIp, page.peerPort)
                        else "(还没通路)"),
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "listen_port 必须是打洞时那个本地端口，否则已建立的 NAT 映射会废",
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Text(
                    text = "UDP 出口固定用已打洞的那个本地端口" +
                        (if (page.myPort > 0) "（本页当前 ${page.myPort}）" else ""),
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun WireGuardPage(page: Page.WireGuard, viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val wgConfig = uiState.wgConfig
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

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        // ── 实现方式：决定 socket 卡片上点 wg 之后走哪条路 ──
        WgImplCard(
            cfg = wgConfig,
            page = page,
            onImplChange = { viewModel.onWgImplChange(it) },
            onExtPackageChange = { viewModel.onWgExtPackageChange(it) },
            onExtActionChange = { viewModel.onWgExtActionChange(it) }
        )

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
