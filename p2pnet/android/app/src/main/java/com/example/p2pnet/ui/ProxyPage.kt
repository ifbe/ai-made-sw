package com.example.p2pnet.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.ui.login.LoginViewModel

private val pxLabelWidth = 72.dp
private val pxFieldHeight = 30.dp

/**
 * Proxy 页：端口转发。**一条洞 ↔ 一个固定端口**，按 ssh 的习惯分正/反向。
 *
 * 两种模式各只负责本机这一侧（另一半要靠对端配合）：
 *  - **正向 -L（本机 listen）**：启动时监听 [ProxyPageConfig.lListenIp]:[ProxyPageConfig.lListenPort]，
 *    accept 之后收到的数据丢进洞里，来自洞里的数据回给这条连接。
 *  - **反向 -R（本机 connect）**：启动时 connect [ProxyPageConfig.rTargetHost]:[ProxyPageConfig.rTargetPort]，
 *    和洞之间互转数据。—— python 端 client/app/proxy.py 就是这一半。
 *
 * 版面：
 *   **配置卡（在上面）**：模式、协议、保活间隔、洞地址、洞端口、启停按钮
 *   **代理卡（在下面）**：按模式只显示该模式的地址/端口（-L 是监听侧，-R 是目标侧）
 */
@Composable
fun ProxyPage(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val cfg = uiState.proxyConfig
    val isL = cfg.mode == ProxyPageConfig.MODE_L
    val channels = uiState.udpSockets.filter { it.handedTo == "proxy" }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── 配置卡（在上面）──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                // 首行与 vpn / switch 完全同一套：左「配置」+ 通道数状态 + Spacer(weight) + 最右启停按钮
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("配置", style = MaterialTheme.typography.labelMedium)
                    Text(
                        text = channelStatusText(channels.size),
                        fontSize = 10.sp,
                        color = if (uiState.proxyRunning) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    // 一个按钮管启停（运行时变红、字变"停止"）
                    Button(
                        onClick = {
                            if (uiState.proxyRunning) viewModel.onProxyStop() else viewModel.onProxyStart()
                        },
                        modifier = Modifier.height(26.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
                        colors = if (uiState.proxyRunning) {
                            ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                        } else {
                            ButtonDefaults.buttonColors()
                        }
                    ) { Text(if (uiState.proxyRunning) "停止" else "启动", fontSize = 10.sp) }
                }

                // 模式
                PxChoiceRow(
                    label = "模式",
                    ids = ProxyPageConfig.MODE_IDS,
                    selected = cfg.mode,
                    labelOf = { ProxyPageConfig.modeLabel(it) },
                    onSelect = { viewModel.onProxyModeChange(it) }
                )
                PxChoiceRow(
                    label = "协议",
                    ids = ProxyPageConfig.PROTO_IDS,
                    selected = cfg.proto,
                    onSelect = { viewModel.onProxyProtoChange(it) }
                )
                PxNumberRow(
                    label = "保活间隔",
                    value = cfg.keepaliveSec,
                    suffix = "s",
                    onChange = { viewModel.onProxyKeepaliveChange(it) }
                )

                // 洞地址 / 洞端口：两行
                PxFieldRow(
                    label = "洞地址",
                    value = cfg.bindAddr,
                    placeholder = "0.0.0.0",
                    onChange = { viewModel.onProxyBindAddrChange(it) }
                )
                PxNumberRow(
                    label = "洞端口",
                    value = cfg.localPort,
                    suffix = if (cfg.localPort.isBlank()) "(用 session 的)" else "",
                    labelWidth = pxLabelWidth,
                    onChange = { viewModel.onProxyLocalPortChange(it) }
                )
                Text(
                    text = "   洞端口留空 = 直接用这条 session 打洞出来的本机端口（推荐）",
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // 启停按钮已经在首行最右（和 vpn / switch 一样），这里不再单独占一行

                // 空态不渲染；有通道时才显示这条明细（数量 + 是哪些洞）
                if (channels.isNotEmpty()) {
                    Text(
                        text = "通道 ${channels.size} 条：" + channels.joinToString("、") {
                            "${it.target}(洞${it.localPort})"
                        },
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        // ── 代理卡（在下面）：按模式只显示该模式的地址/端口 ──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = if (isL) "正向代理 -L（本机监听）" else "反向代理 -R（本机 connect）",
                    style = MaterialTheme.typography.labelMedium
                )

                if (isL) {
                    PxFieldRow(
                        label = "监听地址",
                        value = cfg.lListenIp,
                        placeholder = "127.0.0.1",
                        onChange = { viewModel.onProxyLListenIpChange(it) }
                    )
                    PxNumberRow(
                        label = "监听端口",
                        value = cfg.lListenPort,
                        suffix = if (cfg.lListenPort == "0") "(自动)" else "",
                        onChange = { viewModel.onProxyLListenPortChange(it) }
                    )
                    val port = cfg.lListenPort.toIntOrNull() ?: 0
                    Text(
                        text = "   本机应用连 " +
                            (if (port == 0) "${cfg.lListenIp}:自动" else formatHostPort(cfg.lListenIp, port)) +
                            " → 数据进洞 → 对端 -R 去 connect 它的目标",
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "   监听地址填 127.0.0.1 = 只有本机应用能连；0.0.0.0 = 局域网也能连",
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    PxFieldRow(
                        label = "目标地址",
                        value = cfg.rTargetHost,
                        placeholder = "127.0.0.1",
                        onChange = { viewModel.onProxyRTargetHostChange(it) }
                    )
                    PxNumberRow(
                        label = "目标端口",
                        value = cfg.rTargetPort,
                        placeholder = "3389",
                        onChange = { viewModel.onProxyRTargetPortChange(it) }
                    )
                    val port = cfg.rTargetPort.toIntOrNull() ?: 0
                    Text(
                        text = "   洞里的流量 → " +
                            (if (port == 0) "${cfg.rTargetHost}:(端口未填)" else formatHostPort(cfg.rTargetHost, port)) +
                            "，回包原路送回洞里",
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "   目标通常是本机服务（SSH 22 / 远程桌面 3389…）；填 0.0.0.0 没意义，要填具体地址",
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

/** 一行「标签 + 若干二选一按钮」 */
@Composable
private fun PxChoiceRow(
    label: String,
    ids: List<String>,
    selected: String,
    onSelect: (String) -> Unit,
    labelOf: (String) -> String = { it }
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(pxLabelWidth))
        ids.forEach { id ->
            val on = id == selected
            OutlinedButton(
                onClick = { onSelect(id) },
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
            ) { Text(labelOf(id), fontSize = 10.sp) }
        }
    }
}

/** 一行「标签 + 文本框」 */
@Composable
private fun PxFieldRow(
    label: String,
    value: String,
    enabled: Boolean = true,
    placeholder: String = "",
    labelWidth: Dp = pxLabelWidth,
    onChange: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(labelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            enabled = enabled,
            singleLine = true,
            placeholder = if (placeholder.isEmpty()) null else {
                { Text(placeholder, fontSize = 10.sp) }
            },
            modifier = Modifier.weight(1f).height(pxFieldHeight),
            textStyle = TextStyle(fontSize = 11.sp)
        )
    }
}

/** 一行「标签 + 数字框（+ 可选后缀）」 */
@Composable
private fun PxNumberRow(
    label: String,
    value: String,
    suffix: String = "",
    enabled: Boolean = true,
    placeholder: String = "",
    labelWidth: Dp = pxLabelWidth,
    onChange: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(labelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = { onChange(it.filter { c -> c.isDigit() }) },
            enabled = enabled,
            singleLine = true,
            placeholder = if (placeholder.isEmpty()) null else {
                { Text(placeholder, fontSize = 10.sp) }
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.width(80.dp).height(pxFieldHeight),
            textStyle = TextStyle(fontSize = 11.sp)
        )
        if (suffix.isNotEmpty()) {
            Text(suffix, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
