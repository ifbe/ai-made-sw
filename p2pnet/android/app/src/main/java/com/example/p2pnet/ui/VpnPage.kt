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
import com.example.p2pnet.ui.login.LoginViewModel

private val vpnLabelWidth = 84.dp
private val vpnFieldHeight = 30.dp

/**
 * VPN 页：**一对一**（对应 python 端 client/app/vpn.py：一个洞 ↔ 一块 tun/tap）。
 *
 * 和 [SwitchPage] 的唯一区别就是：**没有网口那张卡**（一对一只有一条隧道，不需要网口那排）。
 * 其余保持一致 —— 配置卡（card 设备 / tun 地址 / 交换模式 / MTU / 路由老化）+ DHCP 卡；
 * 原来放在网口卡里的状态和启停按钮，并进配置卡顶部。
 *
 * 谁和谁是一对：在主页 socket 卡片第 5 行点 `tun`（就是这条隧道），页面顶部的「通道」会显示是哪一条。
 * 真正的 tun/tap 与协议栈还没做，见 usage/Tun.kt。
 */
@Composable
fun VpnPage(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val cfg = uiState.vpnConfig
    val channels = uiState.udpSockets.filter { it.handedTo == "tun" }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── 配置（一对一：没有网口卡，状态和启停并到这一行的右边）──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("配置", style = MaterialTheme.typography.labelMedium)
                    Text(
                        text = if (channels.isEmpty()) "未接线" else "已接 ${channels.size} 条",
                        fontSize = 10.sp,
                        color = if (uiState.vpnRunning) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    // 一对一：一个按钮管启停（运行时变红、字变"停止"）
                    Button(
                        onClick = {
                            if (uiState.vpnRunning) viewModel.onVpnStop() else viewModel.onVpnStart()
                        },
                        modifier = Modifier.height(26.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
                        colors = if (uiState.vpnRunning) {
                            ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                        } else {
                            ButtonDefaults.buttonColors()
                        }
                    ) { Text(if (uiState.vpnRunning) "停止" else "启动", fontSize = 10.sp) }
                }
                Text(
                    text = "一对一：一个洞 ↔ 一块 tun/tap（对应 python 端 client/app/vpn.py）；" +
                        "多人互联用 switch 页",
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                ChoiceRow(
                    label = "card 设备",
                    ids = VpnPageConfig.CARD_IDS,
                    selected = cfg.cardMode,
                    onSelect = { viewModel.onVpnCardModeChange(it) },
                    // 选了 tun/tap 才有地址可配：文本框跟在按钮右边同一行；选 none 时整格不出现
                    trailing = {
                        if (cfg.cardMode != VpnPageConfig.CARD_NONE) {
                            OutlinedTextField(
                                value = cfg.tunIp,
                                onValueChange = { viewModel.onVpnTunIpChange(it) },
                                singleLine = true,
                                placeholder = { Text("tun 地址", fontSize = 10.sp) },
                                modifier = Modifier.weight(1f).height(vpnFieldHeight),
                                textStyle = TextStyle(fontSize = 11.sp)
                            )
                        }
                    }
                )
                ChoiceRow(
                    label = "交换模式",
                    ids = VpnPageConfig.MODE_IDS,
                    selected = cfg.mode,
                    onSelect = { viewModel.onVpnModeChange(it) }
                )
                NumberField(
                    label = "MTU",
                    value = cfg.mtu,
                    labelWidth = vpnLabelWidth,
                    onChange = { viewModel.onVpnMtuChange(it) }
                )
                NumberField(
                    label = "路由老化",
                    value = cfg.routeTtl,
                    labelWidth = vpnLabelWidth,
                    suffix = "s",
                    onChange = { viewModel.onVpnRouteTtlChange(it) }
                )

                Text(
                    text = if (channels.isEmpty()) {
                        "通道：还没有（在主页 socket 卡片第 5 行点 tun）"
                    } else {
                        "通道：" + channels.joinToString("、") {
                            "${it.target}(洞${it.localPort})"
                        } + if (channels.size > 1) "  ⚠️ 一对一只要一条" else ""
                    },
                    fontSize = 9.sp,
                    color = if (channels.size > 1) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        // ── DHCP（和 switch 页一致；以后别的内嵌服务各自单独一张卡）──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("嵌入 DHCP 服务器", fontSize = 11.sp, modifier = Modifier.weight(1f))
                    Text(
                        text = "尚未实现",
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(end = 6.dp)
                    )
                    Switch(
                        checked = cfg.dhcpEnabled,
                        onCheckedChange = { viewModel.onVpnDhcpEnabledChange(it) }
                    )
                }
                FieldRow(
                    label = "地址池",
                    value = cfg.dhcpPool,
                    enabled = false,
                    onChange = { viewModel.onVpnDhcpPoolChange(it) }
                )
                FieldRow(
                    label = "网关",
                    value = cfg.dhcpGateway,
                    enabled = false,
                    onChange = { viewModel.onVpnDhcpGatewayChange(it) }
                )
                FieldRow(
                    label = "DNS",
                    value = cfg.dhcpDns,
                    enabled = false,
                    onChange = { viewModel.onVpnDhcpDnsChange(it) }
                )
            }
        }
    }
}

/** 一行「标签 + 若干二选一按钮（+ 可选尾巴，比如按钮右边跟个输入框）】 */
@Composable
private fun ChoiceRow(
    label: String,
    ids: List<String>,
    selected: String,
    onSelect: (String) -> Unit,
    trailing: (@Composable RowScope.() -> Unit)? = null
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(vpnLabelWidth))
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
            ) { Text(id, fontSize = 10.sp) }
        }
        trailing?.invoke(this)
    }
}

/** 一行「标签 + 文本框」 */
@Composable
private fun FieldRow(
    label: String,
    value: String,
    enabled: Boolean = true,
    onChange: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(vpnLabelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            enabled = enabled,
            singleLine = true,
            modifier = Modifier.weight(1f).height(vpnFieldHeight),
            textStyle = TextStyle(fontSize = 11.sp)
        )
    }
}

/** 一行「标签 + 数字框（+ 可选后缀）」 */
@Composable
private fun NumberField(
    label: String,
    value: String,
    labelWidth: Dp,
    suffix: String = "",
    onChange: (String) -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(labelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = { onChange(it.filter { c -> c.isDigit() }) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.width(64.dp).height(vpnFieldHeight),
            textStyle = TextStyle(fontSize = 11.sp)
        )
        if (suffix.isNotEmpty()) Text(suffix, fontSize = 10.sp)
    }
}
