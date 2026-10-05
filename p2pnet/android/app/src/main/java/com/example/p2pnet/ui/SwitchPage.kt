package com.example.p2pnet.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.ui.login.LoginViewModel

private val swLabelWidth = 84.dp
private val swFieldHeight = 30.dp

/**
 * Switch 页：虚拟交换机（对应 python 端 client/app/switch.py 的单例 hub）。
 *
 * 版面：
 *   第一张卡 = 交换机本体，只有两行网口（**动态增长**，一个都没插时显示一个虚线空位）+ 状态 + 启停
 *      —— 本机那个 card 口（tun/tap）不在这里画，它的设备和地址都在下面「配置」卡里选，画两遍是重复
 *   第二张卡 = 配置（card 设备 / tun 地址 / 交换模式 / MTU / 路由老化）
 *   第三张卡 = 内嵌服务（现在是 DHCP，以后还可能加别的）
 *
 * 网口不另存状态：直接由 `handedTo == "switch"` 的 session 派生，顺序就是 port1..portN。
 * 点一个网口 = 拔线（detachUsage），socket 卡片关掉线也自然掉 —— 页面显示的和真实状态永远一致。
 *
 * 目前只有页面 + 配置 + 网口编排：真正的转发（进程内 hub）还没做，和 VpnService 一起留给后续
 * （见 usage/Vswitch.kt）。
 */
@Composable
fun SwitchPage(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val cfg = uiState.switchConfig
    val ports = uiState.udpSockets.filter { it.handedTo == "switch" }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── 交换机本体：正好两行 ──
        //   第一行：「网口」 + 状态 + 启停按钮 + 说明文字
        //   第二行：各个网口
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    // 左对齐：[名字] [已插 N 个] [说明文字（可有可无，放不下就省略）]
                    Text(
                        "网口",
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "已插 ${ports.size} 个",
                        fontSize = 10.sp,
                        color = if (uiState.switchRunning) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = if (ports.isEmpty()) "点 switch 插线" else "点网口 = 拔线",
                        fontSize = 9.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f)
                    )
                    // 右对齐：一个按钮管启停（运行时变红、字变"停止"）
                    Button(
                        onClick = {
                            if (uiState.switchRunning) viewModel.onSwitchStop()
                            else viewModel.onSwitchStart()
                        },
                        modifier = Modifier.height(26.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
                        colors = if (uiState.switchRunning) {
                            ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                        } else {
                            ButtonDefaults.buttonColors()
                        }
                    ) { Text(if (uiState.switchRunning) "停止" else "启动", fontSize = 10.sp) }
                }

                // 第二行：网口，动态增长；0 个时显示一个虚线空位
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    if (ports.isEmpty()) {
                        PortCell(
                            title = "空",
                            line1 = "未插线",
                            line2 = "",
                            filled = false,
                            dashed = true,
                            width = 84.dp
                        )
                    } else {
                        ports.forEachIndexed { index, card ->
                            PortCell(
                                title = "port${index + 1}",
                                line1 = card.target,
                                line2 = formatHostPort(card.peerPublicIp, card.peerPublicPort),
                                filled = true,
                                width = 108.dp,
                                onClick = { viewModel.unplugSwitchPort(card.id) }
                            )
                        }
                    }
                }
            }
        }

        // ── 配置 ──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text("配置", style = MaterialTheme.typography.labelMedium)
                Text(
                    text = "和 python 端 client/app/switch.py 的参数一一对应；配置是全局一份（交换机是单例）",
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                ChoiceRow(
                    label = "card 设备",
                    ids = SwitchPageConfig.CARD_IDS,
                    selected = cfg.cardMode,
                    onSelect = { viewModel.onSwitchCardModeChange(it) },
                    // 选了 tun/tap 才有地址可配：文本框跟在按钮右边同一行，不再另起一行；
                    // 选 none 时整格不出现（没设备就没地址）
                    trailing = {
                        if (cfg.cardMode != SwitchPageConfig.CARD_NONE) {
                            OutlinedTextField(
                                value = cfg.tunIp,
                                onValueChange = { viewModel.onSwitchTunIpChange(it) },
                                singleLine = true,
                                placeholder = { Text("tun 地址", fontSize = 10.sp) },
                                modifier = Modifier.weight(1f).height(swFieldHeight),
                                textStyle = TextStyle(fontSize = 11.sp)
                            )
                        }
                    }
                )
                ChoiceRow(
                    label = "交换模式",
                    ids = SwitchPageConfig.MODE_IDS,
                    selected = cfg.mode,
                    onSelect = { viewModel.onSwitchModeChange(it) }
                )
                NumberField(
                    label = "MTU",
                    value = cfg.mtu,
                    labelWidth = swLabelWidth,
                    onChange = { viewModel.onSwitchMtuChange(it) }
                )
                NumberField(
                    label = "路由老化",
                    value = cfg.routeTtl,
                    labelWidth = swLabelWidth,
                    suffix = "s",
                    onChange = { viewModel.onSwitchRouteTtlChange(it) }
                )
            }
        }

        // ── DHCP（以后别的内嵌服务各自单独一张卡）──
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
                        onCheckedChange = { viewModel.onSwitchDhcpEnabledChange(it) }
                    )
                }
                FieldRow(
                    label = "地址池",
                    value = cfg.dhcpPool,
                    enabled = false,
                    onChange = { viewModel.onSwitchDhcpPoolChange(it) }
                )
                FieldRow(
                    label = "网关",
                    value = cfg.dhcpGateway,
                    enabled = false,
                    onChange = { viewModel.onSwitchDhcpGatewayChange(it) }
                )
                FieldRow(
                    label = "DNS",
                    value = cfg.dhcpDns,
                    enabled = false,
                    onChange = { viewModel.onSwitchDhcpDnsChange(it) }
                )
            }
        }
    }
}

/** 一个网口的格子：标题（portN）+ 两行内容；filled = 已插线，dashed = 空位 */
@Composable
private fun PortCell(
    title: String,
    line1: String,
    line2: String,
    filled: Boolean,
    width: Dp,
    dashed: Boolean = false,
    onClick: (() -> Unit)? = null
) {
    val accent = MaterialTheme.colorScheme.primary
    val faint = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
    // drawBehind 里不能读 MaterialTheme，先取出来
    val dashColor = faint
    Column(
        modifier = Modifier
            .width(width)
            .height(48.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(
                if (filled) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
                else Color.Transparent
            )
            .then(
                if (dashed) {
                    Modifier.drawBehind {
                        drawRoundRect(
                            color = dashColor,
                            cornerRadius = CornerRadius(6.dp.toPx()),
                            style = Stroke(
                                width = 1.dp.toPx(),
                                pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 4f), 0f)
                            )
                        )
                    }
                } else {
                    Modifier.border(BorderStroke(1.dp, if (filled) accent else faint), RoundedCornerShape(6.dp))
                }
            )
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 6.dp, vertical = 4.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = title,
            fontSize = 10.sp,
            maxLines = 1,
            color = if (filled) accent else MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (line1.isNotEmpty()) {
            Text(line1, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (line2.isNotEmpty()) {
            Text(
                text = line2,
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/** 一行「标签 + 若干二选一按钮（+ 可选的尾巴，比如按钮右边跟个输入框）」 */
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
        Text(label, fontSize = 11.sp, modifier = Modifier.width(swLabelWidth))
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
        Text(label, fontSize = 11.sp, modifier = Modifier.width(swLabelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            enabled = enabled,
            singleLine = true,
            modifier = Modifier.weight(1f).height(swFieldHeight),
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
            modifier = Modifier.width(64.dp).height(swFieldHeight),
            textStyle = TextStyle(fontSize = 11.sp)
        )
        if (suffix.isNotEmpty()) Text(suffix, fontSize = 10.sp)
    }
}
