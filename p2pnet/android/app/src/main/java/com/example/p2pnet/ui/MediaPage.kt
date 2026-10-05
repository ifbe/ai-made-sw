package com.example.p2pnet.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.p2pnet.net.formatHostPort
import com.example.p2pnet.net.localAddresses
import com.example.p2pnet.ui.login.LoginViewModel

private val mdLabelWidth = 72.dp

/**
 * media 页：多媒体聊天（对应 python 端 client/app/media.py + app/ffmpeg.sh）。
 *
 * **我们的程序只负责打洞**：打好了把这条洞的参数交给聊天程序，由它去收发流。
 *
 * ⚠️ 所以这一页里**没有地址和端口可填**：它们是打洞结果带出来的，双方端口是打洞时定下来的，
 * 不一定是 1935（RTMP 的默认端口在这里没有意义）。这一页只让人选协议、采集来源、拉起哪个应用：
 *   - 收流卡：本机收流地址 = 洞的本机侧；对方要推往的地址 = 服务器看到的我的地址
 *   - 推流卡：目标 = 洞的对端侧
 * 没接通道之前这些位置显示"打洞后自动带出"（不是让人去填）。
 *
 * ⚠️ 经洞那一段只能是 UDP（洞本身就是 UDP 端口），要封装（mpegts / RTP）——
 * ffmpeg.sh 就是这么做的：`udp://:PORT?listen=1` ↔ `udp://对端:端口@本机:端口`。
 */
@Composable
fun MediaPage(viewModel: LoginViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val cfg = uiState.mediaConfig
    val channels = uiState.udpSockets.filter { it.handedTo == "media" }
    val chan = channels.firstOrNull()

    // 双方地址端口全部由打洞结果带出来（没有通道就是空）
    val localAddr = chan?.localIp.orEmpty()
    val localPort = chan?.localPort?.toString().orEmpty()
    val peerAddr = chan?.peerPublicIp.orEmpty()
    val peerPort = chan?.peerPublicPort?.toString().orEmpty()
    // 洞是绑在"任意网卡"（:: / 0.0.0.0）上的，把本机真实网卡地址也列出来给人看
    val nics = remember {
        val (v4, v6) = localAddresses()
        (v4 + v6).joinToString(", ")
    }
    val addrIsAny = localAddr.isEmpty() || localAddr == "::" || addrIsAnyV4(localAddr)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ── 收流（对端 → 本机）──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text("收流（对端 → 本机）", style = MaterialTheme.typography.labelMedium)
                MdChoiceRow(
                    label = "协议",
                    ids = MediaPageConfig.PROTO_IDS,
                    selected = cfg.recvProto,
                    onSelect = { viewModel.onMediaRecvProtoChange(it) }
                )
                // 展示用（只读）：值是打洞结果，不是让人填的
                MdReadOnlyRow(label = "本机地址", value = localAddr, pending = "打洞后自动带出")
                MdReadOnlyRow(label = "本机端口", value = localPort, pending = "打洞后自动带出")
                Text(
                    text = if (chan == null) {
                        "   这两个值是打洞结果，不用填；打通后自动出现在这里"
                    } else if (addrIsAny) {
                        "   $localAddr 表示绑任意网卡（洞就是绑在任意网卡上的）" +
                            (if (nics.isNotEmpty()) "；本机网卡：$nics" else "")
                    } else {
                        "   洞的本机侧，媒体程序照这个绑定/接收"
                    },
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // ── 推流（本机 → 对端）──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text("推流（本机 → 对端）", style = MaterialTheme.typography.labelMedium)
                MdChoiceRow(
                    label = "协议",
                    ids = MediaPageConfig.PROTO_IDS,
                    selected = cfg.sendProto,
                    onSelect = { viewModel.onMediaSendProtoChange(it) }
                )
                // 对端只关心"路由器公网地址:端口"，对方内网地址不管
                MdReadOnlyRow(label = "对端地址", value = peerAddr, pending = "打洞后自动带出")
                MdReadOnlyRow(label = "对端端口", value = peerPort, pending = "打洞后自动带出")
                Text(
                    text = "   对方路由器公网地址:端口（对方内网地址不用管）",
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                MdChoiceRow(
                    label = "采集",
                    ids = MediaPageConfig.CAPTURE_IDS,
                    selected = cfg.capture,
                    onSelect = { viewModel.onMediaCaptureChange(it) }
                )
            }
        }

        // ── 拉起应用 ──
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(8.dp)) {
            Column(
                modifier = Modifier.padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text("拉起应用", style = MaterialTheme.typography.labelMedium)
                MdFieldRow(
                    label = "应用包名",
                    value = cfg.appPackage,
                    placeholder = "留空 = 只按 action 找",
                    onChange = { viewModel.onMediaAppPackageChange(it) }
                )
                MdFieldRow(
                    label = "Action",
                    value = cfg.appAction,
                    onChange = { viewModel.onMediaAppActionChange(it) }
                )
                Text(
                    text = "将传给聊天程序（全部由打洞结果带出）：",
                    fontSize = 9.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "   localaddr=${localAddr.ifEmpty { "—" }}  localport=${localPort.ifEmpty { "—" }}\n" +
                        "   peeraddr=${peerAddr.ifEmpty { "—" }}  peerport=${peerPort.ifEmpty { "—" }}\n" +
                        "   recv=${cfg.recvProto}  send=${cfg.sendProto}  capture=${cfg.capture}",
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                // 空态不渲染；有通道时才显示这条明细
                if (channels.isNotEmpty()) {
                    Text(
                        text = "通道：" + channels.joinToString("、") { "${it.target}(洞${it.localPort})" } +
                            if (channels.size > 1) "  ⚠️ 多媒体聊天一般只要一条" else "",
                        fontSize = 9.sp,
                        color = if (channels.size > 1) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Button(
                    onClick = { viewModel.onMediaLaunchApp() },
                    enabled = chan != null,
                    modifier = Modifier.fillMaxWidth().height(32.dp),
                    contentPadding = PaddingValues(vertical = 0.dp)
                ) { Text(if (chan != null) "拉起应用" else "打洞后才能拉起", fontSize = 11.sp) }
            }
        }
    }
}

/**
 * 只读的地址/端口框：**值是打洞结果**（洞本机侧 / 对端公网侧），
 * 放在文本框里只是给人看（可以选中复制），不能改；没通道时显示占位提示。
 */
@Composable
private fun MdReadOnlyRow(label: String, value: String, pending: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(mdLabelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            singleLine = true,
            placeholder = { Text(pending, fontSize = 10.sp) },
            modifier = Modifier.weight(1f).height(30.dp),
            textStyle = TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        )
    }
}

/** "任意网卡"的 v4 写法（v6 的 `::` 在调用处一起判） */
private fun addrIsAnyV4(addr: String): Boolean = addr == "0.0.0.0"

/** 一行「标签 + 若干二选一按钮」 */
@Composable
private fun MdChoiceRow(
    label: String,
    ids: List<String>,
    selected: String,
    onSelect: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(mdLabelWidth))
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
    }
}

/** 一行「标签 + 文本框」 */
@Composable
private fun MdFieldRow(
    label: String,
    value: String,
    placeholder: String = "",
    onChange: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(label, fontSize = 11.sp, modifier = Modifier.width(mdLabelWidth))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            singleLine = true,
            placeholder = if (placeholder.isEmpty()) null else {
                { Text(placeholder, fontSize = 10.sp) }
            },
            modifier = Modifier.weight(1f).height(30.dp),
            textStyle = TextStyle(fontSize = 11.sp)
        )
    }
}
