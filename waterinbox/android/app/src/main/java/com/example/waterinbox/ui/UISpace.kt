package com.example.waterinbox.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.waterinbox.sensor.SensorData
import com.example.waterinbox.math.FusionConfig
import com.example.waterinbox.math.FusionState
import com.example.waterinbox.socket.SocketManager

private var _boxSpaceRef: com.example.waterinbox.renderer.BoxSpace? = null

private typealias FontStyle = Pair<FontFamily, androidx.compose.ui.unit.TextUnit>

@Composable
fun UISpace(
    data: SensorData,
    boxSpace: com.example.waterinbox.renderer.BoxSpace? = null
) {
    var leftExpanded by remember { mutableStateOf(false) }
    var topRightExpanded by remember { mutableStateOf(false) }
    var bottomLeftExpanded by remember { mutableStateOf(false) }
    var bottomRightExpanded by remember { mutableStateOf(false) }

    val monoFont = FontFamily.Monospace
    LaunchedEffect(boxSpace) { _boxSpaceRef = boxSpace }
    val labelColor = Color(0xFF90CAF9)
    val fontSize = 8.sp
    val style: FontStyle = monoFont to fontSize

    // Socket params
    var socketProtocol by remember { mutableStateOf(SocketManager.protocol) }
    var socketIp by remember { mutableStateOf(SocketManager.ip) }
    var socketPort by remember { mutableStateOf(SocketManager.port.toString()) }
    var socketContent by remember { mutableStateOf(SocketManager.contentType) }
    var isConnecting by remember { mutableStateOf(false) }

    val algoP = data.algoParams
    val gravity = data.gravity

    Box(modifier = Modifier.fillMaxSize()) {

        // ── TOP-LEFT: toggle button ──
        Surface(
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(start = 12.dp, top = 16.dp)
                .size(28.dp)
                .clickable { leftExpanded = !leftExpanded },
            shape = CircleShape,
            color = if (leftExpanded) Color(0xFF44FF88).copy(alpha = 0.85f) else Color.Black.copy(alpha = 0.6f)
        ) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("▼", color = Color.White, fontSize = 10.sp)
            }
        }

        // ── TOP-LEFT: sensor data panel (below toggle) ──
        if (leftExpanded) {
            Column(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(start = 12.dp, top = 52.dp)
                    .background(Color.Black.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                LabeledRow("dt   ", floatArrayOf(data.dt), style, "%.6f")
                DividerRow(style)
                LabeledRow("Gyro ", data.gyro, style)
                LabeledRow("Accel", data.accel, style)
                LabeledRow("Mag  ", data.magnet, style)
                DividerRow(style)
                LabeledRow("GyroC", data.gyroCorr, style)
                LabeledRow("AccelC", data.accelCorr, style)
                LabeledRow("MagC ", data.magnetCorr, style)
                DividerRow(style)
                LabeledRow("qFused", data.quatFused, style)
                LabeledRow("qFixed", data.quatFixed, style)
                DividerRow(style)
                LabeledRow("Euler", data.euler, style)
                LabeledRow("AxisA", data.axisAngle, style)
                DividerRow(style)
                LabeledRow("WrdX ", data.worldAxisX, style, "%.4f", Color(0xFFFF4444))
                LabeledRow("WrdY ", data.worldAxisY, style, "%.4f", Color(0xFF44FF44))
                LabeledRow("WrdZ ", data.worldAxisZ, style, "%.4f", Color(0xFF4444FF))
                DividerRow(style)
                LabeledRow("Grav ", gravity, style)
                DividerRow(style)
                val bv = _boxSpaceRef?.getBoatVertices()
                if (bv != null) {
                    LabeledRow("bFL  ", floatArrayOf(bv[3],bv[4],bv[5]), style, "%.2f", Color(0xFFFF8800))
                    LabeledRow("bFR  ", floatArrayOf(bv[0],bv[1],bv[2]), style, "%.2f", Color(0xFFFF6600))
                    LabeledRow("bBL  ", floatArrayOf(bv[6],bv[7],bv[8]), style, "%.2f", Color(0xFFFFAA00))
                    LabeledRow("bBR  ", floatArrayOf(bv[9],bv[10],bv[11]), style, "%.2f", Color(0xFFFFCC00))
                    LabeledRow("tFL  ", floatArrayOf(bv[15],bv[16],bv[17]), style, "%.2f", Color(0xFF00CCFF))
                    LabeledRow("tFR  ", floatArrayOf(bv[12],bv[13],bv[14]), style, "%.2f", Color(0xFF00FFFF))
                    LabeledRow("tBL  ", floatArrayOf(bv[18],bv[19],bv[20]), style, "%.2f", Color(0xFF0099FF))
                    LabeledRow("tBR  ", floatArrayOf(bv[21],bv[22],bv[23]), style, "%.2f", Color(0xFF0066FF))
                }
                DividerRow(style)
                data.waterPoly.forEachIndexed { i, pt ->
                    LabeledRow("P$i   ", pt, style, "%.2f", Color(0xFF80FF80))
                }
            }
        }

        // ── TOP-RIGHT: toggle button ──
        Surface(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(end = 12.dp, top = 16.dp)
                .size(28.dp)
                .clickable { topRightExpanded = !topRightExpanded },
            shape = CircleShape,
            color = if (topRightExpanded) Color(0xFF4488FF).copy(alpha = 0.85f) else Color.Black.copy(alpha = 0.6f)
        ) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("▼", color = Color.White, fontSize = 10.sp)
            }
        }

// ── TOP-RIGHT: render toggles panel (to the LEFT of toggle, same row) ──
        if (topRightExpanded) {
            Column(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(end = 12.dp, top = 52.dp)
                    .background(Color.Black.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
                    .padding(8.dp)
                    .width(110.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                // ── DEBUG GROUP ───────────────────────────────────────────
                RenderMasterToggle(
                    label = "debug",
                    isOn = (boxSpace?.drawWorldAxes == true && boxSpace?.drawGravityArrow == true && boxSpace?.drawMagnetArrow == true),
                    onToggle = { on ->
                        boxSpace?.drawWorldAxes = on
                        boxSpace?.drawGravityArrow = on
                        boxSpace?.drawMagnetArrow = on
                    }
                )
                RenderToggle("坐标轴", boxSpace?.drawWorldAxes == true, { boxSpace?.drawWorldAxes = it }, indent = 12.dp)
                RenderToggle("重力箭头", boxSpace?.drawGravityArrow == true, { boxSpace?.drawGravityArrow = it }, indent = 12.dp)
                RenderToggle("磁力箭头", boxSpace?.drawMagnetArrow == true, { boxSpace?.drawMagnetArrow = it }, indent = 12.dp)
                RenderToggleSeparator()

                // ── WATER GROUP ────────────────────────────────────────────
                RenderMasterToggle(
                    label = "water",
                    isOn = (boxSpace?.drawBoat == true && boxSpace?.drawWaterSurface == true && boxSpace?.drawWaterBody == true),
                    onToggle = { on ->
                        boxSpace?.drawBoat = on
                        boxSpace?.drawWaterSurface = on
                        boxSpace?.drawWaterBody = on
                    }
                )
                RenderToggle("小船", boxSpace?.drawBoat == true, { boxSpace?.drawBoat = it }, indent = 12.dp)
                RenderToggle("水面", boxSpace?.drawWaterSurface == true, { boxSpace?.drawWaterSurface = it }, indent = 12.dp)
                RenderToggle("水体", boxSpace?.drawWaterBody == true, { boxSpace?.drawWaterBody = it }, indent = 12.dp)
                RenderToggleSeparator()

                // ── HUMAN GROUP ────────────────────────────────────────────
                RenderMasterToggle(
                    label = "human",
                    isOn = (boxSpace?.drawHuman == true && boxSpace?.drawFixation == true),
                    onToggle = { on ->
                        boxSpace?.drawFixation = on
                        boxSpace?.drawHuman = on
                    }
                )
                RenderToggle("固定装置", boxSpace?.drawFixation == true, { boxSpace?.drawFixation = it }, indent = 12.dp)
                RenderToggle("人形", boxSpace?.drawHuman == true, { boxSpace?.drawHuman = it }, indent = 12.dp)
            }
        }

        // ── BOTTOM-LEFT: toggle + buttons ──
        Row(
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(start = 12.dp, bottom = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Toggle button
            Surface(
                modifier = Modifier
                    .size(28.dp)
                    .clickable { bottomLeftExpanded = !bottomLeftExpanded },
                shape = CircleShape,
                color = if (bottomLeftExpanded) Color(0xFF44FF88).copy(alpha = 0.85f) else Color.Black.copy(alpha = 0.6f)
            ) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("▲", color = Color.White, fontSize = 10.sp)
                }
            }

            // 切换融合算法
            Surface(
                modifier = Modifier
                    .clickable {
                        val next = when (FusionConfig.algorithm) {
                            "mahony3"  -> "mahony6"
                            "mahony6"  -> "madgwick"
                            "madgwick" -> "ekf"
                            else       -> "mahony3"
                        }
                        FusionConfig.algorithm = next
                        FusionState.reset()
                    },
                shape = RoundedCornerShape(6.dp),
                color = Color.Black.copy(alpha = 0.7f)
            ) {
                Box(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                    Text(when (FusionConfig.algorithm) {
                        "mahony3"  -> "MH3"
                        "mahony6"  -> "MH6"
                        "madgwick" -> "MDW"
                        "ekf"      -> "EKF"
                        else       -> "??"
                    }, color = Color.White, fontSize = 10.sp, fontFamily = monoFont)
                }
            }

            // yaw修正算法
            Surface(
                modifier = Modifier
                    .clickable {
                        val next = when (FusionConfig.yawAlgorithm) {
                            "none" -> "mag"
                            "mag"  -> "none"
                            else   -> "none"
                        }
                        FusionConfig.yawAlgorithm = next
                    },
                shape = RoundedCornerShape(6.dp),
                color = Color.Black.copy(alpha = 0.7f)
            ) {
                Box(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                    Text(
                        "YAW:${FusionConfig.yawAlgorithm}",
                        color = if (FusionConfig.yawAlgorithm == "none") Color.Gray else Color(0xFF44FF88),
                        fontSize = 10.sp,
                        fontFamily = monoFont
                    )
                }
            }
        }

        // ── BOTTOM-LEFT: algo params panel (above buttons) ──
        if (bottomLeftExpanded) {
            Column(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .padding(start = 12.dp, bottom = 56.dp)
                    .background(Color.Black.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                val algoColor = when (FusionConfig.algorithm) {
                    "madgwick" -> Color(0xFF4488FF)
                    "mahony3"  -> Color(0xFFFF8844)
                    "ekf"      -> Color(0xFFFF44FF)
                    else       -> Color(0xFF44FF88)
                }
                when (FusionConfig.algorithm) {
                    "madgwick" -> {
                        Row { Text("beta ", color = algoColor, fontSize = 9.sp, fontFamily = monoFont); Text(String.format("%.3f", algoP[0]), color = Color.White, fontSize = 9.sp, fontFamily = monoFont) }
                    }
                    "mahony6" -> {
                        Row { Text("Kp  ", color = algoColor, fontSize = 9.sp, fontFamily = monoFont); Text(String.format("%.2f", algoP[0]), color = Color.White, fontSize = 9.sp, fontFamily = monoFont) }
                        Row { Text("Ki  ", color = algoColor, fontSize = 9.sp, fontFamily = monoFont); Text(String.format("%.3f", algoP[1]), color = Color.White, fontSize = 9.sp, fontFamily = monoFont) }
                    }
                    "ekf" -> {
                        Text("EKF placeholder", color = algoColor, fontSize = 9.sp, fontFamily = monoFont)
                    }
                    else -> {
                        Text("MH3: no params", color = algoColor, fontSize = 9.sp, fontFamily = monoFont)
                    }
                }
            }
        }

        // ── BOTTOM-RIGHT: toggle + socket connect ──
        Row(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 12.dp, bottom = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 连接 button
            val connColor = if (SocketManager.isConnected) Color(0xFF44FF44) else Color(0xFFFF4444)
            val connLabel = if (SocketManager.isConnected) "已连接" else "未连接"
            Surface(
                modifier = Modifier
                    .clickable {
                        if (!SocketManager.isConnected && !isConnecting) {
                            SocketManager.protocol = socketProtocol
                            SocketManager.ip = socketIp
                            SocketManager.port = socketPort.toIntOrNull() ?: 999
                            SocketManager.contentType = socketContent
                            isConnecting = true
                            SocketManager.connect { isConnecting = false }
                        } else if (SocketManager.isConnected) {
                            SocketManager.disconnect()
                        }
                    },
                shape = RoundedCornerShape(6.dp),
                color = connColor.copy(alpha = 0.85f)
            ) {
                Box(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                    Text(
                        if (isConnecting) "连接中.." else connLabel,
                        color = Color.White,
                        fontSize = 10.sp,
                        fontFamily = monoFont
                    )
                }
            }

            // Toggle button
            Surface(
                modifier = Modifier
                    .size(28.dp)
                    .clickable { bottomRightExpanded = !bottomRightExpanded },
                shape = CircleShape,
                color = if (bottomRightExpanded) Color(0xFF44FF88).copy(alpha = 0.85f) else Color.Black.copy(alpha = 0.6f)
            ) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("▲", color = Color.White, fontSize = 10.sp)
                }
            }
        }

        // ── BOTTOM-RIGHT: socket panel (above buttons) ──
        if (bottomRightExpanded) {
            Column(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 12.dp, bottom = 56.dp)
                    .background(Color.Black.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("IP:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    SocketTextField(socketIp, { socketIp = it }, 110.dp, 9.sp)
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("端口:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    SocketTextField(socketPort, { socketPort = it }, 64.dp, 9.sp)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("协议:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    Text(
                        text = if (socketProtocol == "TCP") "[TCP]" else "TCP",
                        color = if (socketProtocol == "TCP") Color(0xFF44FF44) else Color.Gray,
                        fontSize = 9.sp, fontFamily = monoFont,
                        modifier = Modifier.clickable { socketProtocol = "TCP" }
                    )
                    Text(
                        text = if (socketProtocol == "UDP") "[UDP]" else "UDP",
                        color = if (socketProtocol == "UDP") Color(0xFF44FF44) else Color.Gray,
                        fontSize = 9.sp, fontFamily = monoFont,
                        modifier = Modifier.clickable { socketProtocol = "UDP" }
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("内容:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    Text(
                        text = if (socketContent == "quaternion") "[quat]" else "quat",
                        color = if (socketContent == "quaternion") Color(0xFF44FF44) else Color.Gray,
                        fontSize = 9.sp, fontFamily = monoFont,
                        modifier = Modifier.clickable { socketContent = "quaternion" }
                    )
                    Text(
                        text = if (socketContent == "measure") "[meas]" else "meas",
                        color = if (socketContent == "measure") Color(0xFF44FF44) else Color.Gray,
                        fontSize = 9.sp, fontFamily = monoFont,
                        modifier = Modifier.clickable { socketContent = "measure" }
                    )
                }
            }
        }

    }
}

@Composable
private fun RenderToggleSeparator() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
            .height(1.dp)
            .background(Color(0xFF444444))
    )
}

@Composable
private fun RenderMasterToggle(label: String, isOn: Boolean, onToggle: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggle(!isOn) }
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = if (isOn) "■" else "□",
            color = if (isOn) Color(0xFF44FF44) else Color.Gray,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = label,
            color = Color(0xFF90CAF9),
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun RenderToggle(
    label: String,
    isEnabled: Boolean,
    onToggle: (Boolean) -> Unit,
    indent: androidx.compose.ui.unit.Dp = 0.dp
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggle(!isEnabled) }
            .padding(start = indent)
            .padding(vertical = 1.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(
            text = if (isEnabled) "■" else "□",
            color = if (isEnabled) Color(0xFF44FF44) else Color.Gray,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = label,
            color = Color.White,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun LabeledRow(
    label: String,
    values: FloatArray,
    style: FontStyle,
    fmt: String = "%.4f",
    valueColor: Color = Color.White
) {
    val (monoFont, fontSize) = style
    Row(modifier = Modifier.padding(vertical = 0.dp)) {
        Text(
            text = label,
            color = Color(0xFF90CAF9),
            fontSize = fontSize,
            fontFamily = monoFont,
            lineHeight = (fontSize.value * 1.0f).sp,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(
            text = values.joinToString(" ") { String.format(fmt, it) },
            color = valueColor,
            fontSize = fontSize,
            fontFamily = monoFont,
            lineHeight = (fontSize.value * 1.0f).sp
        )
    }
}

@Composable
private fun DividerRow(style: FontStyle) {
    val (monoFont, fontSize) = style
    Text(
        text = "────────────────────",
        color = Color.Gray,
        fontSize = fontSize,
        fontFamily = monoFont,
        lineHeight = (fontSize.value * 1.0f).sp,
        modifier = Modifier.padding(vertical = 0.dp)
    )
}

@Composable
private fun SocketTextField(
    value: String,
    onValueChange: (String) -> Unit,
    width: androidx.compose.ui.unit.Dp,
    fontSize: androidx.compose.ui.unit.TextUnit
) {
    var focused by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf(value) }
    LaunchedEffect(value) { if (!focused) text = value }
    Box(
        modifier = Modifier
            .size(width = width, height = (fontSize.value * 1.8f).dp)
            .background(
                if (focused) Color(0xFF1A1A1A) else Color(0xFF0D0D0D),
                RoundedCornerShape(2.dp)
            )
            .padding(horizontal = 4.dp)
            .onFocusChanged { focused = it.isFocused },
        contentAlignment = Alignment.CenterStart
    ) {
        BasicTextField(
            value = text,
            onValueChange = { text = it; onValueChange(it) },
            textStyle = TextStyle(color = Color.White, fontSize = fontSize, fontFamily = FontFamily.Monospace),
            singleLine = true,
            modifier = Modifier.fillMaxSize(),
            cursorBrush = SolidColor(Color(0xFF44FF44))
        )
    }
}
