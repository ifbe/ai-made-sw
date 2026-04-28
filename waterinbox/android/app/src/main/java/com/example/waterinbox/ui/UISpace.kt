package com.example.waterinbox.ui

import android.util.DisplayMetrics
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.waterinbox.sensor.SensorData
import com.example.waterinbox.math.FusionConfig
import com.example.waterinbox.math.FusionState
import com.example.waterinbox.socket.SocketManager
import kotlin.math.sqrt

private var _boxSpaceRef: com.example.waterinbox.renderer.BoxSpace? = null
@Composable
fun UISpace(data: SensorData, algoLabel: String = "MH6", boxSpace: com.example.waterinbox.renderer.BoxSpace? = null) {
    var expanded by remember { mutableStateOf(true) }
    var algoExpanded by remember { mutableStateOf(true) }
    var socketExpanded by remember { mutableStateOf(false) }

    val monoFont = FontFamily.Monospace
    LaunchedEffect(boxSpace) { _boxSpaceRef = boxSpace }
    val labelColor = Color(0xFF90CAF9)
    val fontSize = 8.sp

    // Socket params — all read from / written to SocketManager (single source of truth)
    var socketProtocol by remember { mutableStateOf(SocketManager.protocol) }
    var socketIp by remember { mutableStateOf(SocketManager.ip) }
    var socketPort by remember { mutableStateOf(SocketManager.port.toString()) }
    var socketContent by remember { mutableStateOf(SocketManager.contentType) }
    var isConnecting by remember { mutableStateOf(false) }

    // Screen pixel dimensions
    val metrics: DisplayMetrics = LocalContext.current.resources.displayMetrics
    val density = metrics.density
    val screenW = metrics.widthPixels
    val screenH = metrics.heightPixels
    val boxD = minOf(screenW, screenH) / 2f
    val shaftLen = boxD * 0.5f

    // Arrow geometry
    val gravity = data.gravity
    val gLen = sqrt(gravity[0]*gravity[0] + gravity[1]*gravity[1] + gravity[2]*gravity[2])
    val gx = if (gLen > 0.001f) gravity[0]/gLen else 0f
    val gy = if (gLen > 0.001f) gravity[1]/gLen else 0f
    val gz = if (gLen > 0.001f) gravity[2]/gLen else 0f
    val tipX = gx * shaftLen
    val tipY = gy * shaftLen
    val tipZ = gz * shaftLen

    // Algo colors
    val algoColor = when (FusionConfig.algorithm) {
        "madgwick" -> Color(0xFF4488FF)
        "mahony3"  -> Color(0xFFFF8844)
        "ekf"      -> Color(0xFFFF44FF)
        else       -> Color(0xFF44FF88)
    }
    val algoP = data.algoParams

    // Socket connection color
    val socketConnColor = if (SocketManager.isConnected) Color(0xFF44FF44) else Color(0xFFFF4444)

    Box(modifier = Modifier.fillMaxSize()) {
        // ── Left: toggle button always visible ──
        Surface(
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(top = 16.dp, start = 12.dp)
                .size(32.dp)
                .clickable { expanded = !expanded },
            shape = CircleShape,
            color = Color.Black.copy(alpha = 0.6f)
        ) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text("▶", color = Color.White, fontSize = 10.sp)
            }
        }

        // ── Left panel: below toggle button ──
        if (expanded) {
            BoxWithConstraints(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(top = 56.dp, start = 12.dp)
                    .background(Color.Black.copy(alpha = 0.5f))
                    .padding(8.dp)
            ) {
                val glW = maxWidth.value
                val glH = maxHeight.value
                Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                    LabeledRow("Screen", floatArrayOf(screenW.toFloat(), screenH.toFloat()), monoFont, labelColor, fontSize, "%.0f")
                    LabeledRow("GLsurf", floatArrayOf(glW * density, glH * density), monoFont, labelColor, fontSize, "%.0f px")
                    DividerRow(monoFont, fontSize)
                    LabeledRow("dt  ", floatArrayOf(data.dt), monoFont, labelColor, fontSize, "%.6f")
                    LabeledRow("Gyro", data.gyro, monoFont, labelColor, fontSize)
                    LabeledRow("Accel", data.accel, monoFont, labelColor, fontSize)
                    LabeledRow("Magnet", data.magnet, monoFont, labelColor, fontSize)
                    DividerRow(monoFont, fontSize)
                    LabeledRow("GyroC", data.gyroCorr, monoFont, labelColor, fontSize)
                    LabeledRow("AccelC", data.accelCorr, monoFont, labelColor, fontSize)
                    LabeledRow("MagnetC", data.magnetCorr, monoFont, labelColor, fontSize)
                    DividerRow(monoFont, fontSize)
                    LabeledRow("Quat", data.quaternion, monoFont, labelColor, fontSize)
                    LabeledRow("Euler", data.euler, monoFont, labelColor, fontSize)
                    LabeledRow("AxisA", data.axisAngle, monoFont, labelColor, fontSize)
                    DividerRow(monoFont, fontSize)
                    LabeledRow("WrdX ", data.worldAxisX, monoFont, Color(0xFFFF4444), fontSize, "%.4f")
                    LabeledRow("WrdY ", data.worldAxisY, monoFont, Color(0xFF44FF44), fontSize, "%.4f")
                    LabeledRow("WrdZ ", data.worldAxisZ, monoFont, Color(0xFF4444FF), fontSize, "%.4f")
                    DividerRow(monoFont, fontSize)
                    LabeledRow("Gravity", gravity, monoFont, labelColor, fontSize)
                    LabeledRow("ArrTail", floatArrayOf(0f, 0f, 0f), monoFont, labelColor, fontSize)
                    LabeledRow("ArrTip", floatArrayOf(tipX, tipY, tipZ), monoFont, labelColor, fontSize)
                    DividerRow(monoFont, fontSize)
                    // 8 boat corners fetched directly from BoxSpace.drawBoat (no recomputation)
                    val bv = _boxSpaceRef?.getBoatVertices()
                    if (bv != null) {
                        LabeledRow("bFR   ", floatArrayOf(bv[0],bv[1],bv[2]), monoFont, Color(0xFFFF6600), fontSize, "%.2f")
                        LabeledRow("bFL   ", floatArrayOf(bv[3],bv[4],bv[5]), monoFont, Color(0xFFFF8800), fontSize, "%.2f")
                        LabeledRow("bBL   ", floatArrayOf(bv[6],bv[7],bv[8]), monoFont, Color(0xFFFFAA00), fontSize, "%.2f")
                        LabeledRow("bBR   ", floatArrayOf(bv[9],bv[10],bv[11]), monoFont, Color(0xFFFFCC00), fontSize, "%.2f")
                        LabeledRow("tFR   ", floatArrayOf(bv[12],bv[13],bv[14]), monoFont, Color(0xFF00FFFF), fontSize, "%.2f")
                        LabeledRow("tFL   ", floatArrayOf(bv[15],bv[16],bv[17]), monoFont, Color(0xFF00CCFF), fontSize, "%.2f")
                        LabeledRow("tBL   ", floatArrayOf(bv[18],bv[19],bv[20]), monoFont, Color(0xFF0099FF), fontSize, "%.2f")
                        LabeledRow("tBR   ", floatArrayOf(bv[21],bv[22],bv[23]), monoFont, Color(0xFF0066FF), fontSize, "%.2f")
                    }
                    DividerRow(monoFont, fontSize)
                    data.waterPoly.forEachIndexed { i, pt ->
                        LabeledRow("P$i    ", pt, monoFont, Color(0xFF80FF80), fontSize, "%.2f")
                    }
                }
            }
        }

        // ── Algo cycling button ──
        Surface(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 16.dp, end = 56.dp)
                .size(40.dp)
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
            shape = CircleShape,
            color = algoColor.copy(alpha = 0.85f)
        ) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(algoLabel, color = Color.White, fontSize = 10.sp)
            }
        }

        // ── Right: collapse button always visible ──
        Surface(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 16.dp, end = 16.dp)
                .size(32.dp)
                .clickable { algoExpanded = !algoExpanded },
            shape = CircleShape,
            color = Color.Black.copy(alpha = 0.6f)
        ) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text("◀", color = Color.White, fontSize = 10.sp)
            }
        }

        // ── Right panel: algo params ──
        if (algoExpanded) {
            Column(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(top = 56.dp, end = 16.dp)
                    .background(Color.Black.copy(alpha = 0.6f))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                when (FusionConfig.algorithm) {
                    "madgwick" -> {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("beta", color = algoColor, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                            Text(String.format("%.3f", algoP[0]), color = Color.White, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                    "mahony6" -> {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("Kp ", color = algoColor, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                            Text(String.format("%.2f", algoP[0]), color = Color.White, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("Ki ", color = algoColor, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                            Text(String.format("%.3f", algoP[1]), color = Color.White, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                    "ekf" -> {
                        Text("EKF placeholder", color = algoColor, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                    }
                    else -> { /* mahony3: no params */ }
                }
            }
        }

        // ── Bottom-left: toggle + connection button (always visible) ──
        Row(
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(bottom = 16.dp, start = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Toggle button
            Surface(
                modifier = Modifier
                    .size(32.dp)
                    .clickable { socketExpanded = !socketExpanded },
                shape = CircleShape,
                color = Color.Black.copy(alpha = 0.6f)
            ) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text("▶", color = Color.White, fontSize = 10.sp)
                }
            }

            // Connection status button (always visible)
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
                shape = CircleShape,
                color = connColor.copy(alpha = 0.85f)
            ) {
                Box(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (isConnecting) "连接中.." else connLabel,
                        color = Color.White,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }

        // ── Bottom-left: socket panel (collapsible) ──
        if (socketExpanded) {
            Column(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .padding(bottom = 56.dp, start = 12.dp)
                    .background(Color.Black.copy(alpha = 0.6f))
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                // IP input (editable text field)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text("IP:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    SocketTextField(
                        value = socketIp,
                        onValueChange = { socketIp = it },
                        width = 110.dp,
                        fontSize = 9.sp
                    )
                }
                // Port input (editable text field)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text("端口:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    SocketTextField(
                        value = socketPort,
                        onValueChange = { socketPort = it },
                        width = 64.dp,
                        fontSize = 9.sp
                    )
                }
                // Protocol selector
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("协议:", color = labelColor, fontSize = 9.sp, fontFamily = monoFont)
                    Text(
                        text = if (socketProtocol == "TCP") "[TCP]" else "[TCP]",
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
                // Content selector
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

/**
 * Click-to-cycle editable text. Each click cycles to next preset option.
 */
@Composable
private fun EditableText(
    options: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    color: Color,
    fontSize: androidx.compose.ui.unit.TextUnit,
    modifier: Modifier = Modifier
) {
    val current = options.getOrElse(selectedIndex) { "_" }
    Text(
        text = current,
        color = color,
        fontSize = fontSize,
        fontFamily = FontFamily.Monospace,
        modifier = modifier.clickable {
            onSelect((selectedIndex + 1) % options.size)
        }
    )
}

@Composable
private fun LabeledRow(
    label: String,
    values: FloatArray,
    monoFont: FontFamily,
    labelColor: Color,
    fontSize: androidx.compose.ui.unit.TextUnit,
    fmt: String = "%.4f"
) {
    Row(modifier = Modifier.padding(vertical = 0.dp)) {
        Text(
            text = label,
            color = labelColor,
            fontSize = fontSize,
            fontFamily = monoFont,
            lineHeight = (fontSize.value * 1.0f).sp,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(
            text = values.joinToString(" ") { String.format(fmt, it) },
            color = Color.White,
            fontSize = fontSize,
            fontFamily = monoFont,
            lineHeight = (fontSize.value * 1.0f).sp
        )
    }
}

@Composable
private fun DividerRow(monoFont: FontFamily, fontSize: androidx.compose.ui.unit.TextUnit) {
    Text(
        text = "────────────────────",
        color = Color.Gray,
        fontSize = fontSize,
        fontFamily = monoFont,
        lineHeight = (fontSize.value * 1.0f).sp,
        modifier = Modifier.padding(vertical = 0.dp)
    )
}

/**
 * Minimal editable text field for socket IP / port input.
 */
@Composable
private fun SocketTextField(
    value: String,
    onValueChange: (String) -> Unit,
    width: androidx.compose.ui.unit.Dp,
    fontSize: androidx.compose.ui.unit.TextUnit
) {
    var focused by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf(value) }

    LaunchedEffect(value) {
        if (!focused) text = value
    }

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
            onValueChange = {
                text = it
                onValueChange(it)
            },
            textStyle = TextStyle(
                color = Color.White,
                fontSize = fontSize,
                fontFamily = FontFamily.Monospace
            ),
            singleLine = true,
            modifier = Modifier.fillMaxSize(),
            cursorBrush = SolidColor(Color(0xFF44FF44))
        )
    }
}
