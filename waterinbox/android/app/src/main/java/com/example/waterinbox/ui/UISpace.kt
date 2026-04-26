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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.waterinbox.sensor.SensorData
import com.example.waterinbox.math.FusionConfig
import com.example.waterinbox.math.FusionState
import kotlin.math.sqrt

@Composable
fun UISpace(data: SensorData, algoLabel: String = "MH6") {
    var expanded by remember { mutableStateOf(true) }
    var algoExpanded by remember { mutableStateOf(true) }

    val monoFont = FontFamily.Monospace
    val labelColor = Color(0xFF90CAF9)
    val fontSize = 8.sp

    // Screen pixel dimensions
    val metrics: DisplayMetrics = LocalContext.current.resources.displayMetrics
    val density = metrics.density
    val screenW = metrics.widthPixels
    val screenH = metrics.heightPixels
    val boxD = minOf(screenW, screenH) / 5f
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
//                    Text(
//                        text = "▼ Sensor",
//                        color = Color(0xFFFFAA44),
//                        fontSize = 10.sp,
//                        fontFamily = monoFont,
//                        modifier = Modifier.padding(bottom = 4.dp)
//                    )
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
                    data.waterPoly.forEachIndexed { i, pt ->
                        LabeledRow("P$i    ", pt, monoFont, Color(0xFF80FF80), fontSize, "%.2f")
                    }
                }
            }
        }

        // ── Algo cycling button (left of collapse button) ──
        val algoColor = when (FusionConfig.algorithm) {
            "madgwick" -> Color(0xFF4488FF)
            "mahony3"  -> Color(0xFFFF8844)
            "ekf"      -> Color(0xFFFF44FF)
            else       -> Color(0xFF44FF88)
        }
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

        // ── Right panel: algo params below collapse button ──
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
    }
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
