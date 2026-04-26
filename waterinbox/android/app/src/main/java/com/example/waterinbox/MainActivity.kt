package com.example.waterinbox

import android.view.WindowManager
import android.opengl.GLSurfaceView
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.example.waterinbox.math.FusionConfig
import com.example.waterinbox.math.FusionState
import com.example.waterinbox.renderer.BoxSpace
import com.example.waterinbox.sensor.SensorProbe
import com.example.waterinbox.ui.UISpace
import com.example.waterinbox.ui.theme.WaterinboxTheme

class MainActivity : ComponentActivity() {

    private lateinit var sensorProbe: SensorProbe

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        sensorProbe = SensorProbe(this)

        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        WindowCompat.setDecorFitsSystemWindows(window, false)
        WindowInsetsControllerCompat(window, window.decorView).let { controller ->
            controller.hide(WindowInsetsCompat.Type.systemBars())
            controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }

        setContent {
            WaterinboxTheme {
                val sensorData by sensorProbe.data.collectAsState()
                // Create renderer inside composition so it survives re-composition
                val context = androidx.compose.ui.platform.LocalContext.current
                val renderer = remember { BoxSpace(context) }

                // Update GL renderer with pre-computed gravity from SensorManager.emit()
                renderer.setGravity(
                    sensorData.gravity[0],
                    sensorData.gravity[1],
                    sensorData.gravity[2]
                )
                renderer.setQuaternion(
                    sensorData.quaternion[0],
                    sensorData.quaternion[1],
                    sensorData.quaternion[2],
                    sensorData.quaternion[3]
                )

                Box(modifier = Modifier.fillMaxSize()) {
                    AndroidView(
                        factory = { ctx ->
                            GLSurfaceView(ctx).apply {
                                setEGLContextClientVersion(3)
                                setRenderer(renderer)
                                renderMode = GLSurfaceView.RENDERMODE_CONTINUOUSLY
                            }
                        },
                        modifier = Modifier.fillMaxSize()
                    )

                    UISpace(data = sensorData)

                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        sensorProbe.start()
    }

    override fun onPause() {
        super.onPause()
        sensorProbe.stop()
    }
}
