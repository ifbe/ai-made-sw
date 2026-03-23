package com.example.pusher

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.SurfaceView
import android.view.TextureView
import android.view.View
import android.widget.*
import androidx.annotation.RequiresPermission
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.example.pusher.camera.CameraHelper
import com.example.pusher.push.PusherController
import com.example.pusher.ui.AudioWaveformView
import com.example.pusher.ui.PreviewEntry
import com.example.pusher.ui.PreviewLogView
import com.example.pusher.PushService


class MainActivity : AppCompatActivity() {
    private lateinit var etServerHost: EditText
    private lateinit var etAppPath: EditText
    private lateinit var etPort: EditText
    private lateinit var spinnerProtocol: Spinner
    private lateinit var previewRtmp: PreviewLogView
    private lateinit var spinnerFormat: Spinner
    private lateinit var previewMux: PreviewLogView
    private lateinit var spinnerVideoCodec: Spinner
    private lateinit var etVideoBitrate: EditText
    private lateinit var etVideoFps: EditText
    private lateinit var spinnerAudioCodec: Spinner
    private lateinit var etAudioBitrate: EditText
    private lateinit var etAudioSamplerate: EditText
    private lateinit var previewVideo: PreviewLogView
    private lateinit var previewAudio: PreviewLogView
    private lateinit var spinnerCamera: Spinner
    private lateinit var spinnerResolution: Spinner
    private lateinit var spinnerMic: Spinner
    private lateinit var spinnerChannels: Spinner
    private lateinit var texturePreview: TextureView
    private lateinit var waveformView: AudioWaveformView
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button

    private var pusherController: PusherController? = null
    private var cameraHelper: CameraHelper? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_Pusher)
        super.onCreate(savedInstanceState)

        // 沉浸式状态栏
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            @Suppress("DEPRECATION")
            window.setDecorFitsSystemWindows(false)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = (
                    View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                            View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    )
            @Suppress("DEPRECATION")
            window.statusBarColor = Color.TRANSPARENT
        }

        setContentView(R.layout.activity_main)

        // 初始化视图
        etServerHost = findViewById(R.id.et_server_host)
        etAppPath = findViewById(R.id.et_app_path)
        etPort = findViewById(R.id.et_port)
        spinnerProtocol = findViewById(R.id.spinner_protocol)
        previewRtmp = findViewById(R.id.preview_rtmp)
        spinnerFormat = findViewById(R.id.spinner_format)
        previewMux = findViewById(R.id.preview_mux)
        spinnerVideoCodec = findViewById(R.id.spinner_video_codec)
        etVideoBitrate = findViewById(R.id.et_video_bitrate)
        etVideoFps = findViewById(R.id.et_video_fps)
        spinnerAudioCodec = findViewById(R.id.spinner_audio_codec)
        etAudioBitrate = findViewById(R.id.et_audio_bitrate)
        etAudioSamplerate = findViewById(R.id.et_audio_samplerate)
        previewVideo = findViewById(R.id.preview_video)
        previewAudio = findViewById(R.id.preview_audio)
        spinnerCamera = findViewById(R.id.spinner_camera)
        spinnerResolution = findViewById(R.id.spinner_resolution)
        spinnerMic = findViewById(R.id.spinner_mic)
        spinnerChannels = findViewById(R.id.spinner_channels)
        waveformView = findViewById(R.id.waveform_view)
        btnStart = findViewById(R.id.btn_start)
        btnStop = findViewById(R.id.btn_stop)
        texturePreview = findViewById(R.id.texture_preview)

        texturePreview.post {
            Log.d("MainActivity", "SurfaceView size: ${texturePreview.width} x ${texturePreview.height}")
            Log.d("MainActivity", "SurfaceView visibility: ${texturePreview.visibility}")
            Log.d("MainActivity", "SurfaceView isShown: ${texturePreview.isShown}")
            //Log.d("MainActivity", "SurfaceView holder surface isValid: ${texturePreview.holder.surface.isValid}")
        }

        // ========== 设置 Spinner 适配器 ==========

        val protocols = arrayOf("RTMP", "RTSP", "SRT")
        spinnerProtocol.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, protocols).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val formats = arrayOf("FLV", "fMP4", "MPEG-TS")
        spinnerFormat.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, formats).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val videoCodecs = arrayOf("H.264", "H.265")
        spinnerVideoCodec.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, videoCodecs).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val audioCodecs = arrayOf("AAC", "OPUS")
        spinnerAudioCodec.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, audioCodecs).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val cameras = arrayOf("后置摄像头", "前置摄像头")
        spinnerCamera.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, cameras).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val resolutions = arrayOf("1920x1080", "1280x720", "854x480", "640x360", "480x270")
        spinnerResolution.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, resolutions).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val mics = arrayOf("内置麦克风", "外接麦克风", "默认设备")
        spinnerMic.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, mics).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val channels = arrayOf("单声道", "立体声")
        spinnerChannels.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, channels).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        requestPermissions()

        btnStart.setOnClickListener { checkPermissionsAndStart() }
        btnStop.setOnClickListener { stopPushing() }
    }

    private fun requestPermissions() {
        val permissions = arrayOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.INTERNET
        )
        val need = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (need.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, need.toTypedArray(), PERMISSION_REQUEST_CODE)
        }
    }

    private fun checkPermissionsAndStart() {
        val permissions = arrayOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.INTERNET
        )

        val missingPermissions = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isEmpty()) {
            startPushing()
        } else {
            ActivityCompat.requestPermissions(
                this,
                missingPermissions.toTypedArray(),
                PERMISSION_REQUEST_CODE
            )
        }
    }

    @RequiresPermission(Manifest.permission.RECORD_AUDIO)
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            val allGranted = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            if (allGranted) {
                startPushing()
            } else {
                Toast.makeText(this, "需要相机和麦克风权限才能推流", Toast.LENGTH_SHORT).show()
            }
        }
    }

    @RequiresPermission(Manifest.permission.RECORD_AUDIO)
    private fun startPushing() {
        Log.d("MainActivity", "=== startPushing START ===")

        PushService.start(this)

        // 先获取预览尺寸（不启动相机）
        val tempCameraHelper = CameraHelper(this)
        tempCameraHelper.getPreviewSize { width, height ->
            Log.d("MainActivity", "Preview size: ${width}x${height}")

            // 使用预览尺寸进行推流
            val encodeWidth = width
            val encodeHeight = height

            // 构建 URL 和编码参数...
            val protocol = when (spinnerProtocol.selectedItemPosition) {
                0 -> "rtmp"
                1 -> "rtsp"
                else -> "srt"
            }
            val host = etServerHost.text.toString()
            val port = etPort.text.toString()
            val appPath = etAppPath.text.toString()

            val url = if (port.isNotEmpty() && port != "1935" && port != "554") {
                "$protocol://$host:$port$appPath"
            } else {
                "$protocol://$host$appPath"
            }

            val format = when (spinnerFormat.selectedItemPosition) {
                0 -> "flv"
                1 -> "mp4"
                else -> "mpegts"
            }

            val videoCodec = when (spinnerVideoCodec.selectedItemPosition) {
                0 -> "H.264"
                else -> "H.265"
            }
            val videoBitrate = etVideoBitrate.text.toString().toIntOrNull() ?: 2500
            val videoFps = etVideoFps.text.toString().toIntOrNull() ?: 30

            val audioCodec = when (spinnerAudioCodec.selectedItemPosition) {
                0 -> "AAC"
                else -> "OPUS"
            }
            val audioBitrate = etAudioBitrate.text.toString().toIntOrNull() ?: 128
            val audioSamplerate = (etAudioSamplerate.text.toString().toDoubleOrNull() ?: 44.1) * 1000
            val channelCount = if (spinnerChannels.selectedItemPosition == 0) 1 else 2

            // 创建 PusherController
            pusherController = PusherController(
                onAvioData = { direction, timestamp, data ->
                    runOnUiThread {
                        if (data.isNotEmpty()) {
                            previewRtmp.addEntry(PreviewEntry(timestamp, direction, data))
                        }
                    }
                },
                onVideoFrameCallback = { data, timestamp, isKey ->
                    runOnUiThread {
                        if (data.isNotEmpty()) {
                            previewVideo.addEntry(PreviewEntry(timestamp, -1, data, ""))
                        }
                    }
                },
                onAudioFrameCallback = { data, timestamp ->
                    runOnUiThread {
                        if (data.isNotEmpty()) {
                            previewAudio.addEntry(PreviewEntry(timestamp, -1, data, ""))
                        }
                    }
                },
                onMuxData = { data, timestamp ->
                    runOnUiThread {
                        if (data.isNotEmpty()) {
                            previewMux.addEntry(PreviewEntry(timestamp, -1, data, ""))
                        }
                    }
                },
                onPcmData = { pcmData ->
                    // 波形显示
                    try {
                        val shortBuffer = java.nio.ByteBuffer.wrap(pcmData).order(java.nio.ByteOrder.LITTLE_ENDIAN).asShortBuffer()
                        val samples = mutableListOf<Float>()
                        var count = 0
                        while (shortBuffer.hasRemaining()) {
                            val sample = shortBuffer.get().toFloat() / 32768f
                            if (count % 64 == 0) {
                                val normalized = (sample.coerceIn(-1f, 1f) + 1f) / 2f
                                samples.add(normalized)
                            }
                            count++
                        }
                        val waveformData = samples.take(100).toFloatArray()
                        if (waveformData.isNotEmpty()) {
                            runOnUiThread { waveformView.setWaveformData(waveformData, waveformData) }
                        }
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Waveform error", e)
                    }
                }
            )

            val result = pusherController?.initPush(
                url, protocol, format, videoCodec, videoBitrate * 1000, encodeWidth, encodeHeight,
                audioCodec, audioBitrate * 1000, audioSamplerate.toInt(), channelCount, videoFps
            )

            if (result != null) {
                val (inputSurface, errorMsg) = result
                // 无论推流是否成功，都启动相机（编码器已经初始化）
                cameraHelper = CameraHelper(this)
                cameraHelper?.startPreview(texturePreview, inputSurface) { cameraSuccess ->
                    Log.d("MainActivity", "Camera start result: $cameraSuccess")
                    if (cameraSuccess) {
                        Toast.makeText(this, "推流已启动", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this, "相机启动失败", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun stopPushing() {
        Log.d("MainActivity", "stopPushing called")

        // 先停止 PusherController，停止所有 JNI 回调
        pusherController?.stopPush()
        pusherController = null

        // 再停止相机预览
        cameraHelper?.stopPreview()
        cameraHelper = null

        Toast.makeText(this, "推流已停止", Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val PERMISSION_REQUEST_CODE = 100
    }
}