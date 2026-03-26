package com.example.pusher

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Log
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
    private lateinit var etFilePath: EditText
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

    // 7个模块的 FrameLayout（用于控制背景色）
    private lateinit var frameRtmp: FrameLayout      // 模块1: RTMP 推流
    private lateinit var frameRecord: FrameLayout    // 模块2: 本地录制
    private lateinit var frameFlv: FrameLayout       // 模块3: FLV 封装器
    private lateinit var frameVideoEncoder: FrameLayout  // 模块4: 视频编码
    private lateinit var frameAudioEncoder: FrameLayout  // 模块5: 音频编码
    private lateinit var frameVideoPreview: FrameLayout  // 模块6: 视频采集
    private lateinit var frameAudioPreview: FrameLayout  // 模块7: 音频采集

    // 7个模块的 Switch
    private lateinit var switchRtmp: Switch
    private lateinit var switchRecord: Switch
    private lateinit var switchFlv: Switch
    private lateinit var switchVideoEncoder: Switch
    private lateinit var switchAudioEncoder: Switch
    private lateinit var switchVideoPreview: Switch
    private lateinit var switchAudioPreview: Switch

    // 7个模块的状态
    private var rtmpEnabled = false
    private var recordEnabled = false
    private var flvEnabled = false
    private var videoEncoderEnabled = false
    private var audioEncoderEnabled = false
    private var videoPreviewEnabled = false
    private var audioPreviewEnabled = false

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
        etFilePath = findViewById(R.id.et_file_path)
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
        texturePreview = findViewById(R.id.texture_preview)

        // 初始化7个模块的 FrameLayout
        frameRtmp = findViewById(R.id.frame_rtmp)
        frameRecord = findViewById(R.id.frame_record)
        frameFlv = findViewById(R.id.frame_flv)
        frameVideoEncoder = findViewById(R.id.frame_video_encoder)
        frameAudioEncoder = findViewById(R.id.frame_audio_encoder)
        frameVideoPreview = findViewById(R.id.frame_video_preview)
        frameAudioPreview = findViewById(R.id.frame_audio_preview)

        // 初始化7个模块的 Switch
        switchRtmp = findViewById(R.id.switch_rtmp)
        switchRecord = findViewById(R.id.switch_record)
        switchFlv = findViewById(R.id.switch_flv)
        switchVideoEncoder = findViewById(R.id.switch_video_encoder)
        switchAudioEncoder = findViewById(R.id.switch_audio_encoder)
        switchVideoPreview = findViewById(R.id.switch_video_preview)
        switchAudioPreview = findViewById(R.id.switch_audio_preview)

        texturePreview.post {
            Log.d("MainActivity", "SurfaceView size: ${texturePreview.width} x ${texturePreview.height}")
            Log.d("MainActivity", "SurfaceView visibility: ${texturePreview.visibility}")
            Log.d("MainActivity", "SurfaceView isShown: ${texturePreview.isShown}")
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

        // 设置默认文件路径
        val defaultPath = "${getExternalFilesDir(null)}/record_${System.currentTimeMillis()}.flv"
        etFilePath.setText(defaultPath)

        // 设置浏览按钮点击事件
        val btnBrowse = findViewById<Button>(R.id.btn_browse)
        btnBrowse.setOnClickListener {
            // TODO: 实现文件选择器
            Toast.makeText(this, "文件将保存到: ${etFilePath.text}", Toast.LENGTH_SHORT).show()
        }

        // ========== 设置7个模块的 Switch 监听（控制背景色和推流功能） ==========
        setupSwitchListeners()

        // 批量初始化所有模块为禁用状态
        initAllModulesDisabled()

        requestPermissions()
    }

    private var isUpdating = false  // 防止循环的标志位

    private fun setAllButtonsEnabled(enabled: Boolean) {
        if (isUpdating) return
        isUpdating = true

        try {
            // 设置所有 Switch 的状态
            switchRtmp.isChecked = enabled
            switchRecord.isChecked = enabled
            switchFlv.isChecked = enabled
            switchVideoEncoder.isChecked = enabled
            switchAudioEncoder.isChecked = enabled
            switchVideoPreview.isChecked = enabled
            switchAudioPreview.isChecked = enabled

            // 更新所有模块的背景色
            updateModuleState(frameRtmp, enabled)
            updateModuleState(frameRecord, enabled)
            updateModuleState(frameFlv, enabled)
            updateModuleState(frameVideoEncoder, enabled)
            updateModuleState(frameAudioEncoder, enabled)
            updateModuleState(frameVideoPreview, enabled)
            updateModuleState(frameAudioPreview, enabled)

            // 更新状态变量
            rtmpEnabled = enabled
            recordEnabled = enabled
            flvEnabled = enabled
            videoEncoderEnabled = enabled
            audioEncoderEnabled = enabled
            videoPreviewEnabled = enabled
            audioPreviewEnabled = enabled

            if (enabled) {
                // 打开：启动推流
                checkPermissionsAndStart()
            } else {
                // 关闭：停止推流
                stopPushing()
            }
        } finally {
            isUpdating = false
        }
    }

    private fun setupSwitchListeners() {
        // 模块1: RTMP 推流
        switchRtmp.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            rtmpEnabled = isChecked
//            updateModuleState(frameRtmp, rtmpEnabled)
//            Log.d("MainActivity", "RTMP推流模块: enabled=$rtmpEnabled")
        }

        // 模块2: 本地录制
        switchRecord.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            recordEnabled = isChecked
//            updateModuleState(frameRecord, recordEnabled)
//            Log.d("MainActivity", "本地录制模块: enabled=$recordEnabled")
            // TODO: 控制本地录制
        }

        // 模块3: FLV 封装器
        switchFlv.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            flvEnabled = isChecked
//            updateModuleState(frameFlv, flvEnabled)
//            Log.d("MainActivity", "FLV封装器模块: enabled=$flvEnabled")
            // TODO: 控制 FLV 封装
        }

        // 模块4: 视频编码
        switchVideoEncoder.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            videoEncoderEnabled = isChecked
//            updateModuleState(frameVideoEncoder, videoEncoderEnabled)
//            Log.d("MainActivity", "视频编码模块: enabled=$videoEncoderEnabled")
            // TODO: 控制视频编码
        }

        // 模块5: 音频编码
        switchAudioEncoder.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            audioEncoderEnabled = isChecked
//            updateModuleState(frameAudioEncoder, audioEncoderEnabled)
//            Log.d("MainActivity", "音频编码模块: enabled=$audioEncoderEnabled")
            // TODO: 控制音频编码
        }

        // 模块6: 视频采集/预览
        switchVideoPreview.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            videoPreviewEnabled = isChecked
//            updateModuleState(frameVideoPreview, videoPreviewEnabled)
//            Log.d("MainActivity", "视频采集模块: enabled=$videoPreviewEnabled")
            // TODO: 控制视频采集
        }

        // 模块7: 音频采集/预览
        switchAudioPreview.setOnCheckedChangeListener { _, isChecked ->
            setAllButtonsEnabled(isChecked)
//            audioPreviewEnabled = isChecked
//            updateModuleState(frameAudioPreview, audioPreviewEnabled)
//            Log.d("MainActivity", "音频采集模块: enabled=$audioPreviewEnabled")
            // TODO: 控制音频采集
        }
    }

    private fun initAllModulesDisabled() {
        val frames = listOf(
            frameRtmp, frameRecord,
            frameFlv,
            frameVideoEncoder, frameAudioEncoder,
            frameVideoPreview, frameAudioPreview
        )
        frames.forEach { frame ->
            frame.isEnabled = false
        }

        rtmpEnabled = false
        recordEnabled = false
        flvEnabled = false
        videoEncoderEnabled = false
        audioEncoderEnabled = false
        videoPreviewEnabled = false
        audioPreviewEnabled = false

        Log.d("MainActivity", "All modules initialized to disabled")
    }

    /**
     * 更新模块的启用状态（改变背景色）
     * @param frame 模块的 FrameLayout
     * @param enabled 是否启用
     */
    private fun updateModuleState(frame: FrameLayout, enabled: Boolean) {
        frame.isEnabled = enabled
        Log.d("MainActivity", "updateModuleState: frame=${frame.id}, enabled=$enabled")
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

            // 设置推流停止回调，当推流异常断开时重置 Switch
//            pusherController?.onPushStoppedByError = {
//                runOnUiThread {
//                    switchRtmp.isChecked = false
//                    Log.d("MainActivity", "推流异常断开，RTMP Switch 已重置")
//                }
//            }

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