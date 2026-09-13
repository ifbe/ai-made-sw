package com.example.pusher

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Color
import android.hardware.camera2.CameraCharacteristics
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.content.res.ColorStateList
import android.util.Log
import android.animation.ValueAnimator
import android.graphics.Rect
import android.view.TextureView
import android.view.ViewTreeObserver
import android.view.animation.AccelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.view.View
import android.widget.*
import androidx.annotation.RequiresPermission
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.example.pusher.camera.CameraHelper
import com.example.pusher.push.JniWrapper
import com.example.pusher.push.LocalRecorder
import com.example.pusher.push.PusherController
import com.example.pusher.ui.AudioWaveformAggregator
import com.example.pusher.ui.AudioWaveformView
import com.example.pusher.ui.PreviewEntry
import com.example.pusher.ui.PreviewLogView
import com.example.pusher.utils.AppLog
import com.example.pusher.utils.RecordPath
import com.example.pusher.PushService


class MainActivity : AppCompatActivity() {
    private lateinit var etServerHost: EditText
    private lateinit var etAppPath: EditText
    private lateinit var tvAppPathLabel: TextView
    private lateinit var etPort: EditText
    private lateinit var etFilePath: EditText
    private lateinit var spinnerRecordEnabled: Spinner
    private lateinit var spinnerProtocol: Spinner
    private lateinit var previewRtmp: PreviewLogView
    private lateinit var previewRecord: PreviewLogView
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
    private lateinit var previewAppLog: PreviewLogView

    // 7个模块的 FrameLayout（用于控制背景色 / 展开显示）
    private lateinit var frameRtmp: FrameLayout      // 模块1: RTMP 推流
    private lateinit var frameRecord: FrameLayout    // 模块2: 本地录制
    private lateinit var frameFlv: FrameLayout       // 模块3: 封装
    private lateinit var frameVideoEncoder: FrameLayout  // 模块4: 视频编码
    private lateinit var frameAudioEncoder: FrameLayout  // 模块5: 音频编码
    private lateinit var frameVideoPreview: FrameLayout  // 模块6: 视频采集
    private lateinit var frameAudioPreview: FrameLayout  // 模块7: 音频采集
    private lateinit var frameSubtitle: FrameLayout
    private lateinit var spinnerSubtitle: Spinner
    private lateinit var etSubtitleText: EditText
    private lateinit var frameAppLog: FrameLayout        // 模块8: 特殊日志

    // 首页按钮面板 / 展开卡片
    private lateinit var rootLayout: FrameLayout
    private lateinit var panelArea: FrameLayout
    private lateinit var panelModules: View
    private lateinit var overlayExpanded: FrameLayout
    private lateinit var cardExpanded: FrameLayout
    private lateinit var cardContent: FrameLayout
    private lateinit var btnToggle: Button

    // 合并后的开始/停止按钮状态
    private enum class PushState { STOPPED, STARTING, STREAMING, STOPPING }

    @Volatile
    private var pushState = PushState.STOPPED

    /** 首页模块/按钮当前是否处于"推流中"配色 */
    private var modulesEnabled = false

    /** 已标记为"故障"的按钮（红色）：刷新配色时不再覆盖，直到下一次开始/停止推流 */
    private val failedButtonIds = mutableSetOf<Int>()
    private var appStartMs = 0L

    // 小按钮 -> 对应模块
    private val moduleButtons = linkedMapOf<Int, FrameLayout>()
    private var currentModule: FrameLayout? = null

    private var pusherController: PusherController? = null
    private var cameraHelper: CameraHelper? = null
    private var isActivityRunning = false  // 防止 Activity 销毁后回调执行导致崩溃

    // 会话代次：启动是异步的，用它判断回调回来时这次启动是否已经过期
    private var sessionGeneration = 0

    // 波形聚合：固定 1 秒窗口（跨 AudioRecord 的读块累积）
    @Volatile
    private var waveAggregator: AudioWaveformAggregator? = null

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
        tvAppPathLabel = findViewById(R.id.tv_app_path_label)
        etPort = findViewById(R.id.et_port)
        etFilePath = findViewById(R.id.et_file_path)
        spinnerRecordEnabled = findViewById(R.id.spinner_record_enabled)
        spinnerProtocol = findViewById(R.id.spinner_protocol)
        previewRtmp = findViewById(R.id.preview_rtmp)
        previewRecord = findViewById(R.id.preview_record)
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
        frameSubtitle = findViewById(R.id.frame_subtitle)
        spinnerSubtitle = findViewById(R.id.spinner_subtitle)
        etSubtitleText = findViewById(R.id.et_subtitle_text)
        frameAppLog = findViewById(R.id.frame_applog)
        previewAppLog = findViewById(R.id.preview_applog)

        // 首页按钮面板 / 展开卡片
        rootLayout = findViewById(R.id.root_layout)
        panelArea = findViewById(R.id.panel_area)
        panelModules = findViewById(R.id.panel_modules)
        overlayExpanded = findViewById(R.id.overlay_expanded)
        cardExpanded = findViewById(R.id.card_expanded)
        cardContent = findViewById(R.id.card_content)

        // 小按钮 -> 模块
        moduleButtons[R.id.btn_open_video_preview] = frameVideoPreview
        moduleButtons[R.id.btn_open_audio_preview] = frameAudioPreview
        moduleButtons[R.id.btn_open_video_encoder] = frameVideoEncoder
        moduleButtons[R.id.btn_open_audio_encoder] = frameAudioEncoder
        moduleButtons[R.id.btn_open_flv] = frameFlv
        moduleButtons[R.id.btn_open_rtmp] = frameRtmp
        moduleButtons[R.id.btn_open_record] = frameRecord
        moduleButtons[R.id.btn_open_subtitle] = frameSubtitle
        moduleButtons[R.id.btn_open_applog] = frameAppLog
        moduleButtons.forEach { (btnId, module) ->
            findViewById<Button>(btnId).setOnClickListener { expandModule(module) }
        }

        // 右上角折叠按钮 + 点击卡片外区域折叠
        findViewById<Button>(R.id.btn_collapse).setOnClickListener { collapseModule() }
        overlayExpanded.setOnClickListener { collapseModule() }
        // 卡片本身消费点击，避免点卡片内部空白处被当成“点外部”而折叠
        cardExpanded.setOnClickListener { /* 消费掉，不折叠 */ }

        // 右下角：开始/停止 合并按钮
        btnToggle = findViewById(R.id.btn_toggle)
        btnToggle.setOnClickListener { onToggleClicked() }

        // 特殊日志面板：注册接收器 + 回填历史
        appStartMs = SystemClock.elapsedRealtime()
        previewAppLog.setMaxEntries(200)
        previewRecord.setMaxEntries(300)
        AppLog.setSink { line -> onAppLogLine(line) }
        AppLog.snapshot().forEach { line -> previewAppLog.addEntry(appLogEntry(line)) }

        applyCardSize()
        applyPanelSize()
        updateToggleButton()
        AppLog.log("App 启动（特殊日志面板就绪）")

        // 屏幕尺寸变化（旋转）时重算卡片尺寸与预览比例。
        // onConfigurationChanged 里读到的宽高可能还是旧值，靠这个回调兜底。
        rootLayout.addOnLayoutChangeListener { _, left, top, right, bottom,
                                                oldLeft, oldTop, oldRight, oldBottom ->
            val w = right - left
            val h = bottom - top
            if (w != oldRight - oldLeft || h != oldBottom - oldTop) {
                Log.d("MainActivity", "root size changed: ${w}x$h")
                applyCardSize()
                applyPanelSize()
                if (overlayExpanded.visibility == View.VISIBLE) {
                    texturePreview.post { cameraHelper?.refreshPreviewLayout() }
                }
            }
        }

        texturePreview.post {
            Log.d("MainActivity", "SurfaceView size: ${texturePreview.width} x ${texturePreview.height}")
        }

        // ========== 设置 Spinner 适配器 ==========

        // 协议下拉：按**这份 FFmpeg 库实际编进去的能力**生成。
        // 好处：重编 FFmpeg（例如加上 libsrt）后 SRT 会自动出现；
        // 没编进去的协议不会出现在列表里，避免"选得出来但连不上"。
        val ffmpegProtocols: Set<String> = try {
            val raw = JniWrapper.nativeGetOutputProtocols()
            AppLog.log("FFmpeg 支持的输出协议: $raw")
            raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        } catch (t: Throwable) {
            Log.w("MainActivity", "query output protocols failed", t)
            AppLog.log("FFmpeg 协议能力查询失败，协议下拉退回 RTMP")
            emptySet()
        }
        val protocolItems = ArrayList<String>()
        if (ffmpegProtocols.contains("rtmp")) protocolItems.add("RTMP")
        if (ffmpegProtocols.contains("srt")) protocolItems.add("SRT")
        if (ffmpegProtocols.contains("tcp")) protocolItems.add("TCP")
        if (protocolItems.isEmpty()) protocolItems.add("RTMP")   // 查询失败时保持原行为
        // 最后一项"关闭" = 不推流，只把封装写到本地文件（录制的字节仍然产得出来）
        protocolItems.add("关闭")
        spinnerProtocol.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, protocolItems).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        // 封装格式：三种都列出来，**不随推流协议变**（免得你选好的格式被自动改掉），
        // 只在文案里提示适用范围；默认选 fMP4（裸推场景常用，且在 mpegts 前面）
        val formats = arrayOf("flv（都支持）", "fMP4（只支持 tcp）", "mpegts（只支持 tcp）")
        spinnerFormat.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, formats).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinnerFormat.setSelection(FORMAT_INDEX_FLV)
        // 录制文件名后缀跟随封装（默认 flv → pusher.flv）
        spinnerFormat.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                syncRecordExtension(position)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        spinnerProtocol.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val name = protocolItems.getOrElse(position) { protocolItems.first() }
                applyAppPathForProtocol(protocolKeyOf(name))
                // 协议选"关闭"时推流按钮要立刻变灰
                refreshPipelineStates(updateCards = false)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // 「应用/流名」这一栏的含义随协议变（rtmp=流名，tcp/srt=URL 参数），
        // 初始先把当前值记到 rtmp 名下（见 applyAppPathForProtocol）
        applyAppPathForProtocol("rtmp")

        val videoCodecs = arrayOf("H.264", "H.265")
        spinnerVideoCodec.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, videoCodecs).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        // OPUS 暂未实现（native 侧固定 AAC），先不提供该选项，避免选到后静默发出标签错误的流
        val audioCodecs = arrayOf("AAC")
        spinnerAudioCodec.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, audioCodecs).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        // 第一个是"默认设备"，最后一个是"关闭"（关闭 = 这一路不推，可以实现只推音频/只推视频）
        val cameras = arrayOf("默认设备", "后置摄像头", "前置摄像头", "关闭")
        spinnerCamera.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, cameras).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val resolutions = arrayOf("1920x1080", "1280x720", "854x480", "640x360", "480x270")
        spinnerResolution.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, resolutions).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        // 同上：0=默认设备 1=内置 2=外接 3=关闭
        val mics = arrayOf("默认设备", "内置麦克风", "外接麦克风", "关闭")
        spinnerMic.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, mics).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val channels = arrayOf("单声道", "立体声")
        spinnerChannels.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, channels).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        // 字幕来源：固定文字 / ASR / 关闭（默认关闭 —— 字幕链路还没接入）
        val subtitleSources = arrayOf("固定文字", "ASR", "关闭")
        spinnerSubtitle.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, subtitleSources).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinnerSubtitle.setSelection(SUBTITLE_INDEX_OFF)
        etSubtitleText.isEnabled = false

        // 摄像头 / 麦克风 / 字幕的选择变化 → 首页按钮的灰度立刻跟着变
        val onPathChanged = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                refreshPipelineStates(updateCards = false)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        spinnerCamera.onItemSelectedListener = onPathChanged
        spinnerMic.onItemSelectedListener = onPathChanged
        spinnerSubtitle.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                // 只有"固定文字"模式才让输入框可编辑
                etSubtitleText.isEnabled = position == SUBTITLE_INDEX_FIXED
                refreshPipelineStates(updateCards = false)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // 本地录制：默认开启，默认目录 /sdcard/Download（具体文件名在实际录制时再拼）
        etFilePath.setText(DEFAULT_RECORD_PATH)
        // 把初始后缀对齐到当前封装（避免出现 flv 内容叫 .mp4）
        syncRecordExtension(spinnerFormat.selectedItemPosition)
        val recordOptions = arrayOf("开启", "关闭")
        spinnerRecordEnabled.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, recordOptions).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinnerRecordEnabled.setSelection(RECORD_INDEX_ON)
        spinnerRecordEnabled.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val on = position == RECORD_INDEX_ON
                // 关掉录制：路径不可编辑且置灰
                etFilePath.isEnabled = on
                etFilePath.alpha = if (on) 1.0f else 0.4f
                refreshPipelineStates(updateCards = false)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // 初始：全部模块为“未启用”外观
        setModulesEnabled(false)

        requestPermissions()

        isActivityRunning = true
    }

    private fun allModules(): List<FrameLayout> = listOf(
        frameRtmp, frameRecord, frameFlv,
        frameVideoEncoder, frameAudioEncoder,
        frameVideoPreview, frameAudioPreview,
        frameSubtitle,
        frameAppLog
    )

    /** 参与“推流中/未推流”配色的模块（日志模块不参与，始终正常显示） */
    private fun pipelineModules(): List<FrameLayout> = listOf(
        frameRtmp, frameRecord, frameFlv,
        frameVideoEncoder, frameAudioEncoder,
        frameVideoPreview, frameAudioPreview,
        frameSubtitle
    )

    /** 与 pipelineModules() 一一对应的首页按钮 */
    private fun pipelineButtonIds(): List<Int> = listOf(
        R.id.btn_open_rtmp, R.id.btn_open_record, R.id.btn_open_flv,
        R.id.btn_open_video_encoder, R.id.btn_open_audio_encoder,
        R.id.btn_open_video_preview, R.id.btn_open_audio_preview,
        R.id.btn_open_subtitle
    )

    /** 所有模块的启用外观（边框色 + 透明度）与首页按钮配色，由开始/停止驱动 */
    private fun setModulesEnabled(enabled: Boolean) {
        modulesEnabled = enabled
        // 每次开始/停止都清掉上一轮的故障标记
        failedButtonIds.clear()
        refreshPipelineStates(updateCards = true)
    }

    /** 摄像头/麦克风选"关闭"、字幕选"关闭" → 这一路没启用 */
    private fun isVideoPathOff() = spinnerCamera.selectedItemPosition == CAMERA_INDEX_OFF
    private fun isAudioPathOff() = spinnerMic.selectedItemPosition == MIC_INDEX_OFF
    private fun isSubtitlePathOff() = spinnerSubtitle.selectedItemPosition == SUBTITLE_INDEX_OFF
    private fun isRecordPathOff() = spinnerRecordEnabled.selectedItemPosition == RECORD_INDEX_OFF

    /**
     * 刷新首页按钮/模块的 4 态配色：
     *   灰 = 这一路被关闭（设备/字幕选"关闭"）
     *   绿 = 推流中且这一路启用
     *   蓝灰 = 还没开始
     *   红 = 该环节故障（markModuleFailed / RTMP 失败时单独设置，不在这里覆盖）
     *
     * @param updateCards 是否同时更新模块卡片状态（改下拉选项时只刷按钮，别把"故障红框"冲掉）
     */
    private fun refreshPipelineStates(updateCards: Boolean) {
        val videoOff = isVideoPathOff()
        val audioOff = isAudioPathOff()
        val subtitleOff = isSubtitlePathOff()
        val frames = pipelineModules()
        val ids = pipelineButtonIds()
        for (i in frames.indices) {
            val off = when (ids[i]) {
                R.id.btn_open_video_preview, R.id.btn_open_video_encoder -> videoOff
                R.id.btn_open_audio_preview, R.id.btn_open_audio_encoder -> audioOff
                R.id.btn_open_subtitle -> subtitleOff
                R.id.btn_open_record -> isRecordPathOff()
                R.id.btn_open_rtmp -> isPushOff()
                else -> false
            }
            val btn = findViewById<Button>(ids[i])
            if (ids[i] in failedButtonIds) {
                // 故障红优先，也不动卡片（卡片的红框由 markModuleFailed 设置）
                btn.backgroundTintList = ColorStateList.valueOf(COLOR_BUTTON_FAILED)
                continue
            }
            if (updateCards) updateModuleState(frames[i], !off && modulesEnabled)
            btn.backgroundTintList = ColorStateList.valueOf(
                when {
                    off -> COLOR_BUTTON_DISABLED
                    modulesEnabled -> COLOR_BUTTON_OK
                    else -> COLOR_BUTTON_DEFAULT
                }
            )
        }
    }

    /** 把最多 16 字节转成 "00 00 00 01 67 42 ..." 的十六进制，用于预览 */
    private fun hexPreview(data: ByteArray, max: Int = 16): String {
        val n = minOf(data.size, max)
        val sb = StringBuilder(n * 3)
        for (i in 0 until n) {
            sb.append(String.format(java.util.Locale.US, "%02X", data[i]))
            if (i != n - 1) sb.append(' ')
        }
        return sb.toString()
    }

    /** 封装（也就是录制容器）变了：同步「文件路径」那一栏的后缀 */
    private fun syncRecordExtension(formatPosition: Int) {
        if (!::etFilePath.isInitialized) return
        val ext = when (formatPosition) {
            FORMAT_INDEX_FLV -> "flv"
            FORMAT_INDEX_FMP4 -> "mp4"
            else -> "ts"
        }
        val text = etFilePath.text.toString().trim()
        if (text.isEmpty()) return
        val newText = if (text.contains('/')) {
            val dir = text.substringBeforeLast('/')
            val name = text.substringAfterLast('/').ifBlank { RecordPath.DEFAULT_BASE }
            "$dir/${name.substringBeforeLast('.', name)}.$ext"
        } else {
            "${text.substringBeforeLast('.', text)}.$ext"
        }
        if (newText != text) {
            etFilePath.setText(newText)
            AppLog.log("录制文件名后缀跟随封装: → $newText")
        }
    }

    private fun protocolKeyOf(displayName: String): String = when (displayName) {
        "SRT" -> "srt"
        "TCP" -> "tcp"
        "关闭" -> "off"
        else -> "rtmp"
    }

    /** 协议选"关闭"：不推流，只写本地文件 */
    private fun isPushOff(): Boolean = spinnerProtocol.selectedItem?.toString() == "关闭"

    /** 每个协议各自记住「应用/流名」栏的内容；切换协议时自动填该协议的常用值 */
    private val appPathByProtocol = mutableMapOf("rtmp" to "", "tcp" to "?tcp_nodelay=1", "srt" to "")
    private var currentProtocolKey = "rtmp"

    private fun applyAppPathForProtocol(protocolKey: String) {
        if (::etAppPath.isInitialized) {
            appPathByProtocol[currentProtocolKey] = etAppPath.text.toString()
        }
        currentProtocolKey = protocolKey
        val value = appPathByProtocol[protocolKey].orEmpty()
        if (::etAppPath.isInitialized) {
            etAppPath.setText(value)
            tvAppPathLabel.text = if (protocolKey == "rtmp") "应用/流名:" else "参数:"
        }
        AppLog.log("「应用/流名」栏(${protocolKey}) = ${if (value.isEmpty()) "(空)" else value}")
    }

    /** 字幕来源的显示文案（给日志用） */
    private fun subtitleSourceLabel(): String = when (spinnerSubtitle.selectedItem?.toString()) {
        "固定文字" -> "固定文字「${etSubtitleText.text}」"
        "ASR" -> "ASR（实时语音识别）"
        else -> "关闭"
    }

    // ==================== 合并后的开始/停止按钮 ====================

    private fun onToggleClicked() {
        when (pushState) {
            PushState.STOPPED -> {
                Log.d("MainActivity", "toggle clicked: start")
                pushState = PushState.STARTING
                updateToggleButton()
                checkPermissionsAndStart()
            }
            PushState.STREAMING -> {
                Log.d("MainActivity", "toggle clicked: stop")
                stopPushing()
            }
            PushState.STARTING, PushState.STOPPING -> {
                Log.d("MainActivity", "toggle ignored, state=$pushState")
            }
        }
    }

    /** 按钮文字即当前状态 */
    private fun updateToggleButton() {
        if (!::btnToggle.isInitialized) return
        val text: String
        val color: Int
        when (pushState) {
            PushState.STOPPED -> {
                text = "已停止"; color = 0xFF757575.toInt()
            }
            PushState.STARTING -> {
                text = "开启中…"; color = 0xFFFF9800.toInt()
            }
            PushState.STREAMING -> {
                text = "推流中"; color = 0xFF43A047.toInt()
            }
            PushState.STOPPING -> {
                text = "停止中…"; color = 0xFFFF9800.toInt()
            }
        }
        btnToggle.text = text
        btnToggle.backgroundTintList = ColorStateList.valueOf(color)
    }

    // ==================== 特殊日志面板 ====================

    private fun appLogEntry(line: String) = PreviewEntry(
        timestamp = SystemClock.elapsedRealtime() - appStartMs,
        direction = -1,
        data = EMPTY_BYTES,
        extra = line
    )

    private fun onAppLogLine(line: String) {
        if (!isActivityRunning) return
        runOnUiThread {
            if (isActivityRunning) previewAppLog.addEntry(appLogEntry(line))
        }
    }

    /**
     * 展开某个模块：只显示它，隐藏按钮面板。
     * 同一个按钮再点一次 → 折叠回去。
     *
     * 带动画：从被点的那个小按钮矩形，放大/平移到卡片的最终矩形（矩形形变，不是缩放整屏）。
     */
    private fun expandModule(module: FrameLayout) {
        if (currentModule === module && overlayExpanded.visibility == View.VISIBLE) {
            collapseModule()
            return
        }
        val button = moduleButtonFor(module)
        allModules().forEach { it.visibility = View.GONE }
        module.visibility = View.VISIBLE
        currentModule = module
        panelModules.visibility = View.GONE

        // 先按 80% 定好卡片尺寸（有尺寸就同步生效，减少等一帧）
        applyCardSizeNow()
        applyCardSize()

        overlayExpanded.visibility = View.VISIBLE
        // 只淡入"背景遮罩"，卡片本身始终实心 —— 否则整块一起半透明，矩形形变会看不清
        overlayExpanded.alpha = 1f
        overlayExpanded.background?.mutate()?.setAlpha(0)
        animateScrimAlpha(0, 255, EXPAND_MS)

        if (button != null) {
            // 等卡片真正布局完成后再量矩形（尺寸变化是异步的）
            cardExpanded.viewTreeObserver.addOnGlobalLayoutListener(
                object : ViewTreeObserver.OnGlobalLayoutListener {
                    override fun onGlobalLayout() {
                        cardExpanded.viewTreeObserver.removeOnGlobalLayoutListener(this)
                        playExpandAnimation(button)
                    }
                }
            )
        }
        // 容器尺寸从“无”变成 80% 卡片，视频预览要按新容器重算比例
        overlayExpanded.post { cameraHelper?.refreshPreviewLayout() }
        Log.d("MainActivity", "expand module: ${resources.getResourceEntryName(module.id)}")
        AppLog.log("展开模块: ${resources.getResourceEntryName(module.id)}")
    }

    /** 折叠回小按钮：动画从卡片矩形缩小落到对应的按钮上 */
    private fun collapseModule() {
        val button = currentModule?.let { moduleButtonFor(it) }
        val card = cardExpanded
        if (button == null || card.width <= 0 || card.height <= 0) {
            finishCollapse()
            return
        }
        // 面板先亮出来：这样"缩小落到按钮"的过程是看得见的（scrim 同时在淡出）
        panelModules.visibility = View.VISIBLE
        val target = rectOf(button)
        val cur = rectOf(card)
        card.pivotX = 0f
        card.pivotY = 0f
        card.animate()
            .scaleX(target.width().toFloat() / cur.width())
            .scaleY(target.height().toFloat() / cur.height())
            .translationX((target.left - cur.left).toFloat())
            .translationY((target.top - cur.top).toFloat())
            .setDuration(COLLAPSE_MS)
            .setInterpolator(AccelerateInterpolator())
            .withEndAction { finishCollapse() }
            .start()
        animateScrimAlpha(overlayExpanded.background?.alpha ?: 255, 0, COLLAPSE_MS)
        Log.d("MainActivity", "collapse module (animated)")
    }

    /** 动画结束后真正收起（并把卡片恢复原状，供下次展开使用） */
    private fun finishCollapse() {
        overlayExpanded.visibility = View.GONE
        overlayExpanded.alpha = 1f
        overlayExpanded.background?.mutate()?.setAlpha(255)
        cardExpanded.animate().cancel()
        cardExpanded.scaleX = 1f
        cardExpanded.scaleY = 1f
        cardExpanded.translationX = 0f
        cardExpanded.translationY = 0f
        panelModules.visibility = View.VISIBLE
        allModules().forEach { it.visibility = View.GONE }
        currentModule = null
        Log.d("MainActivity", "collapse module done")
    }

    /** 模块 → 首页上对应的那个小按钮 */
    private fun moduleButtonFor(module: FrameLayout): View? {
        val id = moduleButtons.entries.firstOrNull { it.value === module }?.key ?: return null
        return findViewById<View>(id)
    }

    /** 相对根布局的矩形（用于计算"按钮 → 卡片"的位移与缩放） */
    private fun rectOf(v: View): Rect {
        val rootLoc = IntArray(2)
        val loc = IntArray(2)
        rootLayout.getLocationInWindow(rootLoc)
        v.getLocationInWindow(loc)
        return Rect(
            loc[0] - rootLoc[0],
            loc[1] - rootLoc[1],
            loc[0] - rootLoc[0] + v.width,
            loc[1] - rootLoc[1] + v.height
        )
    }

    /** 从按钮矩形放大到卡片矩形（pivot 固定在左上角，几何上等价于矩形形变） */
    private fun playExpandAnimation(button: View) {
        val card = cardExpanded
        if (card.width <= 0 || card.height <= 0) return
        val from = rectOf(button)
        val to = rectOf(card)
        if (from.width() <= 0 || from.height() <= 0) return
        card.pivotX = 0f
        card.pivotY = 0f
        card.scaleX = from.width().toFloat() / to.width()
        card.scaleY = from.height().toFloat() / to.height()
        card.translationX = (from.left - to.left).toFloat()
        card.translationY = (from.top - to.top).toFloat()
        card.animate()
            .scaleX(1f)
            .scaleY(1f)
            .translationX(0f)
            .translationY(0f)
            .setDuration(EXPAND_MS)
            .setInterpolator(OvershootInterpolator(0.55f))
            .start()
    }

    /** 只动画"背景遮罩"的不透明度（卡片不参与淡入淡出） */
    private fun animateScrimAlpha(from: Int, to: Int, duration: Long, onEnd: (() -> Unit)? = null) {
        val bg = overlayExpanded.background ?: run {
            onEnd?.invoke()
            return
        }
        bg.mutate()
        ValueAnimator.ofInt(from, to).apply {
            this.duration = duration
            addUpdateListener {
                bg.setAlpha(it.animatedValue as Int)
                overlayExpanded.invalidate()
            }
            if (onEnd != null) addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: android.animation.Animator) = onEnd()
            })
            start()
        }
    }

    /** 同步按 80% 设置卡片尺寸（根布局已有尺寸时立刻生效） */
    private fun applyCardSizeNow(): Boolean {
        val w = (rootLayout.width * 0.8f).toInt()
        val h = (rootLayout.height * 0.8f).toInt()
        if (w <= 0 || h <= 0) return false
        val lp = cardExpanded.layoutParams
        if (lp.width != w || lp.height != h) {
            lp.width = w
            lp.height = h
            cardExpanded.layoutParams = lp
        }
        return true
    }

    /**
     * 首页按钮区域：以屏幕中心为中心、边长 = min(屏宽, 屏高) 的正方形。
     * 正方形边长取"短边"，并且内部全用固定 dp，所以横竖屏切换时面板渲染完全一致。
     */
    private fun applyPanelSize() {
        rootLayout.post {
            val side = minOf(rootLayout.width, rootLayout.height)
            if (side <= 0) return@post
            val lp = panelArea.layoutParams
            if (lp.width != side || lp.height != side) {
                lp.width = side
                lp.height = side
                panelArea.layoutParams = lp
                Log.d("MainActivity", "panel area: ${side}x$side (root ${rootLayout.width}x${rootLayout.height})")
            }
        }
    }

    /** 展开卡片：长宽都只占屏幕的 80%，居中 */
    private fun applyCardSize() {
        rootLayout.post {
            val w = (rootLayout.width * 0.8f).toInt()
            val h = (rootLayout.height * 0.8f).toInt()
            if (w <= 0 || h <= 0) return@post
            val lp = cardExpanded.layoutParams
            if (lp.width != w || lp.height != h) {
                lp.width = w
                lp.height = h
                cardExpanded.layoutParams = lp
                Log.d("MainActivity", "card size: ${w}x$h (root ${rootLayout.width}x${rootLayout.height})")
            }
        }
    }

    /**
     * 更新模块的启用状态（改变边框色 / 透明度）
     * @param frame 模块的 FrameLayout
     * @param enabled 是否启用
     */
    private fun updateModuleState(frame: FrameLayout, enabled: Boolean) {
        // 先恢复成状态选择器（会清掉“失败”红框），再改 enabled 让它重新解析状态
        frame.setBackgroundResource(R.drawable.module_bg_state)
        frame.isEnabled = enabled
        frame.alpha = if (enabled) 1.0f else 0.5f
        Log.d("MainActivity", "updateModuleState: frame=${frame.id}, enabled=$enabled")
    }

    /** 该环节失败：卡片用红色边框标出（与首页按钮的红色对应） */
    private fun markModuleFailed(frame: FrameLayout) {
        frame.setBackgroundResource(R.drawable.module_bg_failed)
        frame.isEnabled = true
        frame.alpha = 1.0f
        // 首页按钮同步转红，并记入故障集合（刷新配色时不再被覆盖）
        val btnId = moduleButtons.entries.firstOrNull { it.value === frame }?.key
        if (btnId != null) {
            failedButtonIds.add(btnId)
            findViewById<Button>(btnId).backgroundTintList = ColorStateList.valueOf(COLOR_BUTTON_FAILED)
        }
        Log.d("MainActivity", "markModuleFailed: frame=${frame.id}, btn=$btnId")
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
        } else {
            // 相机/麦克风都齐了，顺手把通知权限要一下（它不参与"能否推流"的判断）
            requestNotificationPermissionIfNeeded()
        }
    }

    /**
     * Android 13+ 的通知权限。
     *
     * 只影响状态栏那条"推流中/停止推流"通知：不给，前台服务照常运行、推流完全不受影响，
     * 所以这里单独申请，结果也不参与 [checkPermissionsAndStart] 的判断。
     */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        try {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                NOTIFICATION_PERMISSION_REQUEST_CODE
            )
        } catch (t: Throwable) {
            Log.w("MainActivity", "request POST_NOTIFICATIONS failed", t)
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
            requestNotificationPermissionIfNeeded()
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
        if (requestCode == STORAGE_PERMISSION_REQUEST_CODE) {
            val granted = grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED
            AppLog.log("存储权限: " + if (granted) "已允许（录制可写公共下载目录）" else "已拒绝（录制会失败，推流不受影响）")
        }
        if (requestCode == NOTIFICATION_PERMISSION_REQUEST_CODE) {
            val granted = grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED
            AppLog.log(
                "通知权限: " + if (granted) "已允许（状态栏显示推流提示）"
                else "已拒绝（推流不受影响，状态栏无提示）"
            )
            // 授权时如果已经在推流，把可能被系统丢掉的那条通知补上
            if (granted && pushState != PushState.STOPPED) {
                PushService.refreshNotification(this)
            }
        }
        if (requestCode == PERMISSION_REQUEST_CODE) {
            val allGranted = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            AppLog.log("权限结果: " + permissions.mapIndexed { i, p ->
                "${p.substringAfterLast('.')}=${grantResults.getOrNull(i) == PackageManager.PERMISSION_GRANTED}"
            }.joinToString(", "))
            if (allGranted) {
                requestNotificationPermissionIfNeeded()
                startPushing()
            } else {
                Toast.makeText(this, "需要相机和麦克风权限才能推流", Toast.LENGTH_SHORT).show()
                pushState = PushState.STOPPED
                updateToggleButton()
            }
        }
    }

    @RequiresPermission(Manifest.permission.RECORD_AUDIO)
    private fun startPushing() {
        Log.d("MainActivity", "=== startPushing START ===")

        if (isFinishing || isDestroyed) {
            Log.w("MainActivity", "startPushing ignored: activity is finishing")
            return
        }

        // 摄像头下拉：0=默认设备（按后置处理）1=后置 2=前置 3=关闭
        // 麦克风下拉：0=默认设备 1=内置 2=外接 3=关闭
        val cameraPosition = spinnerCamera.selectedItemPosition
        val micPosition = spinnerMic.selectedItemPosition
        val videoEnabled = cameraPosition != CAMERA_INDEX_OFF
        val audioEnabled = micPosition != MIC_INDEX_OFF
        if (!videoEnabled && !audioEnabled) {
            AppLog.log("摄像头和麦克风都选了“关闭”，没有可推的内容")
            Toast.makeText(this, "摄像头和麦克风都选了“关闭”，没有可推的内容", Toast.LENGTH_LONG).show()
            pushState = PushState.STOPPED
            updateToggleButton()
            return
        }
        // 字幕：固定文字能真正写轨；ASR 还没接；关闭则完全不写
        val subtitleText: String? = when (spinnerSubtitle.selectedItem?.toString()) {
            "固定文字" -> etSubtitleText.text.toString().trim().ifBlank {
                AppLog.log("字幕: 固定文字为空，本次不写字幕")
                null
            }
            "ASR" -> {
                AppLog.log("字幕: ASR 尚未接入，本次不写字幕")
                null
            }
            else -> null
        }
        AppLog.log(
            if (subtitleText != null)
                "字幕: 固定文字「$subtitleText」→ 每 2s 一条，写入独立字幕轨(tx3g)"
            else
                "字幕: ${subtitleSourceLabel()}（本次不写字幕）"
        )
        if (subtitleText != null) {
            AppLog.log("字幕: 独立字幕轨已停用（fMP4 分片会导致 movenc 断言崩溃），本次只记录选择")
        }
        if (isRecordPathOff()) {
            AppLog.log("本地录制: 关闭（本次不录）")
        } else {
            val recordPath = etFilePath.text.toString()
            AppLog.log("本地录制: 开启，落盘=${RecordPath.describe(recordPath)}")
            // Android 10 及以下要存储权限；拒绝也不影响推流
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED
            ) {
                try {
                    ActivityCompat.requestPermissions(
                        this,
                        arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                        STORAGE_PERMISSION_REQUEST_CODE
                    )
                } catch (t: Throwable) {
                    Log.w("MainActivity", "request WRITE_EXTERNAL_STORAGE failed", t)
                }
            }
        }
        if (!videoEnabled) AppLog.log("视频已关闭（摄像头=关闭）→ 本次只推音频")
        if (!audioEnabled) AppLog.log("音频已关闭（麦克风=关闭）→ 本次只推视频")

        // 协议名（下拉项就是显示文本，直接映射成 URL scheme）
        val protocol = when (spinnerProtocol.selectedItem?.toString()) {
            "SRT" -> "srt"
            "TCP" -> "tcp"
            "关闭" -> "off"
            else -> "rtmp"
        }
        if (protocol == "off" && isRecordPathOff()) {
            AppLog.log("协议=关闭 且 本地录制=关闭：没有任何输出，已阻止")
            Toast.makeText(this, "协议和本地录制都关闭了，没有输出", Toast.LENGTH_LONG).show()
            pushState = PushState.STOPPED
            updateToggleButton()
            return
        }
        val hostText = etServerHost.text.toString().trim()
        val portText = etPort.text.toString().trim()
        val appPathText = etAppPath.text.toString()

        // 协议 × 封装 兼容性：只提示，不拦截（列表是固定的，选错也能看到明确原因）
        val formatLabelCheck = spinnerFormat.selectedItem?.toString().orEmpty()
        val formatMismatch = when {
            protocol == "off" -> null
            protocol == "rtmp" && !formatLabelCheck.startsWith("flv", ignoreCase = true) ->
                "RTMP 只认 flv（RTMP 的载荷必须是 FLV tag），当前选的是「$formatLabelCheck」"
            protocol != "rtmp" && formatLabelCheck.startsWith("flv", ignoreCase = true) ->
                "flv 只有 RTMP 端能解，tcp/srt 建议用 fMP4 或 mpegts"
            else -> null
        }
        if (formatMismatch != null) {
            AppLog.log("封装与协议可能不匹配: $formatMismatch")
            Toast.makeText(this, formatMismatch, Toast.LENGTH_LONG).show()
        }

        // SRT/TCP 是 host:port 直连，地址和端口必填（"关闭"不需要地址）
        if (protocol != "rtmp" && protocol != "off") {
            val missing = when {
                hostText.isEmpty() -> "服务器地址"
                portText.isEmpty() -> "端口"
                else -> null
            }
            if (missing != null) {
                AppLog.log("SRT/TCP 推送需要填写$missing")
                Toast.makeText(this, "SRT/TCP 推送需要填写$missing", Toast.LENGTH_LONG).show()
                pushState = PushState.STOPPED
                updateToggleButton()
                return
            }
        }

        PushService.start(this)
        // 通知栏“停止推流”按钮的回调（服务在后台被点击时调用）
        PushService.onStopRequested = { stopPushing() }

        // 模块切到“启用”外观（全局开始/停止驱动）
        setModulesEnabled(true)

        if (pushState != PushState.STARTING) {
            pushState = PushState.STARTING
            updateToggleButton()
        }

        // 本次会话的代次
        val generation = ++sessionGeneration

        // 相机选择：0=默认设备（按后置处理）1=后置 2=前置；分辨率按下拉框选择
        val lensFacing = if (cameraPosition <= 1) {
            CameraCharacteristics.LENS_FACING_BACK
        } else {
            CameraCharacteristics.LENS_FACING_FRONT
        }
        val (prefWidth, prefHeight) = parseResolution(
            spinnerResolution.selectedItem?.toString() ?: DEFAULT_RESOLUTION_TEXT
        )
        // 视频编码类型：编码器能力校验要用到，提前读出来
        val videoCodecForSizing = when (spinnerVideoCodec.selectedItemPosition) {
            0 -> "H.264"
            else -> "H.265"
        }
        val videoMimeForSizing = if (videoCodecForSizing == "H.265") {
            android.media.MediaFormat.MIMETYPE_VIDEO_HEVC
        } else {
            android.media.MediaFormat.MIMETYPE_VIDEO_AVC
        }

        // 相机对象提前建好：预览尺寸查询和真正的预览用同一个实例、同一套参数。
        // 视频关闭时不需要相机，也不去查尺寸。
        val helper = if (videoEnabled) {
            CameraHelper(this, lensFacing, prefWidth, prefHeight, videoMimeForSizing)
                .also { cameraHelper = it }
        } else {
            null
        }

        val startWithSizes: (Int, Int) -> Unit = { width, height ->
            Log.d("MainActivity", "Preview size: ${width}x${height}")

            // 使用预览尺寸进行推流；关闭的那一路用 0 表示（native 侧 0 尺寸就不建那条流）
            val encodeWidth = if (videoEnabled) width else 0
            val encodeHeight = if (videoEnabled) height else 0

            // 构建 URL 和编码参数...
            // rtmp：协议://host:port/流名；srt/tcp：协议://host:port（裸字节流，不带流名）
            val url = if (protocol == "off") {
                AppLog.log("推流: 关闭 → 只把封装写到本地文件（不连服务器）")
                ""
            } else if (protocol == "rtmp") {
                if (portText.isNotEmpty() && portText != "1935") "$protocol://$hostText:$portText$appPathText"
                else "$protocol://$hostText$appPathText"
            } else {
                // tcp/srt：「应用/流名」那一栏就是 URL 参数（例如 ?tcp_nodelay=1）
                val suffix = when {
                    appPathText.isBlank() -> ""
                    appPathText.startsWith("?") || appPathText.startsWith("&") -> appPathText
                    else -> "?$appPathText"
                }
                "$protocol://$hostText:$portText$suffix"
            }

            // 按显示文本的前缀映射封装（文案里带提示，不能按位置硬编码）
            val formatLabel = spinnerFormat.selectedItem?.toString().orEmpty()
            val format = when {
                formatLabel.startsWith("flv", ignoreCase = true) -> "flv"
                formatLabel.startsWith("fmp", ignoreCase = true) -> "mp4"
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
            // 采样率同时兼容 kHz（历史默认 44.1）和 Hz（44100）两种写法：
            // 小于 1000 视为 kHz，否则按 Hz。旧代码无条件 ×1000，填 44100 会变成 44.1MHz 直接失败。
            val sampleRateInput = etAudioSamplerate.text.toString().toDoubleOrNull() ?: 44.1
            val audioSamplerate = if (sampleRateInput < 1000.0) {
                (sampleRateInput * 1000).toInt()
            } else {
                sampleRateInput.toInt()
            }
            val channelCount = if (spinnerChannels.selectedItemPosition == 0) 1 else 2

            // 创建 PusherController
            val controller = PusherController(
                onAvioData = { direction, timestamp, data, totalSize ->
                    if (!isActivityRunning) return@PusherController
                    runOnUiThread {
                        if (!isActivityRunning) return@runOnUiThread
                        if (data.isNotEmpty()) {
                            previewRtmp.addEntry(PreviewEntry(timestamp, direction, data))
                            // 录制预览：这次写了多少字节 + 前 16 字节内容
                            previewRecord.addEntry(
                                PreviewEntry(
                                    timestamp, direction, data,
                                    "write: byte=$totalSize data=${hexPreview(data)}"
                                )
                            )
                        }
                    }
                },
                onVideoFrameCallback = { data, timestamp, isKey ->
                    if (!isActivityRunning) return@PusherController
                    runOnUiThread {
                        if (!isActivityRunning) return@runOnUiThread
                        if (data.isNotEmpty()) {
                            previewVideo.addEntry(PreviewEntry(timestamp, -1, data, ""))
                        }
                    }
                },
                onAudioFrameCallback = { data, timestamp ->
                    if (!isActivityRunning) return@PusherController
                    runOnUiThread {
                        if (!isActivityRunning) return@runOnUiThread
                        if (data.isNotEmpty()) {
                            previewAudio.addEntry(PreviewEntry(timestamp, -1, data, ""))
                        }
                    }
                },
                onMuxData = { data, timestamp ->
                    if (!isActivityRunning) return@PusherController
                    runOnUiThread {
                        if (!isActivityRunning) return@runOnUiThread
                        if (data.isNotEmpty()) {
                            previewMux.addEntry(PreviewEntry(timestamp, -1, data, ""))
                        }
                    }
                },
                onPcmData = { pcmData ->
                    if (!isActivityRunning) return@PusherController
                    // 波形：固定 1 秒窗口的 min/max 包络，左右声道分别取、叠在同一张图里用颜色区分
                    try {
                        val snapshot = waveAggregator?.add(pcmData) ?: return@PusherController
                        runOnUiThread {
                            if (!isActivityRunning) return@runOnUiThread
                            waveformView.setChannelMode(if (channelCount == 1) 1 else 2)
                            waveformView.setWaveformData(
                                snapshot.leftMin, snapshot.leftMax,
                                snapshot.rightMin, snapshot.rightMax
                            )
                        }
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Waveform error", e)
                    }
                },
                onRtmpError = { errorMsg ->
                    if (!isActivityRunning) return@PusherController
                    runOnUiThread {
                        if (!isActivityRunning) return@runOnUiThread
                        // 只有 RTMP 这一环失败：标红，其余环节继续跑，不整体停止
                        markModuleFailed(frameRtmp)
                        AppLog.log("RTMP 失败（其余环节继续）: $errorMsg")
                        Toast.makeText(this, "RTMP 连接失败: $errorMsg", Toast.LENGTH_LONG).show()
                    }
                }
            )
            pusherController = controller

            // 波形聚合器：固定 1 秒窗口。必须在本会话开始采集之前建好。
            val aggregator = AudioWaveformAggregator(audioSamplerate, channelCount)
            waveAggregator = aggregator
            Log.d("MainActivity", "waveform window: ${aggregator.windowFrames} frames " +
                    "(${AudioWaveformAggregator.WINDOW_MS}ms), ${AudioWaveformAggregator.DEFAULT_POINTS} points, " +
                    "${aggregator.framesPerPointValue} frames/point")

            // 初始化（FFmpeg 连接/握手、MediaCodec、AudioRecord）在后台线程执行，
            // 完成后回到主线程再启动相机，避免阻塞 UI。
            AppLog.log("开始推流: $url 封装=$format 视频=$videoCodec " +
                    "${encodeWidth}x${encodeHeight}@${videoFps}fps ${videoBitrate}kbps " +
                    "音频=$audioCodec ${audioSamplerate}Hz ${channelCount}ch")
            // 本地录制：录的就是推出去的那份字节，容器跟随「封装」下拉
            val recordExt = when (format) {
                "flv" -> "flv"
                "mp4" -> "mp4"
                else -> "ts"
            }
            val localRecorder: LocalRecorder? = if (isRecordPathOff()) {
                null
            } else {
                // 文件名固定（默认 pusher），扩展名按实际封装修正；同名直接覆盖
                val target = RecordPath.prepare(this, etFilePath.text.toString(), recordExt)
                if (target == null) {
                    AppLog.log("本地录制: 目标文件准备失败，本次不录")
                    null
                } else {
                    AppLog.log("本地录制: 容器=$recordExt，文件=${target.displayPath}（同名覆盖）")
                    LocalRecorder(this, target) { info ->
                        runOnUiThread {
                            Toast.makeText(this, "录制已保存: $info", Toast.LENGTH_LONG).show()
                        }
                    }.takeIf { it.open() }
                }
            }
            // 没录（关闭/准备失败/打开失败）时也明确告诉 native 一次，
            // 免得上一次会话的 fd 残留、把这次的字节写进旧文件
            if (localRecorder == null) JniWrapper.nativeStartRecord(-1)

            controller.startPush(
                url, protocol, format, videoCodec, videoBitrate * 1000, encodeWidth, encodeHeight,
                audioCodec, audioBitrate * 1000,
                if (audioEnabled) audioSamplerate else 0,
                if (audioEnabled) channelCount else 0,
                videoFps,
                resolveMicDevice(micPosition),
                localRecorder,
                subtitleText
            ) { inputSurface, errorMsg ->
                if (generation != sessionGeneration || isFinishing || isDestroyed) {
                    Log.w("MainActivity", "session $generation is stale (current=$sessionGeneration), abort camera start")
                    controller.stopPush()
                    return@startPush
                }

                Log.d("MainActivity", "initPush ready, surface=$inputSurface, err=$errorMsg")
                AppLog.log("会话就绪: surface=${inputSurface != null} msg=$errorMsg")
                pushState = PushState.STREAMING
                updateToggleButton()

                // 无论推流是否成功，都启动相机（编码器已经初始化）；
                // 视频关闭时根本没有 helper，也就没有相机
                val h = helper
                if (h != null) {
                    h.startPreview(texturePreview, inputSurface) { cameraSuccess ->
                        Log.d("MainActivity", "Camera start result: $cameraSuccess")
                        AppLog.log("相机启动: $cameraSuccess")
                        if (cameraSuccess) {
                            Toast.makeText(this, "推流已启动", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this, "相机启动失败", Toast.LENGTH_SHORT).show()
                        }
                    }
                } else {
                    Log.d("MainActivity", "Video disabled, camera not started")
                    AppLog.log("视频已关闭：未启动相机（只推音频）")
                    Toast.makeText(this, "推流已启动（仅音频）", Toast.LENGTH_SHORT).show()
                }
            }
        }

        // 视频关闭时直接以 0x0 走启动流程（不经过相机尺寸查询）
        if (helper != null) {
            helper.getPreviewSize(startWithSizes)
        } else {
            startWithSizes(0, 0)
        }
    }

    private fun stopPushing() {
        Log.d("MainActivity", "stopPushing called")
        AppLog.log("停止推流")

        if (pushState != PushState.STOPPING) {
            pushState = PushState.STOPPING
            updateToggleButton()
        }

        // 代次 +1：让还没回来的启动回调失效（避免在已停止的会话上启动相机）
        sessionGeneration++

        // 先停相机（生产者），再停推流控制器。
        // 旧顺序是先停编码器再停相机，相机在中间还会往已释放的编码 Surface 送帧。
        cameraHelper?.stopPreview()
        cameraHelper = null

        // stopPush 只做状态切换，耗时的拆除在后台线程完成，不阻塞 UI 线程
        val controller = pusherController
        pusherController = null
        if (controller != null) {
            controller.stopPush {
                // 后台拆除完成
                pushState = PushState.STOPPED
                updateToggleButton()
                AppLog.log("推流已完全停止")
            }
        } else {
            pushState = PushState.STOPPED
            updateToggleButton()
        }

        // 波形聚合器属于这一次会话，停流后丢弃
        waveAggregator = null

        // 通知栏的“停止推流”按钮不再有效，并把前台服务停掉
        // （否则"推流中"那条常驻通知会一直留着，CPU/WiFi 唤醒锁也不会释放）
        PushService.onStopRequested = null
        PushService.stop(this)

        // 模块恢复“未启用”外观
        setModulesEnabled(false)

        Toast.makeText(this, "推流已停止", Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        Log.d("MainActivity", "onDestroy called")
        AppLog.log("Activity onDestroy (isFinishing=$isFinishing)")
        isActivityRunning = false
        // 注销日志接收器，避免持有已销毁的 Activity
        AppLog.setSink(null)
        // 只有真正退出（返回键 / finish）才停止推流；
        // 锁屏、回 home、旋转（已用 configChanges 处理）都不会走到“销毁”这一步。
        if (isFinishing) {
            stopPushing()
            PushService.stop(this)
        }
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        isActivityRunning = true
        AppLog.log("前台 onResume")
    }

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        // 声明了 configChanges 后旋转不会重建 Activity，需要手动跟进：
        //  - 卡片 80% 尺寸
        //  - 预览方向：相机预览的旋转是配置会话时烤进 Surface 的，必须重建会话
        AppLog.log("屏幕方向变化: ${newConfig.orientation}")
        applyCardSize()
        applyPanelSize()
        texturePreview.post { cameraHelper?.onDisplayRotationChanged() }
    }

    override fun onPause() {
        Log.d("MainActivity", "onPause called")
        AppLog.log("后台 onPause（推流继续）")
        // 注意：这里不再停止推流。锁屏 / 回 home 时继续推流（前台服务保持运行），
        // 只有点右下角按钮、点通知里的“停止推流”或退出应用才会结束。
        // 界面不可见，回调不再投递到 UI。
        isActivityRunning = false
        super.onPause()
    }

    /**
     * 解析分辨率下拉框（形如 "1280x720"）。
     */
    private fun parseResolution(text: String): Pair<Int, Int> {
        val parts = text.split("x", "X")
        val w = parts.getOrNull(0)?.trim()?.toIntOrNull()
        val h = parts.getOrNull(1)?.trim()?.toIntOrNull()
        return if (w != null && h != null && w > 0 && h > 0) Pair(w, h) else DEFAULT_RESOLUTION
    }

    /**
     * 按麦克风下拉框选择输入设备：0=内置, 1=外接, 2=默认（返回 null 交给系统）。
     */
    private fun resolveMicDevice(position: Int): AudioDeviceInfo? {
        // 0=默认设备（交给系统选）3=关闭（不会走到这里，音频整条链路都跳过了）
        if (position == 0 || position == MIC_INDEX_OFF) return null
        return try {
            val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
            val inputs = am.getDevices(AudioManager.GET_DEVICES_INPUTS)
            val picked = when (position) {
                1 -> inputs.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_MIC }
                2 -> inputs.firstOrNull {
                    it.type == AudioDeviceInfo.TYPE_WIRED_HEADSET ||
                            it.type == AudioDeviceInfo.TYPE_USB_DEVICE ||
                            it.type == AudioDeviceInfo.TYPE_USB_HEADSET ||
                            it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO
                }
                else -> null
            }
            Log.d("MainActivity", "mic device: position=$position picked=${picked?.type} inputs=${inputs.map { it.type }}")
            picked
        } catch (t: Throwable) {
            Log.w("MainActivity", "resolveMicDevice failed", t)
            null
        }
    }

    companion object {
        private const val PERMISSION_REQUEST_CODE = 100
        private const val NOTIFICATION_PERMISSION_REQUEST_CODE = 101
        private const val STORAGE_PERMISSION_REQUEST_CODE = 102

        /** 摄像头/麦克风下拉里"关闭"的位置（索引 3）；选它表示这一路不推 */
        private const val CAMERA_INDEX_OFF = 3
        private const val MIC_INDEX_OFF = 3

        /** 展开/收起动画时长（ms） */
        private const val EXPAND_MS = 380L
        private const val COLLAPSE_MS = 300L

        /** 本地录制：0=开启 1=关闭；默认目录 */
        private const val RECORD_INDEX_ON = 0
        private const val RECORD_INDEX_OFF = 1
        private const val DEFAULT_RECORD_PATH = RecordPath.DEFAULT_FILE

        /** 封装下拉：0=flv 1=fMP4 2=mpegts（默认 flv） */
        private const val FORMAT_INDEX_FLV = 0
        private const val FORMAT_INDEX_FMP4 = 1

        /** 字幕来源下拉：0=固定文字 1=ASR 2=关闭 */
        private const val SUBTITLE_INDEX_FIXED = 0
        private const val SUBTITLE_INDEX_OFF = 2
        private const val DEFAULT_RESOLUTION_TEXT = "1920x1080"
        private val DEFAULT_RESOLUTION = Pair(1920, 1080)
        private val EMPTY_BYTES = ByteArray(0)

        // 首页模块按钮配色
        private val COLOR_BUTTON_DEFAULT = 0xFF546E7A.toInt()   // 默认（未开始）
        private val COLOR_BUTTON_OK = 0xFF43A047.toInt()        // 该环节正常 = 绿
        private val COLOR_BUTTON_FAILED = 0xFFE53935.toInt()    // 该环节失败 = 红
        private val COLOR_BUTTON_DISABLED = 0xFF9E9E9E.toInt()  // 该路被关闭 = 灰
    }
}