package com.example.pusher.push

import android.media.AudioDeviceInfo
import android.media.MediaFormat
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.Surface
import com.example.pusher.audio.AudioCapture
import com.example.pusher.encoder.*
import com.example.pusher.utils.AppLog
import java.io.ByteArrayOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class PusherController(
    private val onAvioData: (direction: Int, timestamp: Long, data: ByteArray, totalSize: Int) -> Unit,
    private val onVideoFrameCallback: (data: ByteArray, timestamp: Long, isKey: Boolean) -> Unit,
    private val onAudioFrameCallback: (data: ByteArray, timestamp: Long) -> Unit,
    private val onMuxData: (data: ByteArray, timestamp: Long) -> Unit,
    private val onPcmData: ((ByteArray) -> Unit)? = null,
    private val onRtmpError: ((String) -> Unit)? = null
) {
    /** 本地录制器：把推出去的字节旁路一份写到本地（可为 null = 不录） */
    private var localRecorder: LocalRecorder? = null

    private var videoEncoder: VideoEncoder? = null
    private var audioEncoder: AudioEncoder? = null
    private var audioCapture: AudioCapture? = null
    private val isPushing = AtomicBoolean(false)

    // 视频写入 + 音频编码
    private var executor: ExecutorService = newSingleThread("PusherEncode")
    // 独立的音频写入线程池，避免网络阻塞影响音频编码
    private var audioWriteExecutor: ExecutorService = newSingleThread("PusherAudioWrite")

    // 推流开关。跨线程读写，必须是 volatile，否则写入线程可能长时间看不到 false，
    // 继续往一个已经 close 的 FFmpeg 上下文里写。
    @Volatile
    private var isStreamingEnabled = false

    // 已经请求停止：init 在后台线程完成时用它判断会话是否已被取消
    @Volatile
    private var stopRequested = false

    // ===== 音视频 PTS 共用同一个时钟（SystemClock.elapsedRealtime）=====
    // sessionT0Ms 是会话起点。两条流都相对它计算 PTS，这样“相机比麦克风晚启动
    // 200ms”这种真实差异会被保留；旧实现让 native 各自归零，把起始差抹掉了。
    private var sessionT0Ms = 0L
    private var videoFirstArrivalMs = -1L
    private var videoFirstRawPtsMs = -1L
    private var audioFirstArrivalMs = -1L
    private var audioFirstRawPtsMs = -1L

    private var capturedSamples = 0L  // 已采集的采样数（累计），用于计算音频 PTS

    // 封装预览回调计数（仅用于前几条打日志确认链路是通的）
    private val muxCallbackCount = java.util.concurrent.atomic.AtomicInteger(0)

    /** 诊断用计数：媒体帧数 + 封装输出字节数（判断"录制为空"是推流没产出还是录制漏了） */
    private val videoPacketCount = java.util.concurrent.atomic.AtomicLong(0)
    private val audioPacketCount = java.util.concurrent.atomic.AtomicLong(0)
    private val avioBytes = java.util.concurrent.atomic.AtomicLong(0)

    // 预览用（仅 UI 显示，与推流时间轴无关）
    private var videoBasePtsUs = -1L
    private var audioBasePtsUs = -1L

    private val tag = "PusherController"

    companion object {
        // 所有会话的 init / close 都在这一个后台线程上串行执行：
        // 1) 不会再把网络连接、MediaCodec 拆除等耗时操作放在主线程（卡顿/ANR 的主要来源）；
        // 2) native 侧的 FFmpeg 全局状态不会被并发 init/close。
        private val sessionExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "PusherSession")
        }
        private val mainHandler = Handler(Looper.getMainLooper())

        private fun newSingleThread(name: String): ExecutorService =
            Executors.newSingleThreadExecutor { r -> Thread(r, name) }
    }

    /**
     * 将 AVCC 格式（长度前缀）转换为 Annex-B 格式（起始码 00 00 00 01）
     */
    private fun convertToAnnexB(data: ByteArray): ByteArray {
        if (data.size >= 4 &&
            data[0] == 0x00.toByte() && data[1] == 0x00.toByte() &&
            data[2] == 0x00.toByte() && data[3] == 0x01.toByte()) {
            // 已经是 Annex-B 格式，直接返回
            return data
        }

        if (data.size >= 3 &&
            data[0] == 0x00.toByte() && data[1] == 0x00.toByte() &&
            data[2] == 0x01.toByte()) {
            return data
        }

        val output = ByteArrayOutputStream()
        var i = 0
        while (i < data.size) {
            // 剩余字节不够 4 字节长度字段，先尝试当成 3 字节起始码处理
            if (i + 4 > data.size) {
                if (i + 3 <= data.size) {
                    // 不足 4 字节当长度 = 剩余全部
                    val length = data.size - i
                    output.write(0x00)
                    output.write(0x00)
                    output.write(0x00)
                    output.write(0x01)
                    output.write(data, i, length)
                }
                break
            }

            val length = ((data[i].toInt() and 0xFF) shl 24) or
                    ((data[i+1].toInt() and 0xFF) shl 16) or
                    ((data[i+2].toInt() and 0xFF) shl 8) or
                    (data[i+3].toInt() and 0xFF)
            i += 4

            if (length <= 0 || i + length > data.size) {
                // NAL 损坏或越界，当成剩余全部
                val remain = data.size - i
                if (remain > 0) {
                    output.write(0x00)
                    output.write(0x00)
                    output.write(0x00)
                    output.write(0x01)
                    output.write(data, i, remain)
                }
                break
            }

            output.write(0x00)
            output.write(0x00)
            output.write(0x00)
            output.write(0x01)
            output.write(data, i, length)
            i += length
        }

        val result = output.toByteArray()
        return if (result.isEmpty()) data else result
    }

    /**
     * 异步启动推流：真正的初始化（FFmpeg 连接/握手、MediaCodec、AudioRecord）
     * 全部在 sessionExecutor 上执行，完成后把 inputSurface 回传到主线程。
     *
     * 旧实现是同步的，导致 avio_open2 / avformat_write_header 这些网络操作
     * 直接阻塞 UI 线程（服务器不可达时界面假死数秒到数十秒）。
     */
    fun startPush(
        url: String,
        protocol: String,
        format: String,
        videoCodec: String,
        videoBitrate: Int,
        videoWidth: Int,
        videoHeight: Int,
        audioCodec: String,
        audioBitrate: Int,
        sampleRate: Int,
        channelCount: Int,
        fps: Int = 30,
        audioDevice: AudioDeviceInfo? = null,
        recorder: LocalRecorder? = null,
        subtitleText: String? = null,
        onReady: (Surface?, String) -> Unit
    ) {
        sessionExecutor.execute {
            val result: Pair<Surface?, String> = try {
                initPush(
                    url, protocol, format, videoCodec, videoBitrate, videoWidth, videoHeight,
                    audioCodec, audioBitrate, sampleRate, channelCount, fps, audioDevice, recorder,
                    subtitleText
                )
            } catch (t: Throwable) {
                Log.e(tag, "initPush threw", t)
                Pair(null, t.message ?: "初始化异常")
            }
            mainHandler.post {
                try {
                    onReady(result.first, result.second)
                } catch (t: Throwable) {
                    Log.e(tag, "onReady callback error", t)
                }
            }
        }
    }

    private fun initPush(
        url: String,
        protocol: String,
        format: String,
        videoCodec: String,
        videoBitrate: Int,
        videoWidth: Int,
        videoHeight: Int,
        audioCodec: String,
        audioBitrate: Int,
        sampleRate: Int,
        channelCount: Int,
        fps: Int,
        audioDevice: AudioDeviceInfo?,
        recorder: LocalRecorder?,
        subtitleText: String?
    ): Pair<Surface?, String> {

        Log.d(tag, "=== initPush START ===")
        Log.d(tag, "URL: $url, Format: $format, Codec: $videoCodec")

        // 哪几路要推：用 0 尺寸/0 采样率表示"这一路关闭"。
        // native 侧同一约定（画面 0x0 就不建视频流、采样率 0 就不建音频流），
        // 所以这里不需要给 JNI 加开关参数。
        val hasVideo = videoWidth > 0 && videoHeight > 0
        val hasAudio = sampleRate > 0 && channelCount > 0
        Log.d(tag, "streams: hasVideo=$hasVideo hasAudio=$hasAudio")
        AppLog.log("本次推流: 视频=${if (hasVideo) "开" else "关"}, 音频=${if (hasAudio) "开" else "关"}")

        val isHevc = (videoCodec == "H.265")

        // 会话时间基准：两条流的 PTS 都相对它计算
        sessionT0Ms = SystemClock.elapsedRealtime()
        videoFirstArrivalMs = -1L
        videoFirstRawPtsMs = -1L
        audioFirstArrivalMs = -1L
        audioFirstRawPtsMs = -1L
        this.isStreamingEnabled = false
        this.stopRequested = false
        this.capturedSamples = 0L
        this.muxCallbackCount.set(0)
        this.videoPacketCount.set(0)
        this.audioPacketCount.set(0)
        this.avioBytes.set(0)
        this.videoBasePtsUs = -1L
        this.audioBasePtsUs = -1L

        // 重建线程池（上一次 stopPush 会关闭它们）
        ensureExecutors()

        // 本地录制：fd 已在 MainActivity 侧注册好（必须在 initPusher 写封装头之前注册），
        // 这里只留引用，推流结束后用来收尾/报告大小；真正的写盘在 native 里做。
        localRecorder = recorder

        var ffmpegErrorMsg = ""

        // Step 0: **必须在 initPusher 之前注册 AVIO 回调**。
        // 封装头（FLV/MP4 的文件头、onMetaData）是 initPusher 里写出去的，
        // 回调注册晚了这些字节到不了 Java → 本地录制出来的文件缺文件头、播放器打不开。
        // 先注册回调：封装头是在 initPusher 里写出去的，注册晚了就录不到文件头
        Log.d(tag, "Step 0: Setting AVIO callback (must be before initPusher)")
        try {
            JniWrapper.setAvioCallback(object : AvioDataListener {
                override fun onSendData(data: ByteArray, timestamp: Long, totalSize: Int) {
                    avioBytes.addAndGet(totalSize.toLong())
                    if (!isPushing.get()) return
                    onAvioData(0, timestamp, data, totalSize)
                }

                override fun onMuxData(data: ByteArray, timestamp: Long) {
                    // 封装预览是纯展示，早期（序列头）也要能看到，所以只挡“已请求停止”
                    if (stopRequested) return
                    val n = muxCallbackCount.getAndIncrement()
                    if (n < 3) {
                        Log.d(tag, "mux packet #$n size=${data.size} ts=$timestamp")
                    }
                    this@PusherController.onMuxData.invoke(data, timestamp)
                }

                override fun onRtmpError(errorMsg: String) {
                    Log.e(tag, "RTMP error: $errorMsg")
                    this@PusherController.onRtmpError?.invoke(errorMsg)
                }
            })
            Log.d(tag, "Step 0: AVIO callback registered")
        } catch (e: Exception) {
            Log.e(tag, "setAvioCallback failed", e)
            ffmpegErrorMsg = "设置 AVIO 回调失败: ${e.message}"
            onRtmpError?.invoke(ffmpegErrorMsg)
        }

        // Step 1: 初始化 FFmpeg（尝试连接，失败不影响编码器）
        Log.d(tag, "Step 1: Calling JniWrapper.initPusher...")
        try {
            val initResult = JniWrapper.initPusher(
                url, protocol, format, videoWidth, videoHeight, sampleRate, channelCount,
                fps, videoBitrate, audioBitrate, if (isHevc) 1 else 0,
                subtitleText != null
            )
            if (initResult == null) {
                Log.e(tag, "JniWrapper.initPusher returned null")
                ffmpegErrorMsg = "JNI initPusher 返回 null"
                onRtmpError?.invoke(ffmpegErrorMsg)
            } else {
                val success = initResult.first
                val errorMsg = initResult.second
                Log.d(tag, "Step 1 result: success=$success, errorMsg=$errorMsg")
                AppLog.log("FFmpeg 初始化: success=$success msg=$errorMsg")
                if (success) {
                    // AVIO 回调已经在 Step 0 注册好了，这里只放行推流
                    isStreamingEnabled = true
                    Log.d(tag, "Step 1 SUCCESS, streaming enabled")
                } else {
                    // native 会把真实原因（打不开地址/写头失败…）放进 lastError
                    val detail = try {
                        JniWrapper.getLastError()
                    } catch (t: Throwable) {
                        ""
                    }
                    ffmpegErrorMsg = if (detail.isNotEmpty()) "$errorMsg: $detail" else errorMsg
                    Log.e(tag, "FFmpeg init failed: $ffmpegErrorMsg")
                    AppLog.log("FFmpeg 初始化失败: $ffmpegErrorMsg")
                    onRtmpError?.invoke(ffmpegErrorMsg)
                }
            }
        } catch (e: Exception) {
            Log.e(tag, "JNI initPusher exception", e)
            ffmpegErrorMsg = "JNI 异常: ${e.message}"
            onRtmpError?.invoke(ffmpegErrorMsg)
        }

        // Step 3: 创建视频编码器（无论推流是否成功；视频关闭时整块跳过）
        var inputSurface: Surface? = null
        if (!hasVideo) {
            Log.d(tag, "Step 3: 视频已关闭，跳过视频编码器")
            AppLog.log("视频已关闭: 跳过视频编码器（本次只推音频）")
        }
        if (hasVideo) try {
            Log.d(tag, "Step 3: Creating video encoder...")
            val videoMime = if (isHevc) MediaFormat.MIMETYPE_VIDEO_HEVC else MediaFormat.MIMETYPE_VIDEO_AVC
            videoEncoder = VideoEncoder(videoWidth, videoHeight, videoBitrate, fps, videoMime)

            inputSurface = videoEncoder?.prepare(object : EncoderCallback {
                override fun onVideoFrame(data: ByteArray, timestamp: Long, isKeyFrame: Boolean) {
                    // 检测 CSD 帧：H.264 是 SPS(7)/PPS(8)，HEVC 是 VPS(32)/SPS(33)/PPS(34)
                    // 起始码 3 字节 / 4 字节都要兼容，否则 CSD 认不出来会导致整条视频没有画面
                    var isCsd = false
                    val nalOffset = when {
                        data.size >= 5 && data[0] == 0x00.toByte() && data[1] == 0x00.toByte() &&
                                data[2] == 0x00.toByte() && data[3] == 0x01.toByte() -> 4
                        data.size >= 4 && data[0] == 0x00.toByte() && data[1] == 0x00.toByte() &&
                                data[2] == 0x01.toByte() -> 3
                        else -> -1
                    }
                    if (nalOffset > 0) {
                        val nalHeader = data[nalOffset].toInt() and 0xFF
                        isCsd = if (isHevc) {
                            ((nalHeader shr 1) and 0x3F) in listOf(32, 33, 34)
                        } else {
                            (nalHeader and 0x1F) in listOf(7, 8)
                        }
                    }

                    // 预览：用系统 uptime 增量，这样预览时间和实际运行时间一致
                    val previewPts = System.currentTimeMillis()
                    if (!isCsd && videoBasePtsUs < 0) {
                        videoBasePtsUs = previewPts
                    }
                    val normalizedPreviewPts = previewPts - videoBasePtsUs

                    // 所有帧都转换为 Annex-B
                    val annexBData = convertToAnnexB(data)

                    // 预览回调（用系统 uptime 归一化的 PTS）
                    onVideoFrameCallback(data, normalizedPreviewPts, isKeyFrame)

                    // 如果推流已启用，写入 JNI
                    if (isStreamingEnabled && isPushing.get() && !stopRequested) {
                        try {
                            executor.execute {
                                try {
                                    if (isStreamingEnabled && isPushing.get() && !stopRequested) {
                                        if (isCsd) {
                                            // CSD 帧：native 用它构造 extradata（avcC / hvcC）
                                            val result = JniWrapper.writeVideoFrame(annexBData, 0L, isKeyFrame, true)
                                            if (!result) {
                                                Log.e(tag, "writeVideoFrame CSD FAILED")
                                            }
                                            return@execute
                                        }
                                        // 该流第一次出现在统一时间轴上的位置
                                        if (videoFirstArrivalMs < 0) {
                                            videoFirstArrivalMs = SystemClock.elapsedRealtime()
                                            videoFirstRawPtsMs = timestamp
                                            Log.d(tag, "video timeline: start=+${videoFirstArrivalMs - sessionT0Ms}ms, rawPts=$timestamp")
                                            AppLog.log("视频时间轴起点: +${videoFirstArrivalMs - sessionT0Ms}ms")
                                        }
                                        // PTS = 该流在会话时间轴上的起点 + 流内增量
                                        val videoPtsMs = (videoFirstArrivalMs - sessionT0Ms) + (timestamp - videoFirstRawPtsMs)
                                        val result = JniWrapper.writeVideoFrame(annexBData, videoPtsMs, isKeyFrame, false)
                                        if (result) videoPacketCount.incrementAndGet()
                                        if (!result) {
                                            Log.e(tag, "writeVideoFrame FAILED: size=${annexBData.size}, pts=$videoPtsMs, key=$isKeyFrame")
                                        }
                                    }
                                } catch (e: Exception) {
                                    Log.e(tag, "writeVideoFrame error", e)
                                }
                            }
                        } catch (e: RejectedExecutionException) {
                            Log.w(tag, "video frame dropped: executor already closed")
                        }
                    }
                }
                override fun onAudioFrame(data: ByteArray, timestamp: Long) {}
            })

            if (inputSurface == null) {
                Log.e(tag, "Video encoder prepare returned null")
                return Pair(null, "视频编码器初始化失败")
            }
            Log.d(tag, "Step 3: Video encoder SUCCESS, inputSurface=$inputSurface")
            AppLog.log("视频编码器就绪: ${videoWidth}x$videoHeight @${fps}fps, ${videoBitrate}bps, $videoCodec")
        } catch (e: Exception) {
            Log.e(tag, "Video encoder failed", e)
            return Pair(null, "视频编码器异常: ${e.message}")
        }

        // Step 4: 创建音频编码器（无论推流是否成功；音频关闭时整块跳过）
        if (!hasAudio) {
            Log.d(tag, "Step 4/5: 音频已关闭，跳过音频编码器与采集")
            AppLog.log("音频已关闭: 跳过音频编码器与采集（本次只推视频）")
        }
        if (hasAudio) try {
            Log.d(tag, "Step 4: Creating audio encoder...")
            val audioMime = if (audioCodec == "AAC") MediaFormat.MIMETYPE_AUDIO_AAC else MediaFormat.MIMETYPE_AUDIO_OPUS
            audioEncoder = AudioEncoder(sampleRate, channelCount, audioBitrate, audioMime)

            val audioPrepared = audioEncoder?.prepare(object : EncoderCallback {
                override fun onVideoFrame(data: ByteArray, timestamp: Long, isKeyFrame: Boolean) {}
                override fun onAudioFrame(data: ByteArray, timestamp: Long) {
                    if (data.isEmpty()) return

                    // 预览：用系统 uptime 增量（毫秒），与视频预览保持同步
                    val previewPts = System.currentTimeMillis()
                    if (audioBasePtsUs < 0) audioBasePtsUs = previewPts
                    val normalizedPreviewPts = previewPts - audioBasePtsUs

                    onAudioFrameCallback(data, normalizedPreviewPts)

                    if (isStreamingEnabled && isPushing.get() && !stopRequested) {
                        try {
                            audioWriteExecutor.execute {
                                try {
                                    if (isStreamingEnabled && isPushing.get() && !stopRequested) {
                                        if (audioFirstArrivalMs < 0) {
                                            audioFirstArrivalMs = SystemClock.elapsedRealtime()
                                            audioFirstRawPtsMs = timestamp
                                            Log.d(tag, "audio timeline: start=+${audioFirstArrivalMs - sessionT0Ms}ms, rawPts=$timestamp")
                                            AppLog.log("音频时间轴起点: +${audioFirstArrivalMs - sessionT0Ms}ms")
                                        }
                                        // 与视频共用同一个会话时间基准
                                        val audioPtsMs = (audioFirstArrivalMs - sessionT0Ms) + (timestamp - audioFirstRawPtsMs)
                                        val result = JniWrapper.writeAudioFrame(data, audioPtsMs)
                                        if (result) audioPacketCount.incrementAndGet()
                                        if (!result) {
                                            Log.e(tag, "writeAudioFrame FAILED: size=${data.size}, pts=$audioPtsMs")
                                        }
                                    }
                                } catch (e: Exception) {
                                    Log.e(tag, "writeAudioFrame error", e)
                                }
                            }
                        } catch (e: RejectedExecutionException) {
                            Log.w(tag, "audio frame dropped: audio write executor already closed")
                        }
                    }
                }
            }) ?: false

            if (!audioPrepared) {
                Log.e(tag, "Audio encoder prepare returned false")
                return Pair(null, "音频编码器初始化失败")
            }
            Log.d(tag, "Step 4: Audio encoder SUCCESS")
            AppLog.log("音频编码器就绪: ${sampleRate}Hz ${channelCount}ch ${audioBitrate}bps $audioCodec")
        } catch (e: Exception) {
            Log.e(tag, "Audio encoder failed", e)
            return Pair(null, "音频编码器异常: ${e.message}")
        }

        // Step 5: 启动音频采集
        if (hasAudio) try {
            Log.d(tag, "Step 5: Starting audio capture...")
            val channelConfig = if (channelCount == 1) android.media.AudioFormat.CHANNEL_IN_MONO else android.media.AudioFormat.CHANNEL_IN_STEREO
            audioCapture = AudioCapture(sampleRate, channelConfig, android.media.AudioFormat.ENCODING_PCM_16BIT, audioDevice)
            audioCapture?.start { pcmData ->
                val bytesPerSample = 2
                val frameSamples = pcmData.size / bytesPerSample / channelCount
                // 用累计采样数算 PTS。旧代码是“帧序号 × 当前块的样本数”，
                // 只要某次 read 长度不同（首尾很常见）就会整体偏移。
                val pts = (capturedSamples * 1_000_000L) / sampleRate
                capturedSamples += frameSamples
                Log.v(tag, "Audio capture: size=${pcmData.size}, frameSamples=$frameSamples, pts=$pts")

                // 传递给波形显示
                try {
                    onPcmData?.invoke(pcmData)
                } catch (t: Throwable) {
                    Log.e(tag, "onPcmData callback error", t)
                }

                try {
                    executor.execute {
                        audioEncoder?.encode(pcmData, pts)
                    }
                } catch (e: RejectedExecutionException) {
                    Log.w(tag, "audio pcm dropped: executor already closed")
                }
            }
            Log.d(tag, "Step 5: Audio capture SUCCESS")
            AppLog.log("音频采集已启动 (mic device=${audioDevice?.type ?: "default"})")
        } catch (e: Exception) {
            Log.e(tag, "Audio capture failed", e)
            return Pair(null, "音频采集失败: ${e.message}")
        }

        // 初始化期间已经被要求停止：不要进入 pushing 状态，后面排队的 teardown 会清理资源
        if (stopRequested) {
            Log.w(tag, "initPush finished after stop was requested, session cancelled")
            AppLog.log("会话在初始化期间被取消")
            return Pair(null, "会话已取消")
        }

        // 字幕：只把文本交给 native；真正的样本在视频关键帧处写（和分片边界对齐，
        // 否则 fMP4 稀疏文本轨会触发 movenc 的 av_assert0 崩溃）
        if (subtitleText != null) {
            try {
                JniWrapper.setSubtitleText(subtitleText)
                AppLog.log("字幕已交给 native: 「$subtitleText」（随视频关键帧写入，仅 fMP4/mp4 有效）")
            } catch (t: Throwable) {
                Log.e(tag, "setSubtitleText failed", t)
            }
        }

        isPushing.set(true)
        Log.d(tag, "=== initPush SUCCESS ===")
        AppLog.log("推流会话已启动")
        return Pair(inputSurface, ffmpegErrorMsg)
    }

    /**
     * 请求停止。只做状态切换（很快），耗时的拆除放到 sessionExecutor 上执行，
     * 避免在 UI 线程做 MediaCodec 拆除 / 网络 trailer / 线程池等待（ANR 来源）。
     *
     * @param onDone 拆除真正完成后（主线程）回调，用于更新界面状态
     */
    fun stopPush(onDone: (() -> Unit)? = null) {
        Log.d(tag, "stopPush called")
        AppLog.log("PusherController: stopPush")
        stopRequested = true
        isPushing.set(false)
        isStreamingEnabled = false
        sessionExecutor.execute {
            teardownInternal()
            if (onDone != null) {
                mainHandler.post {
                    try {
                        onDone()
                    } catch (t: Throwable) {
                        Log.e(tag, "stopPush onDone error", t)
                    }
                }
            }
        }
    }

    /**
     * 仅关闭 RTMP 连接，保留编码器和相机继续运行
     */
    fun stopRtmpOnly() {
        Log.d(tag, "stopRtmpOnly called")
        stopRequested = true
        isStreamingEnabled = false
        // closePusher 可能阻塞在网络 trailer 上，放到会话线程执行；
        // native 侧还会等待正在进行中的写入退出，所以这里不会和写入打架。
        sessionExecutor.execute {
            try {
                JniWrapper.closePusher()
            } catch (e: Exception) {
                Log.e(tag, "closePusher error", e)
            }
        }
        Log.d(tag, "stopRtmpOnly completed, encoders still running")
    }

    /**
     * 真正释放资源。只在 sessionExecutor 上执行。
     *
     * 顺序很重要：
     *   1. 停生产者（麦克风）→ 不再有新数据
     *   2. 停视频编码器 → 不再有新帧提交（它会排空自己的输出线程）
     *   3. 排空 encode 线程池 → 不再有 encode()/writeVideoFrame() 在跑
     *   4. 停音频编码器 → 此时它独占 codec，不会和 encode() 并发访问输入 buffer
     *   5. 排空音频写入线程池
     *   6. 最后才 closePusher（native 侧还会等所有写者退出）
     * 旧实现是先 closePusher 再停编码器/相机，导致：
     *   - 写入线程往已释放的 AVFormatContext 里写（UAF）
     *   - 相机还在往已释放的编码 Surface 送帧
     */
    private fun teardownInternal() {
        Log.d(tag, "teardownInternal start")
        AppLog.log("开始释放会话资源")
        isPushing.set(false)
        isStreamingEnabled = false

        // 1. 停音频采集（生产者）
        try {
            audioCapture?.stop()
        } catch (e: Exception) {
            Log.e(tag, "stop audio capture error", e)
        }
        audioCapture = null

        // 2. 停视频编码器（它会排空自己的输出线程，之后不会再有新帧提交）
        try {
            videoEncoder?.stop()
        } catch (e: Exception) {
            Log.e(tag, "stop video encoder error", e)
        }
        videoEncoder = null

        // 3. 排空编码/写入线程池。
        //    必须在 audioEncoder.stop() 之前：encode() 跑在这个线程池上，
        //    它和 stop() 都会访问 MediaCodec 的输入 buffer，两个线程并发是未定义行为。
        shutdownExecutor(executor, "encode")

        // 4. 停音频编码器（此时它是唯一还在碰这个 codec 的线程）
        try {
            audioEncoder?.stop()
        } catch (e: Exception) {
            Log.e(tag, "stop audio encoder error", e)
        }
        audioEncoder = null

        // 5. 排空音频写入线程池（保证没有线程还在写 FFmpeg）
        shutdownExecutor(audioWriteExecutor, "audio write")

        // 6. 关闭 FFmpeg（native 侧还有写者保护作为第二道防线）
        try {
            JniWrapper.closePusher()
        } catch (e: Exception) {
            Log.e(tag, "closePusher error", e)
        }

        // 7. 收尾本地录制（放在 closePusher 之后：结尾的 trailer 字节也已经写进 fd 了）
        try {
            val recorded = JniWrapper.nativeStopRecord()
            localRecorder?.finish(recorded)
        } catch (e: Exception) {
            Log.e(tag, "stop recorder error", e)
        }
        localRecorder = null

        // 8. 复位状态
        capturedSamples = 0L
        videoBasePtsUs = -1L
        audioBasePtsUs = -1L
        videoFirstArrivalMs = -1L
        videoFirstRawPtsMs = -1L
        audioFirstArrivalMs = -1L
        audioFirstRawPtsMs = -1L

        AppLog.log(
            "本次会话统计: 视频帧=${videoPacketCount.get()} 音频帧=${audioPacketCount.get()} " +
                    "封装输出=${avioBytes.get() / 1024} KB"
        )
        Log.d(tag, "teardownInternal completed")
        AppLog.log("会话资源已释放")
    }

    private fun ensureExecutors() {
        if (executor.isShutdown || executor.isTerminated) {
            executor = newSingleThread("PusherEncode")
        }
        if (audioWriteExecutor.isShutdown || audioWriteExecutor.isTerminated) {
            audioWriteExecutor = newSingleThread("PusherAudioWrite")
        }
    }

    private fun shutdownExecutor(target: ExecutorService, name: String) {
        try {
            target.shutdown()
            if (!target.awaitTermination(1000, TimeUnit.MILLISECONDS)) {
                Log.w(tag, "$name executor did not terminate in time, forcing shutdown")
                target.shutdownNow()
            }
        } catch (e: InterruptedException) {
            target.shutdownNow()
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            Log.e(tag, "$name executor shutdown error", e)
            target.shutdownNow()
        }
    }
}
