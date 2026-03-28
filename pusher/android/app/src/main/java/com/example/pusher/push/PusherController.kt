package com.example.pusher.push

import android.media.MediaFormat
import android.util.Log
import android.view.Surface
import com.example.pusher.audio.AudioCapture
import com.example.pusher.encoder.*
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit

class PusherController(
    private val onAvioData: (direction: Int, timestamp: Long, data: ByteArray) -> Unit,
    private val onVideoFrameCallback: (data: ByteArray, timestamp: Long, isKey: Boolean) -> Unit,
    private val onAudioFrameCallback: (data: ByteArray, timestamp: Long) -> Unit,
    private val onMuxData: (data: ByteArray, timestamp: Long) -> Unit,
    private val onPcmData: ((ByteArray) -> Unit)? = null,
    private val onRtmpError: ((String) -> Unit)? = null
) {
    private var videoEncoder: VideoEncoder? = null
    private var audioEncoder: AudioEncoder? = null
    private var audioCapture: AudioCapture? = null
    private var isPushing = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor()

    private var videoWidth = 0
    private var videoHeight = 0
    private var videoFps = 30
    private var sampleRate = 44100
    private var channelCount = 2
    private var extradataSet = false
    private var isStreamingEnabled = false  // 推流开关
    private var audioFrameCount = 0L  // 音频帧计数，用于计算 PTS
    private var videoBasePtsUs = -1L   // 视频首帧 PTS 基线（来自 camera uptime）
    private var audioBasePtsUs = -1L   // 音频首帧 PTS 基线（来自 audio encoder）

    // 视频基准 PTS（微秒）：第一个非 CSD 视频帧设定
    // CSD 帧的 PTS=0 不用来设定基准，这样 CSD 会相对于 I-frame 有负的 PTS
    private var videoAnchorPtsUs = -1L
    // 音频首个帧的 PTS（微秒）
    private var audioStartPtsUs = -1L

    private val tag = "PusherController"

    /**
     * 将 AVCC 格式（长度前缀）转换为 Annex-B 格式（起始码 00 00 00 01）
     */
    private fun convertToAnnexB(data: ByteArray): ByteArray {
        if (data.size >= 4 &&
            data[0] == 0x00.toByte() && data[1] == 0x00.toByte() &&
            data[2] == 0x00.toByte() && data[3] == 0x01.toByte()) {
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

    fun initPush(
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
        fps: Int = 30
    ): Pair<Surface?, String> {

        Log.d(tag, "=== initPush START ===")
        Log.d(tag, "URL: $url, Format: $format")

        this.videoWidth = videoWidth
        this.videoHeight = videoHeight
        this.videoFps = fps
        this.sampleRate = sampleRate
        this.channelCount = channelCount
        this.extradataSet = false
        this.isStreamingEnabled = false
        this.audioFrameCount = 0L
        this.videoBasePtsUs = -1L
        this.audioBasePtsUs = -1L
        this.videoAnchorPtsUs = -1L
        this.audioStartPtsUs = -1L

        var ffmpegErrorMsg = ""

        // Step 1: 初始化 FFmpeg（尝试连接，失败不影响编码器）
        Log.d(tag, "Step 1: Calling JniWrapper.initPusher...")
        try {
            val initResult = JniWrapper.initPusher(url, protocol, format, videoWidth, videoHeight, sampleRate, channelCount)
            if (initResult == null) {
                Log.e(tag, "JniWrapper.initPusher returned null")
                ffmpegErrorMsg = "JNI initPusher 返回 null"
                onRtmpError?.invoke(ffmpegErrorMsg)
            } else {
                val success = initResult.component1() as Boolean
                val errorMsg = initResult.component2() as String
                Log.d(tag, "Step 1 result: success=$success, errorMsg=$errorMsg")
                if (success) {
                    // Step 2: 设置 AVIO 回调
                    Log.d(tag, "Step 2: Setting AVIO callback...")
                    try {
                        JniWrapper.setAvioCallback(object : AvioDataListener {
                            override fun onSendData(data: ByteArray, timestamp: Long) {
                                if (!isPushing.get()) return  // 添加检查
                                Log.d(tag, "AVIO send: size=${data.size}, ts=$timestamp")
                                onAvioData(0, timestamp, data)
                            }
                            override fun onRecvData(data: ByteArray, timestamp: Long) {
                                if (!isPushing.get()) return  // 添加检查
                                Log.d(tag, "AVIO recv: size=${data.size}, ts=$timestamp")
                                onAvioData(1, timestamp, data)
                            }
                        })
                        isStreamingEnabled = true
                        Log.d(tag, "Step 2: AVIO callback set SUCCESS, streaming enabled")
                    } catch (e: Exception) {
                        Log.e(tag, "setAvioCallback failed", e)
                        ffmpegErrorMsg = "设置 AVIO 回调失败: ${e.message}"
                        onRtmpError?.invoke(ffmpegErrorMsg)
                    }
                } else {
                    ffmpegErrorMsg = errorMsg
                    Log.e(tag, "FFmpeg init failed: $errorMsg")
                    onRtmpError?.invoke(ffmpegErrorMsg)
                }
            }
        } catch (e: Exception) {
            Log.e(tag, "JNI initPusher exception", e)
            ffmpegErrorMsg = "JNI 异常: ${e.message}"
            onRtmpError?.invoke(ffmpegErrorMsg)
        }

        // Step 3: 创建视频编码器（无论推流是否成功）
        Log.d(tag, "Step 3: Creating video encoder...")
        var inputSurface: Surface? = null
        try {
            val videoMime = if (videoCodec == "H.264") MediaFormat.MIMETYPE_VIDEO_AVC else MediaFormat.MIMETYPE_VIDEO_HEVC
            videoEncoder = VideoEncoder(videoWidth, videoHeight, videoBitrate, fps, videoMime)

            inputSurface = videoEncoder?.prepare(object : EncoderCallback {
                override fun onVideoFrame(data: ByteArray, timestamp: Long, isKeyFrame: Boolean) {
                    // 检测 CSD 帧（SPS=0x67, PPS=0x68）
                    val isCsd = data.size >= 5 && data[0] == 0x00.toByte() && data[1] == 0x00.toByte()
                            && data[2] == 0x00.toByte() && data[3] == 0x01.toByte()
                            && (data[4].toInt() and 0x1F) in listOf(7, 8)  // SPS or PPS

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
                    if (isStreamingEnabled && isPushing.get()) {
                        executor.execute {
                            try {
                                // 双重检查：isStreamingEnabled 和 isPushing 都为 true 时才调用
                                if (isStreamingEnabled && isPushing.get()) {
                                    // CSD 帧 PTS=0（Native 层会作为 extradata 处理）
                                    if (isCsd) {
                                        val result = JniWrapper.writeVideoFrame(annexBData, 0, isKeyFrame)
                                        if (!result) {
                                            Log.e(tag, "writeVideoFrame CSD FAILED")
                                        }
                                        return@execute
                                    }
                                    // 第一个视频帧（非 CSD）设定 PTS 基准
                                    // CSD 帧 rawTsMs=0 不用来设定 anchor
                                    // timestamp 已经是毫秒（来自 info.presentationTimeUs / 1000）
                                    val isCSD = (rawTsMs == 0L)
                                    if (!isCSD && videoAnchorPtsUs < 0) {
                                        videoAnchorPtsUs = timestamp
                                        Log.d(tag, "Video anchor set: rawTs=${timestamp}ms, anchorMs=$videoAnchorPtsUs")
                                    }
                                    // 视频帧 PTS = (现在 PTS - 基准 PTS)，归一化到第一个视频帧为 0
                                    val videoPtsUs = timestamp - videoAnchorPtsUs  // 毫秒，传入 native 后 *1000 转微秒
                                    Log.d(tag, "writeVideoFrame: rawTsMs=${timestamp}, ptsMs=$videoPtsUs")
                                    val result = JniWrapper.writeVideoFrame(annexBData, videoPtsUs, isKeyFrame)
                                    if (!result) {
                                        Log.e(tag, "writeVideoFrame FAILED: size=${annexBData.size}, pts=$videoPtsUs, key=$isKeyFrame")
                                    }
                                }
                            } catch (e: Exception) {
                                Log.e(tag, "writeVideoFrame error", e)
                            }
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
        } catch (e: Exception) {
            Log.e(tag, "Video encoder failed", e)
            return Pair(null, "视频编码器异常: ${e.message}")
        }

        // Step 4: 创建音频编码器（无论推流是否成功）
        Log.d(tag, "Step 4: Creating audio encoder...")
        try {
            val audioMime = if (audioCodec == "AAC") MediaFormat.MIMETYPE_AUDIO_AAC else MediaFormat.MIMETYPE_AUDIO_OPUS
            audioEncoder = AudioEncoder(sampleRate, channelCount, audioBitrate, audioMime)

            val audioPrepared = audioEncoder?.prepare(object : EncoderCallback {
                override fun onVideoFrame(data: ByteArray, timestamp: Long, isKeyFrame: Boolean) {}
                override fun onAudioFrame(data: ByteArray, timestamp: Long) {
                    if (data.isEmpty()) {
                        Log.d(tag, "Audio encoder output: empty frame, skipping")
                        return
                    }

                    // 预览：用系统 uptime 增量（毫秒），与视频预览保持同步
                    val previewPts = System.currentTimeMillis()
                    if (audioBasePtsUs < 0) audioBasePtsUs = previewPts
                    val normalizedPreviewPts = previewPts - audioBasePtsUs

                    // 预览回调
                    onAudioFrameCallback(data, normalizedPreviewPts)

                    // 如果推流已启用，写入 JNI
                    if (isStreamingEnabled && isPushing.get()) {
                        executor.execute {
                            try {
                                // 双重检查：isStreamingEnabled 和 isPushing 都为 true 时才调用
                                if (isStreamingEnabled && isPushing.get()) {
                                    // 记录音频开始 PTS（微秒）
                                    if (audioStartPtsUs < 0) {
                                        audioStartPtsUs = timestamp
                                        Log.d(tag, "Audio start recorded: audioTimestampUs=$audioStartPtsUs, videoAnchorMs=$videoAnchorPtsUs")
                                    }
                                    // audioTimestamp (微秒) 和 audioStartPtsUs (微秒) 是微秒，videoAnchorPtsUs 是毫秒
                                    // 正确公式: ((audioTimestamp - audioStartPtsUs) / 1000) - videoAnchorPtsMs
                                    val audioPtsUs = if (videoAnchorPtsUs > 0) {
                                        ((timestamp - audioStartPtsUs) / 1000) - videoAnchorPtsUs
                                    } else {
                                        0L
                                    }
                                    Log.d(tag, "writeAudioFrame: audioTsUs=$timestamp, ptsMs=$audioPtsUs")
                                    val result = JniWrapper.writeAudioFrame(data, audioPtsUs)
                                    if (!result) {
                                        Log.e(tag, "writeAudioFrame FAILED: size=${data.size}, pts=$audioPtsUs")
                                    }
                                }
                            } catch (e: Exception) {
                                Log.e(tag, "writeAudioFrame error", e)
                            }
                        }
                    }
                }
            }) ?: false

            if (!audioPrepared) {
                Log.e(tag, "Audio encoder prepare returned false")
                return Pair(null, "音频编码器初始化失败")
            }
            Log.d(tag, "Step 4: Audio encoder SUCCESS")
        } catch (e: Exception) {
            Log.e(tag, "Audio encoder failed", e)
            return Pair(null, "音频编码器异常: ${e.message}")
        }

        // Step 5: 启动音频采集
        Log.d(tag, "Step 5: Starting audio capture...")
        try {
            val channelConfig = if (channelCount == 1) android.media.AudioFormat.CHANNEL_IN_MONO else android.media.AudioFormat.CHANNEL_IN_STEREO
            audioCapture = AudioCapture(sampleRate, channelConfig, android.media.AudioFormat.ENCODING_PCM_16BIT)
            audioCapture?.start { pcmData ->
                val bytesPerSample = 2
                val frameSamples = pcmData.size / bytesPerSample / channelCount
                val pts = (audioFrameCount * frameSamples * 1_000_000L) / sampleRate
                audioFrameCount++
                Log.d(tag, "Audio capture: size=${pcmData.size}, frameSamples=$frameSamples, pts=$pts")

                // 传递给波形显示
                onPcmData?.invoke(pcmData)

                executor.execute {
                    audioEncoder?.encode(pcmData, pts)
                }
            }
            Log.d(tag, "Step 5: Audio capture SUCCESS")
        } catch (e: Exception) {
            Log.e(tag, "Audio capture failed", e)
            return Pair(null, "音频采集失败: ${e.message}")
        }

        isPushing.set(true)
        Log.d(tag, "=== initPush SUCCESS ===")
        return Pair(inputSurface, ffmpegErrorMsg)
    }

    fun stopPush() {
        Log.d(tag, "stopPush called")

        // 1. 立即设置所有标志，防止新任务提交
        isPushing.set(false)
        isStreamingEnabled = false

        // 2. 关闭 FFmpeg（首要任务，防止 JNI 回调）
        try {
            JniWrapper.closePusher()
        } catch (e: Exception) {
            Log.e(tag, "closePusher error", e)
        }

        // 3. 停止音频采集（阻止新数据进入编码器）
        try {
            audioCapture?.stop()
            audioCapture = null
        } catch (e: Exception) {
            Log.e(tag, "stop audio capture error", e)
        }

        // 4. 停止编码器（等待编码器处理完缓冲数据）
        try {
            videoEncoder?.stop()
            videoEncoder = null
        } catch (e: Exception) {
            Log.e(tag, "stop video encoder error", e)
        }

        try {
            audioEncoder?.stop()
            audioEncoder = null
        } catch (e: Exception) {
            Log.e(tag, "stop audio encoder error", e)
        }

        // 5. 关闭线程池（等待任务完成）
        try {
            executor.shutdown()
            if (!executor.awaitTermination(1000, TimeUnit.MILLISECONDS)) {
                Log.w(tag, "Executor did not terminate in time, forcing shutdown")
                executor.shutdownNow()
            }
        } catch (e: Exception) {
            Log.e(tag, "Executor shutdown error", e)
            executor.shutdownNow()
        }

        // 6. 重置状态变量
        audioFrameCount = 0L
        videoBasePtsUs = -1L
        audioBasePtsUs = -1L
        videoAnchorPtsUs = -1L
        audioStartPtsUs = -1L

        Log.d(tag, "stopPush completed")
    }

    /**
     * 仅关闭 RTMP 连接，保留编码器和相机继续运行
     */
    fun stopRtmpOnly() {
        Log.d(tag, "stopRtmpOnly called")
        isStreamingEnabled = false
        try {
            JniWrapper.closePusher()
        } catch (e: Exception) {
            Log.e(tag, "closePusher error", e)
        }
        Log.d(tag, "stopRtmpOnly completed, encoders still running")
    }
}