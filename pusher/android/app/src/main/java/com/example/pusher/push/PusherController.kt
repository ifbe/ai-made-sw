package com.example.pusher.push

import android.media.MediaFormat
import android.util.Log
import android.view.Surface
import com.example.pusher.audio.AudioCapture
import com.example.pusher.encoder.*
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class PusherController(
    private val onAvioData: (direction: Int, timestamp: Long, data: ByteArray) -> Unit,
    private val onVideoFrameCallback: (data: ByteArray, timestamp: Long, isKey: Boolean) -> Unit,
    private val onAudioFrameCallback: (data: ByteArray, timestamp: Long) -> Unit,
    private val onMuxData: (data: ByteArray, timestamp: Long) -> Unit,
    private val onPcmData: ((ByteArray) -> Unit)? = null
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
            if (i + 4 > data.size) break
            val length = ((data[i].toInt() and 0xFF) shl 24) or
                    ((data[i+1].toInt() and 0xFF) shl 16) or
                    ((data[i+2].toInt() and 0xFF) shl 8) or
                    (data[i+3].toInt() and 0xFF)
            i += 4

            if (i + length > data.size) break

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

        var ffmpegErrorMsg = ""

        // Step 1: 初始化 FFmpeg（尝试连接，失败不影响编码器）
        Log.d(tag, "Step 1: Calling JniWrapper.initPusher...")
        try {
            val initResult = JniWrapper.initPusher(url, protocol, format, videoWidth, videoHeight, sampleRate, channelCount)
            if (initResult == null) {
                Log.e(tag, "JniWrapper.initPusher returned null")
                ffmpegErrorMsg = "JNI initPusher 返回 null"
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
                                Log.d(tag, "AVIO send: size=${data.size}, ts=$timestamp")
                                onAvioData(0, timestamp, data)
                            }
                            override fun onRecvData(data: ByteArray, timestamp: Long) {
                                Log.d(tag, "AVIO recv: size=${data.size}, ts=$timestamp")
                                onAvioData(1, timestamp, data)
                            }
                        })
                        isStreamingEnabled = true
                        Log.d(tag, "Step 2: AVIO callback set SUCCESS, streaming enabled")
                    } catch (e: Exception) {
                        Log.e(tag, "setAvioCallback failed", e)
                        ffmpegErrorMsg = "设置 AVIO 回调失败: ${e.message}"
                    }
                } else {
                    ffmpegErrorMsg = errorMsg
                    Log.e(tag, "FFmpeg init failed: $errorMsg")
                }
            }
        } catch (e: Exception) {
            Log.e(tag, "JNI initPusher exception", e)
            ffmpegErrorMsg = "JNI 异常: ${e.message}"
        }

        // Step 3: 创建视频编码器（无论推流是否成功）
        Log.d(tag, "Step 3: Creating video encoder...")
        var inputSurface: Surface? = null
        try {
            val videoMime = if (videoCodec == "H.264") MediaFormat.MIMETYPE_VIDEO_AVC else MediaFormat.MIMETYPE_VIDEO_HEVC
            videoEncoder = VideoEncoder(videoWidth, videoHeight, videoBitrate, fps, videoMime)

            inputSurface = videoEncoder?.prepare(object : EncoderCallback {
                override fun onVideoFrame(data: ByteArray, timestamp: Long, isKeyFrame: Boolean) {
                    Log.d(tag, "Video encoder output: size=${data.size}, pts=$timestamp, key=$isKeyFrame")

                    // 所有帧都转换为 Annex-B
                    val annexBData = convertToAnnexB(data)

                    // 预览回调
                    onVideoFrameCallback(data, timestamp, isKeyFrame)

                    // 如果推流已启用，写入 JNI
                    if (isStreamingEnabled) {
                        executor.execute {
                            try {
                                val result = JniWrapper.writeVideoFrame(annexBData, timestamp, isKeyFrame)
                                if (!result) {
                                    Log.e(tag, "writeVideoFrame FAILED: size=${annexBData.size}, pts=$timestamp, key=$isKeyFrame")
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
                    Log.d(tag, "Audio encoder output: size=${data.size}, pts=$timestamp")

                    // 预览回调
                    onAudioFrameCallback(data, timestamp)

                    // 如果推流已启用，写入 JNI
                    if (isStreamingEnabled) {
                        executor.execute {
                            try {
                                val result = JniWrapper.writeAudioFrame(data, timestamp)
                                if (!result) {
                                    Log.e(tag, "writeAudioFrame FAILED: size=${data.size}, pts=$timestamp")
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
                val pts = (pcmData.size / bytesPerSample / channelCount) * 1000000L / sampleRate
                Log.d(tag, "Audio capture: size=${pcmData.size}, pts=$pts")

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
        isPushing.set(false)
        try {
            audioCapture?.stop()
            audioEncoder?.stop()
            videoEncoder?.stop()
            if (isStreamingEnabled) {
                JniWrapper.closePusher()
            }
            Log.d(tag, "stopPush completed")
        } catch (e: Exception) {
            Log.e(tag, "stopPush error", e)
        }
        executor.shutdown()
    }
}