package com.example.pusher.encoder

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.util.Log
import android.view.Surface
import java.util.concurrent.Executors

class VideoEncoder(
    private val width: Int,
    private val height: Int,
    private val bitrate: Int,
    private val frameRate: Int,
    private val codecMime: String = MediaFormat.MIMETYPE_VIDEO_AVC
) {
    private var mediaCodec: MediaCodec? = null
    private var inputSurface: Surface? = null
    private var callback: EncoderCallback? = null
    private var isEncoding = false
    private val executor = Executors.newSingleThreadExecutor()

    private fun bytesToHex(bytes: ByteArray, maxLen: Int = 32): String {
        val len = bytes.size.coerceAtMost(maxLen)
        return (0 until len).joinToString(" ") { "%02x".format(bytes[it]) }
    }

    fun prepare(callback: EncoderCallback): Surface? {
        Log.d("VideoEncoder", "prepare: ${width}x${height}, bitrate=$bitrate, fps=$frameRate, mime=$codecMime")
        this.callback = callback

        val format = MediaFormat.createVideoFormat(codecMime, width, height).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, bitrate)
            setInteger(MediaFormat.KEY_FRAME_RATE, frameRate)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 1)
            setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            // 添加编码器参数
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                setInteger(MediaFormat.KEY_LATENCY, 1)  // 低延迟模式
                setInteger(MediaFormat.KEY_PRIORITY, 0) // 实时优先级
            }
        }

        try {
            mediaCodec = MediaCodec.createEncoderByType(codecMime)
            Log.d("VideoEncoder", "MediaCodec created")

            mediaCodec?.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            inputSurface = mediaCodec?.createInputSurface()

            mediaCodec?.setCallback(object : MediaCodec.Callback() {
                override fun onInputBufferAvailable(codec: MediaCodec, index: Int) {}

                override fun onOutputBufferAvailable(codec: MediaCodec, index: Int, info: MediaCodec.BufferInfo) {
                    // 检查是否是 CSD 数据 (SPS/PPS)
                    if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                        val buffer = codec.getOutputBuffer(index) ?: return
                        val csdData = ByteArray(info.size)
                        buffer.get(csdData, 0, info.size)
                        Log.d("VideoEncoder", "CSD data received, size=${csdData.size}, hex=${bytesToHex(csdData)}")
                        callback.onVideoFrame(csdData, 0, true)
                        codec.releaseOutputBuffer(index, false)
                        return
                    }

                    // 普通视频帧
                    val buffer = codec.getOutputBuffer(index) ?: return
                    val data = ByteArray(info.size)
                    buffer.get(data, 0, info.size)
                    val isKey = (info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME) != 0
                    if (isKey) {
                        Log.d("VideoEncoder", "Key frame, size=${data.size}, hex=${bytesToHex(data)}")
                    }
                    callback.onVideoFrame(data, info.presentationTimeUs / 1000, isKey)
                    codec.releaseOutputBuffer(index, false)
                }

                override fun onOutputFormatChanged(codec: MediaCodec, format: MediaFormat) {
                    Log.d("VideoEncoder", "Output format changed")
                    // 从 MediaFormat 获取 SPS/PPS
                    val csd0 = format.getByteBuffer("csd-0")
                    val csd1 = format.getByteBuffer("csd-1")

                    if (csd0 != null && csd0.remaining() > 0) {
                        val sps = ByteArray(csd0.remaining())
                        csd0.get(sps)
                        Log.d("VideoEncoder", "SPS from format, size=${sps.size}, hex=${bytesToHex(sps)}")
                        callback.onVideoFrame(sps, 0, true)
                    }
                    if (csd1 != null && csd1.remaining() > 0) {
                        val pps = ByteArray(csd1.remaining())
                        csd1.get(pps)
                        Log.d("VideoEncoder", "PPS from format, size=${pps.size}, hex=${bytesToHex(pps)}")
                        callback.onVideoFrame(pps, 0, true)
                    }
                }

                override fun onError(codec: MediaCodec, e: MediaCodec.CodecException) {
                    Log.e("VideoEncoder", "Error", e)
                }
            })

            mediaCodec?.start()
            isEncoding = true
            Log.d("VideoEncoder", "prepare SUCCESS")
            return inputSurface

        } catch (e: Exception) {
            Log.e("VideoEncoder", "prepare FAILED", e)
            return null
        }
    }

    fun stop() {
        isEncoding = false
        try {
            mediaCodec?.stop()
            mediaCodec?.release()
            inputSurface?.release()
        } catch (e: Exception) {
            Log.e("VideoEncoder", "stop error", e)
        }
        mediaCodec = null
        inputSurface = null
        executor.shutdown()
    }
}