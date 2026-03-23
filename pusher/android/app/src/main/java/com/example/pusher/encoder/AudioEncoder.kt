package com.example.pusher.encoder

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AudioEncoder(
    private val sampleRate: Int = 44100,
    private val channelCount: Int = 2,
    private val bitrate: Int = 128000,
    private val codecMime: String = MediaFormat.MIMETYPE_AUDIO_AAC
) {
    private var mediaCodec: MediaCodec? = null
    private var callback: EncoderCallback? = null
    private val isEncoding = AtomicBoolean(false)
    private val executor = Executors.newFixedThreadPool(2)

    private val samplesPerFrame = 1024
    private val bytesPerSample = 2
    private val bytesPerFrame = samplesPerFrame * channelCount * bytesPerSample
    private var pendingBuffer = ByteArray(0)
    private var pendingPts = 0L
    private var isStopping = false

    fun prepare(callback: EncoderCallback): Boolean {
        Log.d("AudioEncoder", "prepare: ${sampleRate}Hz, ${channelCount}ch, bitrate=$bitrate, mime=$codecMime")
        this.callback = callback

        val format = MediaFormat.createAudioFormat(codecMime, sampleRate, channelCount).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, bitrate)
            setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
        }

        try {
            mediaCodec = MediaCodec.createEncoderByType(codecMime)
            mediaCodec?.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            mediaCodec?.start()
            isEncoding.set(true)
            isStopping = false

            executor.submit { processOutput() }

            return true
        } catch (e: Exception) {
            Log.e("AudioEncoder", "prepare FAILED", e)
            return false
        }
    }

    fun encode(pcmData: ByteArray, pts: Long) {
        if (!isEncoding.get() || isStopping) return

        // 累积数据
        val newBuffer = ByteArray(pendingBuffer.size + pcmData.size)
        System.arraycopy(pendingBuffer, 0, newBuffer, 0, pendingBuffer.size)
        System.arraycopy(pcmData, 0, newBuffer, pendingBuffer.size, pcmData.size)
        pendingBuffer = newBuffer
        if (pendingPts == 0L) {
            pendingPts = pts
        }

        // 当数据足够一帧时，立即编码
        while (pendingBuffer.size >= bytesPerFrame && !isStopping) {
            val frameData = ByteArray(bytesPerFrame)
            System.arraycopy(pendingBuffer, 0, frameData, 0, bytesPerFrame)

            val remaining = ByteArray(pendingBuffer.size - bytesPerFrame)
            System.arraycopy(pendingBuffer, bytesPerFrame, remaining, 0, remaining.size)
            pendingBuffer = remaining

            sendToEncoder(frameData, pendingPts)
            pendingPts = 0L
        }
    }

    private fun sendToEncoder(data: ByteArray, pts: Long) {
        if (isStopping) return

        try {
            val index = mediaCodec?.dequeueInputBuffer(10000) ?: -1
            if (index < 0) {
                Log.w("AudioEncoder", "No input buffer available")
                return
            }

            val buffer = mediaCodec?.getInputBuffer(index) ?: return
            buffer.clear()
            buffer.put(data)

            mediaCodec?.queueInputBuffer(index, 0, data.size, pts, 0)
            Log.d("AudioEncoder", "Sent frame: size=${data.size}, pts=$pts")
        } catch (e: Exception) {
            Log.e("AudioEncoder", "sendToEncoder error", e)
        }
    }

    private fun processOutput() {
        val bufferInfo = MediaCodec.BufferInfo()
        while (isEncoding.get() && !isStopping) {
            try {
                val outputIndex = mediaCodec?.dequeueOutputBuffer(bufferInfo, 10000) ?: -1
                when {
                    outputIndex >= 0 -> {
                        val outputBuffer = mediaCodec?.getOutputBuffer(outputIndex) ?: continue
                        val data = ByteArray(bufferInfo.size)
                        outputBuffer.get(data, 0, bufferInfo.size)

                        Log.d("AudioEncoder", "Output frame: size=${data.size}, pts=${bufferInfo.presentationTimeUs}")

                        val ptsMs = bufferInfo.presentationTimeUs / 1000
                        callback?.onAudioFrame(data, ptsMs)

                        mediaCodec?.releaseOutputBuffer(outputIndex, false)
                    }
                    outputIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        Log.d("AudioEncoder", "Output format changed")
                    }
                    outputIndex == MediaCodec.INFO_TRY_AGAIN_LATER -> {
                        Thread.sleep(1)
                    }
                }
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (!isStopping) {
                    Log.e("AudioEncoder", "processOutput error", e)
                }
            }
        }
        Log.d("AudioEncoder", "processOutput stopped")
    }

    fun stop() {
        Log.d("AudioEncoder", "stop called")
        if (!isEncoding.getAndSet(false)) {
            return
        }

        try {
            // 发送 EOS 信号
            val inputIndex = mediaCodec?.dequeueInputBuffer(10000) ?: -1
            if (inputIndex >= 0) {
                mediaCodec?.queueInputBuffer(inputIndex, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
            }

            // 等待一小段时间让编码器完成
            Thread.sleep(50)

            mediaCodec?.stop()
            mediaCodec?.release()
        } catch (e: Exception) {
            Log.e("AudioEncoder", "stop error", e)
        }
        mediaCodec = null
        executor.shutdown()
        Log.d("AudioEncoder", "stop completed")
    }
}