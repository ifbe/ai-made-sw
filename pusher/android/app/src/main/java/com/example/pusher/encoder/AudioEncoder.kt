package com.example.pusher.encoder

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.util.Log
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.Executors

class AudioEncoder(
    private val sampleRate: Int = 44100,
    private val channelCount: Int = 2,
    private val bitrate: Int = 128000,
    private val codecMime: String = MediaFormat.MIMETYPE_AUDIO_AAC
) {
    private var mediaCodec: MediaCodec? = null
    private var callback: EncoderCallback? = null
    private var isEncoding = false
    private val inputQueue = LinkedBlockingQueue<Pair<ByteArray, Long>>()
    private val executor = Executors.newSingleThreadExecutor()
    private var isCallbackRunning = false
    private val callbackLock = Any()

    // 计算每个 AAC 帧需要的 PCM 数据量
    private val samplesPerFrame = 1024
    private val bytesPerSample = 2
    private val bytesPerFrame = samplesPerFrame * channelCount * bytesPerSample
    private var pendingBuffer = ByteArray(0)
    private var pendingPts = 0L

    fun prepare(callback: EncoderCallback): Boolean {
        Log.d("AudioEncoder", "prepare: ${sampleRate}Hz, ${channelCount}ch, bitrate=$bitrate, mime=$codecMime")
        this.callback = callback

        val format = MediaFormat.createAudioFormat(codecMime, sampleRate, channelCount).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, bitrate)
            setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
        }

        try {
            mediaCodec = MediaCodec.createEncoderByType(codecMime)
            Log.d("AudioEncoder", "MediaCodec created: $mediaCodec")

            mediaCodec?.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            mediaCodec?.start()
            isEncoding = true
            Log.d("AudioEncoder", "prepare SUCCESS")

            // 启动输出处理线程
            executor.execute {
                processOutput()
            }

            return true

        } catch (e: Exception) {
            Log.e("AudioEncoder", "prepare FAILED", e)
            return false
        }
    }

    fun encode(pcmData: ByteArray, pts: Long) {
        if (!isEncoding) return
        inputQueue.offer(Pair(pcmData, pts))
        processInput()
    }

    private fun processInput() {
        while (isEncoding) {
            val inputIndex = mediaCodec?.dequeueInputBuffer(10000) ?: -1
            if (inputIndex < 0) {
                break
            }

            val inputBuffer = mediaCodec?.getInputBuffer(inputIndex) ?: break

            // 收集足够的 PCM 数据凑满一帧
            while (pendingBuffer.size < bytesPerFrame) {
                val (data, pts) = inputQueue.poll() ?: break
                val newBuffer = ByteArray(pendingBuffer.size + data.size)
                System.arraycopy(pendingBuffer, 0, newBuffer, 0, pendingBuffer.size)
                System.arraycopy(data, 0, newBuffer, pendingBuffer.size, data.size)
                pendingBuffer = newBuffer
                if (pendingPts == 0L) {
                    pendingPts = pts
                }
            }

            if (pendingBuffer.size >= bytesPerFrame) {
                val frameData = ByteArray(bytesPerFrame)
                System.arraycopy(pendingBuffer, 0, frameData, 0, bytesPerFrame)

                val remaining = ByteArray(pendingBuffer.size - bytesPerFrame)
                System.arraycopy(pendingBuffer, bytesPerFrame, remaining, 0, remaining.size)
                pendingBuffer = remaining

                inputBuffer.clear()
                inputBuffer.put(frameData)

                mediaCodec?.queueInputBuffer(inputIndex, 0, frameData.size, pendingPts, 0)
                Log.d("AudioEncoder", "Encode: size=${frameData.size}, pts=$pendingPts")

                pendingPts = 0L
            } else {
                mediaCodec?.queueInputBuffer(inputIndex, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                break
            }
        }
    }

    private fun processOutput() {
        val bufferInfo = MediaCodec.BufferInfo()
        while (isEncoding) {
            val outputIndex = mediaCodec?.dequeueOutputBuffer(bufferInfo, 10000) ?: -1
            when {
                outputIndex >= 0 -> {
                    val outputBuffer = mediaCodec?.getOutputBuffer(outputIndex) ?: continue
                    val data = ByteArray(bufferInfo.size)
                    outputBuffer.get(data, 0, bufferInfo.size)

                    Log.d("AudioEncoder", "Output frame: size=${data.size}, pts=${bufferInfo.presentationTimeUs}")

                    val ptsMs = bufferInfo.presentationTimeUs / 1000

                    // 防重入
                    synchronized(callbackLock) {
                        if (!isCallbackRunning) {
                            isCallbackRunning = true
                            try {
                                callback?.onAudioFrame(data, ptsMs)
                            } finally {
                                isCallbackRunning = false
                            }
                        }
                    }

                    mediaCodec?.releaseOutputBuffer(outputIndex, false)
                }
                outputIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                    Log.d("AudioEncoder", "Output format changed")
                }
                outputIndex == MediaCodec.INFO_TRY_AGAIN_LATER -> {
                    // 继续等待
                }
            }
        }
    }

    fun stop() {
        Log.d("AudioEncoder", "stop called")
        isEncoding = false
        try {
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