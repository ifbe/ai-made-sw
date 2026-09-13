package com.example.pusher.encoder

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
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

    // 单线程即可：输出轮询只需要一个线程，避免和 stop() 并发 dequeue 同一个 codec
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "AudioEncoderOut")
    }

    private val samplesPerFrame = 1024
    private val bytesPerSample = 2
    private val bytesPerFrame = samplesPerFrame * channelCount * bytesPerSample

    // 每帧的时长（微秒），用于把 pendingPts 向前推进，保证 PTS 单调递增
    private val frameDurationUs = samplesPerFrame * 1_000_000L / sampleRate

    private var pendingBuffer = ByteArray(0)
    private var pendingPts = 0L

    // 跨线程可见性：processOutput 线程需要尽快看到停止标志
    @Volatile
    private var isStopping = false

    fun prepare(callback: EncoderCallback): Boolean {
        Log.d(TAG, "prepare: ${sampleRate}Hz, ${channelCount}ch, bitrate=$bitrate, mime=$codecMime")
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
            pendingBuffer = ByteArray(0)
            pendingPts = 0L

            executor.submit { processOutput() }

            return true
        } catch (e: Exception) {
            Log.e(TAG, "prepare FAILED", e)
            try {
                mediaCodec?.release()
            } catch (t: Throwable) {
                Log.w(TAG, "release after prepare failure", t)
            }
            mediaCodec = null
            return false
        }
    }

    fun encode(pcmData: ByteArray, pts: Long) {
        if (!isEncoding.get() || isStopping) return

        // 累积数据
        val wasEmpty = pendingBuffer.isEmpty()
        val newBuffer = ByteArray(pendingBuffer.size + pcmData.size)
        System.arraycopy(pendingBuffer, 0, newBuffer, 0, pendingBuffer.size)
        System.arraycopy(pcmData, 0, newBuffer, pendingBuffer.size, pcmData.size)
        pendingBuffer = newBuffer

        // 只有缓冲区原本是空的时候，才用这一批数据的起始 PTS 作为锚点。
        // （旧代码用 pendingPts == 0L 判断，一旦第一帧 PTS 恰好是 0 就会算错。）
        if (wasEmpty) {
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
            // 旧代码这里直接 pendingPts = 0L：一次 read 里攒够两帧时，
            // 第二帧会带着 PTS=0 送进编码器，导致 dts 非单调、muxer 报错。
            // 正确做法是按帧时长向前推进。
            pendingPts += frameDurationUs
        }
    }

    private fun sendToEncoder(data: ByteArray, pts: Long) {
        if (isStopping) return

        try {
            val index = mediaCodec?.dequeueInputBuffer(10000) ?: -1
            if (index < 0) {
                Log.w(TAG, "No input buffer available")
                return
            }

            val buffer = mediaCodec?.getInputBuffer(index) ?: return
            buffer.clear()
            buffer.put(data)

            mediaCodec?.queueInputBuffer(index, 0, data.size, pts, 0)
            Log.v(TAG, "Sent frame: size=${data.size}, pts=$pts")
        } catch (e: Exception) {
            Log.e(TAG, "sendToEncoder error", e)
        }
    }

    private fun processOutput() {
        val bufferInfo = MediaCodec.BufferInfo()
        while (isEncoding.get() && !isStopping) {
            try {
                val outputIndex = mediaCodec?.dequeueOutputBuffer(bufferInfo, 10000) ?: -1
                when {
                    outputIndex >= 0 -> {
                        val outputBuffer = mediaCodec?.getOutputBuffer(outputIndex)
                        if (outputBuffer == null) {
                            mediaCodec?.releaseOutputBuffer(outputIndex, false)
                            continue
                        }
                        // 编解码配置缓冲（AAC 的 ASC）不是音频数据，不能当帧写出去；
                        // 音频 extradata 已在 native 侧按采样率/声道构造。
                        if (bufferInfo.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                            Log.d(TAG, "skip codec-config buffer: size=${bufferInfo.size}")
                            mediaCodec?.releaseOutputBuffer(outputIndex, false)
                            continue
                        }
                        if (bufferInfo.size <= 0 || bufferInfo.size > outputBuffer.remaining()) {
                            mediaCodec?.releaseOutputBuffer(outputIndex, false)
                            continue
                        }
                        val data = ByteArray(bufferInfo.size)
                        outputBuffer.get(data, 0, bufferInfo.size)

                        Log.v(TAG, "Output frame: size=${data.size}, pts=${bufferInfo.presentationTimeUs}")

                        val ptsMs = bufferInfo.presentationTimeUs / 1000
                        callback?.onAudioFrame(data, ptsMs)

                        mediaCodec?.releaseOutputBuffer(outputIndex, false)
                    }
                    outputIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        Log.d(TAG, "Output format changed")
                    }
                    outputIndex == MediaCodec.INFO_TRY_AGAIN_LATER -> {
                        Thread.sleep(1)
                    }
                    else -> {
                        // codec 已被释放（mediaCodec == null）时避免空转
                        Thread.sleep(1)
                    }
                }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            } catch (e: IllegalStateException) {
                // codec released, exit loop
                Log.w(TAG, "codec released, exiting processOutput")
                break
            } catch (e: Exception) {
                if (!isStopping) {
                    Log.e(TAG, "processOutput error", e)
                }
            }
        }
        Log.d(TAG, "processOutput stopped")
    }

    fun stop() {
        Log.d(TAG, "stop called")
        if (!isEncoding.getAndSet(false)) {
            return
        }

        isStopping = true

        // 1) 发 EOS。输入 buffer 只有 encode()/本方法会碰，而调用方（PusherController）
        //    会先把提交 encode 的线程排空，所以这里不存在并发访问输入 buffer 的问题。
        try {
            val inputIndex = mediaCodec?.dequeueInputBuffer(10000) ?: -1
            if (inputIndex >= 0) {
                mediaCodec?.queueInputBuffer(inputIndex, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "queue EOS failed", t)
        }

        // 2) 等输出轮询线程退出后再释放 codec。
        //    旧代码在 stop() 里也 dequeueOutputBuffer，与 processOutput 线程并发操作
        //    同一个 MediaCodec，属于未定义行为（偶现 native 崩溃）。
        if (!executor.isShutdown) {
            executor.shutdown()
            try {
                if (!executor.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                    Log.w(TAG, "processOutput did not exit in time, forcing shutdown")
                    executor.shutdownNow()
                }
            } catch (e: InterruptedException) {
                executor.shutdownNow()
                Thread.currentThread().interrupt()
            }
        }

        // 3) 释放 codec
        try {
            mediaCodec?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "mediaCodec.stop failed", t)
        }
        try {
            mediaCodec?.release()
        } catch (t: Throwable) {
            Log.w(TAG, "mediaCodec.release failed", t)
        }
        mediaCodec = null
        pendingBuffer = ByteArray(0)
        pendingPts = 0L
        Log.d(TAG, "stop completed")
    }

    private companion object {
        private const val TAG = "AudioEncoder"
    }
}
