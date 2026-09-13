package com.example.pusher.encoder

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.Surface
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

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
    private val isEncoding = AtomicBoolean(false)

    // 真正干活的后台线程：codec 回调里只做“拷贝 + 归还 buffer”，
    // 其余处理（转 Annex-B、UI 预览、JNI 写入）都放到这里，避免阻塞 codec 回调线程。
    private val outputExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "VideoEncoderOut")
    }

    // codec 回调线程：独立 HandlerThread，不占用主线程。
    // （MediaCodec 默认会把回调投递到“创建 codec 的线程的 Looper”，创建线程没有 Looper
    //   时会退化成主线程；这里显式指定，行为确定。）
    private var callbackThread: HandlerThread? = null
    private var callbackHandler: Handler? = null

    // 保证 stop() 释放 codec 时回调不在临界区里
    private val codecLock = ReentrantLock()

    private fun bytesToHex(bytes: ByteArray, maxLen: Int = 32): String {
        val len = bytes.size.coerceAtMost(maxLen)
        return (0 until len).joinToString(" ") { "%02x".format(bytes[it]) }
    }

    fun prepare(callback: EncoderCallback): Surface? {
        Log.d(TAG, "prepare: ${width}x${height}, bitrate=$bitrate, fps=$frameRate, mime=$codecMime")
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
            // 关键：强制输出不旋转
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                setInteger(MediaFormat.KEY_ROTATION, 0)
            }
        }

        try {
            mediaCodec = MediaCodec.createEncoderByType(codecMime)
            Log.d(TAG, "MediaCodec created")

            mediaCodec?.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            inputSurface = mediaCodec?.createInputSurface()

            val thread = HandlerThread("VideoEncoderCb").apply { start() }
            callbackThread = thread
            callbackHandler = Handler(thread.looper)

            mediaCodec?.setCallback(object : MediaCodec.Callback() {
                override fun onInputBufferAvailable(codec: MediaCodec, index: Int) {}

                override fun onOutputBufferAvailable(codec: MediaCodec, index: Int, info: MediaCodec.BufferInfo) {
                    // stop() 正在释放 codec：直接丢弃这一帧，不要再去碰 buffer
                    if (!codecLock.tryLock()) return
                    try {
                        if (!isEncoding.get()) return

                        val isConfig = (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG) != 0
                        val buffer = codec.getOutputBuffer(index) ?: return

                        // 防御：info.size 与实际可读长度不一致时直接归还，避免 BufferUnderflow
                        if (info.size <= 0 || info.size > buffer.remaining()) {
                            codec.releaseOutputBuffer(index, false)
                            return
                        }

                        // 注意：这里不再 rewind()，从 buffer 当前 position（即 info.offset）开始读
                        val data = ByteArray(info.size)
                        buffer.get(data, 0, info.size)
                        codec.releaseOutputBuffer(index, false)

                        if (isConfig) {
                            Log.d(TAG, "CSD from output buffer: info.size=${info.size}, hex=${bytesToHex(data)}")
                            submitFrame(data, 0L, true)
                        } else {
                            val isKey = (info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME) != 0
                            if (isKey) {
                                Log.d(TAG, "Key frame, size=${data.size}, hex=${bytesToHex(data)}")
                            }
                            submitFrame(data, info.presentationTimeUs / 1000, isKey)
                        }
                    } catch (t: Throwable) {
                        // 捕获所有异常（含 NPE/OOM/IllegalStateException），
                        // 避免 codec 的回调线程被未捕获异常干掉。
                        Log.e(TAG, "onOutputBufferAvailable error", t)
                    } finally {
                        codecLock.unlock()
                    }
                }

                override fun onOutputFormatChanged(codec: MediaCodec, format: MediaFormat) {
                    if (!codecLock.tryLock()) return
                    try {
                        if (!isEncoding.get()) return

                        // 从 MediaFormat 获取 SPS/PPS（裸数据，通常已带起始码）
                        val csd0 = format.getByteBuffer("csd-0")
                        val csd1 = format.getByteBuffer("csd-1")

                        val annexB = java.io.ByteArrayOutputStream()
                        if (csd0 != null && csd0.remaining() > 0) {
                            val sps = ByteArray(csd0.remaining())
                            csd0.get(sps)
                            Log.d(TAG, "SPS from format, size=${sps.size}, hex=${bytesToHex(sps)}")
                            annexB.write(sps)
                        }
                        if (csd1 != null && csd1.remaining() > 0) {
                            val pps = ByteArray(csd1.remaining())
                            csd1.get(pps)
                            Log.d(TAG, "PPS from format, size=${pps.size}, hex=${bytesToHex(pps)}")
                            annexB.write(pps)
                        }
                        val combined = annexB.toByteArray()
                        if (combined.isNotEmpty()) {
                            Log.d(TAG, "combined from format, size=${combined.size}")
                            submitFrame(combined, 0L, true)
                        }
                    } catch (t: Throwable) {
                        Log.e(TAG, "onOutputFormatChanged error", t)
                    } finally {
                        codecLock.unlock()
                    }
                }

                override fun onError(codec: MediaCodec, e: MediaCodec.CodecException) {
                    Log.e(TAG, "Error", e)
                }
            }, callbackHandler)

            mediaCodec?.start()
            isEncoding.set(true)
            Log.d(TAG, "prepare SUCCESS")
            return inputSurface

        } catch (e: Exception) {
            Log.e(TAG, "prepare FAILED", e)
            try {
                mediaCodec?.release()
            } catch (t: Throwable) {
                Log.w(TAG, "release after prepare failure", t)
            }
            // createInputSurface() 拿到的 Surface 必须显式 release，
            // 否则每次 prepare 失败都会泄漏一个 BufferQueue
            try {
                inputSurface?.release()
            } catch (t: Throwable) {
                Log.w(TAG, "inputSurface.release after prepare failure", t)
            }
            mediaCodec = null
            inputSurface = null
            outputExecutor.shutdownNow()
            releaseCallbackThread()
            return null
        }
    }

    /**
     * 把帧交给后台线程处理。线程池已关闭（stop 中）时直接丢弃。
     */
    private fun submitFrame(data: ByteArray, ptsMs: Long, isKey: Boolean) {
        try {
            outputExecutor.execute {
                try {
                    callback?.onVideoFrame(data, ptsMs, isKey)
                } catch (t: Throwable) {
                    Log.e(TAG, "onVideoFrame callback error", t)
                }
            }
        } catch (e: RejectedExecutionException) {
            Log.w(TAG, "frame dropped: output executor already closed")
        }
    }

    fun stop() {
        Log.d(TAG, "stop called")
        if (!isEncoding.getAndSet(false)) {
            return
        }

        // 视频编码器是异步回调模式。异步模式下 dequeueInputBuffer / dequeueOutputBuffer
        // 属于非法调用（javadoc 明确会抛 IllegalStateException），所以这里不再做同步排空；
        // 改为：先让回调停在临界区外，再把已提交的帧处理完，最后停止并释放 codec。
        var locked = false
        try {
            locked = codecLock.tryLock(300, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        if (!locked) {
            Log.w(TAG, "stop: codec callback still busy, release anyway")
        }

        try {
            try {
                outputExecutor.shutdown()
                if (!outputExecutor.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                    outputExecutor.shutdownNow()
                }
            } catch (e: InterruptedException) {
                outputExecutor.shutdownNow()
                Thread.currentThread().interrupt()
            }

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
            try {
                inputSurface?.release()
            } catch (t: Throwable) {
                Log.w(TAG, "inputSurface.release failed", t)
            }
        } catch (e: Exception) {
            Log.e(TAG, "stop error", e)
        } finally {
            if (locked) codecLock.unlock()
            mediaCodec = null
            inputSurface = null
            releaseCallbackThread()
        }
        Log.d(TAG, "stop completed")
    }

    private fun releaseCallbackThread() {
        try {
            callbackHandler?.removeCallbacksAndMessages(null)
            callbackThread?.quitSafely()
        } catch (t: Throwable) {
            Log.w(TAG, "releaseCallbackThread failed", t)
        }
        callbackHandler = null
        callbackThread = null
    }

    private companion object {
        private const val TAG = "VideoEncoder"
    }
}
