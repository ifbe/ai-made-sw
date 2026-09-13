package com.example.pusher.audio

import android.media.AudioDeviceInfo
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log
import com.example.pusher.utils.AppLog
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class AudioCapture(
    private val sampleRate: Int = 44100,
    private val channelConfig: Int = AudioFormat.CHANNEL_IN_STEREO,
    private val audioFormat: Int = AudioFormat.ENCODING_PCM_16BIT,
    // 指定的输入设备（内置/外接/蓝牙麦克风）；null = 用系统默认
    private val preferredDevice: AudioDeviceInfo? = null
) {
    @Volatile
    private var audioRecord: AudioRecord? = null
    private val isRecording = AtomicBoolean(false)
    private var callback: ((ByteArray) -> Unit)? = null
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "AudioCapture")
    }

    private val channelCount = if (channelConfig == AudioFormat.CHANNEL_IN_MONO) 1 else 2

    // getMinBufferSize 失败时的兜底缓冲：约 100ms 的 PCM
    private val fallbackBufferBytes = (sampleRate / 10).coerceAtLeast(1024) * channelCount * 2

    fun start(callback: (ByteArray) -> Unit) {
        this.callback = callback

        val minBuffer = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat)
        // getMinBufferSize 失败会返回负数（ERROR / ERROR_BAD_VALUE）。
        // 旧代码直接 ByteArray(bufferSize)，在采集线程抛 NegativeArraySizeException，
        // 而 Android 上任意线程的未捕获异常都会杀掉整个进程。
        if (minBuffer <= 0) {
            Log.w(TAG, "getMinBufferSize failed ($minBuffer), fallback to $fallbackBufferBytes")
        }
        val bufferSize = if (minBuffer > 0) minBuffer else fallbackBufferBytes
        // 一块 = 一次 read 的数据量，也就是示波器一次刷新所覆盖的时间长度
        val blockMs = bufferSize * 1000L / (channelCount * 2 * sampleRate)
        Log.d(TAG, "bufferSize=$bufferSize bytes (~${blockMs}ms per block), minBuffer=$minBuffer, " +
                "sampleRate=$sampleRate, channels=$channelCount")
        AppLog.log("音频采集参数: ${sampleRate}Hz ${channelCount}ch, 每块 ${blockMs}ms, 指定设备=${preferredDevice?.type ?: "默认"}")

        val record = AudioRecord(
            MediaRecorder.AudioSource.MIC,
            sampleRate,
            channelConfig,
            audioFormat,
            bufferSize
        )
        audioRecord = record

        if (record.state != AudioRecord.STATE_INITIALIZED) {
            Log.e(TAG, "AudioRecord init failed, state=${record.state}")
            try {
                record.release()
            } catch (t: Throwable) {
                Log.w(TAG, "release after init failure", t)
            }
            audioRecord = null
            throw IllegalStateException("AudioRecord 初始化失败，请检查采样率/声道/录音权限")
        }

        // 指定输入设备（必须在 startRecording 之前调用）
        val device = preferredDevice
        if (device != null) {
            val ok = try {
                record.setPreferredDevice(device)
            } catch (t: Throwable) {
                Log.w(TAG, "setPreferredDevice failed", t)
                false
            }
            Log.d(TAG, "setPreferredDevice(type=${device.type}, product=${device.productName}) -> $ok")
            AppLog.log("指定录音设备: type=${device.type} 成功=$ok")
        }

        record.startRecording()
        isRecording.set(true)
        Log.d(TAG, "recording started, routedDevice=${record.routedDevice?.type}")
        AppLog.log("录音已开始, 实际设备=${record.routedDevice?.type}")

        executor.execute {
            // 用局部引用，避免 stop() 把字段置空后 read 到空指针
            val rec = record
            val buffer = ByteArray(bufferSize)
            while (isRecording.get()) {
                val len = try {
                    rec.read(buffer, 0, bufferSize)
                } catch (e: IllegalStateException) {
                    // AudioRecord 已被 release()，read 会抛这个；正常 stop 流程里会到这里
                    Log.w(TAG, "audioRecord.read IllegalStateException, exiting read loop")
                    break
                } catch (e: Exception) {
                    // 其他 native 异常也吞掉并退出，避免 Executor 线程被 uncaught 干掉
                    Log.e(TAG, "audioRecord.read unexpected error, exiting read loop", e)
                    break
                }
                if (len > 0) {
                    // 回调里是用户代码（波形刷新、编码提交、JNI），必须兜住异常：
                    // 这里抛出去同样会走 KillApplicationHandler 直接杀进程。
                    try {
                        callback?.invoke(buffer.copyOf(len))
                    } catch (t: Throwable) {
                        Log.e(TAG, "capture callback error", t)
                    }
                } else if (len < 0) {
                    Log.w(TAG, "audioRecord.read returned error code: $len")
                }
            }
            Log.d(TAG, "read loop exited")
        }
    }

    fun stop() {
        isRecording.set(false)

        val record = audioRecord
        audioRecord = null

        try {
            record?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "audioRecord.stop failed", t)
        }
        try {
            record?.release()
        } catch (t: Throwable) {
            Log.w(TAG, "audioRecord.release failed", t)
        }

        // 正确关闭线程池
        if (!executor.isShutdown) {
            executor.shutdown()
            try {
                if (!executor.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                    executor.shutdownNow()
                }
            } catch (e: InterruptedException) {
                executor.shutdownNow()
                Thread.currentThread().interrupt()
            }
        }
    }

    private companion object {
        private const val TAG = "AudioCapture"
    }
}
