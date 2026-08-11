package com.example.chatroom.core

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.concurrent.thread

/**
 * 一次录音的产物：包好的 WAV bytes + 时长（毫秒，浮点）。
 */
data class VoiceRecordingResult(
    val wavBytes: ByteArray,
    val durationMs: Double
)

/**
 * 语音录制器（核心工具类，与 UI 解耦）。
 *
 * 固定 PCM 16 kHz / mono / 16-bit（每秒 32000 bytes）。
 * 后台线程持续读 PCM 到内部 ByteArrayOutputStream；stop() 时包成 WAV 返回。
 *
 * 推荐生命周期：
 *     init(context) → start() → ... → stop() / cancel() → release()
 *
 * 单实例即可，多次 start/stop 在同一个 recorder 上复用。release() 后需重新 init。
 */
class VoiceRecorder {
    companion object {
        private const val TAG = "VoiceRecorder"
        const val SAMPLE_RATE = 16000
        const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        /** 16-bit mono 16kHz = 32000 bytes/s */
        const val BYTES_PER_SECOND = SAMPLE_RATE * 2
        /** WAV header 固定 44 字节（RIFF/fmt/data 三块的标准布局） */
        const val WAV_HEADER_SIZE = 44
    }

    private var audioRecord: AudioRecord? = null
    private var recordThread: Thread? = null
    @Volatile private var isRecording = false
    private val pcmBuffer = ByteArrayOutputStream()
    @Volatile private var pcmBytesWritten = 0

    /**
     * 检查权限并创建 AudioRecord。
     * @return true = 初始化成功；false = 未授权 / 设备不支持 / 创建失败
     */
    fun init(context: Context): Boolean {
        if (audioRecord != null) return true

        val perm = ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO)
        if (perm != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "RECORD_AUDIO not granted")
            return false
        }

        val minBuf = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT)
        if (minBuf <= 0) {
            Log.w(TAG, "AudioRecord.getMinBufferSize returned $minBuf")
            return false
        }
        val bufSize = minBuf * 2

        // VOICE_RECOGNITION 关闭 AGC/NS，更接近原始 mic 输入；
        // API 24+ 支持，低版本回退到 MIC（行为接近）
        val source = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            MediaRecorder.AudioSource.VOICE_RECOGNITION
        } else {
            MediaRecorder.AudioSource.MIC
        }

        return try {
            val ar = AudioRecord(source, SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT, bufSize)
            if (ar.state != AudioRecord.STATE_INITIALIZED) {
                Log.w(TAG, "AudioRecord not initialized, state=${ar.state}")
                ar.release()
                false
            } else {
                audioRecord = ar
                true
            }
        } catch (e: Exception) {
            Log.w(TAG, "AudioRecord ctor failed", e)
            false
        }
    }

    /**
     * 启动录音（后台线程读 PCM）。
     * @return true = 启动成功；false = 未 init / startRecording 失败
     */
    fun start(): Boolean {
        val ar = audioRecord ?: return false
        if (isRecording) return true
        synchronized(pcmBuffer) {
            pcmBuffer.reset()
            pcmBytesWritten = 0
        }
        try {
            ar.startRecording()
        } catch (e: Exception) {
            Log.w(TAG, "startRecording failed", e)
            return false
        }
        isRecording = true
        val bufBytes = ar.bufferSizeInFrames * 2 // 16-bit = 2 bytes/sample
        recordThread = thread(name = "VoiceRecorder-Reader", isDaemon = true) {
            val chunk = ByteArray(bufBytes)
            while (isRecording) {
                val n = ar.read(chunk, 0, chunk.size)
                if (n > 0) {
                    synchronized(pcmBuffer) {
                        pcmBuffer.write(chunk, 0, n)
                        pcmBytesWritten += n
                    }
                }
            }
        }
        return true
    }

    /** 取消录音，丢弃 buffer，不返回数据 */
    fun cancel() {
        stopInternal()
    }

    /**
     * 停止录音。
     * @return 包好 WAV header 的完整 bytes + 时长（毫秒）；空录音返回 null
     */
    fun stop(): VoiceRecordingResult? {
        val (pcm, pcmSize) = synchronized(pcmBuffer) {
            if (pcmBytesWritten == 0) return null
            pcmBuffer.toByteArray().copyOf(pcmBytesWritten) to pcmBytesWritten
        }
        val durationMs = pcmSize.toDouble() * 1000.0 / BYTES_PER_SECOND.toDouble()
        stopInternal()
        return VoiceRecordingResult(wrapAsWav(pcm), durationMs)
    }

    /** 释放 AudioRecord；之后如需再录需要重新 init。会自动 cancel 进行中的录音。 */
    fun release() {
        stopInternal()
        audioRecord?.release()
        audioRecord = null
        synchronized(pcmBuffer) {
            pcmBuffer.reset()
            pcmBytesWritten = 0
        }
    }

    private fun stopInternal() {
        if (!isRecording) return
        isRecording = false
        recordThread?.join(500)
        recordThread = null
        try {
            audioRecord?.stop()
        } catch (_: Exception) {
            // ignore: 可能根本没 start 过
        }
    }

    /**
     * 把 PCM 包成 WAV (RIFF / WAVE / fmt / data)。
     * Format: PCM 16-bit, mono, 16 kHz。
     */
    private fun wrapAsWav(pcm: ByteArray): ByteArray {
        val totalDataLen = pcm.size + 36
        val byteRate = BYTES_PER_SECOND
        val buf = ByteArray(WAV_HEADER_SIZE + pcm.size)
        val bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
        bb.put("RIFF".toByteArray(Charsets.US_ASCII))
        bb.putInt(totalDataLen)
        bb.put("WAVE".toByteArray(Charsets.US_ASCII))
        bb.put("fmt ".toByteArray(Charsets.US_ASCII))
        bb.putInt(16)            // fmt chunk size for PCM
        bb.putShort(1)           // audio format = PCM
        bb.putShort(1)           // num channels = mono
        bb.putInt(SAMPLE_RATE)
        bb.putInt(byteRate)
        bb.putShort(2)           // block align = channels * bitsPerSample / 8
        bb.putShort(16)          // bits per sample
        bb.put("data".toByteArray(Charsets.US_ASCII))
        bb.putInt(pcm.size)
        bb.put(pcm)
        return buf
    }
}