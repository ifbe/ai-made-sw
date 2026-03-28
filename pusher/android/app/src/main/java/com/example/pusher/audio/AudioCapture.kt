package com.example.pusher.audio

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class AudioCapture(
    private val sampleRate: Int = 44100,
    private val channelConfig: Int = AudioFormat.CHANNEL_IN_STEREO,
    private val audioFormat: Int = AudioFormat.ENCODING_PCM_16BIT
) {
    private var audioRecord: AudioRecord? = null
    private var isRecording = AtomicBoolean(false)
    private var callback: ((ByteArray) -> Unit)? = null
    private var executor = Executors.newSingleThreadExecutor()

    fun start(callback: (ByteArray) -> Unit) {
        this.callback = callback
        val bufferSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat)
        audioRecord = AudioRecord(MediaRecorder.AudioSource.MIC, sampleRate, channelConfig, audioFormat, bufferSize)
        audioRecord?.startRecording()
        isRecording.set(true)
        
        executor.execute {
            val buffer = ByteArray(bufferSize)
            while (isRecording.get()) {
                val len = audioRecord?.read(buffer, 0, bufferSize) ?: 0
                if (len > 0) {
                    callback(buffer.copyOf(len))
                }
            }
        }
    }

    fun stop() {
        isRecording.set(false)
        try {
            audioRecord?.stop()
            audioRecord?.release()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        audioRecord = null
        
        // 正确关闭线程池
        executor.shutdown()
        try {
            if (!executor.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                executor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            executor.shutdownNow()
        }
    }
}
