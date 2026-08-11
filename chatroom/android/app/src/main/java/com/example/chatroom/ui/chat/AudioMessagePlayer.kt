package com.example.chatroom.ui.chat

import android.media.MediaPlayer
import android.util.Log
import java.io.File
import java.util.UUID

/**
 * 全局单例音频播放器（短期工具，仅用于 chat 内的语音气泡点击播放）。
 *
 * 用法：
 *     AudioMessagePlayer.play(wavBytes, context.cacheDir) { /* onComplete */ }
 *
 * 行为：
 * - 同一时刻只播一条；新 play() 会先停掉当前的
 * - 把 wav 写到 cacheDir/voice_{uuid}.wav 临时文件，MediaPlayer 异步 prepare 播放
 * - 播放完 / 出错自动 release MediaPlayer 并删除临时文件
 *
 * 不持久化状态、不维护播放列表；AudioMessageAdapter 不需要管它。
 */
object AudioMessagePlayer {
    private const val TAG = "AudioMessagePlayer"

    @Volatile private var currentPlayer: MediaPlayer? = null
    @Volatile private var currentFile: File? = null

    /**
     * 播放一段 WAV bytes。
     * @param wavBytes 完整的 WAV（含 44 字节 header + PCM data）
     * @param cacheDir 用于写临时文件（建议传 context.cacheDir）
     * @param onComplete 播放结束或失败时回调（主线程不一定，回调方自己切线程）
     */
    fun play(wavBytes: ByteArray, cacheDir: File, onComplete: (() -> Unit)? = null) {
        // 先停掉之前的（会 release + 删临时文件）
        stop()

        val tmpFile = File(cacheDir, "voice_${UUID.randomUUID()}.wav")
        try {
            tmpFile.writeBytes(wavBytes)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to write temp wav", e)
            tmpFile.delete()
            onComplete?.invoke()
            return
        }

        val player = MediaPlayer()
        try {
            player.setDataSource(tmpFile.absolutePath)
            player.setOnPreparedListener { mp ->
                mp.start()
            }
            player.setOnCompletionListener {
                cleanup()
                onComplete?.invoke()
            }
            player.setOnErrorListener { _, what, extra ->
                Log.w(TAG, "MediaPlayer error what=$what extra=$extra")
                cleanup()
                onComplete?.invoke()
                true
            }
            currentPlayer = player
            currentFile = tmpFile
            player.prepareAsync()
        } catch (e: Exception) {
            Log.w(TAG, "MediaPlayer init failed", e)
            tmpFile.delete()
            try { player.release() } catch (_: Exception) {}
            onComplete?.invoke()
        }
    }

    /** 停掉当前播放（如有）；release player + 删临时文件 */
    fun stop() {
        currentPlayer?.let {
            try {
                if (it.isPlaying) it.stop()
            } catch (_: Exception) {}
            try { it.release() } catch (_: Exception) {}
        }
        currentPlayer = null
        currentFile?.let {
            try { if (it.exists()) it.delete() } catch (_: Exception) {}
        }
        currentFile = null
    }

    private fun cleanup() {
        currentPlayer = null
        currentFile?.let {
            try { if (it.exists()) it.delete() } catch (_: Exception) {}
        }
        currentFile = null
    }
}