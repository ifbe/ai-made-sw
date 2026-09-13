package com.example.pusher.ui

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 把 PCM 聚合成固定时间窗（默认 1 秒）的波形包络。
 *
 * 为什么不用“每 N 帧取 1 个样本”：
 *   1 秒 @44.1kHz 是 44100 帧，若取 200 个点，每点要覆盖 220 帧，
 *   只取其中 1 个样本会严重丢瞬态（混叠）。这里每个点保留该区间内的
 *   min/max（峰值保持），画出来就是标准的音频包络。
 *
 * 维护跨 chunk 的环形缓冲，所以窗口长度与 AudioRecord 的缓冲大小无关
 * （旧实现一次只画一块数据，窗口长度取决于设备，约 20~80ms）。
 *
 * 线程：在采集线程调用 add()，返回值是不可变快照，可安全交给 UI 线程。
 */
class AudioWaveformAggregator(
    private val sampleRate: Int,
    private val channelCount: Int,
    /** 窗口内的点数（约等于横轴像素粒度） */
    private val pointCount: Int = DEFAULT_POINTS
) {
    companion object {
        /** 1 秒窗口 */
        const val WINDOW_MS = 1000

        /** 默认点数：1 秒 / 200 点 = 每点 5ms */
        const val DEFAULT_POINTS = 200
    }

    private val framesPerPoint =
        (sampleRate.toLong() * WINDOW_MS / 1000L / pointCount).toInt().coerceAtLeast(1)

    // 环形缓冲
    private val bufLeftMin = FloatArray(pointCount)
    private val bufLeftMax = FloatArray(pointCount)
    private val bufRightMin = FloatArray(pointCount)
    private val bufRightMax = FloatArray(pointCount)
    private var writeIndex = 0
    private var filled = 0

    // 当前正在累积的这一个点
    private var curMinL = 0f
    private var curMaxL = 0f
    private var curMinR = 0f
    private var curMaxR = 0f
    private var curFrames = 0

    /** 一帧窗口快照（时间顺序：旧 -> 新） */
    class Snapshot(
        val leftMin: FloatArray,
        val leftMax: FloatArray,
        val rightMin: FloatArray,
        val rightMax: FloatArray
    )

    /** 这一秒窗口实际覆盖的采样帧数 */
    val windowFrames: Int get() = pointCount * framesPerPoint

    /** 每个点覆盖的帧数 */
    val framesPerPointValue: Int get() = framesPerPoint

    /**
     * 喂入一块 PCM16（小端、交错）。
     * @return 这一块数据里凑满了至少一个点时返回快照，否则返回 null（避免高频刷 UI）
     */
    fun add(pcm: ByteArray): Snapshot? {
        if (pcm.isEmpty()) return null
        val shorts = ByteBuffer.wrap(pcm).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer()
        val frames = shorts.remaining() / channelCount
        if (frames <= 0) return null

        var produced = false
        for (f in 0 until frames) {
            val base = f * channelCount
            val l = shorts.get(base) / 32768f
            val r = if (channelCount > 1) shorts.get(base + 1) / 32768f else l

            if (curFrames == 0) {
                curMinL = l; curMaxL = l
                curMinR = r; curMaxR = r
            } else {
                if (l < curMinL) curMinL = l
                if (l > curMaxL) curMaxL = l
                if (r < curMinR) curMinR = r
                if (r > curMaxR) curMaxR = r
            }
            curFrames++

            if (curFrames >= framesPerPoint) {
                pushPoint()
                produced = true
            }
        }
        return if (produced) snapshot() else null
    }

    private fun pushPoint() {
        bufLeftMin[writeIndex] = curMinL
        bufLeftMax[writeIndex] = curMaxL
        bufRightMin[writeIndex] = curMinR
        bufRightMax[writeIndex] = curMaxR
        writeIndex = (writeIndex + 1) % pointCount
        if (filled < pointCount) filled++
        curFrames = 0
    }

    private fun snapshot(): Snapshot {
        val n = filled
        val lm = FloatArray(pointCount)
        val lM = FloatArray(pointCount)
        val rm = FloatArray(pointCount)
        val rM = FloatArray(pointCount)
        // 还没攒满 1 秒时，左侧留 0（视为静音），时间轴从右往左生长
        val offset = pointCount - n
        for (i in 0 until n) {
            val src = ((writeIndex - n + i) % pointCount + pointCount) % pointCount
            lm[offset + i] = bufLeftMin[src]
            lM[offset + i] = bufLeftMax[src]
            rm[offset + i] = bufRightMin[src]
            rM[offset + i] = bufRightMax[src]
        }
        return Snapshot(lm, lM, rm, rM)
    }
}
