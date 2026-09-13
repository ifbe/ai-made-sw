package com.example.pusher.ui

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View

/**
 * 音频包络显示：每个横坐标点画一条从该区间 min 到 max 的竖线。
 * 左右声道叠在同一张图里，用颜色区分（左绿、右青）。
 */
class AudioWaveformView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.GREEN
        strokeWidth = 2f
        style = Paint.Style.STROKE
    }
    private val bgPaint = Paint().apply {
        color = Color.DKGRAY
        style = Paint.Style.FILL
    }

    private var leftMin = FloatArray(0)
    private var leftMax = FloatArray(0)
    private var rightMin = FloatArray(0)
    private var rightMax = FloatArray(0)
    private var channelMode = 2  // 1: mono, 2: stereo

    fun setWaveformData(leftMin: FloatArray, leftMax: FloatArray, rightMin: FloatArray, rightMax: FloatArray) {
        this.leftMin = leftMin
        this.leftMax = leftMax
        this.rightMin = rightMin
        this.rightMax = rightMax
        invalidate()
    }

    fun setChannelMode(mode: Int) {
        if (channelMode != mode) {
            channelMode = mode
            invalidate()
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), bgPaint)

        drawChannel(canvas, leftMin, leftMax, Color.GREEN)
        if (channelMode != 1) {
            drawChannel(canvas, rightMin, rightMax, Color.CYAN)
        }
    }

    private fun drawChannel(canvas: Canvas, min: FloatArray, max: FloatArray, color: Int) {
        val n = min.size
        if (n == 0 || width <= 0 || height <= 0) return
        paint.color = color
        val step = width.toFloat() / n
        val midY = height / 2f
        val halfHeight = height / 2f
        var x = step / 2f
        for (i in 0 until n) {
            val top = midY - max[i].coerceIn(-1f, 1f) * halfHeight
            var bottom = midY - min[i].coerceIn(-1f, 1f) * halfHeight
            if (bottom - top < 1f) {
                // 静音/极小信号也画 1px，免得整段消失
                bottom = top + 1f
            }
            canvas.drawLine(x, top, x, bottom, paint)
            x += step
        }
    }
}
