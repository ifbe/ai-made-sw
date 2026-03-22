package com.example.pusher.ui

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View

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
    private var leftAmplitudes = FloatArray(0)
    private var rightAmplitudes = FloatArray(0)
    private var channelMode = 2  // 1: mono, 2: stereo

    fun setWaveformData(left: FloatArray, right: FloatArray) {
        leftAmplitudes = left
        rightAmplitudes = right
        invalidate()
    }

    fun setChannelMode(mode: Int) {
        channelMode = mode
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), bgPaint)

        if (channelMode == 1) {
            drawChannel(canvas, leftAmplitudes, 0f, height.toFloat(), Color.GREEN)
        } else {
            val halfHeight = height / 2f
            drawChannel(canvas, leftAmplitudes, 0f, halfHeight, Color.GREEN)
            drawChannel(canvas, rightAmplitudes, halfHeight, halfHeight, Color.CYAN)
        }
    }

    private fun drawChannel(canvas: Canvas, amplitudes: FloatArray, topY: Float, channelHeight: Float, color: Int) {
        if (amplitudes.isEmpty()) return
        paint.color = color
        val step = width.toFloat() / amplitudes.size
        var x = 0f
        val midY = topY + channelHeight / 2
        for (i in amplitudes.indices) {
            val amp = amplitudes[i].coerceIn(0f, 1f) * (channelHeight / 2)
            val startY = midY - amp
            val endY = midY + amp
            canvas.drawLine(x, startY, x, endY, paint)
            x += step
        }
    }
}
