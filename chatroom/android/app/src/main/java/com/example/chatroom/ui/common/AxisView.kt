package com.example.chatroom.ui.common

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View

/**
 * 3D 坐标轴视图
 * 红=X，绿=Y，蓝=Z
 * 轴线从负端画到正端
 * +方向末端有箭头 + 旋转按钮
 * -方向末端有旋转按钮
 */
class AxisView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    var listener: OnRotationClickListener? = null

    interface OnRotationClickListener {
        fun onXRotateCW()
        fun onXRotateCCW()
        fun onYRotateCW()
        fun onYRotateCCW()
        fun onZRotateCW()
        fun onZRotateCCW()
    }

    private val xColor = 0xFFFF4444.toInt()
    private val yColor = 0xFF44AA44.toInt()
    private val zColor = 0xFF4444FF.toInt()

    private val axisPaint = Paint().apply {
        style = Paint.Style.STROKE
        strokeWidth = 2.5f
        isAntiAlias = true
    }

    private val fillPaint = Paint().apply {
        style = Paint.Style.FILL
        isAntiAlias = true
    }

    private val labelPaint = Paint().apply {
        style = Paint.Style.FILL
        textSize = 18f
        isAntiAlias = true
    }

    private val btnFill = Paint().apply {
        style = Paint.Style.FILL
        color = 0xFFFFFFFF.toInt()
        isAntiAlias = true
    }

    private val btnStroke = Paint().apply {
        style = Paint.Style.STROKE
        strokeWidth = 1.5f
        color = 0xFF888888.toInt()
        isAntiAlias = true
    }

    // 旋转按钮文字继续加大
    private val btnText = Paint().apply {
        style = Paint.Style.FILL
        textSize = 48f
        textAlign = Paint.Align.CENTER
        isAntiAlias = true
    }

    // +方向箭头
    private val arrowFill = Paint().apply {
        style = Paint.Style.FILL
        isAntiAlias = true
    }

    // 6个按钮的屏幕区域
    private val btnRects = Array(6) { FloatArray(4) }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        setMeasuredDimension(
            MeasureSpec.getSize(widthMeasureSpec),
            MeasureSpec.getSize(heightMeasureSpec)
        )
    }

    private fun drawArrow(canvas: Canvas, x: Float, y: Float, angle: Float, color: Int) {
        // 画一个三角形箭头
        arrowFill.color = color
        val path = Path()
        val size = minOf(width, height) * 0.05f
        // 箭头指向 angle 方向
        path.moveTo(x + size * kotlin.math.cos(angle), y + size * kotlin.math.sin(angle))
        path.lineTo(x + size * 0.5f * kotlin.math.cos(angle + 2.5f), y + size * 0.5f * kotlin.math.sin(angle + 2.5f))
        path.lineTo(x + size * 0.5f * kotlin.math.cos(angle - 2.5f), y + size * 0.5f * kotlin.math.sin(angle - 2.5f))
        path.close()
        canvas.drawPath(path, arrowFill)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0 || h <= 0) return

        val cx = w / 2f
        val cy = h / 2f
        val len = minOf(w, h) * 0.28f
        val btnR = minOf(w, h) * 0.11f

        // === X轴（红）===
        axisPaint.color = xColor
        canvas.drawLine(cx - len, cy, cx + len, cy, axisPaint)

        // X+ 箭头
        drawArrow(canvas, cx + len, cy, 0f, xColor)

        // X+ 按钮
        val bx = cx + len + btnR + 4f
        canvas.drawCircle(bx, cy, btnR, btnFill)
        canvas.drawCircle(bx, cy, btnR, btnStroke)
        btnText.color = xColor
        canvas.drawText("⟳", bx, cy + btnR * 0.4f, btnText)
        btnRects[0] = floatArrayOf(bx - btnR, cy - btnR, bx + btnR, cy + btnR)

        // X- 按钮
        val bx2 = cx - len - btnR - 4f
        canvas.drawCircle(bx2, cy, btnR, btnFill)
        canvas.drawCircle(bx2, cy, btnR, btnStroke)
        btnText.color = xColor
        canvas.drawText("⟲", bx2, cy + btnR * 0.4f, btnText)
        btnRects[1] = floatArrayOf(bx2 - btnR, cy - btnR, bx2 + btnR, cy + btnR)

        // === Y轴（绿）===
        axisPaint.color = yColor
        canvas.drawLine(cx, cy - len, cx, cy + len, axisPaint)

        // Y+ 箭头（向上）
        drawArrow(canvas, cx, cy - len, -Math.PI.toFloat() / 2f, yColor)

        // Y+ 按钮
        val by = cy - len - btnR - 4f
        canvas.drawCircle(cx, by, btnR, btnFill)
        canvas.drawCircle(cx, by, btnR, btnStroke)
        btnText.color = yColor
        canvas.drawText("⟳", cx, by + btnR * 0.4f, btnText)
        btnRects[2] = floatArrayOf(cx - btnR, by - btnR, cx + btnR, by + btnR)

        // Y- 按钮
        val by2 = cy + len + btnR + 4f
        canvas.drawCircle(cx, by2, btnR, btnFill)
        canvas.drawCircle(cx, by2, btnR, btnStroke)
        btnText.color = yColor
        canvas.drawText("⟲", cx, by2 + btnR * 0.4f, btnText)
        btnRects[3] = floatArrayOf(cx - btnR, by2 - btnR, cx + btnR, by2 + btnR)

        // === Z轴（蓝）：斜向 45度 ===
        val dz = len * 0.4f
        axisPaint.color = zColor
        canvas.drawLine(cx - dz, cy - dz, cx + dz, cy + dz, axisPaint)

        // Z+ 箭头
        drawArrow(canvas, cx + dz, cy + dz, Math.PI.toFloat() / 4f, zColor)

        // Z+ 按钮
        val bzx = cx + dz + btnR * 0.7f
        val bzy = cy + dz + btnR * 0.7f
        canvas.drawCircle(bzx, bzy, btnR, btnFill)
        canvas.drawCircle(bzx, bzy, btnR, btnStroke)
        btnText.color = zColor
        canvas.drawText("⟲", bzx, bzy + btnR * 0.4f, btnText)
        btnRects[4] = floatArrayOf(bzx - btnR, bzy - btnR, bzx + btnR, bzy + btnR)

        // Z- 按钮
        val bzx2 = cx - dz - btnR * 0.7f
        val bzy2 = cy - dz - btnR * 0.7f
        canvas.drawCircle(bzx2, bzy2, btnR, btnFill)
        canvas.drawCircle(bzx2, bzy2, btnR, btnStroke)
        btnText.color = zColor
        canvas.drawText("⟳", bzx2, bzy2 + btnR * 0.4f, btnText)
        btnRects[5] = floatArrayOf(bzx2 - btnR, bzy2 - btnR, bzx2 + btnR, bzy2 + btnR)

        // 轴标签
        labelPaint.color = xColor
        canvas.drawText("X", cx + len + 2f, cy - 4f, labelPaint)
        labelPaint.color = yColor
        canvas.drawText("Y", cx + 5f, cy - len - 2f, labelPaint)
        labelPaint.color = zColor
        canvas.drawText("Z", cx + dz + 4f, cy + dz + 5f, labelPaint)

        // 中心点
        fillPaint.color = 0xFF333333.toInt()
        canvas.drawCircle(cx, cy, 3f, fillPaint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (event.action == MotionEvent.ACTION_DOWN) {
            val x = event.x
            val y = event.y
            for (i in btnRects.indices) {
                val r = btnRects[i]
                if (x >= r[0] && x <= r[2] && y >= r[1] && y <= r[3]) {
                    when (i) {
                        0 -> listener?.onXRotateCW()
                        1 -> listener?.onXRotateCCW()
                        2 -> listener?.onYRotateCW()
                        3 -> listener?.onYRotateCCW()
                        4 -> listener?.onZRotateCW()
                        5 -> listener?.onZRotateCCW()
                    }
                    return true
                }
            }
        }
        return super.onTouchEvent(event)
    }
}
