package com.example.chess.xiangqi

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.util.TypedValue
import android.view.MotionEvent
import android.view.View
import kotlin.math.max
import kotlin.math.min

/**
 * 象棋页。
 *
 * 布局规则见 [ChessGeometry]：9 路 × 10 路，细长屏时短边 9 路 / 长边 10 路，
 * 接近正方形时短边 10 路 / 长边 9 路；棋盘居中，落点在各自格子的正中心。
 * 中间留出楚河汉界，两端画出九宫斜线。
 *
 * 规则：
 *  - 不做任何走法判断，只判断轮次；
 *  - 棋盘上的子谁都能拿起来拖，但「不该这一方下」的时候松手会弹回原位；
 *  - 该自己下时走到对方子的位置 = 直接吃掉对方子；
 *  - 把子拖出棋盘 = 这个子被吃掉，直接消失（不换手）。
 */
class ChessBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    companion object {
        /** 横排落点数。 */
        const val FILES = ChessGeometry.FILES

        /** 竖排落点数。 */
        const val RANKS = ChessGeometry.RANKS

        private const val EMPTY = 0
        private const val RED = 1
        private const val BLACK = 2

        /** 两端的底线：车马象仕将仕象马车。 */
        private val BLACK_BACK_ROW = charArrayOf('车', '马', '象', '士', '将', '士', '象', '马', '车')
        private val RED_BACK_ROW = charArrayOf('车', '马', '相', '仕', '帅', '仕', '相', '马', '车')

        /** 楚河汉界：两半带子里的字和它们的位置（0..1）。 */
        private val RIVER_TEXTS = arrayOf("楚 河", "汉 界")
        private val RIVER_POSITIONS = floatArrayOf(0.25f, 0.75f)
    }

    // ------------------------------------------------------------------ 状态

    /** 按棋盘坐标存：下标 = rank * FILES + file（file 0..8 从左到右，rank 0..9 从上到下）。 */
    private val colors = IntArray(FILES * RANKS)
    private val labels = CharArray(FILES * RANKS)

    /** 红方先走。 */
    private var redToMove = true

    // ------------------------------------------------------------------ 几何

    private var geo: ChessGeometry? = null
    private val boardRect = RectF()

    // ------------------------------------------------------------------ 拖动

    private var dragging = false
    private var dragColor = EMPTY
    private var dragLabel = ' '
    private var dragFrom = -1
    private var dragX = 0f
    private var dragY = 0f

    /** 手指悬停的落点下标，-1 表示不在棋盘内。 */
    private var hoverIndex = -1

    // ------------------------------------------------------------------ 画笔

    private val density = resources.displayMetrics.density

    private val boardFillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFFFE999.toInt() // 棋盘底色：鹅黄
    }
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF3A3226.toInt() // 深墨色的线
    }
    private val riverTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFF8A7748.toInt() // 楚河汉界：淡淡的褐色
        textAlign = Paint.Align.CENTER
    }
    private val pieceFacePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFFFFBF0.toInt() // 棋子面
    }
    private val redPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFC0392B.toInt()
    }
    private val blackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF1F1F1F.toInt()
    }
    private val pieceTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
    }

    /** 轮到的一方：提示框用黄色方框圈起来。 */
    private val activeBoxPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFE6B24C.toInt()
    }

    /** 悬停在空落点上。 */
    private val hoverPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF3A3226.toInt()
    }

    /** 悬停在已经有子的落点上（会被退回原位）。 */
    private val blockedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFC62828.toInt()
    }

    private val indicatorTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFEDEDED.toInt() // 提示画在棋盘外的黑底上，用浅色字
        textAlign = Paint.Align.LEFT
    }
    private val indicatorBounds = RectF()

    init {
        setBackgroundColor(0xFF000000.toInt())
        setupInitialPosition()
    }

    // ------------------------------------------------------------------ 初始局面

    /** 摆好开局：红方在下、黑方在上，中间隔着楚河汉界。 */
    private fun setupInitialPosition() {
        colors.fill(EMPTY)
        labels.fill(' ')

        for (file in 0 until FILES) {
            put(file, 0, BLACK, BLACK_BACK_ROW[file])
            put(file, 9, RED, RED_BACK_ROW[file])
        }
        put(1, 2, BLACK, '炮')
        put(7, 2, BLACK, '炮')
        put(1, 7, RED, '炮')
        put(7, 7, RED, '炮')
        for (file in 0 until FILES step 2) {
            put(file, 3, BLACK, '卒')
            put(file, 6, RED, '兵')
        }
        redToMove = true
    }

    private fun put(file: Int, rank: Int, color: Int, label: Char) {
        val index = rank * FILES + file
        colors[index] = color
        labels[index] = label
    }

    /**
     * 重置棋盘：摆回开局，重新由红方先走。
     */
    fun reset() {
        setupInitialPosition()
        dragging = false
        dragColor = EMPTY
        dragFrom = -1
        hoverIndex = -1
        invalidate()
    }

    // ------------------------------------------------------------------ 尺寸

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return

        val g = ChessGeometry(w.toFloat(), h.toFloat())
        geo = g
        boardRect.set(g.boardLeft, g.boardTop, g.boardLeft + g.boardWidth, g.boardTop + g.boardHeight)

        linePaint.strokeWidth = max(dp(1f), g.cell * 0.03f)
        redPaint.strokeWidth = max(dp(2f), g.cell * 0.045f)
        blackPaint.strokeWidth = max(dp(2f), g.cell * 0.045f)
        activeBoxPaint.strokeWidth = dp(2f)
        hoverPaint.strokeWidth = max(dp(2f), g.cell * 0.06f)
        blockedPaint.strokeWidth = max(dp(2f), g.cell * 0.06f)
        riverTextPaint.textSize = g.cell * 0.42f
        indicatorTextPaint.textSize = max(sp(16f), g.cell * 0.42f)
    }

    private fun dp(value: Float) = value * density

    private fun sp(value: Float) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, value, resources.displayMetrics)

    private fun pieceRadius(g: ChessGeometry) = g.cell * 0.42f

    private fun currentColor() = if (redToMove) RED else BLACK

    // ------------------------------------------------------------------ 绘制

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val g = geo ?: return

        canvas.drawRect(boardRect, boardFillPaint)
        drawGrid(canvas, g)
        drawPalaces(canvas, g)
        drawRiverText(canvas, g)
        drawPieces(canvas, g)
        drawHover(canvas, g)
        drawSideBadge(canvas, g, black = true)
        drawSideBadge(canvas, g, black = false)
        drawDraggedPiece(canvas, g)
    }

    private fun drawGrid(canvas: Canvas, g: ChessGeometry) {
        val left = g.gridX(0)
        val right = g.gridX(g.cols - 1)
        val top = g.gridY(0)
        val bottom = g.gridY(g.rows - 1)

        // 外框是完整的一圈，楚河汉界只打断里面的线。
        canvas.drawRect(left, top, right, bottom, linePaint)

        for (col in 1 until g.cols - 1) {
            val x = g.gridX(col)
            if (g.rotated) {
                canvas.drawLine(x, top, x, bottom, linePaint)
            } else {
                // 竖向的线在楚河汉界处断开
                canvas.drawLine(x, top, x, g.riverStart, linePaint)
                canvas.drawLine(x, g.riverEnd, x, bottom, linePaint)
            }
        }
        for (row in 1 until g.rows - 1) {
            val y = g.gridY(row)
            if (g.rotated) {
                // 棋盘转了 90° 时，断开的换成横向的线
                canvas.drawLine(left, y, g.riverStart, y, linePaint)
                canvas.drawLine(g.riverEnd, y, right, y, linePaint)
            } else {
                canvas.drawLine(left, y, right, y, linePaint)
            }
        }
    }

    /** 两端的九宫斜线（file 3..5，rank 0..2 和 7..9）。 */
    private fun drawPalaces(canvas: Canvas, g: ChessGeometry) {
        for (baseRank in intArrayOf(0, 7)) {
            canvas.drawLine(
                g.pieceX(3, baseRank), g.pieceY(3, baseRank),
                g.pieceX(5, baseRank + 2), g.pieceY(5, baseRank + 2),
                linePaint,
            )
            canvas.drawLine(
                g.pieceX(5, baseRank), g.pieceY(5, baseRank),
                g.pieceX(3, baseRank + 2), g.pieceY(3, baseRank + 2),
                linePaint,
            )
        }
    }

    /** 楚河汉界四个字，跟着棋盘方向走。 */
    private fun drawRiverText(canvas: Canvas, g: ChessGeometry) {
        val metrics = riverTextPaint.fontMetrics
        val offset = -(metrics.ascent + metrics.descent) / 2f
        val start = g.riverStart
        val end = g.riverEnd

        for (i in RIVER_TEXTS.indices) {
            if (g.rotated) {
                // 河界是竖着的一条带子，字也跟着转 90°（偏移量同样要跟着转）
                val x = (start + end) / 2f + offset
                val y = g.boardTop + g.boardHeight * RIVER_POSITIONS[i]
                canvas.save()
                canvas.rotate(90f, x, y)
                canvas.drawText(RIVER_TEXTS[i], x, y, riverTextPaint)
                canvas.restore()
            } else {
                val x = g.boardLeft + g.boardWidth * RIVER_POSITIONS[i]
                val y = (start + end) / 2f + offset
                canvas.drawText(RIVER_TEXTS[i], x, y, riverTextPaint)
            }
        }
    }

    private fun drawPieces(canvas: Canvas, g: ChessGeometry) {
        val radius = pieceRadius(g)
        // 轮到谁走，整盘棋子的字就朝着谁（竖屏时就是 0° / 180°）。
        val textRotation = g.pieceTextRotation(redToMove)
        for (rank in 0 until RANKS) {
            for (file in 0 until FILES) {
                val index = rank * FILES + file
                val color = colors[index]
                if (color == EMPTY) continue
                drawPiece(
                    canvas,
                    g.pieceX(file, rank),
                    g.pieceY(file, rank),
                    radius,
                    color,
                    labels[index],
                    255,
                    textRotation,
                )
            }
        }
    }

    private fun drawPiece(
        canvas: Canvas,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Int,
        label: Char,
        alpha: Int,
        textRotation: Float = 0f,
    ) {
        val ring = if (color == RED) redPaint else blackPaint
        val savedRingAlpha = ring.alpha
        val savedFaceAlpha = pieceFacePaint.alpha
        ring.alpha = alpha
        pieceFacePaint.alpha = alpha

        canvas.drawCircle(cx, cy, radius, pieceFacePaint)
        canvas.drawCircle(cx, cy, radius - ring.strokeWidth / 2f, ring)

        pieceTextPaint.color = ring.color
        pieceTextPaint.alpha = alpha
        pieceTextPaint.textSize = radius * 1.1f
        val metrics = pieceTextPaint.fontMetrics
        val baseline = cy - (metrics.ascent + metrics.descent) / 2f

        // 绕棋子中心转，所以文字转完还是正好居中在棋子上。
        val rotate = textRotation != 0f
        if (rotate) {
            canvas.save()
            canvas.rotate(textRotation, cx, cy)
        }
        canvas.drawText(label.toString(), cx, baseline, pieceTextPaint)
        if (rotate) canvas.restore()

        ring.alpha = savedRingAlpha
        pieceFacePaint.alpha = savedFaceAlpha
        pieceTextPaint.alpha = 255
    }

    private fun drawHover(canvas: Canvas, g: ChessGeometry) {
        if (!dragging || hoverIndex < 0) return
        // 该自己走、且目标不是自己的子（空格或对方子）⇒ 能落下；其余情况松手会弹回。
        val occupant = colors[hoverIndex]
        val canDrop = dragColor == currentColor() && occupant != dragColor
        val paint = if (canDrop) hoverPaint else blockedPaint
        val file = hoverIndex % FILES
        val rank = hoverIndex / FILES
        canvas.drawCircle(g.pieceX(file, rank), g.pieceY(file, rank), pieceRadius(g) * 1.12f, paint)
    }

    /**
     * 棋盘外空出来的那一端挂一方的小牌子：一枚棋子 + 这一方的名字。
     * 轮到谁走，谁的牌子就被黄色方框圈住；牌子里的棋子和字始终和棋盘上的棋子一个颜色，不变暗。
     * 牌子上的字朝着坐在那一端的玩家转，所以对面那家看到的是正的。
     */
    private fun drawSideBadge(canvas: Canvas, g: ChessGeometry, black: Boolean) {
        val strip = g.badgeStrip
        if (strip <= 0f) return

        val isActive = (currentColor() == BLACK) == black
        val radius = min(g.cell * 0.42f, strip * 0.38f)
        val label = if (black) "黑方" else "红方"
        val gap = radius * 0.5f
        val textWidth = indicatorTextPaint.measureText(label)
        val groupWidth = radius * 2f + gap + textWidth

        val anchorX = g.sideAnchorX(black)
        val anchorY = g.sideAnchorY(black)

        canvas.save()
        canvas.rotate(g.sideTextRotation(black), anchorX, anchorY)

        val left = anchorX - groupWidth / 2f
        val pieceCx = left + radius
        indicatorBounds.set(left, anchorY - radius, left + groupWidth, anchorY + radius)
        indicatorBounds.inset(-radius * 0.45f, -radius * 0.45f)
        if (isActive) canvas.drawRect(indicatorBounds, activeBoxPaint)

        // 和棋盘上的棋子完全同一套画法（同样的底色、描边和字色），保证看得清。
        drawPiece(
            canvas,
            pieceCx,
            anchorY,
            radius,
            if (black) BLACK else RED,
            if (black) '将' else '帅',
            255,
        )

        val metrics = indicatorTextPaint.fontMetrics
        canvas.drawText(
            label,
            pieceCx + radius + gap,
            anchorY - (metrics.ascent + metrics.descent) / 2f,
            indicatorTextPaint,
        )

        canvas.restore()
    }

    private fun drawDraggedPiece(canvas: Canvas, g: ChessGeometry) {
        if (!dragging) return
        // 拖在手上的这颗子，字也一样朝着当前该走的一方。
        drawPiece(
            canvas,
            dragX,
            dragY,
            pieceRadius(g),
            dragColor,
            dragLabel,
            255,
            g.pieceTextRotation(redToMove),
        )
    }

    // ------------------------------------------------------------------ 触摸

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        val g = geo ?: return false
        val x = event.x
        val y = event.y

        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                val index = g.indexAt(x, y)
                if (index < 0) return false
                val color = colors[index]
                if (color == EMPTY) return false
                // 棋盘上的子谁都能拿起来（不看轮次），但见 dropAt：不该这一方下就会弹回原位。

                dragging = true
                dragFrom = index
                dragColor = color
                dragLabel = labels[index]
                colors[index] = EMPTY
                labels[index] = ' '
                dragX = x
                dragY = y
                hoverIndex = index
                parent?.requestDisallowInterceptTouchEvent(true)
                invalidate()
                return true
            }

            MotionEvent.ACTION_MOVE -> {
                if (!dragging) return false
                dragX = x
                dragY = y
                hoverIndex = g.indexAt(x, y)
                invalidate()
                return true
            }

            MotionEvent.ACTION_UP -> {
                if (!dragging) return false
                dropAt(g, x, y)
                dragging = false
                dragColor = EMPTY
                dragFrom = -1
                hoverIndex = -1
                invalidate()
                return true
            }

            MotionEvent.ACTION_CANCEL -> {
                if (!dragging) return false
                restoreDraggedPiece()
                dragging = false
                dragColor = EMPTY
                dragFrom = -1
                hoverIndex = -1
                invalidate()
                return true
            }
        }
        return super.onTouchEvent(event)
    }

    /**
     * 松手：
     *  - 拖出棋盘（松手时不在棋盘内）⇒ 这个子被吃掉，直接消失，不换手；
     *  - 松在原位（点一下没动）⇒ 不算走棋，不换手；
     *  - 不是这一方该走 ⇒ 退回原位（不该自己下的时候不能真的走棋）；
     *  - 该自己走时走到对方子上 ⇒ 直接把对方子吃掉，自己占住这一格并换手；
     *  - 走到自己的子上 / 其余放不下的情况 ⇒ 退回原位；
     *  - 空格 ⇒ 落子并换手。
     */
    private fun dropAt(g: ChessGeometry, x: Float, y: Float) {
        val target = g.indexAt(x, y)
        if (target < 0) return // 被吃了：拿起来时就已从盘上移除，这里什么都不做
        if (target == dragFrom || dragColor != currentColor()) {
            restoreDraggedPiece()
            return
        }
        if (colors[target] == dragColor) {
            // 自己的子占着这一格，放不下
            restoreDraggedPiece()
            return
        }
        // 空位就直接落子；对方子则把它吃掉（直接覆盖）
        colors[target] = dragColor
        labels[target] = dragLabel
        redToMove = !redToMove
    }

    private fun restoreDraggedPiece() {
        if (dragFrom < 0) return
        colors[dragFrom] = dragColor
        labels[dragFrom] = dragLabel
    }
}
