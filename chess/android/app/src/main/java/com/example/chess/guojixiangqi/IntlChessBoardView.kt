package com.example.chess.guojixiangqi

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
 * 国际象棋页。
 *
 * 棋盘：min(w,h) 的正方形居中，8 × 8 个方格，标准棋盘配色（浅格 #F0D9B5 / 深格 #B58863），
 * 白方在下、黑方在上（横屏时整块转 90°，黑方在左、白方在右）。
 *
 * 规则（和另外几种棋一致）：
 *  - 不做任何走法判断，只判断轮次（白先）；
 *  - 棋盘上的子谁都能拿起来拖，但「不该这一方下」的时候松手会弹回原位；
 *  - 该自己下时走到对方子的位置 = 直接吃掉对方子；
 *  - 把子拖出棋盘 = 这个子被吃掉，直接消失（不换手）；
 *  - 走到自己的子上 = 放不下，弹回原位。
 */
class IntlChessBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    companion object {
        const val FILES = IntlChessGeometry.FILES
        const val RANKS = IntlChessGeometry.RANKS

        private const val EMPTY = 0
        private const val WHITE = 1
        private const val BLACK = 2

        /** 棋子用实心字形，靠颜色区分黑白。 */
        private val GLYPHS = mapOf(
            'k' to "♚",
            'q' to "♛",
            'r' to "♜",
            'b' to "♝",
            'n' to "♞",
            'p' to "♟",
        )

        /** 底线从左到右：车 马 象 后 王 象 马 车。 */
        private val BACK_RANK = charArrayOf('r', 'n', 'b', 'q', 'k', 'b', 'n', 'r')
    }

    // ------------------------------------------------------------------ 状态

    /** 下标 = rank * FILES + file。 */
    private val colors = IntArray(FILES * RANKS)
    private val types = CharArray(FILES * RANKS)

    /** 白先。 */
    private var whiteToMove = true

    // ------------------------------------------------------------------ 几何

    private var geo: IntlChessGeometry? = null
    private val boardRect = RectF()

    // ------------------------------------------------------------------ 拖动

    private var dragging = false
    private var dragColor = EMPTY
    private var dragType = ' '
    private var dragFrom = -1
    private var dragX = 0f
    private var dragY = 0f

    /** 手指悬停的格子下标，-1 表示不在棋盘内。 */
    private var hoverIndex = -1

    // ------------------------------------------------------------------ 画笔

    private val density = resources.displayMetrics.density

    private val lightSquarePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFF0D9B5.toInt() // 标准棋盘浅格
    }
    private val darkSquarePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFB58863.toInt() // 标准棋盘深格
    }
    private val boardBorderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF6B4A2F.toInt()
    }

    /** 白子：白色填充 + 深色描边，浅格深格上都看得清。 */
    private val whiteGlyphFill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFFFFFFF.toInt()
        textAlign = Paint.Align.CENTER
    }
    private val whiteGlyphStroke = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF3A3226.toInt()
        textAlign = Paint.Align.CENTER
        strokeJoin = Paint.Join.ROUND
    }

    /** 黑子：近黑填充 + 浅色描边。 */
    private val blackGlyphFill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFF1B1B1B.toInt()
        textAlign = Paint.Align.CENTER
    }
    private val blackGlyphStroke = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFEFE6D5.toInt()
        textAlign = Paint.Align.CENTER
        strokeJoin = Paint.Join.ROUND
    }

    private val labelTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFFFFFFF.toInt() // 牌子写在棋盘外的黑底上
        textAlign = Paint.Align.LEFT
    }

    /** 轮到的一方：棋子 + 名字外面的黄色方框。 */
    private val activeBoxPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFE6B24C.toInt()
    }

    /** 悬停在空格上。 */
    private val hoverPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x40E6B24C.toInt()
    }

    /** 悬停在已经有子的格子上（会被弹回原位）。 */
    private val blockedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x40C62828.toInt()
    }

    private val badgeBounds = RectF()

    init {
        setBackgroundColor(0xFF000000.toInt())
        setupInitialPosition()
    }

    // ------------------------------------------------------------------ 初始局面

    private fun setupInitialPosition() {
        colors.fill(EMPTY)
        types.fill(' ')
        for (file in 0 until FILES) {
            put(file, 0, BLACK, BACK_RANK[file])
            put(file, 1, BLACK, 'p')
            put(file, 6, WHITE, 'p')
            put(file, 7, WHITE, BACK_RANK[file])
        }
        whiteToMove = true
    }

    private fun put(file: Int, rank: Int, color: Int, type: Char) {
        val index = rank * FILES + file
        colors[index] = color
        types[index] = type
    }

    /** 重置：摆回开局，重新白先。 */
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

        val g = IntlChessGeometry(w.toFloat(), h.toFloat())
        geo = g
        boardRect.set(g.boardLeft, g.boardTop, g.boardLeft + g.boardSize, g.boardTop + g.boardSize)

        boardBorderPaint.strokeWidth = max(dp(2f), g.cell * 0.05f)
        whiteGlyphStroke.strokeWidth = max(dp(2f), g.cell * 0.035f)
        blackGlyphStroke.strokeWidth = max(dp(1.5f), g.cell * 0.022f)
        activeBoxPaint.strokeWidth = dp(2f)
        labelTextPaint.textSize = max(sp(16f), g.cell * 0.42f)
    }

    private fun dp(value: Float) = value * density

    private fun sp(value: Float) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, value, resources.displayMetrics)

    private fun currentColor() = if (whiteToMove) WHITE else BLACK

    private fun glyphSize(g: IntlChessGeometry) = g.cell * 0.8f

    // ------------------------------------------------------------------ 绘制

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val g = geo ?: return

        drawSquares(canvas, g)
        drawPieces(canvas, g)
        drawHover(canvas, g)
        drawSideBadge(canvas, g, black = true)
        drawSideBadge(canvas, g, black = false)
        drawDraggedPiece(canvas, g)
    }

    private fun drawSquares(canvas: Canvas, g: IntlChessGeometry) {
        for (rank in 0 until RANKS) {
            for (file in 0 until FILES) {
                val left = g.squareLeft(file, rank)
                val top = g.squareTop(file, rank)
                val paint = if (g.isDarkSquare(file, rank)) darkSquarePaint else lightSquarePaint
                canvas.drawRect(left, top, left + g.cell, top + g.cell, paint)
            }
        }
        val inset = boardBorderPaint.strokeWidth / 2f
        canvas.drawRect(
            boardRect.left + inset,
            boardRect.top + inset,
            boardRect.right - inset,
            boardRect.bottom - inset,
            boardBorderPaint,
        )
    }

    private fun drawPieces(canvas: Canvas, g: IntlChessGeometry) {
        val rotation = g.pieceTextRotation(whiteToMove)
        val size = glyphSize(g)
        for (index in colors.indices) {
            val color = colors[index]
            if (color == EMPTY) continue
            val file = index % FILES
            val rank = index / FILES
            drawGlyph(canvas, g.squareX(file, rank), g.squareY(file, rank), size, color, types[index], rotation)
        }
    }

    /** 画一枚棋子：先描边再填色，两种底色上都清楚。 */
    private fun drawGlyph(
        canvas: Canvas,
        cx: Float,
        cy: Float,
        size: Float,
        color: Int,
        type: Char,
        rotation: Float,
    ) {
        val glyph = GLYPHS[type] ?: return
        val fill = if (color == WHITE) whiteGlyphFill else blackGlyphFill
        val stroke = if (color == WHITE) whiteGlyphStroke else blackGlyphStroke
        fill.textSize = size
        stroke.textSize = size

        val baseline = cy - (fill.fontMetrics.ascent + fill.fontMetrics.descent) / 2f
        val rotate = rotation != 0f
        if (rotate) {
            canvas.save()
            canvas.rotate(rotation, cx, cy)
        }
        canvas.drawText(glyph, cx, baseline, stroke)
        canvas.drawText(glyph, cx, baseline, fill)
        if (rotate) canvas.restore()
    }

    private fun drawHover(canvas: Canvas, g: IntlChessGeometry) {
        if (!dragging || hoverIndex < 0) return
        val file = hoverIndex % FILES
        val rank = hoverIndex / FILES
        val left = g.squareLeft(file, rank)
        val top = g.squareTop(file, rank)
        // 该自己走、且目标不是自己的子（空格或对方子）⇒ 能落下；其余情况松手会弹回。
        val canDrop = dragColor == currentColor() && colors[hoverIndex] != dragColor
        val paint = if (canDrop) hoverPaint else blockedPaint
        canvas.drawRect(left, top, left + g.cell, top + g.cell, paint)
    }

    /**
     * 棋盘外空出来的那一端挂一方的小牌子：一枚王 + 这一方的名字。
     * 轮到谁走，谁的牌子就被黄色方框圈住；牌子上的字朝着坐在那一端的玩家转。
     */
    private fun drawSideBadge(canvas: Canvas, g: IntlChessGeometry, black: Boolean) {
        val strip = g.badgeStrip
        if (strip <= 0f) return

        val isActive = (currentColor() == BLACK) == black
        val radius = min(g.cell * 0.42f, strip * 0.38f)
        val label = if (black) "黑方" else "白方"
        val gap = radius * 0.5f
        val textWidth = labelTextPaint.measureText(label)
        val groupWidth = radius * 2f + gap + textWidth

        val anchorX = g.sideAnchorX(black)
        val anchorY = g.sideAnchorY(black)

        canvas.save()
        canvas.rotate(g.sideTextRotation(black), anchorX, anchorY)

        val left = anchorX - groupWidth / 2f
        val pieceCx = left + radius
        badgeBounds.set(left, anchorY - radius, left + groupWidth, anchorY + radius)
        badgeBounds.inset(-radius * 0.45f, -radius * 0.45f)
        if (isActive) canvas.drawRect(badgeBounds, activeBoxPaint)

        drawGlyph(
            canvas,
            pieceCx,
            anchorY,
            radius * 2f,
            if (black) BLACK else WHITE,
            'k',
            0f,
        )

        val metrics = labelTextPaint.fontMetrics
        canvas.drawText(
            label,
            pieceCx + radius + gap,
            anchorY - (metrics.ascent + metrics.descent) / 2f,
            labelTextPaint,
        )

        canvas.restore()
    }

    private fun drawDraggedPiece(canvas: Canvas, g: IntlChessGeometry) {
        if (!dragging) return
        drawGlyph(
            canvas,
            dragX,
            dragY,
            glyphSize(g) * 1.1f,
            dragColor,
            dragType,
            g.pieceTextRotation(whiteToMove),
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
                // 棋盘上的子谁都能拿起来（不看轮次），能不能真的走掉见 dropAt。

                dragging = true
                dragFrom = index
                dragColor = color
                dragType = types[index]
                colors[index] = EMPTY
                types[index] = ' '
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
     *  - 拖出棋盘 ⇒ 这个子被吃掉，直接消失，不换手；
     *  - 松在原位（点一下没动）⇒ 放回去，不换手；
     *  - 不是这一方该走 ⇒ 弹回原位；
     *  - 该自己走时走到对方子上 ⇒ 直接把对方子吃掉，自己占住这一格并换手；
     *  - 走到自己的子上 ⇒ 放不下，弹回原位。
     */
    private fun dropAt(g: IntlChessGeometry, x: Float, y: Float) {
        val target = g.indexAt(x, y)
        if (target < 0) return // 被吃了：拿起来时就已从盘上移除
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
        types[target] = dragType
        whiteToMove = !whiteToMove
    }

    private fun restoreDraggedPiece() {
        if (dragFrom < 0) return
        colors[dragFrom] = dragColor
        types[dragFrom] = dragType
    }
}
