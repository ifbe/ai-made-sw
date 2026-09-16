package com.example.chess.game.guojixiangqi

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.util.TypedValue
import android.view.MotionEvent
import android.view.View
import com.example.chess.game.share.core.DragOverlay
import com.example.chess.game.share.core.Gesture
import com.example.chess.game.share.core.MoveEventSink
import com.example.chess.game.share.protocol.MoveEvent
import kotlin.math.max
import kotlin.math.min

/**
 * 国际象棋页。**只负责画和报手势**，盘面数据、轮次、吃子、落子全在 [IntlChessGame] 里。
 *
 * 棋盘：min(w,h) 的正方形居中，8 × 8 个方格，标准棋盘配色（浅格 #F0D9B5 / 深格 #B58863），
 * 白方在下、黑方在上（横屏时整块转 90°，黑方在左、白方在右）。
 */
class IntlChessBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    companion object {
        const val FILES = IntlChessGame.FILES
        const val RANKS = IntlChessGame.RANKS

        private const val EMPTY = IntlChessGame.EMPTY
        private const val WHITE = IntlChessGame.WHITE
        private const val BLACK = IntlChessGame.BLACK

        /** 棋子用实心字形，靠颜色区分黑白。 */
        private val GLYPHS = mapOf(
            'K' to "♚",
            'Q' to "♛",
            'R' to "♜",
            'B' to "♝",
            'N' to "♞",
            'P' to "♟",
        )
    }

    /** 盘面数据 + 逻辑。 */
    private val game = IntlChessGame()

    /** 本地事件的出口：联网时把 WebSocket 的 Session 接到这里。 */
    var eventSink: MoveEventSink? = null

    /** 收到对端事件时调用（下一轮由 Session 驱动）。 */
    fun submitRemote(event: MoveEvent) {
        game.apply(event)
        invalidate()
    }

    /** 全量棋盘快照。 */
    fun snapshot() = game.snapshot()

    private fun emit(events: List<MoveEvent>) {
        if (events.isEmpty()) return
        eventSink?.onLocalEvents(events)
    }

    // ------------------------------------------------------------------ 几何

    private var geo: IntlChessGeometry? = null
    private val boardRect = RectF()

    // ------------------------------------------------------------------ 手势

    /** 本机正在拖（只用于决定要不要接后续的 MOVE/UP）。 */
    private var dragging = false

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

    /** 悬停在能落下的格子上。 */
    private val hoverPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x40E6B24C.toInt()
    }

    /** 悬停在放不下的格子上（自己的子 / 不该自己走）。 */
    private val blockedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x40C62828.toInt()
    }

    private val badgeBounds = RectF()

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

    private fun glyphSize(g: IntlChessGeometry) = g.cell * 0.8f

    /** 重开一局（事件交给外部广播）。 */
    fun reset() {
        emit(game.reset())
        dragging = false
        hoverIndex = -1
        invalidate()
    }

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
        val rotation = g.pieceTextRotation(game.whiteToMove)
        val size = glyphSize(g)
        val draggingFrom = game.drag?.from ?: -1
        for (index in game.colors.indices) {
            if (index == draggingFrom) continue
            val color = game.colors[index]
            if (color == EMPTY) continue
            val code = game.types[index]?.code ?: continue
            drawGlyph(
                canvas,
                g.squareX(index % FILES, index / FILES),
                g.squareY(index % FILES, index / FILES),
                size,
                color,
                code,
                rotation,
            )
        }
    }

    /** 画一枚棋子：先描边再填色，两种底色上都清楚。 */
    private fun drawGlyph(
        canvas: Canvas,
        cx: Float,
        cy: Float,
        size: Float,
        color: Int,
        code: Char,
        rotation: Float,
    ) {
        val glyph = GLYPHS[code] ?: return
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
        // 该自己走、且落点不是自己的子（空格或对方子）⇒ 能落下；其余情况松手会弹回。
        val overlay = game.drag
        val canDrop = overlay != null &&
            overlay.piece.side == game.turn &&
            game.colors[hoverIndex] != IntlChessGame.colorOf(overlay.piece.side)
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

        val isActive = (IntlChessGame.colorOf(game.turn) == BLACK) == black
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
            'K',
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
        val overlay: DragOverlay = game.drag ?: return
        drawGlyph(
            canvas,
            g.pxOfCell(overlay.cellX, overlay.cellY),
            g.pyOfCell(overlay.cellX, overlay.cellY),
            glyphSize(g) * 1.1f,
            IntlChessGame.colorOf(overlay.piece.side),
            overlay.piece.name.firstOrNull() ?: return,
            g.pieceTextRotation(game.whiteToMove),
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
                if (index < 0 || !game.hasPieceAt(index)) return false
                dragging = true
                hoverIndex = index
                emit(game.onGesture(Gesture.PickUp(index)))
                parent?.requestDisallowInterceptTouchEvent(true)
                invalidate()
                return true
            }

            MotionEvent.ACTION_MOVE -> {
                if (!dragging) return false
                hoverIndex = g.indexAt(x, y)
                emit(game.onGesture(Gesture.DragTo(g.cellXAt(x, y), g.cellYAt(x, y))))
                invalidate()
                return true
            }

            MotionEvent.ACTION_UP -> {
                if (!dragging) return false
                emit(game.onGesture(Gesture.Drop(g.cellXAt(x, y), g.cellYAt(x, y), g.indexAt(x, y))))
                dragging = false
                hoverIndex = -1
                invalidate()
                return true
            }

            MotionEvent.ACTION_CANCEL -> {
                if (!dragging) return false
                emit(game.onGesture(Gesture.Cancel))
                dragging = false
                hoverIndex = -1
                invalidate()
                return true
            }
        }
        return super.onTouchEvent(event)
    }
}
