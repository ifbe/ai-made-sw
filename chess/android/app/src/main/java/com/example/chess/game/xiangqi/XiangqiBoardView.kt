package com.example.chess.game.xiangqi

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
 * 象棋页。**只负责画和报手势**，盘面数据、轮次、吃子、落子全在 [XiangqiGame] 里。
 *
 * 布局规则见 [XiangqiGeometry]：9 路 × 10 路，短边 9 路 / 长边 10 路，棋盘居中，
 * 落点在各自格子的正中心；中间留出楚河汉界，两端画出九宫斜线。
 */
class XiangqiBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    companion object {
        const val FILES = XiangqiGame.FILES
        const val RANKS = XiangqiGame.RANKS

        private const val EMPTY = XiangqiGame.EMPTY
        private const val RED = XiangqiGame.RED
        private const val BLACK = XiangqiGame.BLACK

        /** 楚河汉界：两半带子里的字和它们的位置（0..1）。 */
        private val RIVER_TEXTS = arrayOf("楚 河", "汉 界")
        private val RIVER_POSITIONS = floatArrayOf(0.25f, 0.75f)
    }

    /** 盘面数据 + 逻辑。 */
    private val game = XiangqiGame()

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

    private var geo: XiangqiGeometry? = null
    private val boardRect = RectF()

    // ------------------------------------------------------------------ 手势

    /** 本机正在拖（只用于决定要不要接后续的 MOVE/UP）。 */
    private var dragging = false

    /** 手指悬停的落点下标，-1 表示不在棋盘内。 */
    private var hoverIndex = -1

    // ------------------------------------------------------------------ 画笔

    private val density = resources.displayMetrics.density

    private val boardFillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFFFE999.toInt() // 棋盘底色：鹅黄
    }
    private val boardBorderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFE0C67E.toInt() // 比底色稍深一点的边
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

    /** 悬停在能落下的落点上。 */
    private val hoverPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF3A3226.toInt()
    }

    /** 悬停在放不下的落点上（自己的子 / 不该自己走）。 */
    private val blockedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFC62828.toInt()
    }

    private val indicatorTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFFFFFFF.toInt() // 提示画在棋盘外的黑底上，用浅色字
        textAlign = Paint.Align.LEFT
    }
    private val indicatorBounds = RectF()

    // ------------------------------------------------------------------ 尺寸

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return

        val g = XiangqiGeometry(w.toFloat(), h.toFloat())
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

    private fun pieceRadius(g: XiangqiGeometry) = g.cell * 0.42f

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

    private fun drawGrid(canvas: Canvas, g: XiangqiGeometry) {
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
    private fun drawPalaces(canvas: Canvas, g: XiangqiGeometry) {
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
    private fun drawRiverText(canvas: Canvas, g: XiangqiGeometry) {
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

    private fun drawPieces(canvas: Canvas, g: XiangqiGeometry) {
        val radius = pieceRadius(g)
        // 轮到谁走，整盘棋子的字就朝着谁（竖屏时就是 0° / 180°）。
        val textRotation = g.pieceTextRotation(game.redToMove)
        val draggingFrom = game.drag?.from ?: -1

        for (rank in 0 until RANKS) {
            for (file in 0 until FILES) {
                val index = rank * FILES + file
                if (index == draggingFrom) continue
                val color = game.colors[index]
                if (color == EMPTY) continue
                val piece = game.pieces[index] ?: continue
                drawPiece(
                    canvas,
                    g.pieceX(file, rank),
                    g.pieceY(file, rank),
                    radius,
                    color,
                    piece.nameOf(color),
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

    private fun drawHover(canvas: Canvas, g: XiangqiGeometry) {
        if (!dragging || hoverIndex < 0) return
        // 该自己走、且落点不是自己的子（空格或对方子）⇒ 能落下；其余情况松手会弹回。
        val overlay = game.drag
        val canDrop = overlay != null &&
            overlay.piece.side == game.turn &&
            game.colors[hoverIndex] != XiangqiGame.colorOf(overlay.piece.side)
        val paint = if (canDrop) hoverPaint else blockedPaint
        val file = hoverIndex % FILES
        val rank = hoverIndex / FILES
        canvas.drawCircle(g.pieceX(file, rank), g.pieceY(file, rank), pieceRadius(g) * 1.12f, paint)
    }

    /**
     * 棋盘外空出来的那一端挂一方的小牌子：一枚棋子 + 这一方的名字。
     * 轮到谁走，谁的牌子就被黄色方框圈住；牌子上的字朝着坐在那一端的玩家转。
     */
    private fun drawSideBadge(canvas: Canvas, g: XiangqiGeometry, black: Boolean) {
        val strip = g.badgeStrip
        if (strip <= 0f) return

        val isActive = (game.turn == if (black) 1 else 0)
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

        drawPiece(
            canvas,
            pieceCx,
            anchorY,
            radius,
            if (black) BLACK else RED,
            if (black) XiangqiPiece.KING.black else XiangqiPiece.KING.red,
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

    private fun drawDraggedPiece(canvas: Canvas, g: XiangqiGeometry) {
        val overlay: DragOverlay = game.drag ?: return
        drawPiece(
            canvas,
            g.pxOfCell(overlay.cellX, overlay.cellY),
            g.pyOfCell(overlay.cellX, overlay.cellY),
            pieceRadius(g),
            XiangqiGame.colorOf(overlay.piece.side),
            overlay.piece.name.firstOrNull() ?: return,
            255,
            g.pieceTextRotation(game.redToMove),
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
