package com.example.chess.game.share.stone

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.util.TypedValue
import android.view.MotionEvent
import android.view.View
import com.example.chess.R
import com.example.chess.game.share.core.DragOverlay
import com.example.chess.game.share.core.Gesture
import com.example.chess.game.share.core.MoveEventSink
import com.example.chess.game.share.protocol.GameKind
import com.example.chess.game.share.protocol.MoveEvent
import kotlin.math.max
import kotlin.math.min

/**
 * 围棋 / 五子棋共用的「石头棋盘」页。**只负责画和报手势**，
 * 盘面数据、轮次、吃子、落子全在 [StoneGame] 里（纯 Kotlin，可单测）。
 * 具体某种棋（围棋 19 路 / 五子棋 15 路）见 `weiqi.GoBoardView`、`wuziqi.GomokuBoardView`。
 *
 * 布局规则（见 [BoardGeometry]）：
 *  - 页面底色纯黑；
 *  - 棋盘是边长 = min(视图宽, 视图高)、中心 = 屏幕中心的正方形；
 *  - 正方形等分成 (lines+1) × (lines+1) 个格子，格子正中心就是横竖线交叉点（落点）；
 *  - 正方形外剩下的两侧余量放黑 / 白棋子托盘（圆形 + 剩余数量文字）。
 *
 * 每边多少个落点默认用 [defaultLines]，也可以在 XML 里用 `boardLines` 属性覆盖。
 */
open class StoneBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
    defaultLines: Int = DEFAULT_LINES,
    defaultKind: GameKind = GameKind.WEIQI,
) : View(context, attrs, defStyleAttr) {

    companion object {
        /** 默认每边 19 个落点。 */
        const val DEFAULT_LINES = 19

        private const val EMPTY = StoneGame.EMPTY
        private const val BLACK = StoneGame.BLACK
        private const val WHITE = StoneGame.WHITE
    }

    /** 每边多少个落点（19 路等）。 */
    val lines: Int

    /** 棋盘正方形被等分成的格子数：落点落在每个格子的正中心，所以格子数 = 落点数 + 1。 */
    private val subdivisions: Int

    /** 星位坐标：[col0, row0, col1, row1, ...]。 */
    private val starPoints: IntArray

    /** 盘面数据 + 逻辑。 */
    private val game: StoneGame

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

    private var geo: BoardGeometry? = null
    private val boardRect = RectF()

    /** 复用的矩形：某一方托盘（棋子 + 数量文字）的包围盒，黄框就画在它上面。 */
    private val trayBounds = RectF()

    /** 复用的托盘排版结果，每次绘制 / 命中测试时重新算，避免在 onDraw 里 new 对象。 */
    private var trayStoneCx = 0f
    private var trayStoneCy = 0f
    private var trayTextLeft = 0f
    private var trayTextBaseline = 0f

    // ------------------------------------------------------------------ 手势

    /** 本机正在拖（只用于决定要不要接后续的 MOVE/UP，跟棋局状态无关）。 */
    private var dragging = false

    /** 手指当前悬停的落点下标，-1 表示不在棋盘内。 */
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
        color = 0xFF3A3226.toInt() // 深墨色的横竖线
        strokeCap = Paint.Cap.ROUND
    }
    private val starPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFF3A3226.toInt() // 星位跟线同色
    }
    private val blackStonePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFF0A0A0A.toInt()
    }
    private val whiteStonePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xFFF2F2F2.toInt()
    }
    private val blackRimPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF3A3A3A.toInt()
    }
    private val whiteRimPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF9E9E9E.toInt()
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFFFFFFF.toInt() // 数量写在棋盘外的黑底上，用纯白字看得最清楚
        textAlign = Paint.Align.LEFT
    }

    /** 轮到自己走的那一方：把「棋子 + 数量」圈起来的黄色方框（还可以拖）。 */
    private val activeBoxPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFE6B24C.toInt()
    }

    /** 手指悬停在棋盘空落点上时的提示圈（棋盘是浅底色，所以用深色画）。 */
    private val hoverPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFF3A3226.toInt()
    }

    /** 拖到已经有子的落点上时的提示圈。 */
    private val blockedRingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0xFFC62828.toInt()
    }

    init {
        val typed = context.obtainStyledAttributes(attrs, R.styleable.StoneBoardView)
        lines = try {
            typed.getInt(R.styleable.StoneBoardView_boardLines, defaultLines)
        } finally {
            typed.recycle()
        }
        subdivisions = lines + 1
        starPoints = BoardGeometry.starPoints(lines)
        game = StoneGame(lines, defaultKind)

        setBackgroundColor(0xFF000000.toInt())
    }

    // ------------------------------------------------------------------ 尺寸

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return

        val g = BoardGeometry(w.toFloat(), h.toFloat(), lines, subdivisions)
        geo = g

        boardRect.set(g.boardLeft, g.boardTop, g.boardLeft + g.boardSize, g.boardTop + g.boardSize)

        boardBorderPaint.strokeWidth = max(dp(1f), g.cell * 0.05f)
        linePaint.strokeWidth = max(dp(1f), g.cell * 0.035f)
        blackRimPaint.strokeWidth = max(dp(1f), g.cell * 0.05f)
        whiteRimPaint.strokeWidth = max(dp(1f), g.cell * 0.05f)
        activeBoxPaint.strokeWidth = dp(2f)
        hoverPaint.strokeWidth = max(dp(2f), g.cell * 0.06f)
        blockedRingPaint.strokeWidth = max(dp(2f), g.cell * 0.06f)
        // 数字要看得清，不跟着棋子一起缩小，所以按格子大小 / 15sp 里取大的那个。
        textPaint.textSize = max(sp(15f), g.cell * 0.5f)
    }

    private fun dp(value: Float) = value * density

    private fun sp(value: Float) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, value, resources.displayMetrics)

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

        drawBoardSurface(canvas)
        drawGrid(canvas, g)
        drawPlacedStones(canvas, g)
        drawHover(canvas, g)
        drawTray(canvas, g, BLACK)
        drawTray(canvas, g, WHITE)
        drawDraggedStone(canvas, g)
    }

    private fun drawBoardSurface(canvas: Canvas) {
        canvas.drawRect(boardRect, boardFillPaint)
        val inset = boardBorderPaint.strokeWidth / 2f
        canvas.drawRect(
            boardRect.left + inset,
            boardRect.top + inset,
            boardRect.right - inset,
            boardRect.bottom - inset,
            boardBorderPaint,
        )
    }

    private fun drawGrid(canvas: Canvas, g: BoardGeometry) {
        val last = lines - 1
        for (i in 0 until lines) {
            val x = g.gridX(i)
            canvas.drawLine(x, g.gridY(0), x, g.gridY(last), linePaint)
            val y = g.gridY(i)
            canvas.drawLine(g.gridX(0), y, g.gridX(last), y, linePaint)
        }

        val starRadius = max(dp(2.5f), g.cell * 0.11f)
        var i = 0
        while (i + 1 < starPoints.size) {
            canvas.drawCircle(g.gridX(starPoints[i]), g.gridY(starPoints[i + 1]), starRadius, starPaint)
            i += 2
        }
    }

    private fun drawPlacedStones(canvas: Canvas, g: BoardGeometry) {
        // 正在被拖（本地或对端）的那颗，原位不画，画在浮层上。
        val draggingFrom = game.drag?.from ?: -1
        for (index in game.grid.indices) {
            if (index == draggingFrom) continue
            val color = game.grid[index]
            if (color == EMPTY) continue
            drawStone(canvas, g.gridX(index % lines), g.gridY(index / lines), g.stoneRadius, color, 255)
        }
    }

    private fun drawStone(canvas: Canvas, cx: Float, cy: Float, radius: Float, color: Int, alpha: Int) {
        val fill = if (color == BLACK) blackStonePaint else whiteStonePaint
        val rim = if (color == BLACK) blackRimPaint else whiteRimPaint
        val savedFillAlpha = fill.alpha
        val savedRimAlpha = rim.alpha
        fill.alpha = alpha
        rim.alpha = alpha
        canvas.drawCircle(cx, cy, radius, fill)
        canvas.drawCircle(cx, cy, radius - rim.strokeWidth / 2f, rim)
        fill.alpha = savedFillAlpha
        rim.alpha = savedRimAlpha
    }

    private fun drawHover(canvas: Canvas, g: BoardGeometry) {
        if (!dragging || hoverIndex < 0) return
        // 该自己走、且落点是空的 ⇒ 能落下；其余情况松手会弹回。
        val overlay = game.drag
        val canDrop = overlay != null &&
            overlay.piece.side == game.turn &&
            game.grid[hoverIndex] == EMPTY
        val paint = if (canDrop) hoverPaint else blockedRingPaint
        canvas.drawCircle(
            g.gridX(hoverIndex % lines),
            g.gridY(hoverIndex / lines),
            g.stoneRadius * 1.15f,
            paint,
        )
    }

    private fun drawTray(canvas: Canvas, g: BoardGeometry, color: Int) {
        val isActive = (if (color == BLACK) 0 else 1) == game.turn
        val label = "x${game.remainingOf(color)}"
        val radius = g.pieceRadius

        // 先算好棋子圆和数量文字的位置，顺手拿到「棋子 + 数字」的包围盒。
        val bounds = trayLayout(g, color, label)

        // 该走的那一方：用黄色方框把棋子和数量一起圈起来（另一方只是没有黄框，颜色不变暗）。
        if (isActive) canvas.drawRect(bounds, activeBoxPaint)

        // 托盘里的棋子和棋盘上的棋子同一个半径、同一个颜色，白子也不会发灰。
        drawStone(canvas, trayStoneCx, trayStoneCy, radius, color, 255)

        val savedAlign = textPaint.textAlign
        textPaint.textAlign = if (g.trayOnSides) Paint.Align.CENTER else Paint.Align.LEFT
        canvas.drawText(label, trayTextLeft, trayTextBaseline, textPaint)
        textPaint.textAlign = savedAlign
    }

    /**
     * 算出一方托盘的排版：棋子圆心、数量文字的左端 / 基线，以及把两者都包住的矩形（已留内边距）。
     * 结果通过 [trayBounds] 和 tray* 字段返回，避免在 onDraw 里分配对象。
     */
    private fun trayLayout(g: BoardGeometry, color: Int, label: String): RectF {
        val black = color == BLACK
        val radius = g.pieceRadius
        val gap = radius * 0.45f
        val textWidth = textPaint.measureText(label)
        val metrics = textPaint.fontMetrics

        val textLeft: Float
        val textBaseline: Float
        if (g.trayOnSides) {
            // 左右余量很窄：圆放在空带正中间，数量写在圆的正下方并水平居中。
            trayStoneCx = g.trayCenterX(black)
            trayStoneCy = g.trayCenterY(black)
            textLeft = trayStoneCx - textWidth / 2f
            textBaseline = trayStoneCy + radius + gap - metrics.ascent
        } else {
            // 上下余量很宽：数量写在圆的右侧，整组（圆 + 数字）水平居中。
            trayStoneCy = g.trayCenterY(black)
            val groupWidth = radius * 2f + gap + textWidth
            trayStoneCx = width / 2f - groupWidth / 2f + radius
            textLeft = trayStoneCx + radius + gap
            textBaseline = trayStoneCy - (metrics.ascent + metrics.descent) / 2f
        }
        trayTextLeft = textLeft
        trayTextBaseline = textBaseline

        trayBounds.set(
            min(trayStoneCx - radius, textLeft),
            min(trayStoneCy - radius, textBaseline + metrics.ascent),
            max(trayStoneCx + radius, textLeft + textWidth),
            max(trayStoneCy + radius, textBaseline + metrics.descent),
        )
        // 方框比内容再大一圈。
        trayBounds.inset(-radius * 0.4f, -radius * 0.4f)
        return trayBounds
    }

    /** 拖动中的那颗子：位置来自 [DragOverlay]，本地和远端的画法完全一样。 */
    private fun drawDraggedStone(canvas: Canvas, g: BoardGeometry) {
        val overlay: DragOverlay = game.drag ?: return
        drawStone(
            canvas,
            g.pxOfCell(overlay.cellX),
            g.pyOfCell(overlay.cellY),
            g.pieceRadius,
            StoneGame.colorOf(overlay.piece.side),
            255,
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
                // 先看是不是按在盘上的棋子上：是的话谁都能拿起来（不看轮次）。
                val index = g.indexAt(x, y)
                if (index >= 0 && game.hasPieceAt(index)) {
                    dragging = true
                    hoverIndex = index
                    emit(game.onGesture(Gesture.PickUp(index)))
                    parent?.requestDisallowInterceptTouchEvent(true)
                    invalidate()
                    return true
                }

                // 否则看是不是按在该走的那一方的托盘上。
                val side = game.turn
                val color = StoneGame.colorOf(side)
                if (game.remaining(side) <= 0) return false
                if (!hitTray(g, color, x, y)) return false
                dragging = true
                hoverIndex = -1
                // 托盘中心换算成棋盘语义坐标（在棋盘外，对端照样看得见）
                val trayCx = trayStoneCx
                val trayCy = trayStoneCy
                emit(game.onGesture(Gesture.PickUpNew(side, g.cellXAt(trayCx), g.cellYAt(trayCy))))
                parent?.requestDisallowInterceptTouchEvent(true)
                invalidate()
                return true
            }

            MotionEvent.ACTION_MOVE -> {
                if (!dragging) return false
                hoverIndex = g.indexAt(x, y)
                emit(game.onGesture(Gesture.DragTo(g.cellXAt(x), g.cellYAt(y))))
                invalidate()
                return true
            }

            MotionEvent.ACTION_UP -> {
                if (!dragging) return false
                emit(game.onGesture(Gesture.Drop(g.cellXAt(x), g.cellYAt(y), g.indexAt(x, y))))
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

    /**
     * 托盘的可点区域：就是那个「棋子 + 数字」的方框再往外放一点，
     * 所以手指按在黄框里任意位置都能开始拖。
     */
    private fun hitTray(g: BoardGeometry, color: Int, x: Float, y: Float): Boolean {
        val bounds = trayLayout(g, color, "x${game.remainingOf(color)}")
        val slop = dp(12f)
        return x >= bounds.left - slop && x <= bounds.right + slop &&
            y >= bounds.top - slop && y <= bounds.bottom + slop
    }
}
