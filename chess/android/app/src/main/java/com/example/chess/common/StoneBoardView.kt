package com.example.chess.common

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
import kotlin.math.max
import kotlin.math.min

/**
 * 围棋 / 五子棋共用的「石头棋盘」页：把棋子在托盘和棋盘之间拖来拖去。
 * 具体某种棋（围棋 19 路 / 五子棋 15 路）见 `weiqi.GoBoardView`、`wuziqi.GomokuBoardView`。
 *
 * 布局规则（见 [BoardGeometry]）：
 *  - 页面底色纯黑；
 *  - 棋盘是边长 = min(视图宽, 视图高)、中心 = 屏幕中心的正方形；
 *  - 正方形等分成 (lines+1) × (lines+1) 个格子，格子正中心就是横竖线交叉点（落点）；
 *  - 正方形外剩下的两侧余量放黑 / 白棋子托盘（圆形 + 剩余数量文字）。
 *
 * 每边多少个落点默认用 [defaultLines]，也可以在 XML 里用 `boardLines` 属性覆盖。
 *
 * 规则：
 *  - 不做任何吃子 / 提子 / 连五判断，只判断轮次；
 *  - 棋盘上的子谁都能拿起来拖，但「不该这一方下」的时候松手会弹回原位；
 *  - 把盘上的子拖出棋盘 = 这颗子被吃掉，直接消失（不回托盘、不换手）；
 *  - 托盘还是只有该走的那一方能拖，拖到盘上就落子并把数量 -1。
 */
open class StoneBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
    defaultLines: Int = DEFAULT_LINES,
) : View(context, attrs, defStyleAttr) {

    companion object {
        /** 默认每边 19 个落点。 */
        const val DEFAULT_LINES = 19

        /** 每色棋子初始数量。 */
        const val INITIAL_STONES = 180

        private const val EMPTY = 0
        private const val BLACK = 1
        private const val WHITE = 2
    }

    /** 每边多少个落点（19 路等）。 */
    val lines: Int

    /** 棋盘正方形被等分成的格子数：落点落在每个格子的正中心，所以格子数 = 落点数 + 1。 */
    private val subdivisions: Int

    /** 每个落点上的棋子：EMPTY / BLACK / WHITE，下标 = row * lines + col。 */
    private val grid: IntArray

    /** 星位坐标：[col0, row0, col1, row1, ...]。 */
    private val starPoints: IntArray

    // ------------------------------------------------------------------ 状态

    /** 该黑棋走时为 true；黑棋先手。 */
    private var blackToMove = true
    private var blackRemaining = INITIAL_STONES
    private var whiteRemaining = INITIAL_STONES

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

    // ------------------------------------------------------------------ 拖动

    private var dragging = false
    private var dragColor = EMPTY
    private var dragX = 0f
    private var dragY = 0f

    /** true 表示手上这颗是从棋盘上拿起来的（不是从托盘拖出来的新子）。 */
    private var dragFromBoard = false

    /** 从棋盘上拿起来时那颗子原来的落点下标，-1 表示不是从盘上拿的。 */
    private var dragFromIndex = -1

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
        grid = IntArray(lines * lines)
        starPoints = BoardGeometry.starPoints(lines)

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

    private fun remainingOf(color: Int) = if (color == BLACK) blackRemaining else whiteRemaining

    private fun currentColor() = if (blackToMove) BLACK else WHITE

    private fun switchTurn() {
        blackToMove = !blackToMove
    }

    /**
     * 重置棋盘：清空所有棋子，两色可用数量回到初始值，重新由黑棋先走。
     * （没有实现任何规则，所以重置只是把这些状态恢复原样。）
     */
    fun reset() {
        grid.fill(EMPTY)
        blackToMove = true
        blackRemaining = INITIAL_STONES
        whiteRemaining = INITIAL_STONES
        dragging = false
        dragColor = EMPTY
        dragFromBoard = false
        dragFromIndex = -1
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
        for (index in grid.indices) {
            val color = grid[index]
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
        val paint = if (grid[hoverIndex] == EMPTY) hoverPaint else blockedRingPaint
        canvas.drawCircle(
            g.gridX(hoverIndex % lines),
            g.gridY(hoverIndex / lines),
            g.stoneRadius * 1.15f,
            paint,
        )
    }

    private fun drawTray(canvas: Canvas, g: BoardGeometry, color: Int) {
        val isActive = (color == BLACK) == blackToMove
        val label = "x${remainingOf(color)}"
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

    private fun drawDraggedStone(canvas: Canvas, g: BoardGeometry) {
        if (!dragging) return
        // 和托盘里的棋子用同一个半径：拖起来大小不变。
        drawStone(canvas, dragX, dragY, g.pieceRadius, dragColor, 255)
    }

    // ------------------------------------------------------------------ 触摸

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        val g = geo ?: return false
        val x = event.x
        val y = event.y

        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                // 先看是不是按在盘上的棋子上：是的话谁都能拿起来（不看轮次），
                // 至于能不能真的挪走，见 dropAt。
                val index = g.indexAt(x, y)
                if (index >= 0 && grid[index] != EMPTY) {
                    dragging = true
                    dragFromBoard = true
                    dragFromIndex = index
                    dragColor = grid[index]
                    grid[index] = EMPTY
                    dragX = x
                    dragY = y
                    hoverIndex = index
                    parent?.requestDisallowInterceptTouchEvent(true)
                    invalidate()
                    return true
                }

                // 否则看是不是按在该走的那一方的托盘上。
                val color = currentColor()
                if (remainingOf(color) <= 0) return false
                if (!hitTray(g, color, x, y)) return false
                dragging = true
                dragFromBoard = false
                dragFromIndex = -1
                dragColor = color
                dragX = x
                dragY = y
                hoverIndex = -1
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
                dragFromBoard = false
                dragFromIndex = -1
                hoverIndex = -1
                invalidate()
                return true
            }

            MotionEvent.ACTION_CANCEL -> {
                if (!dragging) return false
                restoreBoardStone()
                dragging = false
                dragColor = EMPTY
                dragFromBoard = false
                dragFromIndex = -1
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
        val bounds = trayLayout(g, color, "x${remainingOf(color)}")
        val slop = dp(12f)
        return x >= bounds.left - slop && x <= bounds.right + slop &&
            y >= bounds.top - slop && y <= bounds.bottom + slop
    }

    /**
     * 松手：
     *  - 手上是从盘上拿起来的子：
     *      拖出棋盘 ⇒ 被吃掉，直接消失（数量不回托盘，也不换手）；
     *      松在原位（点一下没动）⇒ 放回去，不换手；
     *      不是这一方该走 / 落点已经有子 ⇒ 弹回原位；
     *      其余 ⇒ 挪过去并换手；
     *  - 手上是从托盘拖出来的新子：落在盘上空位才落子，数量 -1 并换手；松在盘外等于放回托盘。
     *
     * 不做任何规则判断（围棋不吃子、五子棋不判连五），只有「落点不能已经有子」这条物理约束。
     */
    private fun dropAt(g: BoardGeometry, x: Float, y: Float) {
        val target = g.indexAt(x, y)

        if (dragFromBoard) {
            if (target < 0) return // 被吃了：拿起来时就已从盘上移除，这里什么都不做
            if (target == dragFromIndex || dragColor != currentColor() || grid[target] != EMPTY) {
                restoreBoardStone()
                return
            }
            grid[target] = dragColor
            switchTurn()
            return
        }

        if (target < 0) return
        if (grid[target] != EMPTY) return
        if (remainingOf(dragColor) <= 0) return

        grid[target] = dragColor
        if (dragColor == BLACK) blackRemaining-- else whiteRemaining--
        switchTurn()
    }

    /** 把手上这颗从盘上拿起来的子放回它原来的落点。 */
    private fun restoreBoardStone() {
        if (!dragFromBoard || dragFromIndex < 0) return
        grid[dragFromIndex] = dragColor
    }
}
