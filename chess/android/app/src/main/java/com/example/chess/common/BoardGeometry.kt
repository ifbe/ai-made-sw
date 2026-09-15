package com.example.chess.common

import kotlin.math.min
import kotlin.math.roundToInt

/**
 * 棋盘几何计算。纯 Kotlin，不依赖 Android，方便用 JVM 单元测试验证。
 *
 * 规则：
 *  - 棋盘正方形边长 = min(width, height)，中心 = 视图中心；
 *  - 正方形被等分成 [subdivisions] × [subdivisions] 个格子，格子边长 = 边长 / subdivisions；
 *  - 第 i 个落点落在第 i 个格子的正中心，即 (i + 1) * cell，所以最外圈落点离正方形边界正好一格；
 *  - 正方形外的两侧余量用来放托盘，哪两侧余量大就放哪两侧。
 */
class BoardGeometry(
    val width: Float,
    val height: Float,
    val lines: Int = 19,
    val subdivisions: Int = 20,
) {

    companion object {
        /**
         * 各尺寸棋盘的传统星位，返回 [col0, row0, col1, row1, ...]。
         * 19 路围棋是 9 个星；15 路五子棋（连珠）和 13 / 9 路是 5 个星（四角 + 天元）。
         */
        fun starPoints(lines: Int): IntArray = when (lines) {
            19 -> intArrayOf(
                3, 3, 9, 3, 15, 3,
                3, 9, 9, 9, 15, 9,
                3, 15, 9, 15, 15, 15,
            )
            15 -> intArrayOf(3, 3, 11, 3, 3, 11, 11, 11, 7, 7)
            13 -> intArrayOf(3, 3, 9, 3, 3, 9, 9, 9, 6, 6)
            9 -> intArrayOf(2, 2, 6, 2, 2, 6, 6, 6, 4, 4)
            else -> IntArray(0)
        }
    }

    /** 棋盘正方形边长 = min(width, height)。 */
    val boardSize: Float = min(width, height)

    /** 棋盘正方形左边 / 上边坐标（正方形中心 = 视图中心）。 */
    val boardLeft: Float = (width - boardSize) / 2f
    val boardTop: Float = (height - boardSize) / 2f

    /** 格子边长。 */
    val cell: Float = boardSize / subdivisions

    /** 棋盘上棋子的半径。 */
    val stoneRadius: Float = cell * 0.46f

    /**
     * 托盘里的棋子和拖动中的那颗棋子共用同一个半径（比盘上的子略大一点），
     * 所以「棋盘外的棋子」和「拖动时的棋子」永远一样大。
     */
    val pieceRadius: Float = stoneRadius * 1.08f

    /** 棋盘正方形左右的余量（每侧）与上下的余量（每侧）。 */
    val sideSpace: Float = boardLeft
    val verticalSpace: Float = boardTop

    /** true：托盘放左右两侧（横屏 / 平板）；false：托盘放上下两侧（竖屏手机）。 */
    val trayOnSides: Boolean = boardLeft > boardTop

    /** 放托盘那条空带的宽度。 */
    val trayStrip: Float = if (trayOnSides) boardLeft else boardTop

    /** 落点 (col, row) 的中心坐标。 */
    fun gridX(col: Int): Float = boardLeft + (col + 1) * cell

    fun gridY(row: Int): Float = boardTop + (row + 1) * cell

    fun isInsideBoard(x: Float, y: Float): Boolean =
        x >= boardLeft && x <= boardLeft + boardSize &&
            y >= boardTop && y <= boardTop + boardSize

    /**
     * 手指位置吸附到最近的落点，返回下标（row * lines + col）。
     * 不在棋盘正方形里时返回 -1。
     */
    fun indexAt(x: Float, y: Float): Int {
        if (!isInsideBoard(x, y)) return -1
        val col = ((x - boardLeft) / cell - 1f).roundToInt().coerceIn(0, lines - 1)
        val row = ((y - boardTop) / cell - 1f).roundToInt().coerceIn(0, lines - 1)
        return row * lines + col
    }

    /** 托盘圆心的 x / y。[black] 为 true 表示黑棋托盘。 */
    fun trayCenterX(black: Boolean): Float = if (trayOnSides) {
        if (black) boardLeft / 2f else width - boardLeft / 2f
    } else {
        width / 2f
    }

    fun trayCenterY(black: Boolean): Float = if (trayOnSides) {
        height / 2f
    } else {
        if (black) boardTop / 2f else height - boardTop / 2f
    }
}
