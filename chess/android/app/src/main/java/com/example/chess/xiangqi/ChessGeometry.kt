package com.example.chess.xiangqi

import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * 象棋棋盘几何。纯 Kotlin，不依赖 Android，方便用 JVM 单元测试验证。
 *
 * 棋盘是 9 路 × 10 路（横排 9 个落点：车马象仕将仕象马车；竖排 10 个落点，中间是楚河汉界）：
 *  - 屏幕短边 / 长边 < 9/10（细长屏，比如手机竖屏）：格子边长 = min(w,h)/9，
 *    短边放 9 路、长边放 10 路；
 *  - 否则（屏幕接近正方形）：格子边长 = min(w,h)/10，短边放 10 路、长边放 9 路。
 *
 * 落点都在各自格子的正中心，所以最外圈离屏幕边还有半格，边上的棋子不会被切掉。
 */
class ChessGeometry(
    val width: Float,
    val height: Float,
) {

    companion object {
        /** 横排落点数。 */
        const val FILES = 9

        /** 竖排落点数。 */
        const val RANKS = 10

        /** 两条边界：短边 / 长边小于这个比例就按细长屏处理。 */
        const val ELONGATED_RATIO = 9f / 10f
    }

    private val shortSide = min(width, height)
    private val longSide = max(width, height)

    /** 细长屏：短边放 9 路。 */
    val elongated: Boolean = shortSide / longSide < ELONGATED_RATIO

    /** 短边 / 长边上各放几路。 */
    val shortAxisCells: Int = if (elongated) FILES else RANKS
    val longAxisCells: Int = if (elongated) RANKS else FILES

    /** 格子边长。 */
    val cell: Float = shortSide / shortAxisCells

    /** 屏幕横向 / 纵向各有多少个落点。 */
    val cols: Int = if (width <= height) shortAxisCells else longAxisCells
    val rows: Int = if (width <= height) longAxisCells else shortAxisCells

    /** 棋盘（cols × rows 个格子）的像素尺寸和左上角。 */
    val boardWidth: Float = cols * cell
    val boardHeight: Float = rows * cell
    val boardLeft: Float = (width - boardWidth) / 2f
    val boardTop: Float = (height - boardHeight) / 2f

    /** 棋盘外左右 / 上下剩下的空间（每侧），用来放「轮到谁走」的提示。 */
    val sideSpace: Float = boardLeft
    val verticalSpace: Float = boardTop

    /** true：棋盘转了 90°（10 路沿着屏幕横向走）。 */
    val rotated: Boolean = cols == RANKS

    /** 屏幕列 / 行对应的像素中心。 */
    fun gridX(col: Int): Float = boardLeft + (col + 0.5f) * cell

    fun gridY(row: Int): Float = boardTop + (row + 0.5f) * cell

    /** 棋盘坐标（file 0..8，rank 0..9）→ 屏幕上的列 / 行。 */
    fun screenCol(file: Int, rank: Int): Int = if (rotated) rank else file

    fun screenRow(file: Int, rank: Int): Int = if (rotated) file else rank

    /** 棋盘坐标上的像素位置。 */
    fun pieceX(file: Int, rank: Int): Float = gridX(screenCol(file, rank))

    fun pieceY(file: Int, rank: Int): Float = gridY(screenRow(file, rank))

    /** 楚河汉界这条带子的起止（屏幕坐标）。 */
    val riverStart: Float get() = if (rotated) gridX(4) else gridY(4)

    val riverEnd: Float get() = if (rotated) gridX(5) else gridY(5)

    fun isInsideBoard(x: Float, y: Float): Boolean =
        x >= boardLeft && x <= boardLeft + boardWidth &&
            y >= boardTop && y <= boardTop + boardHeight

    /**
     * 手指位置吸附到最近的落点，返回棋盘坐标下标（rank * FILES + file）。
     * 不在棋盘内时返回 -1。
     */
    fun indexAt(x: Float, y: Float): Int {
        if (!isInsideBoard(x, y)) return -1
        val col = ((x - boardLeft) / cell - 0.5f).roundToInt().coerceIn(0, cols - 1)
        val row = ((y - boardTop) / cell - 0.5f).roundToInt().coerceIn(0, rows - 1)
        val file = if (rotated) row else col
        val rank = if (rotated) col else row
        return rank * FILES + file
    }

    /** 某个落点是不是在九宫里（file 3..5，rank 0..2 或 7..9）。 */
    fun isInPalace(file: Int, rank: Int): Boolean =
        file in 3..5 && (rank in 0..2 || rank in 7..9)

    /** 挂双方小牌子的那条空带有多宽。 */
    val badgeStrip: Float get() = if (rotated) boardLeft else boardTop

    /** 某一方的牌子挂在棋盘外哪一端（black = 棋盘 rank 0 那一端）。 */
    fun sideAnchorX(black: Boolean): Float = when {
        !rotated -> width / 2f
        black -> boardLeft / 2f
        else -> width - boardLeft / 2f
    }

    fun sideAnchorY(black: Boolean): Float = when {
        rotated -> height / 2f
        black -> boardTop / 2f
        else -> height - boardTop / 2f
    }

    /**
     * 牌子上的字要转多少度，才是正对着坐在那一端的玩家（面对面下棋）：
     * 正常方向时上方那家转 180°；棋盘转了 90° 时，左边那家转 +90°、右边那家转 -90°。
     */
    fun sideTextRotation(black: Boolean): Float = when {
        !rotated -> if (black) 180f else 0f
        black -> 90f
        else -> -90f
    }

    /**
     * 棋盘上棋子里的字要转多少度：朝着当前该走的那一方。
     * 竖屏手机就是「红方走 0°，轮到黑方走 180°」。
     */
    fun pieceTextRotation(redToMove: Boolean): Float = sideTextRotation(black = !redToMove)
}
