package com.example.chess.guojixiangqi

import kotlin.math.min

/**
 * 国际象棋棋盘几何。纯 Kotlin，不依赖 Android，方便用 JVM 单元测试验证。
 *
 *  - 棋盘区就是 min(w,h) 的正方形，居中，分成 8 × 8 个方格（棋子站在方格正中心）；
 *  - 竖屏时白方在下、黑方在上；横屏（宽 > 高）时把棋盘转 90°，黑方在左、白方在右，
 *    这样两端的小牌子正好落在棋盘外的空带上，和象棋页一个做法。
 *
 * 棋盘坐标：file 0..7 = a..h（未旋转时从左到右），rank 0..7 = 第 8 横排..第 1 横排
 * （rank 0 是黑方底线，rank 7 是白方底线）。
 */
class IntlChessGeometry(
    val width: Float,
    val height: Float,
) {

    companion object {
        /** 每边 8 个方格。 */
        const val FILES = 8
        const val RANKS = 8
    }

    /** 棋盘区边长 = min(width, height)。 */
    val boardSize: Float = min(width, height)
    val boardLeft: Float = (width - boardSize) / 2f
    val boardTop: Float = (height - boardSize) / 2f

    /** 每个方格的边长。 */
    val cell: Float = boardSize / FILES

    /** 横屏时把棋盘转 90°。 */
    val rotated: Boolean = width > height

    /** 棋盘外左右 / 上下剩下的空间（每侧）。 */
    val sideSpace: Float = boardLeft
    val verticalSpace: Float = boardTop

    /** 某个格子是不是深色格（a1 是深色，标准棋盘）。 */
    fun isDarkSquare(file: Int, rank: Int): Boolean = (file + rank) % 2 == 1

    /** 棋盘坐标 → 屏幕上的列 / 行。 */
    fun screenCol(file: Int, rank: Int): Int = if (rotated) rank else file

    fun screenRow(file: Int, rank: Int): Int = if (rotated) file else rank

    /** 方格中心坐标。 */
    fun squareX(file: Int, rank: Int): Float = boardLeft + (screenCol(file, rank) + 0.5f) * cell

    fun squareY(file: Int, rank: Int): Float = boardTop + (screenRow(file, rank) + 0.5f) * cell

    /** 方格左上角坐标。 */
    fun squareLeft(file: Int, rank: Int): Float = boardLeft + screenCol(file, rank) * cell

    fun squareTop(file: Int, rank: Int): Float = boardTop + screenRow(file, rank) * cell

    fun isInsideBoard(x: Float, y: Float): Boolean =
        x >= boardLeft && x <= boardLeft + boardSize &&
            y >= boardTop && y <= boardTop + boardSize

    /** 手指落在哪个格子上，返回棋盘坐标下标（rank * FILES + file），不在棋盘内返回 -1。 */
    fun indexAt(x: Float, y: Float): Int {
        if (!isInsideBoard(x, y)) return -1
        val col = ((x - boardLeft) / cell).toInt().coerceIn(0, FILES - 1)
        val row = ((y - boardTop) / cell).toInt().coerceIn(0, RANKS - 1)
        val file = if (rotated) row else col
        val rank = if (rotated) col else row
        return rank * FILES + file
    }

    /** 挂双方小牌子的那条空带有多宽。 */
    val badgeStrip: Float get() = if (rotated) boardLeft else boardTop

    /** 某一方的牌子挂在棋盘外哪一端（black = 黑方，rank 0 那一端）。 */
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

    /** 牌子上的字要转多少度才正对着那一端的玩家（和象棋页同一套规则）。 */
    fun sideTextRotation(black: Boolean): Float = when {
        !rotated -> if (black) 180f else 0f
        black -> 90f
        else -> -90f
    }

    /** 棋子上的字要转多少度：朝着当前该走的那一方（白先）。 */
    fun pieceTextRotation(whiteToMove: Boolean): Float = sideTextRotation(black = !whiteToMove)
}
