package com.example.chess.game.guojixiangqi

import com.example.chess.game.share.protocol.BoardPos
import kotlin.math.roundToInt

/**
 * 国际象棋的**负载编解码**：
 *
 *  - 盘面 → 64 个字符：'.' 表示空，白方大写 `K Q R B N P`，黑方小写；
 *    行序 = rank 0..7（黑方底线在上），列序 = file 0..7；
 *  - 方格下标 ↔ 相对棋盘中心的格坐标：x, y ∈ [-3.5, +3.5]（半整数）。
 */
object IntlChessProtocol {

    const val CELLS = IntlChessGame.SIZE
    private const val EMPTY = '.'

    /** 8 格 → ±3.5。 */
    private const val HALF_FILES = (IntlChessGame.FILES - 1) / 2f
    private const val HALF_RANKS = (IntlChessGame.RANKS - 1) / 2f

    fun encode(colors: IntArray, types: Array<IntlChessPiece?>): String {
        val sb = StringBuilder(CELLS)
        for (index in 0 until CELLS) {
            val color = colors[index]
            val piece = types[index]
            if (color == IntlChessGame.EMPTY || piece == null) {
                sb.append(EMPTY)
                continue
            }
            val code = piece.code
            sb.append(if (color == IntlChessGame.WHITE) code.uppercaseChar() else code.lowercaseChar())
        }
        return sb.toString()
    }

    fun decode(board: String, colors: IntArray, types: Array<IntlChessPiece?>): Boolean {
        if (board.length != CELLS || colors.size != CELLS || types.size != CELLS) return false
        for (index in 0 until CELLS) {
            val c = board[index]
            if (c == EMPTY) {
                colors[index] = IntlChessGame.EMPTY
                types[index] = null
                continue
            }
            val piece = IntlChessPiece.of(c.uppercaseChar()) ?: return false
            colors[index] = if (c.isUpperCase()) IntlChessGame.WHITE else IntlChessGame.BLACK
            types[index] = piece
        }
        return true
    }

    /** 方格下标 → 相对棋盘中心的格坐标。 */
    fun cellXOf(index: Int): Float = index % IntlChessGame.FILES - HALF_FILES

    fun cellYOf(index: Int): Float = index / IntlChessGame.FILES - HALF_RANKS

    fun posOf(index: Int): BoardPos = BoardPos.ofCells(cellXOf(index), cellYOf(index))

    /** 格坐标 → 最近的方格下标（会夹在棋盘范围内；是不是盘外由棋盘几何判断）。 */
    fun indexOf(cellX: Float, cellY: Float): Int {
        val file = (cellX + HALF_FILES).roundToInt().coerceIn(0, IntlChessGame.FILES - 1)
        val rank = (cellY + HALF_RANKS).roundToInt().coerceIn(0, IntlChessGame.RANKS - 1)
        return rank * IntlChessGame.FILES + file
    }
}
