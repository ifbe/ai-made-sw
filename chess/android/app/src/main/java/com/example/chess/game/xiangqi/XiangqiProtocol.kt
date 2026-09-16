package com.example.chess.game.xiangqi

import com.example.chess.game.share.protocol.BoardPos
import kotlin.math.roundToInt

/**
 * 象棋的**负载编解码**：
 *
 *  - 盘面 → 90 个字符：'.' 表示空，红方用大写 `R N B A K C P`，黑方用小写；
 *    行序 = rank 0..9（黑方底线在上），列序 = file 0..8；
 *  - 落点下标 ↔ 相对棋盘中心的格坐标：x ∈ [-4, +4]（整数），y ∈ [-4.5, +4.5]（半整数）。
 */
object XiangqiProtocol {

    const val CELLS = XiangqiGame.SIZE
    private const val EMPTY = '.'

    /** 棋盘左边界 / 上边界对应的偏移（9 路 → 4，10 路 → 4.5）。 */
    private const val HALF_FILES = (XiangqiGame.FILES - 1) / 2f
    private const val HALF_RANKS = (XiangqiGame.RANKS - 1) / 2f

    fun encode(colors: IntArray, pieces: Array<XiangqiPiece?>): String {
        val sb = StringBuilder(CELLS)
        for (index in 0 until CELLS) {
            val color = colors[index]
            val piece = pieces[index]
            if (color == XiangqiGame.EMPTY || piece == null) {
                sb.append(EMPTY)
                continue
            }
            val code = codeOf(piece)
            sb.append(if (color == XiangqiGame.RED) code.uppercaseChar() else code.lowercaseChar())
        }
        return sb.toString()
    }

    /** 把 [board] 写回两个数组；长度或字符不对返回 false（并且不保证数组未被改动）。 */
    fun decode(board: String, colors: IntArray, pieces: Array<XiangqiPiece?>): Boolean {
        if (board.length != CELLS || colors.size != CELLS || pieces.size != CELLS) return false
        for (index in 0 until CELLS) {
            val c = board[index]
            if (c == EMPTY) {
                colors[index] = XiangqiGame.EMPTY
                pieces[index] = null
                continue
            }
            val piece = pieceOf(c.uppercaseChar()) ?: return false
            colors[index] = if (c.isUpperCase()) XiangqiGame.RED else XiangqiGame.BLACK
            pieces[index] = piece
        }
        return true
    }

    /** 落点下标 → 相对棋盘中心的格坐标。 */
    fun cellXOf(index: Int): Float = index % XiangqiGame.FILES - HALF_FILES

    fun cellYOf(index: Int): Float = index / XiangqiGame.FILES - HALF_RANKS

    fun posOf(index: Int): BoardPos = BoardPos.ofCells(cellXOf(index), cellYOf(index))

    /** 格坐标 → 最近的落点下标（会夹在棋盘范围内；是不是盘外由棋盘几何判断）。 */
    fun indexOf(cellX: Float, cellY: Float): Int {
        val file = (cellX + HALF_FILES).roundToInt().coerceIn(0, XiangqiGame.FILES - 1)
        val rank = (cellY + HALF_RANKS).roundToInt().coerceIn(0, XiangqiGame.RANKS - 1)
        return rank * XiangqiGame.FILES + file
    }

    private fun codeOf(piece: XiangqiPiece): Char = when (piece) {
        XiangqiPiece.ROOK -> 'R'
        XiangqiPiece.HORSE -> 'N'
        XiangqiPiece.ELEPHANT -> 'B'
        XiangqiPiece.ADVISOR -> 'A'
        XiangqiPiece.KING -> 'K'
        XiangqiPiece.CANNON -> 'C'
        XiangqiPiece.PAWN -> 'P'
    }

    private fun pieceOf(code: Char): XiangqiPiece? = when (code) {
        'R' -> XiangqiPiece.ROOK
        'N' -> XiangqiPiece.HORSE
        'B' -> XiangqiPiece.ELEPHANT
        'A' -> XiangqiPiece.ADVISOR
        'K' -> XiangqiPiece.KING
        'C' -> XiangqiPiece.CANNON
        'P' -> XiangqiPiece.PAWN
        else -> null
    }
}
