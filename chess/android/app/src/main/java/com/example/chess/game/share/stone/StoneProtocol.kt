package com.example.chess.game.share.stone

import com.example.chess.game.share.protocol.BoardPos
import kotlin.math.roundToInt

/**
 * 围棋 / 五子棋的**负载编解码**。
 *
 *  - 盘面 → lines × lines 个字符：'.' 空，'b' 黑子，'w' 白子；行序 = 行 0..lines-1；
 *  - 落点下标 ↔ 相对棋盘中心的格坐标：19 路是 x,y ∈ [-9, +9]，15 路是 [-7, +7]。
 */
object StoneProtocol {

    private const val EMPTY = '.'
    private const val BLACK = 'b'
    private const val WHITE = 'w'

    fun encode(grid: IntArray): String {
        val sb = StringBuilder(grid.size)
        for (cell in grid) {
            sb.append(
                when (cell) {
                    StoneGame.BLACK -> BLACK
                    StoneGame.WHITE -> WHITE
                    else -> EMPTY
                },
            )
        }
        return sb.toString()
    }

    fun decode(board: String, grid: IntArray): Boolean {
        if (board.length != grid.size) return false
        for (index in grid.indices) {
            grid[index] = when (board[index]) {
                BLACK -> StoneGame.BLACK
                WHITE -> StoneGame.WHITE
                EMPTY -> StoneGame.EMPTY
                else -> return false
            }
        }
        return true
    }

    /** 落点下标 → 相对棋盘中心的格坐标。 */
    fun cellXOf(index: Int, lines: Int): Float = index % lines - (lines - 1) / 2f

    fun cellYOf(index: Int, lines: Int): Float = index / lines - (lines - 1) / 2f

    fun posOf(index: Int, lines: Int): BoardPos = BoardPos.ofCells(cellXOf(index, lines), cellYOf(index, lines))

    /** 格坐标 → 最近的落点下标（会夹在棋盘范围内；是不是盘外由棋盘几何判断）。 */
    fun indexOf(cellX: Float, cellY: Float, lines: Int): Int {
        val col = (cellX + (lines - 1) / 2f).roundToInt().coerceIn(0, lines - 1)
        val row = (cellY + (lines - 1) / 2f).roundToInt().coerceIn(0, lines - 1)
        return row * lines + col
    }
}
