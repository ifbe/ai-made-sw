package com.example.chess.game.share.stone

import com.example.chess.game.share.core.BoardSnapshot
import com.example.chess.game.share.core.DragOverlay
import com.example.chess.game.share.core.Game
import com.example.chess.game.share.core.Gesture
import com.example.chess.game.share.protocol.BoardChanged
import com.example.chess.game.share.protocol.BoardPos
import com.example.chess.game.share.protocol.DragEnded
import com.example.chess.game.share.protocol.DragMoved
import com.example.chess.game.share.protocol.DragStarted
import com.example.chess.game.share.protocol.GameKind
import com.example.chess.game.share.protocol.GameReset
import com.example.chess.game.share.protocol.MoveEvent
import com.example.chess.game.share.protocol.PieceRef

/**
 * 围棋 / 五子棋共用的盘面数据 + 逻辑（两者只有路数不同，围棋 19、五子棋 15）。
 * 纯 Kotlin，可以直接 JVM 单测。
 *
 * 规则：
 *  - 不做任何吃子 / 提子 / 连五判断，只判断轮次；
 *  - 盘上的子谁都能拿起来拖（对端也能看见），不该自己走 ⇒ 松手弹回原位；
 *  - 把盘上的子拖出棋盘 ⇒ 这颗子被吃掉，直接消失（不回托盘、不换手）；
 *  - 托盘只有该走的那一方能拿，落到盘上空位就落子并把数量 -1。
 */
class StoneGame(
    val lines: Int,
    override val kind: GameKind,
) : Game {

    companion object {
        /** 每色棋子初始数量。 */
        const val INITIAL_STONES = 180

        const val EMPTY = 0
        const val BLACK = 1
        const val WHITE = 2

        /** 黑先。 */
        const val FIRST_SIDE = 0

        fun sideOf(color: Int): Int = if (color == BLACK) 0 else 1

        fun colorOf(side: Int): Int = if (side == FIRST_SIDE) BLACK else WHITE
    }

    /** 每个落点上的棋子：EMPTY / BLACK / WHITE。 */
    val grid = IntArray(lines * lines)

    /** 每颗子的自增编号（0 表示这一格没有子）—— 石头没有名字，就用它当身份。 */
    val ids = IntArray(lines * lines)

    var blackToMove = true
        private set

    var blackRemaining = INITIAL_STONES
        private set

    var whiteRemaining = INITIAL_STONES
        private set

    override val turn: Int get() = if (blackToMove) FIRST_SIDE else 1

    override var drag: DragOverlay? = null
        private set

    private var dragFrom = -1
    private var dragColor = EMPTY
    private var dragPiece: PieceRef? = null

    /** 手上这颗是不是刚从托盘拿出来的新子。 */
    private var dragFromTray = false
    private var nextStoneId = 1
    private var seq = 0L

    fun remaining(side: Int) = if (side == FIRST_SIDE) blackRemaining else whiteRemaining

    fun remainingOf(color: Int) = if (color == BLACK) blackRemaining else whiteRemaining

    /** 重开：清空棋盘、数量回到初始值、重新黑先。 */
    private fun setup() {
        grid.fill(EMPTY)
        ids.fill(0)
        blackToMove = true
        blackRemaining = INITIAL_STONES
        whiteRemaining = INITIAL_STONES
        clearDrag()
    }

    private fun clearDrag() {
        drag = null
        dragFrom = -1
        dragColor = EMPTY
        dragPiece = null
        dragFromTray = false
    }

    // ------------------------------------------------------------------ Game

    override fun snapshot() = BoardSnapshot(
        game = kind,
        board = StoneProtocol.encode(grid),
        turn = turn,
        counts = listOf(blackRemaining, whiteRemaining),
    )

    override fun hasPieceAt(index: Int) = index in grid.indices && grid[index] != EMPTY

    override fun onGesture(gesture: Gesture): List<MoveEvent> = when (gesture) {
        is Gesture.PickUp -> pickUpBoardStone(gesture.index)
        is Gesture.PickUpNew -> pickUpNewStone(gesture)
        is Gesture.DragTo -> dragTo(gesture.cellX, gesture.cellY)
        is Gesture.Drop -> drop(gesture)
        Gesture.Cancel -> cancel()
    }

    private fun pickUpBoardStone(index: Int): List<MoveEvent> {
        if (!hasPieceAt(index)) return emptyList()
        val color = grid[index]
        dragFrom = index
        dragColor = color
        dragFromTray = false
        val ref = PieceRef(sideOf(color), name = "", id = ids[index])
        dragPiece = ref
        val pos = StoneProtocol.posOf(index, lines)
        drag = DragOverlay(ref, index, pos.cellX, pos.cellY, byMe = true)
        return listOf(DragStarted(kind, ++seq, ref, index, pos))
    }

    private fun pickUpNewStone(gesture: Gesture.PickUpNew): List<MoveEvent> {
        // 托盘只有该走的那一方能拿
        if (gesture.side != turn) return emptyList()
        if (remaining(gesture.side) <= 0) return emptyList()

        val color = colorOf(gesture.side)
        val ref = PieceRef(gesture.side, name = "", id = nextStoneId++)
        dragFrom = -1
        dragColor = color
        dragFromTray = true
        dragPiece = ref
        val pos = BoardPos.ofCells(gesture.cellX, gesture.cellY)
        drag = DragOverlay(ref, from = -1, cellX = pos.cellX, cellY = pos.cellY, byMe = true)
        return listOf(DragStarted(kind, ++seq, ref, from = -1, pos = pos))
    }

    private fun dragTo(cellX: Float, cellY: Float): List<MoveEvent> {
        val current = drag ?: return emptyList()
        drag = current.copy(cellX = cellX, cellY = cellY)
        return listOf(DragMoved(kind, ++seq, current.piece, BoardPos.ofCells(cellX, cellY)))
    }

    private fun drop(gesture: Gesture.Drop): List<MoveEvent> {
        val current = drag ?: return emptyList()
        val from = dragFrom
        val color = dragColor
        val ref = dragPiece
        val fromTray = dragFromTray
        clearDrag()

        val pos = BoardPos.ofCells(gesture.cellX, gesture.cellY)
        val events = ArrayList<MoveEvent>(2)
        if (ref == null) return emptyList()

        // 从盘上拿起来的子
        if (!fromTray) {
            // 拖出棋盘 = 被吃，直接消失（不回托盘、不换手）
            if (gesture.targetIndex < 0) {
                if (from in grid.indices) {
                    grid[from] = EMPTY
                    ids[from] = 0
                }
                events += DragEnded(kind, ++seq, ref, pos, committed = false)
                events += boardChanged()
                return events
            }
            val blocked = gesture.targetIndex == from ||
                sideOf(color) != turn ||
                grid[gesture.targetIndex] != EMPTY
            if (blocked) {
                events += DragEnded(kind, ++seq, ref, pos, committed = false)
                return events
            }
            grid[gesture.targetIndex] = color
            ids[gesture.targetIndex] = ids[from]
            grid[from] = EMPTY
            ids[from] = 0
            blackToMove = !blackToMove
            events += DragEnded(kind, ++seq, ref, pos, committed = true)
            events += boardChanged()
            return events
        }

        // 从托盘拖出来的新子：落不到盘上就相当于放回托盘
        if (gesture.targetIndex < 0 || grid[gesture.targetIndex] != EMPTY) {
            events += DragEnded(kind, ++seq, ref, pos, committed = false)
            return events
        }
        grid[gesture.targetIndex] = color
        ids[gesture.targetIndex] = ref.id
        if (color == BLACK) blackRemaining-- else whiteRemaining--
        blackToMove = !blackToMove
        events += DragEnded(kind, ++seq, ref, pos, committed = true)
        events += boardChanged()
        return events
    }

    private fun cancel(): List<MoveEvent> {
        val current = drag ?: return emptyList()
        val pos = if (current.from >= 0) {
            StoneProtocol.posOf(current.from, lines)
        } else {
            BoardPos.ofCells(current.cellX, current.cellY)
        }
        val ref = current.piece
        clearDrag()
        return listOf(DragEnded(kind, ++seq, ref, pos, committed = false))
    }

    private fun boardChanged() = BoardChanged(
        game = kind,
        seq = ++seq,
        board = StoneProtocol.encode(grid),
        turn = turn,
        counts = listOf(blackRemaining, whiteRemaining),
    )

    override fun reset(): List<MoveEvent> {
        setup()
        return listOf(GameReset(kind, ++seq), boardChanged())
    }

    override fun apply(event: MoveEvent) {
        if (event.game != kind) return
        seq = maxOf(seq, event.seq)

        when (event) {
            is DragStarted -> {
                // 从托盘拿的新子（from < 0）没法校验，直接显示；盘上的子要确认还在原地
                if (event.from >= 0) {
                    if (!hasPieceAt(event.from)) return
                    if (StoneGame.sideOf(grid[event.from]) != event.piece.side) return
                }
                drag = DragOverlay(event.piece, event.from, event.pos.cellX, event.pos.cellY, byMe = false)
            }

            is DragMoved -> {
                val current = drag ?: return
                if (current.piece != event.piece) return
                drag = current.copy(cellX = event.pos.cellX, cellY = event.pos.cellY)
            }

            is DragEnded -> {
                val current = drag ?: return
                if (current.piece == event.piece) drag = null
            }

            is BoardChanged -> {
                if (StoneProtocol.decode(event.board, grid)) {
                    blackToMove = event.turn == FIRST_SIDE
                    if (event.counts.size >= 2) {
                        blackRemaining = event.counts[0]
                        whiteRemaining = event.counts[1]
                    }
                }
                clearDrag()
            }

            is GameReset -> setup()
        }
    }
}
