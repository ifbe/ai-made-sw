package com.example.chess.game.guojixiangqi

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

/** 国际象棋的六种棋子（显示用的字形在 View 里，这里只存类型字母）。 */
enum class IntlChessPiece(val code: Char) {
    KING('K'),
    QUEEN('Q'),
    ROOK('R'),
    BISHOP('B'),
    KNIGHT('N'),
    PAWN('P'),
    ;

    companion object {
        fun of(code: Char): IntlChessPiece? = entries.firstOrNull { it.code == code }
    }
}

/**
 * 国际象棋的盘面数据 + 全部逻辑。纯 Kotlin，可以直接 JVM 单测。
 *
 * 规则（和另外几种棋一致）：
 *  - 不做任何走法判断，只判断轮次（白先）；
 *  - 盘上的子谁都能拿起来拖（对端也能看见）；
 *  - 不该自己走 / 点一下没动 / 走到自己子上 ⇒ 弹回原位；
 *  - 该自己走时走到对方子上 ⇒ 直接把对方子吃掉；
 *  - 拖出棋盘 ⇒ 这个子被吃掉，直接消失（不换手）。
 */
class IntlChessGame : Game {

    companion object {
        const val FILES = 8
        const val RANKS = 8
        const val SIZE = FILES * RANKS

        const val EMPTY = 0
        const val WHITE = 1
        const val BLACK = 2

        /** 白先。 */
        const val FIRST_SIDE = 0

        /** 底线从左到右：车 马 象 后 王 象 马 车。 */
        private val BACK_RANK = arrayOf(
            IntlChessPiece.ROOK,
            IntlChessPiece.KNIGHT,
            IntlChessPiece.BISHOP,
            IntlChessPiece.QUEEN,
            IntlChessPiece.KING,
            IntlChessPiece.BISHOP,
            IntlChessPiece.KNIGHT,
            IntlChessPiece.ROOK,
        )

        /** 1（白）/ 2（黑）→ 0（先手）/ 1（后手）。 */
        fun sideOf(color: Int): Int = if (color == WHITE) FIRST_SIDE else 1

        fun colorOf(side: Int): Int = if (side == FIRST_SIDE) WHITE else BLACK
    }

    override val kind = GameKind.INTL_CHESS

    /** 下标 = rank * FILES + file。 */
    val colors = IntArray(SIZE)
    val types = arrayOfNulls<IntlChessPiece>(SIZE)

    var whiteToMove = true
        private set

    override val turn: Int get() = if (whiteToMove) FIRST_SIDE else 1

    override var drag: DragOverlay? = null
        private set

    private var dragFrom = -1
    private var dragColor = EMPTY
    private var dragPiece: IntlChessPiece? = null
    private var seq = 0L

    init {
        setup()
    }

    /** 白方在下、黑方在上，标准开局。 */
    private fun setup() {
        colors.fill(EMPTY)
        types.fill(null)
        for (file in 0 until FILES) {
            put(file, 0, BLACK, BACK_RANK[file])
            put(file, 1, BLACK, IntlChessPiece.PAWN)
            put(file, 6, WHITE, IntlChessPiece.PAWN)
            put(file, 7, WHITE, BACK_RANK[file])
        }
        whiteToMove = true
        clearDrag()
    }

    private fun put(file: Int, rank: Int, color: Int, piece: IntlChessPiece) {
        val index = rank * FILES + file
        colors[index] = color
        types[index] = piece
    }

    private fun clearDrag() {
        drag = null
        dragFrom = -1
        dragColor = EMPTY
        dragPiece = null
    }

    // ------------------------------------------------------------------ Game

    override fun snapshot() = BoardSnapshot(
        game = kind,
        board = IntlChessProtocol.encode(colors, types),
        turn = turn,
        counts = emptyList(),
    )

    override fun hasPieceAt(index: Int) = index in 0 until SIZE && colors[index] != EMPTY

    override fun onGesture(gesture: Gesture): List<MoveEvent> = when (gesture) {
        is Gesture.PickUp -> pickUp(gesture.index)
        is Gesture.DragTo -> dragTo(gesture.cellX, gesture.cellY)
        is Gesture.Drop -> drop(gesture)
        Gesture.Cancel -> cancel()
        is Gesture.PickUpNew -> emptyList() // 国际象棋没有托盘
    }

    private fun pickUp(index: Int): List<MoveEvent> {
        if (!hasPieceAt(index)) return emptyList()
        val color = colors[index]
        val piece = types[index] ?: return emptyList()

        dragFrom = index
        dragColor = color
        dragPiece = piece

        val ref = PieceRef(sideOf(color), piece.code.toString(), index)
        val pos = IntlChessProtocol.posOf(index)
        drag = DragOverlay(ref, index, pos.cellX, pos.cellY, byMe = true)
        return listOf(DragStarted(kind, ++seq, ref, index, pos))
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
        val piece = dragPiece
        clearDrag()

        val pos = BoardPos.ofCells(gesture.cellX, gesture.cellY)
        val events = ArrayList<MoveEvent>(2)

        // 拖出棋盘 = 被吃，直接消失（不换手）
        if (gesture.targetIndex < 0) {
            if (from in 0 until SIZE) {
                colors[from] = EMPTY
                types[from] = null
            }
            events += DragEnded(kind, ++seq, current.piece, pos, committed = false)
            events += boardChanged()
            return events
        }

        // 点一下没动 / 不该自己走 / 走到自己子上 ⇒ 弹回原位
        val blocked = piece == null ||
            gesture.targetIndex == from ||
            sideOf(color) != turn ||
            colors[gesture.targetIndex] == color
        if (blocked) {
            events += DragEnded(kind, ++seq, current.piece, pos, committed = false)
            return events
        }

        // 落到空格就是走子，落到对方子上就是把对方吃掉（直接覆盖）
        colors[gesture.targetIndex] = color
        types[gesture.targetIndex] = piece
        colors[from] = EMPTY
        types[from] = null
        whiteToMove = !whiteToMove

        events += DragEnded(kind, ++seq, current.piece, pos, committed = true)
        events += boardChanged()
        return events
    }

    private fun cancel(): List<MoveEvent> {
        val current = drag ?: return emptyList()
        clearDrag()
        return listOf(
            DragEnded(
                kind,
                ++seq,
                current.piece,
                IntlChessProtocol.posOf(current.from),
                committed = false,
            ),
        )
    }

    private fun boardChanged() = BoardChanged(
        game = kind,
        seq = ++seq,
        board = IntlChessProtocol.encode(colors, types),
        turn = turn,
        counts = emptyList(),
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
                val from = event.from
                if (from !in 0 until SIZE) return
                val color = colors[from]
                if (color == EMPTY) return
                val piece = types[from] ?: return
                if (piece.code.toString() != event.piece.name) return
                drag = DragOverlay(event.piece, from, event.pos.cellX, event.pos.cellY, byMe = false)
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
                if (IntlChessProtocol.decode(event.board, colors, types)) {
                    whiteToMove = event.turn == FIRST_SIDE
                }
                clearDrag()
            }

            is GameReset -> setup()
        }
    }
}
