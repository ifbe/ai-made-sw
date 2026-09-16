package com.example.chess.game.xiangqi

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

/** 象棋的七种棋子，红黑两方的显示名不一样（相/象、仕/士、帅/将）。 */
enum class XiangqiPiece(val red: Char, val black: Char) {
    ROOK('车', '车'),
    HORSE('马', '马'),
    ELEPHANT('相', '象'),
    ADVISOR('仕', '士'),
    KING('帅', '将'),
    CANNON('炮', '炮'),
    PAWN('兵', '卒'),
    ;

    fun nameOf(color: Int): Char = if (color == XiangqiGame.RED) red else black
}

/**
 * 象棋的盘面数据 + 全部逻辑。纯 Kotlin，一行 Android 都没有，可以直接 JVM 单测。
 *
 * 规则（和之前一样，只是从 View 里搬出来）：
 *  - 只判断轮次，不做任何走法校验；
 *  - 盘上的子谁都能拿起来拖（对端也能看见我乱动）；
 *  - 不该自己走时松手 ⇒ 弹回原位；点一下没动 / 走到自己子上 ⇒ 弹回原位；
 *  - 该自己走时走到对方子上 ⇒ 直接吃掉；
 *  - 拖出棋盘 ⇒ 这个子被吃掉，直接消失（不换手）。
 */
class XiangqiGame : Game {

    companion object {
        /** 横排 9 路，纵排 10 路。 */
        const val FILES = 9
        const val RANKS = 10
        const val SIZE = FILES * RANKS

        const val EMPTY = 0
        const val RED = 1
        const val BLACK = 2

        /** 红先。 */
        const val FIRST_SIDE = 0

        private val BACK_ROW = arrayOf(
            XiangqiPiece.ROOK,
            XiangqiPiece.HORSE,
            XiangqiPiece.ELEPHANT,
            XiangqiPiece.ADVISOR,
            XiangqiPiece.KING,
            XiangqiPiece.ADVISOR,
            XiangqiPiece.ELEPHANT,
            XiangqiPiece.HORSE,
            XiangqiPiece.ROOK,
        )

        /** 1（红）/ 2（黑）→ 0（先手）/ 1（后手）。 */
        fun sideOf(color: Int): Int = if (color == RED) FIRST_SIDE else 1

        /** 0（先手）/ 1（后手）→ 1（红）/ 2（黑）。 */
        fun colorOf(side: Int): Int = if (side == FIRST_SIDE) RED else BLACK
    }

    override val kind = GameKind.XIANGQI

    /** 每个落点上的棋子，下标 = rank * FILES + file。 */
    val colors = IntArray(SIZE)
    val pieces = arrayOfNulls<XiangqiPiece>(SIZE)

    var redToMove = true
        private set

    override val turn: Int get() = if (redToMove) 0 else 1

    override var drag: DragOverlay? = null
        private set

    private var dragFrom = -1
    private var dragColor = EMPTY
    private var dragPiece: XiangqiPiece? = null
    private var seq = 0L

    init {
        setup()
    }

    /** 摆回开局：红方在下、黑方在上，中间楚河汉界。 */
    private fun setup() {
        colors.fill(EMPTY)
        pieces.fill(null)
        for (file in 0 until FILES) {
            put(file, 0, BLACK, BACK_ROW[file])
            put(file, 9, RED, BACK_ROW[file])
        }
        put(1, 2, BLACK, XiangqiPiece.CANNON)
        put(7, 2, BLACK, XiangqiPiece.CANNON)
        put(1, 7, RED, XiangqiPiece.CANNON)
        put(7, 7, RED, XiangqiPiece.CANNON)
        for (file in 0 until FILES step 2) {
            put(file, 3, BLACK, XiangqiPiece.PAWN)
            put(file, 6, RED, XiangqiPiece.PAWN)
        }
        redToMove = true
        clearDrag()
    }

    private fun put(file: Int, rank: Int, color: Int, piece: XiangqiPiece) {
        val index = rank * FILES + file
        colors[index] = color
        pieces[index] = piece
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
        board = XiangqiProtocol.encode(colors, pieces),
        turn = turn,
        counts = emptyList(),
    )

    override fun hasPieceAt(index: Int) = index in 0 until SIZE && colors[index] != EMPTY

    override fun onGesture(gesture: Gesture): List<MoveEvent> = when (gesture) {
        is Gesture.PickUp -> pickUp(gesture.index)
        is Gesture.DragTo -> dragTo(gesture.cellX, gesture.cellY)
        is Gesture.Drop -> drop(gesture)
        Gesture.Cancel -> cancel()
        is Gesture.PickUpNew -> emptyList() // 象棋没有托盘
    }

    private fun pickUp(index: Int): List<MoveEvent> {
        if (!hasPieceAt(index)) return emptyList()
        val color = colors[index]
        val piece = pieces[index] ?: return emptyList()

        dragFrom = index
        dragColor = color
        dragPiece = piece

        val ref = PieceRef(sideOf(color), piece.nameOf(color).toString(), index)
        val pos = XiangqiProtocol.posOf(index)
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
                pieces[from] = null
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
        pieces[gesture.targetIndex] = piece
        colors[from] = EMPTY
        pieces[from] = null
        redToMove = !redToMove

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
                XiangqiProtocol.posOf(current.from),
                committed = false,
            ),
        )
    }

    private fun boardChanged() = BoardChanged(
        game = kind,
        seq = ++seq,
        board = XiangqiProtocol.encode(colors, pieces),
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
                // 对端拿起一颗子：只有它确实还在那个位置、名字也对得上才开浮层。
                val from = event.from
                if (from !in 0 until SIZE) return
                val color = colors[from]
                if (color == EMPTY) return
                val piece = pieces[from] ?: return
                if (piece.nameOf(color).toString() != event.piece.name) return
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
                if (XiangqiProtocol.decode(event.board, colors, pieces)) {
                    redToMove = event.turn == FIRST_SIDE
                }
                clearDrag()
            }

            is GameReset -> setup()
        }
    }
}
