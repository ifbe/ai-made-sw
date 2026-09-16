package com.example.chess.game.guojixiangqi

import com.example.chess.game.share.core.Gesture
import com.example.chess.game.share.protocol.BoardChanged
import com.example.chess.game.share.protocol.DragEnded
import com.example.chess.game.share.protocol.MoveEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 国际象棋盘面逻辑，纯 JVM。 */
class IntlChessGameTest {

    private fun index(file: Int, rank: Int) = rank * IntlChessGame.FILES + file

    private fun drag(game: IntlChessGame, from: Int, to: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUp(from))
        events += game.onGesture(Gesture.DragTo(IntlChessProtocol.cellXOf(to), IntlChessProtocol.cellYOf(to)))
        events += game.onGesture(
            Gesture.Drop(IntlChessProtocol.cellXOf(to), IntlChessProtocol.cellYOf(to), to),
        )
        return events
    }

    private fun dragOff(game: IntlChessGame, from: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUp(from))
        events += game.onGesture(
            Gesture.Drop(IntlChessProtocol.cellXOf(from), IntlChessProtocol.cellYOf(from) - 5f, -1),
        )
        return events
    }

    @Test
    fun `initial position has 32 pieces and white moves first`() {
        val game = IntlChessGame()
        assertEquals(32, game.colors.count { it != IntlChessGame.EMPTY })
        assertTrue(game.whiteToMove)
        assertEquals(0, game.turn)
        assertEquals(IntlChessPiece.KING, game.types[index(4, 7)])
        assertEquals(IntlChessPiece.QUEEN, game.types[index(3, 7)])
        assertEquals(IntlChessGame.WHITE, game.colors[index(0, 6)])
        assertEquals(IntlChessGame.BLACK, game.colors[index(0, 0)])
        assertNull(game.drag)
    }

    @Test
    fun `white moves a pawn and the turn passes to black`() {
        val game = IntlChessGame()
        val from = index(0, 6)
        val to = index(0, 4)
        val events = drag(game, from, to)

        assertEquals(IntlChessGame.EMPTY, game.colors[from])
        assertEquals(IntlChessGame.WHITE, game.colors[to])
        assertEquals(IntlChessPiece.PAWN, game.types[to])
        assertFalse(game.whiteToMove)
        assertEquals(1, game.turn)
        assertTrue(events.any { it is DragEnded && it.committed })
    }

    @Test
    fun `moving when it is not your turn bounces back`() {
        val game = IntlChessGame()
        drag(game, index(0, 6), index(0, 4)) // 白走一步，轮到黑
        val before = IntlChessProtocol.encode(game.colors, game.types)

        val events = drag(game, index(1, 6), index(1, 5)) // 又动白子
        assertEquals(before, IntlChessProtocol.encode(game.colors, game.types))
        assertEquals(1, game.turn)
        assertTrue(events.filterIsInstance<DragEnded>().all { !it.committed })
    }

    @Test
    fun `moving onto an opponent piece captures it`() {
        val game = IntlChessGame()
        val from = index(0, 6) // 白兵
        val target = index(0, 1) // 黑兵
        assertEquals(IntlChessGame.BLACK, game.colors[target])

        drag(game, from, target)
        assertEquals(IntlChessGame.WHITE, game.colors[target])
        assertEquals(IntlChessPiece.PAWN, game.types[target])
        assertEquals(IntlChessGame.EMPTY, game.colors[from])
        assertEquals(31, game.colors.count { it != IntlChessGame.EMPTY })
    }

    @Test
    fun `moving onto your own piece bounces back`() {
        val game = IntlChessGame()
        drag(game, index(0, 6), index(1, 6))
        assertEquals(IntlChessGame.WHITE, game.colors[index(0, 6)])
        assertEquals(IntlChessGame.WHITE, game.colors[index(1, 6)])
        assertTrue(game.whiteToMove)
    }

    @Test
    fun `dragging off the board removes the piece without changing the turn`() {
        val game = IntlChessGame()
        dragOff(game, index(0, 7)) // 白车
        assertEquals(IntlChessGame.EMPTY, game.colors[index(0, 7)])
        assertNull(game.types[index(0, 7)])
        assertTrue(game.whiteToMove)
    }

    @Test
    fun `drag overlay carries the piece code as its name`() {
        val game = IntlChessGame()
        game.onGesture(Gesture.PickUp(index(3, 7))) // 白后
        val overlay = game.drag
        assertTrue(overlay != null)
        assertEquals("Q", overlay!!.piece.name)
        assertEquals(0, overlay.piece.side)
        assertEquals(index(3, 7), overlay.from)
        assertEquals(index(3, 7), overlay.piece.id)
    }

    @Test
    fun `snapshot round trips between two games`() {
        val a = IntlChessGame()
        drag(a, index(0, 6), index(0, 1)) // 吃一个黑兵
        val snapshot = a.snapshot()

        val b = IntlChessGame()
        b.apply(BoardChanged(snapshot.game, 5, snapshot.board, snapshot.turn, snapshot.counts))

        assertEquals(
            IntlChessProtocol.encode(a.colors, a.types),
            IntlChessProtocol.encode(b.colors, b.types),
        )
        assertEquals(a.turn, b.turn)
        assertEquals(64, snapshot.board.length)
    }

    @Test
    fun `positions are centred on the board`() {
        // 8 格：x, y ∈ [-3.5, +3.5]
        assertEquals(-3.5f, IntlChessProtocol.cellXOf(index(0, 0)), 0.0001f)
        assertEquals(3.5f, IntlChessProtocol.cellXOf(index(7, 0)), 0.0001f)
        assertEquals(-3.5f, IntlChessProtocol.cellYOf(index(0, 0)), 0.0001f)
        assertEquals(3.5f, IntlChessProtocol.cellYOf(index(0, 7)), 0.0001f)

        for (i in 0 until IntlChessGame.SIZE) {
            assertEquals(i, IntlChessProtocol.indexOf(IntlChessProtocol.cellXOf(i), IntlChessProtocol.cellYOf(i)))
        }
    }

    @Test
    fun `board string uses uppercase for white and lowercase for black`() {
        val board = IntlChessGame().snapshot().board
        assertEquals("rnbqkbnr", board.substring(0, 8))
        assertEquals("RNBQKBNR", board.substring(56, 64))
        assertEquals('p', board[8])
        assertEquals('P', board[48])
    }
}
