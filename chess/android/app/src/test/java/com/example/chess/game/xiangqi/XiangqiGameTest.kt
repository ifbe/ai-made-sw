package com.example.chess.game.xiangqi

import com.example.chess.game.share.core.Gesture
import com.example.chess.game.share.protocol.BoardChanged
import com.example.chess.game.share.protocol.DragEnded
import com.example.chess.game.share.protocol.MoveEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 象棋盘面逻辑（数据 + 规则），纯 JVM。 */
class XiangqiGameTest {

    private fun index(file: Int, rank: Int) = rank * XiangqiGame.FILES + file

    /** 把 from 上的子拖到 to 并松手。 */
    private fun drag(game: XiangqiGame, from: Int, to: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUp(from))
        events += game.onGesture(Gesture.DragTo(XiangqiProtocol.cellXOf(to), XiangqiProtocol.cellYOf(to)))
        events += game.onGesture(
            Gesture.Drop(XiangqiProtocol.cellXOf(to), XiangqiProtocol.cellYOf(to), to),
        )
        return events
    }

    /** 把 from 上的子拖出棋盘（-1 = 盘外）。 */
    private fun dragOff(game: XiangqiGame, from: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUp(from))
        events += game.onGesture(
            Gesture.Drop(XiangqiProtocol.cellXOf(from), XiangqiProtocol.cellYOf(from) - 3f, -1),
        )
        return events
    }

    @Test
    fun `initial position has 32 pieces and red moves first`() {
        val game = XiangqiGame()
        assertEquals(32, game.colors.count { it != XiangqiGame.EMPTY })
        assertTrue(game.redToMove)
        assertEquals(0, game.turn)
        assertEquals(XiangqiPiece.KING, game.pieces[index(4, 9)])
        assertEquals(XiangqiPiece.KING, game.pieces[index(4, 0)])
        assertEquals(XiangqiGame.RED, game.colors[index(0, 9)])
        assertEquals(XiangqiGame.BLACK, game.colors[index(0, 0)])
        assertNull(game.drag)
    }

    @Test
    fun `red moves a piece and the turn passes to black`() {
        val game = XiangqiGame()
        val from = index(0, 6) // 红兵
        val to = index(0, 5)
        val events = drag(game, from, to)

        assertEquals(XiangqiGame.EMPTY, game.colors[from])
        assertEquals(XiangqiGame.RED, game.colors[to])
        assertFalse(game.redToMove)
        assertEquals(1, game.turn)
        assertNull(game.drag)

        // 传出去的是「位置流 + 落子后的全量棋盘」
        assertTrue(events.any { it is DragEnded && it.committed })
        val board = events.filterIsInstance<BoardChanged>().last()
        assertEquals(XiangqiGame.SIZE, board.board.length)
        assertEquals(1, board.turn)
    }

    @Test
    fun `moving when it is not your turn bounces back`() {
        val game = XiangqiGame()
        drag(game, index(0, 6), index(0, 5)) // 红先走一步，轮到黑
        val before = XiangqiProtocol.encode(game.colors, game.pieces)

        val events = drag(game, index(2, 6), index(2, 5)) // 又动红子
        assertEquals(before, XiangqiProtocol.encode(game.colors, game.pieces))
        assertEquals(1, game.turn) // 轮次没变
        assertTrue(events.filterIsInstance<DragEnded>().all { !it.committed })
    }

    @Test
    fun `moving onto an opponent piece captures it`() {
        val game = XiangqiGame()
        val from = index(0, 6) // 红兵
        val target = index(0, 3) // 黑卒
        assertEquals(XiangqiGame.BLACK, game.colors[target])

        val events = drag(game, from, target)
        assertEquals(XiangqiGame.RED, game.colors[target])
        assertEquals(XiangqiPiece.PAWN, game.pieces[target])
        assertEquals(XiangqiGame.EMPTY, game.colors[from])
        assertEquals(31, game.colors.count { it != XiangqiGame.EMPTY })
        assertTrue(events.filterIsInstance<DragEnded>().any { it.committed })
    }

    @Test
    fun `moving onto your own piece bounces back`() {
        val game = XiangqiGame()
        val from = index(0, 6)
        val own = index(2, 6)
        val events = drag(game, from, own)

        assertEquals(XiangqiGame.RED, game.colors[from])
        assertEquals(XiangqiGame.RED, game.colors[own])
        assertTrue(game.redToMove)
        assertTrue(events.filterIsInstance<DragEnded>().all { !it.committed })
    }

    @Test
    fun `dragging a piece off the board removes it without changing the turn`() {
        val game = XiangqiGame()
        val from = index(0, 9) // 红车
        val events = dragOff(game, from)

        assertEquals(XiangqiGame.EMPTY, game.colors[from])
        assertNull(game.pieces[from])
        assertTrue(game.redToMove) // 不换手
        assertTrue(events.any { it is BoardChanged })
    }

    @Test
    fun `drag overlay exists while dragging and is cleared after the drop`() {
        val game = XiangqiGame()
        val from = index(4, 9) // 红帅
        game.onGesture(Gesture.PickUp(from))
        val overlay = game.drag
        assertNotNull(overlay)
        assertEquals(from, overlay!!.from)
        assertTrue(overlay.byMe)
        assertEquals("帅", overlay.piece.name)
        assertEquals(0, overlay.piece.side)

        game.onGesture(Gesture.Drop(0f, 0f, from)) // 放回原位
        assertNull(game.drag)
    }

    @Test
    fun `snapshot round trips`() {
        val game = XiangqiGame()
        drag(game, index(0, 6), index(0, 3)) // 吃一个卒
        val snapshot = game.snapshot()

        val restored = XiangqiGame()
        restored.apply(BoardChanged(snapshot.game, seq = 99, board = snapshot.board, turn = snapshot.turn, counts = emptyList()))

        assertEquals(
            XiangqiProtocol.encode(game.colors, game.pieces),
            XiangqiProtocol.encode(restored.colors, restored.pieces),
        )
        assertEquals(game.turn, restored.turn)
    }

    @Test
    fun `board string is 90 chars and only uses the piece alphabet`() {
        val game = XiangqiGame()
        val board = game.snapshot().board
        assertEquals(90, board.length)
        assertTrue(board.all { it == '.' || it in "RNBAKCP" || it in "rnbakcp" })

        // 黑方底线（rank 0）：车马象士将士象马车，编码后是小写
        assertEquals("rnbakabnr", board.substring(0, 9))
        // 红方底线（rank 9）：同样顺序，编码后是大写
        assertEquals("RNBAKABNR", board.substring(81, 90))
        // 黑卒在 rank 3、红兵在 rank 6
        assertEquals("p.p.p.p.p", board.substring(27, 36))
        assertEquals("P.P.P.P.P", board.substring(54, 63))
    }

    @Test
    fun `positions are centred on the board`() {
        // 象棋 9 路：x ∈ [-4, 4]；10 路：y ∈ [-4.5, 4.5]
        assertEquals(-4f, XiangqiProtocol.cellXOf(index(0, 0)), 0.0001f)
        assertEquals(4f, XiangqiProtocol.cellXOf(index(8, 0)), 0.0001f)
        assertEquals(-4.5f, XiangqiProtocol.cellYOf(index(0, 0)), 0.0001f)
        assertEquals(4.5f, XiangqiProtocol.cellYOf(index(0, 9)), 0.0001f)

        for (i in 0 until XiangqiGame.SIZE) {
            assertEquals(i, XiangqiProtocol.indexOf(XiangqiProtocol.cellXOf(i), XiangqiProtocol.cellYOf(i)))
        }
    }

    @Test
    fun `reset puts everything back`() {
        val game = XiangqiGame()
        drag(game, index(0, 6), index(0, 5))
        val events = game.reset()

        assertEquals(32, game.colors.count { it != XiangqiGame.EMPTY })
        assertTrue(game.redToMove)
        assertTrue(events.isNotEmpty())
    }
}
