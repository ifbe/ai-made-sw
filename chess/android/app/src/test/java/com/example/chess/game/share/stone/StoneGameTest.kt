package com.example.chess.game.share.stone

import com.example.chess.game.share.core.Gesture
import com.example.chess.game.share.protocol.BoardChanged
import com.example.chess.game.share.protocol.DragEnded
import com.example.chess.game.share.protocol.GameKind
import com.example.chess.game.share.protocol.MoveEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 围棋 / 五子棋共用的盘面逻辑，纯 JVM。 */
class StoneGameTest {

    private fun go() = StoneGame(lines = 19, kind = GameKind.WEIQI)

    private fun index(col: Int, row: Int, lines: Int = 19) = row * lines + col

    /** 从托盘拿一颗新子放到 [to]。 */
    private fun place(game: StoneGame, side: Int, to: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUpNew(side, cellX = -10f, cellY = -10f))
        events += game.onGesture(
            Gesture.Drop(StoneProtocol.cellXOf(to, game.lines), StoneProtocol.cellYOf(to, game.lines), to),
        )
        return events
    }

    /** 把盘上的子从 [from] 拖到 [to]。 */
    private fun move(game: StoneGame, from: Int, to: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUp(from))
        events += game.onGesture(
            Gesture.Drop(StoneProtocol.cellXOf(to, game.lines), StoneProtocol.cellYOf(to, game.lines), to),
        )
        return events
    }

    /** 把盘上的子拖出棋盘（被吃）。 */
    private fun capture(game: StoneGame, from: Int): List<MoveEvent> {
        val events = ArrayList<MoveEvent>()
        events += game.onGesture(Gesture.PickUp(from))
        events += game.onGesture(
            Gesture.Drop(StoneProtocol.cellXOf(from, game.lines), StoneProtocol.cellYOf(from, game.lines) - 12f, -1),
        )
        return events
    }

    @Test
    fun `fresh board is empty and black moves first`() {
        val game = go()
        assertEquals(0, game.grid.count { it != StoneGame.EMPTY })
        assertEquals(StoneGame.INITIAL_STONES, game.blackRemaining)
        assertEquals(StoneGame.INITIAL_STONES, game.whiteRemaining)
        assertEquals(0, game.turn)
        assertNull(game.drag)
    }

    @Test
    fun `placing a stone from the tray uses one up and passes the turn`() {
        val game = go()
        val target = index(3, 3)
        val events = place(game, side = 0, to = target)

        assertEquals(StoneGame.BLACK, game.grid[target])
        assertEquals(StoneGame.INITIAL_STONES - 1, game.blackRemaining)
        assertEquals(1, game.turn)
        assertTrue(events.any { it is DragEnded && it.committed })

        val board = events.filterIsInstance<BoardChanged>().last()
        assertEquals(19 * 19, board.board.length)
        assertEquals(listOf(179, 180), board.counts)
    }

    @Test
    fun `the tray of the side that is not to move cannot be used`() {
        val game = go()
        val events = place(game, side = 1, to = index(3, 3)) // 黑先，白托盘
        assertTrue(events.isEmpty())
        assertEquals(StoneGame.EMPTY, game.grid[index(3, 3)])
        assertEquals(StoneGame.INITIAL_STONES, game.whiteRemaining)
        assertNull(game.drag)
    }

    @Test
    fun `placing on an occupied point does nothing`() {
        val game = go()
        place(game, side = 0, to = index(3, 3)) // 黑子
        val white = index(4, 4)
        place(game, side = 1, to = white) // 白子，现在轮到黑

        val events = place(game, side = 0, to = index(3, 3)) // 黑想放到已有黑子的位置
        assertTrue(events.filterIsInstance<DragEnded>().all { !it.committed })
        assertEquals(StoneGame.BLACK, game.grid[index(3, 3)])
        assertEquals(StoneGame.INITIAL_STONES - 1, game.blackRemaining) // 数量没有变
    }

    @Test
    fun `a stone on the board can be moved on your turn`() {
        val game = go()
        place(game, side = 0, to = index(3, 3)) // 黑
        place(game, side = 1, to = index(4, 4)) // 白，轮到黑

        val from = index(3, 3)
        val to = index(5, 5)
        val events = move(game, from, to)

        assertEquals(StoneGame.EMPTY, game.grid[from])
        assertEquals(StoneGame.BLACK, game.grid[to])
        assertEquals(1, game.turn) // 换手给白
        assertTrue(events.any { it is DragEnded && it.committed })
        // 移动不是落新子，数量不变
        assertEquals(StoneGame.INITIAL_STONES - 1, game.blackRemaining)
    }

    @Test
    fun `moving out of turn bounces back`() {
        val game = go()
        place(game, side = 0, to = index(3, 3)) // 黑
        place(game, side = 1, to = index(4, 4)) // 白，轮到黑

        val before = StoneProtocol.encode(game.grid)
        val events = move(game, index(4, 4), index(6, 6)) // 动白子
        assertEquals(before, StoneProtocol.encode(game.grid))
        assertEquals(0, game.turn)
        assertTrue(events.filterIsInstance<DragEnded>().all { !it.committed })
    }

    @Test
    fun `dragging a stone off the board removes it and keeps the counts`() {
        val game = go()
        place(game, side = 0, to = index(3, 3))
        val target = index(3, 3)
        capture(game, target)

        assertEquals(StoneGame.EMPTY, game.grid[target])
        assertEquals(StoneGame.INITIAL_STONES - 1, game.blackRemaining) // 被提的子不回托盘
        assertEquals(1, game.turn) // 拎走不算一步，不换手
    }

    @Test
    fun `moving onto an occupied point bounces back`() {
        val game = go()
        place(game, side = 0, to = index(3, 3))
        place(game, side = 1, to = index(4, 4)) // 轮到黑

        move(game, index(3, 3), index(4, 4)) // 黑想挪到白子上
        assertEquals(StoneGame.BLACK, game.grid[index(3, 3)])
        assertEquals(StoneGame.WHITE, game.grid[index(4, 4)])
        assertEquals(0, game.turn)
    }

    @Test
    fun `gomoku uses 15 lines and its own game kind`() {
        val game = StoneGame(lines = 15, kind = GameKind.WUZIQI)
        assertEquals(15 * 15, game.grid.size)
        assertEquals(GameKind.WUZIQI, game.snapshot().game)

        val target = index(7, 7, lines = 15)
        place(game, side = 0, to = target)
        assertEquals(15 * 15, game.snapshot().board.length)
        assertEquals(StoneGame.BLACK, game.grid[target])
    }

    @Test
    fun `snapshot round trips between two games`() {
        val a = go()
        place(a, side = 0, to = index(3, 3))
        place(a, side = 1, to = index(16, 16))
        val snapshot = a.snapshot()

        val b = go()
        b.apply(BoardChanged(snapshot.game, 3, snapshot.board, snapshot.turn, snapshot.counts))

        assertEquals(StoneProtocol.encode(a.grid), StoneProtocol.encode(b.grid))
        assertEquals(a.turn, b.turn)
        assertEquals(a.blackRemaining, b.blackRemaining)
        assertEquals(a.whiteRemaining, b.whiteRemaining)
    }

    @Test
    fun `positions are centred on the board`() {
        // 19 路：x, y ∈ [-9, +9]
        assertEquals(-9f, StoneProtocol.cellXOf(index(0, 0), 19), 0.0001f)
        assertEquals(9f, StoneProtocol.cellXOf(index(18, 0), 19), 0.0001f)
        assertEquals(-9f, StoneProtocol.cellYOf(index(0, 0), 19), 0.0001f)
        assertEquals(9f, StoneProtocol.cellYOf(index(0, 18), 19), 0.0001f)

        // 15 路：±7
        assertEquals(-7f, StoneProtocol.cellXOf(index(0, 0, 15), 15), 0.0001f)
        assertEquals(7f, StoneProtocol.cellXOf(index(14, 0, 15), 15), 0.0001f)

        for (i in 0 until 19 * 19) {
            assertEquals(i, StoneProtocol.indexOf(StoneProtocol.cellXOf(i, 19), StoneProtocol.cellYOf(i, 19), 19))
        }
    }

    @Test
    fun `a remote drag shows up as an overlay without touching the board`() {
        val host = go()
        place(host, side = 0, to = index(3, 3))

        val client = go()
        val snapshot = host.snapshot()
        client.apply(BoardChanged(snapshot.game, 1, snapshot.board, snapshot.turn, snapshot.counts))

        // 对端拖动的只是浮层，本地盘面不受影响
        val started = host.onGesture(Gesture.PickUp(index(3, 3))).first()
        client.apply(started)
        assertEquals(StoneGame.BLACK, client.grid[index(3, 3)])
        assertTrue(client.drag != null)
        assertFalse(client.drag!!.byMe)
    }
}
