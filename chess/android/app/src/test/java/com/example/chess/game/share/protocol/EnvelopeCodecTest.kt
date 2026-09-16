package com.example.chess.game.share.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 报文信封的往返编解码 + 脏数据容错。纯 JVM，不需要设备。 */
class EnvelopeCodecTest {

    private val piece = PieceRef(side = 0, name = "车", id = 54)
    private val pos = BoardPos.ofCells(-1.25f, 3.5f)

    @Test
    fun `drag events round trip`() {
        val events = listOf(
            DragStarted(GameKind.XIANGQI, 1, piece, from = 54, pos = pos),
            DragMoved(GameKind.XIANGQI, 2, piece, pos),
            DragEnded(GameKind.XIANGQI, 3, piece, pos, committed = true),
            DragEnded(GameKind.XIANGQI, 4, piece, pos, committed = false),
        )
        for (event in events) {
            val line = EnvelopeCodec.encode(event)
            assertTrue("应该是一行文本: $line", !line.contains('\n'))
            assertEquals(event, EnvelopeCodec.decode(line))
        }
    }

    @Test
    fun `board and reset events round trip`() {
        val board = BoardChanged(
            game = GameKind.WEIQI,
            seq = 7,
            board = "..b.w...",
            turn = 1,
            counts = listOf(179, 180),
        )
        assertEquals(board, EnvelopeCodec.decode(EnvelopeCodec.encode(board)))

        val reset = GameReset(GameKind.INTL_CHESS, 8)
        assertEquals(reset, EnvelopeCodec.decode(EnvelopeCodec.encode(reset)))
    }

    @Test
    fun `stone piece without a name keeps an empty name field`() {
        val stone = PieceRef(side = 1, name = "", id = 12)
        val event = DragMoved(GameKind.WUZIQI, 5, stone, BoardPos.ORIGIN)
        assertEquals(event, EnvelopeCodec.decode(EnvelopeCodec.encode(event)))
    }

    @Test
    fun `unknown version and garbage decode to null`() {
        assertEquals(GameKind.WUZIQI, GameKind.fromId("wuziqi"))
        assertNull(GameKind.fromId("unknown"))

        assertNull(EnvelopeCodec.decode(""))
        assertNull(EnvelopeCodec.decode("v9|game=weiqi|seq=1|t=reset"))
        assertNull(EnvelopeCodec.decode("v1|seq=1|t=reset")) // 缺 game
        assertNull(EnvelopeCodec.decode("v1|game=weiqi|t=reset")) // 缺 seq
        assertNull(EnvelopeCodec.decode("v1|game=weiqi|seq=1|t=nonsense"))
        assertNull(EnvelopeCodec.decode("完全不是报文"))
    }

    @Test
    fun `positions use 1 over 256 cell fixed point`() {
        val p = BoardPos.ofCells(2f, -4.5f)
        assertEquals(2 * 256, p.x)
        assertEquals(-4 * 256 - 128, p.y)
        assertEquals(2f, p.cellX, 0.0001f)
        assertEquals(-4.5f, p.cellY, 0.0001f)

        // 精度是亚像素级：一格的 1/256
        val a = BoardPos.ofCells(0f, 0f)
        val b = BoardPos.ofCells(1f / 256f, 0f)
        assertEquals(1, b.x - a.x)
    }
}
