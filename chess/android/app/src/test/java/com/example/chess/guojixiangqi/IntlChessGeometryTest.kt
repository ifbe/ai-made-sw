package com.example.chess.guojixiangqi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 只测国际象棋棋盘几何（纯 Kotlin，不需要设备）：
 * 棋盘区是不是 min(w,h) 的居中方块、8 × 8 方格、标准深浅格，
 * 以及两端牌子 / 棋子文字朝向。
 */
class IntlChessGeometryTest {

    /** 手机自然竖屏：1080 x 2400。 */
    private val phone = IntlChessGeometry(1080f, 2400f)

    /** 平板自然横屏：2560 x 1600。 */
    private val tablet = IntlChessGeometry(2560f, 1600f)

    @Test
    fun `board is a centered square of side min(w, h) split into 8x8 squares`() {
        assertEquals(1080f, phone.boardSize, 0.001f)
        assertEquals(0f, phone.boardLeft, 0.001f)
        assertEquals(660f, phone.boardTop, 0.001f)
        assertEquals(135f, phone.cell, 0.001f)
        assertFalse(phone.rotated)

        // 方格中心：a1（file 0, rank 7）在左下角
        assertEquals(67.5f, phone.squareX(0, 7), 0.001f)
        assertEquals(660f + 7.5f * 135f, phone.squareY(0, 7), 0.001f)
        // 棋盘中心 = 屏幕中心
        assertEquals(540f, phone.boardLeft + phone.boardSize / 2f, 0.001f)
        assertEquals(1200f, phone.boardTop + phone.boardSize / 2f, 0.001f)
    }

    @Test
    fun `landscape screen rotates the board so black is on the left`() {
        assertTrue(tablet.rotated)
        assertEquals(1600f, tablet.boardSize, 0.001f)
        assertEquals(200f, tablet.cell, 0.001f)
        assertEquals(480f, tablet.boardLeft, 0.001f)
        assertEquals(0f, tablet.boardTop, 0.001f)

        // rank 0（黑方底线）转到屏幕左边，rank 7（白方底线）转到右边
        assertTrue(tablet.squareX(0, 0) < tablet.boardLeft + tablet.boardSize / 2f)
        assertTrue(tablet.squareX(0, 7) > tablet.boardLeft + tablet.boardSize / 2f)
        assertEquals(480f + 0.5f * 200f, tablet.squareX(0, 0), 0.001f)
    }

    @Test
    fun `a1 is dark and h1 is light`() {
        // 标准的 a1 深色 / h1 浅色（file 0..7 = a..h，rank 7 = 第 1 横排）
        assertTrue(phone.isDarkSquare(0, 7)) // a1
        assertFalse(phone.isDarkSquare(7, 7)) // h1
        assertFalse(phone.isDarkSquare(0, 0)) // a8
        assertTrue(phone.isDarkSquare(7, 0)) // h8
    }

    @Test
    fun `every square maps back to its own file and rank`() {
        for (g in listOf(phone, tablet)) {
            for (rank in 0 until IntlChessGeometry.RANKS) {
                for (file in 0 until IntlChessGeometry.FILES) {
                    val index = g.indexAt(g.squareX(file, rank), g.squareY(file, rank))
                    assertEquals(
                        "file=$file rank=$rank 映射错了",
                        rank * IntlChessGeometry.FILES + file,
                        index,
                    )
                    assertTrue(g.isInsideBoard(g.squareX(file, rank), g.squareY(file, rank)))
                }
            }
        }
    }

    @Test
    fun `indexAt returns -1 outside the board`() {
        assertEquals(-1, phone.indexAt(540f, 100f)) // 棋盘上方
        assertEquals(-1, phone.indexAt(540f, 2300f)) // 棋盘下方
        assertEquals(-1, phone.indexAt(-5f, 1200f))
        assertEquals(-1, phone.indexAt(1085f, 1200f))

        // 棋盘外那一条空带一定够放牌子
        assertTrue(phone.badgeStrip > 0f)
        assertTrue(tablet.badgeStrip > 0f)
    }

    @Test
    fun `side badges sit at each end and text faces that player`() {
        // 竖屏：黑方在上、白方在下
        assertEquals(540f, phone.sideAnchorX(true), 0.001f)
        assertEquals(540f, phone.sideAnchorX(false), 0.001f)
        assertEquals(330f, phone.sideAnchorY(true), 0.001f)
        assertEquals(2070f, phone.sideAnchorY(false), 0.001f)
        assertEquals(180f, phone.sideTextRotation(true), 0.001f)
        assertEquals(0f, phone.sideTextRotation(false), 0.001f)

        // 横屏：黑方在左、白方在右
        assertEquals(tablet.boardLeft / 2f, tablet.sideAnchorX(true), 0.001f)
        assertEquals(2560f - tablet.boardLeft / 2f, tablet.sideAnchorX(false), 0.001f)
        assertEquals(800f, tablet.sideAnchorY(true), 0.001f)
        assertEquals(90f, tablet.sideTextRotation(true), 0.001f)
        assertEquals(-90f, tablet.sideTextRotation(false), 0.001f)
    }

    @Test
    fun `piece glyphs face whoever is to move, white first`() {
        assertEquals(0f, phone.pieceTextRotation(whiteToMove = true), 0.001f)
        assertEquals(180f, phone.pieceTextRotation(whiteToMove = false), 0.001f)
        assertEquals(-90f, tablet.pieceTextRotation(whiteToMove = true), 0.001f)
        assertEquals(90f, tablet.pieceTextRotation(whiteToMove = false), 0.001f)
    }
}
