package com.example.chess.xiangqi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 只测象棋棋盘几何（纯 Kotlin，不需要设备）：
 *  - 短边 / 长边 < 9/10 时，格子边长 = min(w,h)/9，短边 9 路、长边 10 路；
 *  - 否则格子边长 = min(w,h)/10，短边 10 路、长边 9 路；
 *  - 棋盘居中、落在各自格子的正中心、整块棋盘一定放得下屏幕，
 *    而且落点一定映射得回原来的 (file, rank)。
 */
class ChessGeometryTest {

    /** 手机自然竖屏：1080 x 2400，比例 0.45 < 0.9。 */
    private val phone = ChessGeometry(1080f, 2400f)

    /** 平板自然横屏：2560 x 1600，比例 0.625 < 0.9。 */
    private val tablet = ChessGeometry(2560f, 1600f)

    /** 接近正方形的屏幕：1000 x 1050，比例 0.952 >= 0.9。 */
    private val squarish = ChessGeometry(1000f, 1050f)

    @Test
    fun `phone is elongated - 9 cells on the short side, 10 on the long side`() {
        assertTrue(phone.elongated)
        assertEquals(9, phone.shortAxisCells)
        assertEquals(10, phone.longAxisCells)

        // 格边长 = min(w,h)/9
        assertEquals(120f, phone.cell, 0.001f)

        // 竖屏：横向 9 路、纵向 10 路，棋子不会被转 90°
        assertFalse(phone.rotated)
        assertEquals(9, phone.cols)
        assertEquals(10, phone.rows)

        assertEquals(1080f, phone.boardWidth, 0.001f) // 正好占满短边
        assertEquals(1200f, phone.boardHeight, 0.001f)
        assertEquals(0f, phone.boardLeft, 0.001f)
        assertEquals(600f, phone.boardTop, 0.001f) // 上下各剩 600
        assertEquals(600f, phone.verticalSpace, 0.001f)
    }

    @Test
    fun `tablet landscape - 9 cells along the short side (board is rotated)`() {
        assertTrue(tablet.elongated)
        assertEquals(1600f / 9f, tablet.cell, 0.001f) // min(w,h)/9

        // 横屏时短边是高度 ⇒ 9 路竖着排，10 路横着排
        assertTrue(tablet.rotated)
        assertEquals(10, tablet.cols)
        assertEquals(9, tablet.rows)

        assertEquals(1600f, tablet.boardHeight, 0.001f)
        assertEquals(1600f * 10f / 9f, tablet.boardWidth, 0.001f)
        assertTrue(tablet.boardWidth <= 2560f)
        assertEquals(0f, tablet.boardTop, 0.001f)
        assertEquals((2560f - tablet.boardWidth) / 2f, tablet.boardLeft, 0.001f)
    }

    @Test
    fun `squarish screen - 10 cells on the short side, 9 on the long side`() {
        assertFalse(squarish.elongated)
        assertEquals(10, squarish.shortAxisCells)
        assertEquals(9, squarish.longAxisCells)

        // 格边长 = min(w,h)/10
        assertEquals(100f, squarish.cell, 0.001f)
        assertTrue(squarish.rotated)
        assertEquals(10, squarish.cols)
        assertEquals(9, squarish.rows)

        assertEquals(1000f, squarish.boardWidth, 0.001f) // 正好占满短边
        assertEquals(900f, squarish.boardHeight, 0.001f)
        assertEquals(75f, squarish.boardTop, 0.001f)
    }

    @Test
    fun `ratio exactly 9 to 10 goes to the second rule`() {
        val boundary = ChessGeometry(900f, 1000f)
        assertFalse(boundary.elongated) // 条件是不足 9/10 才算细长
        assertEquals(10, boundary.shortAxisCells)
        assertEquals(90f, boundary.cell, 0.001f)
        assertTrue(boundary.boardWidth <= 900f)
        assertTrue(boundary.boardHeight <= 1000f)
    }

    @Test
    fun `board always fits and always touches exactly one screen edge`() {
        val sizes = listOf(
            1080f to 2400f,
            1440f to 3120f,
            2560f to 1600f,
            2048f to 1536f,
            1000f to 1050f,
            1000f to 1000f,
            800f to 1280f,
            1280f to 800f,
            600f to 1024f,
        )
        for ((w, h) in sizes) {
            val g = ChessGeometry(w, h)
            val cells = g.cols * g.cell
            val rowsPx = g.rows * g.cell

            assertTrue("棋盘宽度放不下: $w x $h", cells <= w + 0.01f)
            assertTrue("棋盘高度放不下: $w x $h", rowsPx <= h + 0.01f)
            assertTrue("棋盘没有占满短边: $w x $h", cells >= w - 0.01f || rowsPx >= h - 0.01f)
            assertEquals(w / 2f, g.boardLeft + g.boardWidth / 2f, 0.01f)
            assertEquals(h / 2f, g.boardTop + g.boardHeight / 2f, 0.01f)

            // 9 路 / 10 路各出现一次
            val counts = listOf(g.cols, g.rows).sorted()
            assertEquals(listOf(9, 10), counts)

            // 最外圈的棋子完整落在屏幕里
            assertTrue(g.gridX(0) - g.cell / 2f >= -0.01f)
            assertTrue(g.gridX(g.cols - 1) + g.cell / 2f <= w + 0.01f)
            assertTrue(g.gridY(0) - g.cell / 2f >= -0.01f)
            assertTrue(g.gridY(g.rows - 1) + g.cell / 2f <= h + 0.01f)
        }
    }

    @Test
    fun `every intersection maps back to its own file and rank`() {
        for (g in listOf(phone, tablet, squarish)) {
            for (rank in 0 until ChessGeometry.RANKS) {
                for (file in 0 until ChessGeometry.FILES) {
                    val x = g.pieceX(file, rank)
                    val y = g.pieceY(file, rank)
                    val index = g.indexAt(x, y)
                    assertEquals(
                        "file=$file rank=$rank 映射错了",
                        rank * ChessGeometry.FILES + file,
                        index,
                    )
                    assertTrue(g.isInsideBoard(x, y))
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
    }

    @Test
    fun `river sits between rank 4 and rank 5`() {
        assertEquals(phone.gridY(4), phone.riverStart, 0.001f)
        assertEquals(phone.gridY(5), phone.riverEnd, 0.001f)
        assertTrue(phone.riverEnd > phone.riverStart)

        // 转 90° 时河界变成横坐标上的一条竖带
        assertEquals(tablet.gridX(4), tablet.riverStart, 0.001f)
        assertEquals(tablet.gridX(5), tablet.riverEnd, 0.001f)
    }

    @Test
    fun `palace covers the middle three files of the first and last three ranks`() {
        assertTrue(phone.isInPalace(3, 0))
        assertTrue(phone.isInPalace(4, 1))
        assertTrue(phone.isInPalace(5, 2))
        assertTrue(phone.isInPalace(4, 9))
        assertFalse(phone.isInPalace(2, 1))
        assertFalse(phone.isInPalace(4, 4))
    }

    @Test
    fun `side badges sit in the free strip at each end, text turned to face that player`() {
        // 竖屏手机：黑方在上、红方在下，两块的横向中心都在屏幕中间。
        assertEquals(600f, phone.badgeStrip, 0.001f)
        assertEquals(540f, phone.sideAnchorX(true), 0.001f)
        assertEquals(540f, phone.sideAnchorX(false), 0.001f)
        assertEquals(300f, phone.sideAnchorY(true), 0.001f)
        assertEquals(2100f, phone.sideAnchorY(false), 0.001f)
        // 上方那家的字要转 180°（对面红方看是倒的，黑方自己看是正的）
        assertEquals(180f, phone.sideTextRotation(true), 0.001f)
        assertEquals(0f, phone.sideTextRotation(false), 0.001f)

        // 横屏平板：棋盘转了 90°，黑方在左、红方在右。
        assertEquals(tablet.boardLeft, tablet.badgeStrip, 0.001f)
        assertEquals(tablet.boardLeft / 2f, tablet.sideAnchorX(true), 0.001f)
        assertEquals(2560f - tablet.boardLeft / 2f, tablet.sideAnchorX(false), 0.001f)
        assertEquals(800f, tablet.sideAnchorY(true), 0.001f)
        assertEquals(800f, tablet.sideAnchorY(false), 0.001f)
        // 左边那家转 +90°、右边那家转 -90°
        assertEquals(90f, tablet.sideTextRotation(true), 0.001f)
        assertEquals(-90f, tablet.sideTextRotation(false), 0.001f)

        // 牌子不会压到棋盘，也不会跑出屏幕
        for (g in listOf(phone, tablet, squarish)) {
            val strip = g.badgeStrip
            assertTrue(g.sideAnchorX(true) >= 0f && g.sideAnchorX(false) <= g.width)
            assertTrue(g.sideAnchorY(true) >= 0f && g.sideAnchorY(false) <= g.height)
            assertTrue(strip >= 0f)
        }
    }

    @Test
    fun `piece characters turn to face whoever is to move`() {
        // 竖屏手机：红方走 → 0°，轮到黑方 → 整盘棋子的字转 180°
        assertEquals(0f, phone.pieceTextRotation(redToMove = true), 0.001f)
        assertEquals(180f, phone.pieceTextRotation(redToMove = false), 0.001f)

        // 棋盘转 90° 时同一个道理，只是转的是 ±90°
        assertEquals(-90f, tablet.pieceTextRotation(redToMove = true), 0.001f)
        assertEquals(90f, tablet.pieceTextRotation(redToMove = false), 0.001f)
    }
}
