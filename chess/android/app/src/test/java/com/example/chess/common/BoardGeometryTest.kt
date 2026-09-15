package com.example.chess.common

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 只测棋盘几何（纯 Kotlin，不需要设备）：
 * 棋盘是不是「边长 = min(w,h)、中心 = 屏幕中心」的正方形，
 * 落点是不是每个格子的正中心，托盘是不是落在棋盘外的空余两侧。
 */
class BoardGeometryTest {

    /** 手机自然竖屏：1080 x 2400。 */
    private val phone = BoardGeometry(1080f, 2400f)

    /** 平板自然横屏：2560 x 1600。 */
    private val tablet = BoardGeometry(2560f, 1600f)

    @Test
    fun `board is a centered square with side = min(w, h)`() {
        assertEquals(1080f, phone.boardSize, 0.001f)
        assertEquals(0f, phone.boardLeft, 0.001f)
        assertEquals(660f, phone.boardTop, 0.001f)

        assertEquals(1600f, tablet.boardSize, 0.001f)
        assertEquals(480f, tablet.boardLeft, 0.001f)
        assertEquals(0f, tablet.boardTop, 0.001f)

        // 正方形中心 = 屏幕中心
        assertEquals(540f, phone.boardLeft + phone.boardSize / 2f, 0.001f)
        assertEquals(1200f, phone.boardTop + phone.boardSize / 2f, 0.001f)
        assertEquals(1280f, tablet.boardLeft + tablet.boardSize / 2f, 0.001f)
        assertEquals(800f, tablet.boardTop + tablet.boardSize / 2f, 0.001f)
    }

    @Test
    fun `square is divided into 20 cells and each cell center is an intersection`() {
        assertEquals(54f, phone.cell, 0.001f)
        assertEquals(80f, tablet.cell, 0.001f)

        // 第一个落点在第一个格子的正中心，最后一个落点在最后一个格子的正中心。
        assertEquals(1 * 54f, phone.gridX(0), 0.001f)
        assertEquals(19 * 54f, phone.gridX(18), 0.001f)
        assertEquals(660f + 1 * 54f, phone.gridY(0), 0.001f)
        assertEquals(660f + 19 * 54f, phone.gridY(18), 0.001f)

        // 一共 19 x 19 个落点，最外圈离正方形边界正好一格。
        assertEquals(19, phone.lines)
        assertEquals(19 * 19, phone.lines * phone.lines)
        for (i in 0 until phone.lines) {
            assertTrue(phone.gridX(i) > phone.boardLeft)
            assertTrue(phone.gridX(i) < phone.boardLeft + phone.boardSize)
            assertTrue(phone.gridY(i) > phone.boardTop)
            assertTrue(phone.gridY(i) < phone.boardTop + phone.boardSize)
        }

        // 屏幕正中心正好是一个落点（9, 9）。
        assertEquals(9 * 19 + 9, phone.indexAt(540f, 1200f))
    }

    @Test
    fun `indexAt snaps to the nearest intersection`() {
        // 落点 (3, 5) 附近 ±0.4 格都吸到同一个点。
        val x = phone.gridX(3)
        val y = phone.gridY(5)
        val expected = 5 * 19 + 3
        assertEquals(expected, phone.indexAt(x, y))
        assertEquals(expected, phone.indexAt(x + 0.4f * phone.cell, y - 0.4f * phone.cell))
        assertEquals(expected, phone.indexAt(x - 0.4f * phone.cell, y + 0.4f * phone.cell))

        // 越靠近边缘越吸到边缘的落点。
        assertEquals(0, phone.indexAt(phone.boardLeft + 1f, phone.boardTop + 1f))
        assertEquals(18 * 19 + 18, phone.indexAt(phone.boardLeft + 1080f - 1f, phone.boardTop + 1080f - 1f))
    }

    @Test
    fun `indexAt returns -1 outside the board square`() {
        assertEquals(-1, phone.indexAt(540f, 100f))          // 棋盘上方（托盘区）
        assertEquals(-1, phone.indexAt(540f, 2300f))         // 棋盘下方（托盘区）
        assertEquals(-1, phone.indexAt(-5f, 1200f))          // 棋盘左方
        assertEquals(-1, phone.indexAt(1085f, 1200f))        // 棋盘右方
        assertFalse(phone.isInsideBoard(540f, 100f))
        assertTrue(phone.isInsideBoard(540f, 660f))
    }

    @Test
    fun `trays sit in the free space on the two sides of the board`() {
        // 竖屏手机：上下有空余 ⇒ 黑托盘在棋盘上方、白托盘在下方，两个都水平居中。
        assertFalse(phone.trayOnSides)
        assertEquals(540f, phone.trayCenterX(true), 0.001f)
        assertEquals(540f, phone.trayCenterX(false), 0.001f)
        assertEquals(330f, phone.trayCenterY(true), 0.001f)
        assertEquals(2070f, phone.trayCenterY(false), 0.001f)

        // 横屏平板：左右有空余 ⇒ 黑托盘在左、白托盘在右，两个都垂直居中。
        assertTrue(tablet.trayOnSides)
        assertEquals(240f, tablet.trayCenterX(true), 0.001f)
        assertEquals(2320f, tablet.trayCenterX(false), 0.001f)
        assertEquals(800f, tablet.trayCenterY(true), 0.001f)
        assertEquals(800f, tablet.trayCenterY(false), 0.001f)

        // 托盘里的棋子和拖动中的棋子是同一个半径（比盘上的子略大一点）。
        assertEquals(24.84f, phone.stoneRadius, 0.01f)
        assertEquals(26.83f, phone.pieceRadius, 0.01f)
        assertEquals(phone.stoneRadius * 1.08f, phone.pieceRadius, 0.001f)
        assertEquals(36.8f, tablet.stoneRadius, 0.01f)
        assertEquals(39.74f, tablet.pieceRadius, 0.01f)

        // 托盘整颗棋子都落在屏幕内，并且不压到棋盘上。
        assertTrue(phone.trayCenterY(true) - phone.pieceRadius >= 0f)
        assertTrue(phone.trayCenterY(true) + phone.pieceRadius <= phone.boardTop)
        assertTrue(phone.trayCenterY(false) - phone.pieceRadius >= phone.boardTop + phone.boardSize)
        assertTrue(phone.trayCenterY(false) + phone.pieceRadius <= 2400f)
        assertTrue(tablet.trayCenterX(true) - tablet.pieceRadius >= 0f)
        assertTrue(tablet.trayCenterX(true) + tablet.pieceRadius <= tablet.boardLeft)
        assertTrue(tablet.trayCenterX(false) - tablet.pieceRadius >= tablet.boardLeft + tablet.boardSize)
        assertTrue(tablet.trayCenterX(false) + tablet.pieceRadius <= 2560f)
    }

    @Test
    fun `star points follow the board size`() {
        // 19 路围棋：9 个星（3x3 交叉点）
        val go = BoardGeometry.starPoints(19)
        assertEquals(9 * 2, go.size)
        assertTrue(go.toList().chunked(2).contains(listOf(9, 9))) // 天元
        assertTrue(go.toList().chunked(2).contains(listOf(3, 3)))

        // 15 路五子棋（连珠）：传统 5 个星 —— 四角 + 天元，没有边上的中点
        val gomoku = BoardGeometry.starPoints(15).toList().chunked(2)
        assertEquals(5, gomoku.size)
        assertTrue(gomoku.contains(listOf(7, 7))) // 天元
        assertTrue(gomoku.contains(listOf(3, 3)))
        assertTrue(gomoku.contains(listOf(3, 11)))
        assertTrue(gomoku.contains(listOf(11, 3)))
        assertTrue(gomoku.contains(listOf(11, 11)))
        assertFalse(gomoku.contains(listOf(7, 3)))

        // 星位都在棋盘里
        for ((col, row) in gomoku) {
            assertTrue(col in 0 until 15 && row in 0 until 15)
        }
    }
}
