package com.example.chess.game.share.protocol

import kotlin.math.roundToInt

/**
 * 相对棋盘中心的坐标，单位 = 1/256 格，用整数避免浮点误差。
 *
 * x 沿 file / 列方向（向右为正），y 沿 rank / 行方向（向下为正）——
 * 这是「棋盘语义坐标」而不是屏幕坐标，所以棋盘在横屏被转 90° 也照样对得上。
 *
 * 各种棋的落点范围（拖动中可能超出，超出棋盘 = 被吃）：
 *  - 象棋：x ∈ [-4, +4]（整数），y ∈ [-4.5, +4.5]（半整数）
 *  - 国际象棋：x, y ∈ [-3.5, +3.5]
 *  - 围棋 19 路：x, y ∈ [-9, +9]；五子棋 15 路：x, y ∈ [-7, +7]
 *
 * 1/256 格在 1080p 手机上约等于 0.2~0.5 像素，肉眼绝对看不出台阶。
 */
data class BoardPos(val x: Int, val y: Int) {

    val cellX: Float get() = x / UNITS_PER_CELL.toFloat()

    val cellY: Float get() = y / UNITS_PER_CELL.toFloat()

    companion object {
        /** 一格的精度单位。 */
        const val UNITS_PER_CELL = 256

        val ORIGIN = BoardPos(0, 0)

        fun ofCells(cellX: Float, cellY: Float) = BoardPos(
            (cellX * UNITS_PER_CELL).roundToInt(),
            (cellY * UNITS_PER_CELL).roundToInt(),
        )
    }
}
