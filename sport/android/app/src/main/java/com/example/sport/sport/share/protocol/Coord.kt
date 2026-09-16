package com.example.sport.sport.share.protocol

import kotlin.math.roundToInt

/**
 * 一个球场坐标，**相对球场中心**，单位是**毫米的整数**，用整数传避免浮点误差。
 *
 * x 沿球场长边、y 沿球场短边，跟 [com.example.sport.sport.share.court.CourtGeometry] 的
 * 球场坐标一致 —— 所以横屏竖屏、长边横着还是竖着，对端都能照样还原。
 *
 * 为什么用毫米而不是「几分之一格」：球的场地是按**真实米数**定义的，
 * 足球场 105 米 = 105000 毫米，一个 int 装得下，精度 1 毫米远超肉眼需要。
 */
data class Coord(val x: Int, val y: Int) {

    /** 毫米 → 米。 */
    val metersX: Float get() = x / MM_PER_METER.toFloat()

    val metersY: Float get() = y / MM_PER_METER.toFloat()

    companion object {
        /** 一米有多少毫米。 */
        const val MM_PER_METER = 1000

        val ORIGIN = Coord(0, 0)

        fun ofMeters(x: Float, y: Float) = Coord(
            (x * MM_PER_METER).roundToInt(),
            (y * MM_PER_METER).roundToInt(),
        )
    }
}
