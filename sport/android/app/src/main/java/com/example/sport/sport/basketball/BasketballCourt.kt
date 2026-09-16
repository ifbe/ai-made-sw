package com.example.sport.sport.basketball

import kotlin.math.sqrt

/**
 * 篮球场（FIBA 标准 28 × 15 米）所有线的**真实尺寸**，单位统一是米。
 * 纯 Kotlin，不依赖 Android。
 *
 * 坐标系跟 [com.example.sport.sport.share.court.CourtGeometry] 一致：
 *  - `x` 沿球场**长边**，`y` 沿球场**短边**，原点在球场正中心；
 *  - 所以边界是 `x ∈ [-14, +14]`、`y ∈ [-7.5, +7.5]`；
 *  - 「左半场」= `x < 0`，篮筐在 `x = -12.425`；右半场镜像。
 *
 * 所有「离端线多少米」的数字都是从端线量的 FIBA 尺寸，这里已经换成以中心为原点的坐标。
 * 只有数据，没有逻辑。
 */
object BasketballCourt {

    // ------------------------------------------------------------------ 场地

    /** 场地长边（米）。 */
    const val LENGTH = 28f

    /** 场地短边（米）。 */
    const val WIDTH = 15f

    /** 中线位置：正好是原点。 */
    const val HALF_LINE_X = 0f

    /** 中圈半径（米）。 */
    const val CENTER_CIRCLE_R = 1.8f

    // ------------------------------------------------------------------ 篮筐

    /** 篮筐中心到端线的距离（米）。 */
    const val BASKET_FROM_BASELINE = 1.575f

    /** 篮板正面的宽度（米），篮筐画在这个宽度的正中。 */
    const val BACKBOARD_WIDTH = 1.8f

    /** 篮筐半径（米），画一个小圆。 */
    const val HOOP_R = 0.225f

    /** 篮板到篮筐的连线长度（米）：篮板在篮筐后面 0.375 米。 */
    const val BACKBOARD_BEHIND_HOOP = 0.375f

    // ------------------------------------------------------------------ 限制区（三秒区 / 油漆区）

    /** 罚球线到端线的距离（米），也就是限制区的长。 */
    const val FREE_THROW_FROM_BASELINE = 5.8f

    /** 限制区的宽度（米）。 */
    const val LANE_WIDTH = 4.9f

    /** 罚球圈半径（米）。 */
    const val FREE_THROW_CIRCLE_R = 1.8f

    // ------------------------------------------------------------------ 三分线

    /** 三分弧半径（米）。 */
    const val THREE_POINT_R = 6.75f

    /** 底角三分线到边线的距离（米）。 */
    const val CORNER_THREE_FROM_SIDELINE = 0.9f

    // ------------------------------------------------------------------ 合理冲撞区（无撞人半圆区）

    /** 合理冲撞区半径（米）。 */
    const val RESTRICTED_AREA_R = 1.25f

    // ------------------------------------------------------------------ 令牌与球

    /** 球员令牌的直径（米）。真人肩宽 0.5 米左右，放大到 2 米才点得到。 */
    const val PLAYER_TOKEN_DIAMETER = 2f

    /** 球的直径（米）。真球 0.24 米，放大到 0.7 米才看得见（外面还套一圈环）。 */
    const val BALL_DIAMETER = 0.7f

    // ------------------------------------------------------------------ 换算好的关键坐标

    /** 篮筐中心的 x：`side = -1` 是左半场，`+1` 是右半场。 */
    fun basketX(side: Int): Float =
        if (side < 0) -LENGTH / 2f + BASKET_FROM_BASELINE else LENGTH / 2f - BASKET_FROM_BASELINE

    /** 篮板所在的 x（在篮筐后面 0.375 米，比篮筐更靠端线）。 */
    fun backboardX(side: Int): Float =
        if (side < 0) {
            basketX(side) - BACKBOARD_BEHIND_HOOP
        } else {
            basketX(side) + BACKBOARD_BEHIND_HOOP
        }

    /** 罚球线的 x。 */
    fun freeThrowLineX(side: Int): Float =
        if (side < 0) {
            -LENGTH / 2f + FREE_THROW_FROM_BASELINE
        } else {
            LENGTH / 2f - FREE_THROW_FROM_BASELINE
        }

    /** 端线的 x。 */
    fun baselineX(side: Int): Float = if (side < 0) -LENGTH / 2f else LENGTH / 2f

    /** 底角三分线所在的 y（两条，`±1`）。 */
    fun cornerThreeY(side: Int): Float =
        if (side < 0) -WIDTH / 2f + CORNER_THREE_FROM_SIDELINE else WIDTH / 2f - CORNER_THREE_FROM_SIDELINE

    /**
     * 三分弧与底角直线相接的那个点（**靠端线**的那一侧）。
     *
     * 解一下：弧心在 `(basketX, 0)`、半径 6.75；底角直线是 `y = ±5.8`。
     * 代入圆方程得 `|x - basketX| = √(6.75² - 5.8²) ≈ 3.457`，
     * 取靠近端线的那一侧 ⇒ `x = basketX ∓ 3.457`（左半场减、右半场加）。
     */
    fun threePointCornerX(side: Int): Float {
        val dx = sqrt(THREE_POINT_R * THREE_POINT_R - cornerThreeY(1) * cornerThreeY(1))
        return if (side < 0) basketX(side) - dx else basketX(side) + dx
    }
}
