package com.example.sport.sport.football

/**
 * 足球场（105 × 68 米）所有线的**真实尺寸**，单位统一是米。纯 Kotlin，不依赖 Android。
 *
 * 坐标系跟 [com.example.sport.sport.share.court.CourtGeometry] 一致：
 *  - `x` 沿球场**长边**，`y` 沿球场**短边**，原点在球场正中心；
 *  - 所以边界是 `x ∈ [-52.5, +52.5]`、`y ∈ [-34, +34]`；
 *  - 「左侧球门」= `x = -52.5` 那道端线，「右侧球门」= `x = +52.5`。
 *
 * 这里只有数据，没有逻辑：画线的地方按这些数字换算，不在这里判断任何规则（进球 / 出界都不算）。
 */
object FootballCourt {

    // ------------------------------------------------------------------ 场地

    /** 场地长边（米）。 */
    const val LENGTH = 105f

    /** 场地短边（米）。 */
    const val WIDTH = 68f

    /** 边线宽度（米），只是画出来的粗细。 */
    const val LINE_WIDTH = 0.12f

    /** 中线位置：正好是原点。 */
    const val HALF_LINE_X = 0f

    /** 中圈半径（米）。 */
    const val CENTER_CIRCLE_R = 9.15f

    /** 中圈中心的标志点半径（米）。 */
    const val CENTER_SPOT_R = 0.15f

    // ------------------------------------------------------------------ 球门

    /** 球门宽（米），两根门柱之间的距离。 */
    const val GOAL_WIDTH = 7.32f

    /** 球门深（米），画在端线**外侧**。 */
    const val GOAL_DEPTH = 2f

    /** 球门线（端线）的位置。 */
    const val GOAL_LINE_LEFT = -LENGTH / 2f
    const val GOAL_LINE_RIGHT = LENGTH / 2f

    // ------------------------------------------------------------------ 罚球区（大禁区）

    /** 大禁区沿长边方向的深度（米），从端线往里量。 */
    const val PENALTY_AREA_DEPTH = 16.5f

    /** 大禁区沿短边方向的宽度（米）。 */
    const val PENALTY_AREA_WIDTH = 40.32f

    // ------------------------------------------------------------------ 球门区（小禁区）

    /** 小禁区沿长边方向的深度（米），从端线往里量。 */
    const val GOAL_AREA_DEPTH = 5.5f

    /** 小禁区沿短边方向的宽度（米）。 */
    const val GOAL_AREA_WIDTH = 18.32f

    // ------------------------------------------------------------------ 罚球点与罚球弧

    /** 罚球点到端线的距离（米）。 */
    const val PENALTY_SPOT_FROM_LINE = 11f

    /** 罚球弧半径（米），和禁区弧同源。 */
    const val PENALTY_ARC_R = 9.15f

    // ------------------------------------------------------------------ 角球弧

    /** 角球弧半径（米）。 */
    const val CORNER_ARC_R = 1f

    /** 一个角球弧：圆心、起始角、扫过角度（Android Canvas 的约定，0° 朝右、顺时针为正）。 */
    data class CornerArc(
        val cx: Float,
        val cy: Float,
        val startAngle: Float,
        val sweepAngle: Float,
        val radius: Float = CORNER_ARC_R,
    )

    /**
     * 四个角球弧。
     *
     * 四角的圆心分别是 `(±52.5, ±34)`，弧都是朝**场内**的四分之一圆：
     *  - 右端（x = +52.5）的两条：从 180° 扫到 270°，扫过 +90°；
     *  - 左端（x = -52.5）的两条：从 90° 扫到 0°，扫过 -90°。
     */
    val cornerArcs: List<CornerArc> = listOf(
        CornerArc(GOAL_LINE_RIGHT, -WIDTH / 2f, 180f, 90f),
        CornerArc(GOAL_LINE_RIGHT, WIDTH / 2f, 180f, 90f),
        CornerArc(GOAL_LINE_LEFT, -WIDTH / 2f, 90f, -90f),
        CornerArc(GOAL_LINE_LEFT, WIDTH / 2f, 90f, -90f),
    )

    // ------------------------------------------------------------------ 令牌与球

    /** 球员令牌的直径（米）。真人是 0.5 米宽，这里放大到 2 米才点得到。 */
    const val PLAYER_TOKEN_DIAMETER = 2f

    /** 球的直径（米）。真球 0.22 米，放大到 0.7 米才看得见。 */
    const val BALL_DIAMETER = 0.7f

    /** 球门线所在的端线，哪一侧：`-1` 左、`+1` 右。 */
    fun goalLineX(side: Int): Float = if (side < 0) GOAL_LINE_LEFT else GOAL_LINE_RIGHT
}
