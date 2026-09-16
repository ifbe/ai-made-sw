package com.example.sport.sport.share.court

/**
 * 一个球类项目的场地尺寸与配色。纯 Kotlin，不依赖 Android，JVM 可单测。
 *
 * 尺寸一律用**真实米数**：场地、线宽、人、球。它们会按同一个比例尺 [CourtGeometry.scale]
 * 落到屏幕上，所以「人在球场上看起来多大」在所有项目里都成立。
 *
 * @param fieldLong 场地长边（米）。足球 105、篮球 28、排球 18、乒乓球 2.74。
 * @param fieldShort 场地短边（米）。足球 68、篮球 15、排球 9、乒乓球 1.525。
 * @param lineWidthMeters 线的真实粗细（米），只是画出来的手感，不影响几何。
 * @param playerTokenDiameter 球员令牌的直径（米）。真人都比这窄，放大到看得见 / 点得到。
 * @param ballDiameter 球的直径（米）。同样会放大到看得见（外面还套一圈环）。
 * @param centerCircleRadius 中圈半径（米）。
 * @param surfaceColor 场地底色（草皮 / 木地板 / 塑胶 / 台面）。
 * @param homeColor / [awayColor] 两队令牌颜色，也是黑带上队牌的颜色。
 * @param ballRingColor 球外面那圈环的颜色，要跟两队颜色都区分得开。
 */
data class CourtSpec(
    val fieldLong: Float,
    val fieldShort: Float,
    val lineWidthMeters: Float,
    val playerTokenDiameter: Float,
    val ballDiameter: Float,
    val centerCircleRadius: Float,
    val surfaceColor: Int,
    val homeColor: Int,
    val awayColor: Int,
    val ballRingColor: Int,
    /** 球的初始位置（球场坐标，米），默认在场地正中。 */
    val ballStartLong: Float = 0f,
    val ballStartShort: Float = 0f,
)
