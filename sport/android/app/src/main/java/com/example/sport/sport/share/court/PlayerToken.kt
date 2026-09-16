package com.example.sport.sport.share.court

/**
 * 一名球员的**显示信息 + 位置**。纯 Kotlin，不依赖 Android。
 *
 * [x] / [y] 是球场坐标（米，原点在球场中心，见 [CourtGeometry]）：
 * x 沿球场长边、y 沿球场短边。
 *
 * @param id 唯一标识，拖动时用它认人。
 * @param side 0 = 主队（屏幕下方那一端），1 = 客队。
 * @param number 号码，画在令牌正中。
 */
data class PlayerToken(
    val id: Int,
    val side: Int,
    val number: Int,
    var x: Float,
    var y: Float,
)
