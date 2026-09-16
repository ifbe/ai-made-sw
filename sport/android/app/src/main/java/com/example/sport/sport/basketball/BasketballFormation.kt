package com.example.sport.sport.basketball

import com.example.sport.sport.share.court.PlayerToken

/**
 * 篮球开局站位（每队 5 人）。纯 Kotlin，不依赖 Android。
 *
 * 跟足球那套一样：只写**一队**（客队），用「本方半场在 -x、往 +x 进攻」描述，
 * 主队取 `(-x, -y)` 镜像 —— 两队各占半场，各自篮下站一个人。
 *
 * 篮球没有「开球站位」这种硬规定（跳球后就是活球），所以这里按最常见的半场落位摆：
 * 控卫持球在中圈后、其余四人拉开在两侧。球摆在球场正中（中圈）。
 */
object BasketballFormation {

    private data class Slot(val number: Int, val x: Float, val y: Float)

    /**
     * 1 号位控卫 / 2 号位分卫 / 3 号位小前 / 4 号位大前 / 5 号位中锋。
     *
     * 注意 2 号和 5 号用 `y = ±4` 错开：如果两个人都放在 `y = 0`，主客队镜像之后
     * 会在中圈附近叠成一坨（足球那边也有同样的问题，所以中锋没放在中线上）。
     */
    private val SLOTS = listOf(
        Slot(1, -2.0f, 0.0f),   // 控球后卫：持球
        Slot(2, -5.0f, 4.0f),   // 得分后卫：右侧
        Slot(3, -5.0f, -5.0f),  // 小前锋：左侧
        Slot(4, -9.0f, 3.5f),   // 大前锋：右侧靠篮
        Slot(5, -9.0f, -4.0f),  // 中锋：左侧靠篮
    )

    /** 球摆在球场正中（中圈）。 */
    const val BALL_X = 0f
    const val BALL_Y = 0f

    /** 生成开球阵容：10 个人。 */
    fun players(): List<PlayerToken> {
        val result = ArrayList<PlayerToken>(SLOTS.size * 2)
        // 客队（side = 1）：照抄站位表
        SLOTS.forEachIndexed { index, slot ->
            result += PlayerToken(
                id = index,
                side = 1,
                number = slot.number,
                x = slot.x,
                y = slot.y,
            )
        }
        // 主队（side = 0）：x、y 同时取反 = 绕球场中心转 180°，占住另外半场
        SLOTS.forEachIndexed { index, slot ->
            result += PlayerToken(
                id = SLOTS.size + index,
                side = 0,
                number = slot.number,
                x = -slot.x,
                y = -slot.y,
            )
        }
        return result
    }
}
