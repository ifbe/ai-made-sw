package com.example.sport.sport.football

import com.example.sport.sport.share.court.PlayerToken

/**
 * 4-3-3 开球站位表。纯 Kotlin，不依赖 Android。
 *
 * 阵型只写**一队**（客队），用「本方球门在 -x、往 +x 进攻」这一套坐标描述；
 * 主队直接取 `(-x, -y)` 镜像 —— 所以两队天然各占半场，不需要写两遍。
 *
 * 所有 x 都严格小于 0（本方半场），符合开球站位；中锋要站到中圈（r = 9.15）外面，所以是 -9.5。
 */
object FootballFormation {

    /** 阵型里的一个位置：号码 + 球场坐标（米）。 */
    data class Slot(val number: Int, val x: Float, val y: Float)

    /** 4-3-3：门将 / 四后卫 / 三中场 / 三前锋。 */
    val SLOTS_4_3_3 = listOf(
        Slot(1, -50.0f, 0.0f),    // 门将
        Slot(2, -35.0f, -22.0f),  // 右后卫
        Slot(4, -38.0f, -7.5f),   // 中后卫
        Slot(5, -38.0f, 7.5f),    // 中后卫
        Slot(3, -35.0f, 22.0f),   // 左后卫
        Slot(6, -15.0f, -14.0f),  // 后腰
        Slot(8, -15.0f, 0.0f),    // 中场
        Slot(10, -15.0f, 14.0f),  // 中场
        Slot(7, -9.5f, -21.0f),   // 右边锋
        Slot(9, -9.5f, 0.0f),     // 中锋
        Slot(11, -9.5f, 21.0f),   // 左边锋
    )

    /** 开球时球摆在球场正中心（中圈）。 */
    const val BALL_X = 0f
    const val BALL_Y = 0f

    /**
     * 生成开球阵容：22 个人。
     * 客队照抄阵型表，主队把 `x`、`y` 同时取反 —— 于是两队各占半场，球门前各有一名门将。
     */
    fun players(): List<PlayerToken> {
        val result = ArrayList<PlayerToken>(SLOTS_4_3_3.size * 2)
        // 客队（side = 1）：照抄阵型表
        SLOTS_4_3_3.forEachIndexed { index, slot ->
            result += PlayerToken(
                id = index,
                side = 1,
                number = slot.number,
                x = slot.x,
                y = slot.y,
            )
        }
        // 主队（side = 0）：x、y 同时取反 = 绕球场中心转 180°，于是占住另外半场
        SLOTS_4_3_3.forEachIndexed { index, slot ->
            result += PlayerToken(
                id = SLOTS_4_3_3.size + index,
                side = 0,
                number = slot.number,
                x = -slot.x,
                y = -slot.y,
            )
        }
        return result
    }
}
