package com.example.sport.sport.basketball

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [BasketballCourt] 的纯 JVM 测试：验证 FIBA 尺寸换算成「以球场中心为原点」的坐标之后，
 * 所有线都落在场地内、而且关键长度对得上。
 */
class BasketballCourtTest {

    private val halfLong = BasketballCourt.LENGTH / 2f   // 14
    private val halfShort = BasketballCourt.WIDTH / 2f   // 7.5

    /** 端线在 ±14 米处。 */
    @Test
    fun baselinesAreAtTheFieldEnds() {
        assertEquals(-14f, BasketballCourt.baselineX(-1), 0.001f)
        assertEquals(14f, BasketballCourt.baselineX(1), 0.001f)
        assertEquals(halfLong, BasketballCourt.baselineX(1), 0.001f)
    }

    /** 篮筐中心离端线 1.575 米，所以左半场是 -12.425、右半场是 +12.425。 */
    @Test
    fun basketIs1575FromTheBaseline() {
        assertEquals(-12.425f, BasketballCourt.basketX(-1), 0.001f)
        assertEquals(12.425f, BasketballCourt.basketX(1), 0.001f)

        for (side in intArrayOf(-1, 1)) {
            val distance = kotlin.math.abs(BasketballCourt.basketX(side) - BasketballCourt.baselineX(side))
            assertEquals(BasketballCourt.BASKET_FROM_BASELINE, distance, 0.001f)
        }
    }

    /** 篮板在篮筐后面 0.375 米，也就是离端线 1.2 米。 */
    @Test
    fun backboardIsBehindTheHoop() {
        for (side in intArrayOf(-1, 1)) {
            val distance = kotlin.math.abs(BasketballCourt.backboardX(side) - BasketballCourt.baselineX(side))
            assertEquals(1.2f, distance, 0.001f)
            // 篮板一定比篮筐更靠端线
            assertTrue(
                kotlin.math.abs(BasketballCourt.backboardX(side)) >
                    kotlin.math.abs(BasketballCourt.basketX(side)),
            )
        }
    }

    /** 罚球线离端线 5.8 米 → x = ∓8.2。 */
    @Test
    fun freeThrowLineIs58FromTheBaseline() {
        assertEquals(-8.2f, BasketballCourt.freeThrowLineX(-1), 0.001f)
        assertEquals(8.2f, BasketballCourt.freeThrowLineX(1), 0.001f)
    }

    /** 底角三分线离边线 0.9 米 → y = ±6.6。 */
    @Test
    fun cornerThreeIs09FromTheSideline() {
        assertEquals(-6.6f, BasketballCourt.cornerThreeY(-1), 0.001f)
        assertEquals(6.6f, BasketballCourt.cornerThreeY(1), 0.001f)
        assertEquals(halfShort - 0.9f, BasketballCourt.cornerThreeY(1), 0.001f)
    }

    /**
     * 三分弧与底角直线的接点：`|x - 篮筐x| = √(6.75² - 5.8²) ≈ 3.457`，
     * 而且这个接点必须**在场地里**（底角直线不能戳出端线）。
     */
    @Test
    fun threePointCornerJoinsTheArcInsideTheField() {
        val dy = BasketballCourt.cornerThreeY(1) // 5.8
        val dx = kotlin.math.sqrt(BasketballCourt.THREE_POINT_R * BasketballCourt.THREE_POINT_R - dy * dy)

        for (side in intArrayOf(-1, 1)) {
            val cornerX = BasketballCourt.threePointCornerX(side)
            val basketX = BasketballCourt.basketX(side)
            assertEquals(dx, kotlin.math.abs(cornerX - basketX), 0.001f)
            // 在场地内（不超出端线，也不越过中线）
            assertTrue("接点 $cornerX 越出端线", cornerX > -halfLong && cornerX < halfLong)
            // 底角直线是从端线往里画的，所以接点一定比端线靠近中线
            assertTrue(kotlin.math.abs(cornerX) < halfLong)
        }
    }

    /** 三分弧的两个端点确实在弧上（到篮筐的距离 = 6.75 米）。 */
    @Test
    fun threePointArcEndpointsAreOnTheArc() {
        for (side in intArrayOf(-1, 1)) {
            val cornerX = BasketballCourt.threePointCornerX(side)
            for (edge in intArrayOf(-1, 1)) {
                val dx = cornerX - BasketballCourt.basketX(side)
                val dy = BasketballCourt.cornerThreeY(edge)
                assertEquals(BasketballCourt.THREE_POINT_R, kotlin.math.sqrt(dx * dx + dy * dy), 0.001f)
            }
        }
    }

    /** 合理冲撞区（1.25 米）的两端接在限制区的两条线上：y = ±1.25。 */
    @Test
    fun restrictedAreaEndsOnTheLaneLines() {
        assertEquals(1.25f, BasketballCourt.RESTRICTED_AREA_R, 0.001f)
        assertTrue(BasketballCourt.RESTRICTED_AREA_R < BasketballCourt.LANE_WIDTH / 2f)
    }

    /** 场地是对称的：左半场所有东西取反就是右半场。 */
    @Test
    fun theTwoHalvesAreMirrorImages() {
        assertEquals(BasketballCourt.basketX(-1), -BasketballCourt.basketX(1), 0.001f)
        assertEquals(BasketballCourt.backboardX(-1), -BasketballCourt.backboardX(1), 0.001f)
        assertEquals(BasketballCourt.freeThrowLineX(-1), -BasketballCourt.freeThrowLineX(1), 0.001f)
        assertEquals(BasketballCourt.threePointCornerX(-1), -BasketballCourt.threePointCornerX(1), 0.001f)
    }
}
