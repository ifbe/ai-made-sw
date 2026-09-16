package com.example.sport.sport.share.court

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [CourtArc] 的纯 JVM 测试。
 *
 * 两个真踩过的坑都钉在这里：
 *
 *  1. 判方向不能比「中点离 bulge 点的**距离**」—— 角球弧的圆心顶在角点上、离场地中心很远，
 *     四个角里会挑反两个；
 *  2. 半圆（两端正好隔 180°）压根**没法**用一个方向判出来：两条候选路径的中点方向是垂直的。
 *     所以半圆必须走 `CourtView.drawArc` 明说扫过角度。
 *
 * 测试全部在**屏幕像素**里算，不做「球场坐标 ↔ 像素」的来回换算 —— 那层换算是
 * [CourtGeometry] 的事，这里只想验证角度。
 */
class CourtArcTest {

    /** 球场坐标（米）→ 屏幕像素，规则跟 [CourtGeometry] 一致。 */
    private class Mapping(val vertical: Boolean, val scale: Float, val w: Float, val h: Float) {
        fun xPixel(longAxis: Float, shortAxis: Float) =
            if (vertical) w / 2f + shortAxis * scale else w / 2f + longAxis * scale

        fun yPixel(longAxis: Float, shortAxis: Float) =
            if (vertical) h / 2f + longAxis * scale else h / 2f + shortAxis * scale
    }

    /** 由屏幕角度取弧中点的屏幕坐标。 */
    private fun midpoint(cx: Float, cy: Float, r: Float, angleDeg: Float): Pair<Float, Float> {
        val rad = Math.toRadians(angleDeg.toDouble())
        return cx + r * kotlin.math.cos(rad).toFloat() to cy + r * kotlin.math.sin(rad).toFloat()
    }

    /**
     * 角球弧（足球）：四个角都必须是**四分之一圆**（不是 270° 的大弧），中点朝场地中心。
     * 鼓出方向给「角点 → 场地中心」这条斜对角。
     */
    @Test
    fun cornerArcsAreQuarterCirclesAtAllFourCorners() {
        val halfLong = 52.5f
        val halfShort = 34f
        val r = 1f

        val mappings = listOf(
            Mapping(vertical = true, scale = 15.88f, w = 1080f, h = 2400f),
            Mapping(vertical = false, scale = 10.67f, w = 2400f, h = 1080f),
        )

        for (m in mappings) {
            for (signX in intArrayOf(-1, 1)) {
                for (signY in intArrayOf(-1, 1)) {
                    val cornerLong = signX * halfLong
                    val cornerShort = signY * halfShort
                    val cx = m.xPixel(cornerLong, cornerShort)
                    val cy = m.yPixel(cornerLong, cornerShort)
                    val rPixel = r * m.scale

                    val angles = CourtArc.angles(
                        cx = cx,
                        cy = cy,
                        fromX = m.xPixel(signX * (halfLong - r), cornerShort),
                        fromY = m.yPixel(signX * (halfLong - r), cornerShort),
                        toX = m.xPixel(cornerLong, signY * (halfShort - r)),
                        toY = m.yPixel(cornerLong, signY * (halfShort - r)),
                        // 鼓出方向 = 角点 → 场地中心
                        bulgeDx = m.xPixel(0f, 0f) - cx,
                        bulgeDy = m.yPixel(0f, 0f) - cy,
                    )

                    val corner = "corner($signX,$signY) vertical=${m.vertical}"
                    assertTrue("$corner 没算出角度", angles != null)
                    val (start, sweep) = angles!!

                    // 四分之一圆（方向随屏幕方向，所以只看大小）
                    assertEquals("$corner 扫过角度不对", 90f, kotlin.math.abs(sweep), 0.01f)

                    // 选中的弧，中点必须比另一条候选路径的中点更靠近场地中心
                    val (midX, midY) = midpoint(cx, cy, rPixel, start + sweep / 2f)
                    val centerX = m.xPixel(0f, 0f)
                    val centerY = m.yPixel(0f, 0f)
                    val other = midpoint(cx, cy, rPixel, start + (sweep - 360f * Math.signum(sweep)) / 2f)
                    val chosenDistance = kotlin.math.hypot(midX - centerX, midY - centerY)
                    val otherDistance = kotlin.math.hypot(other.first - centerX, other.second - centerY)
                    assertTrue(
                        "$corner 中点没朝着场地中心（$chosenDistance vs $otherDistance）",
                        chosenDistance < otherDistance - rPixel,
                    )

                    // 中点离角点正好 r
                    assertEquals(
                        "$corner 中点离角点应当是 r",
                        rPixel,
                        kotlin.math.hypot(midX - cx, midY - cy),
                        0.01f,
                    )
                }
            }
        }
    }

    /**
     * 三分线：从一侧底角绕到另一侧底角，走的是**大弧**（约 241°），中点朝中圈。
     * 鼓出方向 = 篮筐 → 场地中心。
     */
    @Test
    fun threePointArcTakesTheLongWayAround() {
        // 篮球：篮筐在 -12.425，三分弧半径 6.75，底角 y = ±5.8
        val basket = -12.425f
        val r = 6.75f
        val cornerY = 5.8f
        val dx = kotlin.math.sqrt(r * r - cornerY * cornerY)
        val cornerX = basket - dx

        val m = Mapping(vertical = true, scale = 68.571f, w = 1080f, h = 2400f)
        val cx = m.xPixel(basket, 0f)
        val cy = m.yPixel(basket, 0f)
        val rPixel = r * m.scale

        val angles = CourtArc.angles(
            cx = cx,
            cy = cy,
            fromX = m.xPixel(cornerX, -cornerY),
            fromY = m.yPixel(cornerX, -cornerY),
            toX = m.xPixel(cornerX, cornerY),
            toY = m.yPixel(cornerX, cornerY),
            bulgeDx = m.xPixel(0f, 0f) - cx,
            bulgeDy = m.yPixel(0f, 0f) - cy,
        )!!

        val halfAngle = Math.toDegrees(kotlin.math.atan2(cornerY.toDouble(), dx.toDouble())).toFloat()
        assertEquals("三分弧扫过角度", 360f - 2f * halfAngle, kotlin.math.abs(angles.second), 0.01f)
        assertTrue("三分弧必须走大弧", kotlin.math.abs(angles.second) > 180f)

        // 中点必须比另一条候选路径的中点更靠近场地中心
        val centerX = m.xPixel(0f, 0f)
        val centerY = m.yPixel(0f, 0f)
        val chosen = midpoint(cx, cy, rPixel, angles.first + angles.second / 2f)
        val other = midpoint(cx, cy, rPixel, angles.first + (angles.second - 360f * Math.signum(angles.second)) / 2f)
        val chosenDistance = kotlin.math.hypot(chosen.first - centerX, chosen.second - centerY)
        val otherDistance = kotlin.math.hypot(other.first - centerX, other.second - centerY)
        assertTrue("三分弧中点要朝中圈（$chosenDistance vs $otherDistance）", chosenDistance < otherDistance)
    }

    /**
     * 罚球圈这两个半圆（`BasketballView.drawLane` 就是这么调的）：两端在**上下**，
     * 一个半圆倒向端线、另一个倒向中场。
     *
     * 这里就是「半圆没法用方向判」的现场：两端隔着 180°，两条候选路径的中点方向
     * 都是垂直的 —— 所以只能显式给扫过角度。
     */
    @Test
    fun freeThrowSemicirclesPickTheRightSide() {
        val freeThrowFromBaseline = 5.8f
        val r = 1.8f
        val m = Mapping(vertical = true, scale = 68.571f, w = 1080f, h = 2400f)
        val rPixel = r * m.scale

        for (side in intArrayOf(-1, 1)) {
            // 左半场：端线 -14、罚球线 -8.2；右半场镜像
            val freeThrowLine = side * (14f - freeThrowFromBaseline)
            val baseline = side * 14f
            val cx = m.xPixel(freeThrowLine, 0f)
            val cy = m.yPixel(freeThrowLine, 0f)

            // 两端都在罚球线上、上下各一个
            val start = CourtArc.angleDeg(0f, -r)

            // 靠端线那半个（实线）：sweep = 180 * side
            val near = midpoint(cx, cy, rPixel, start + 180f * side / 2f)
            // 靠中场那半个（虚线）：sweep = -180 * side
            val far = midpoint(cx, cy, rPixel, start + (-180f * side) / 2f)

            // 横轴（屏幕 x）上：中点应当在罚球线的端线侧 / 中场侧
            val nearLong = kotlin.math.abs((near.first - cx) / m.scale)
            val farLong = kotlin.math.abs((far.first - cx) / m.scale)
            assertEquals("side=$side 半圆中点离罚球线应当是 r（端线侧）", r, nearLong, 0.01f)
            assertEquals("side=$side 半圆中点离罚球线应当是 r（中场侧）", r, farLong, 0.01f)

            val nearIsTowardBaseline = kotlin.math.abs(near.first - cx) > 0f &&
                (near.first - cx) * (baseline - freeThrowLine) > 0f
            assertTrue("side=$side 靠端线那半个应当倒向端线", nearIsTowardBaseline)

            val farIsTowardMidcourt = (far.first - cx) * (0f - freeThrowLine) > 0f
            assertTrue("side=$side 靠中场那半个应当倒向中场", farIsTowardMidcourt)
        }
    }

    /**
     * 平分时取扫过角度更小的那个：扫 90° 和扫 -270° 的中点方向完全一样，必须挑 90°。
     * 这一条是三分线曾经被画成 478° 的根因。
     */
    @Test
    fun tiesPreferTheSmallerSweep() {
        val angles = CourtArc.angles(
            cx = 0f,
            cy = 0f,
            fromX = 100f,
            fromY = 0f,
            toX = 0f,
            toY = 100f,
            bulgeDx = 0f,
            bulgeDy = 1f,
        )!!
        assertEquals("应当挑四分之一圆", 90f, angles.second, 0.01f)
    }

    /** 退化输入（圆心与端点重合、或方向为零向量）返回 null，不抛异常。 */
    @Test
    fun degenerateInputReturnsNull() {
        assertNull(CourtArc.angles(0f, 0f, 0f, 0f, 10f, 0f, 0f, -1f))
        assertNull(CourtArc.angles(0f, 0f, 10f, 0f, 0f, 0f, 0f, -1f))
        assertNull(CourtArc.angles(0f, 0f, 10f, 0f, -10f, 0f, 0f, 0f))
    }

    /** 角度基准：0° 朝右、顺时针为正（y 向下）。 */
    @Test
    fun angleBasisMatchesCanvasConvention() {
        assertEquals(0f, CourtArc.angleDeg(1f, 0f), 0.001f)
        assertEquals(90f, CourtArc.angleDeg(0f, 1f), 0.001f)
        assertEquals(180f, CourtArc.angleDeg(-1f, 0f), 0.001f)
        assertEquals(-90f, CourtArc.angleDeg(0f, -1f), 0.001f)
    }
}
