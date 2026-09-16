package com.example.sport.sport.share.court

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [CourtGeometry] 的纯 JVM 测试：验证「屏幕短边对齐球场短边 / 长边最多占 80%」这条规则，
 * 以及球场坐标 ↔ 屏幕像素的换算在竖屏、横屏下都对。
 */
class CourtGeometryTest {

    private fun field(w: Float, h: Float) = CourtGeometry(
        viewWidth = w,
        viewHeight = h,
        fieldLong = 105f,
        fieldShort = 68f,
    )

    /** 手机竖屏（1080 × 2400）：屏幕特别细长 → 由「短边对齐」那条决定。 */
    @Test
    fun portrait_longScreen_shortSideFillsScreenShortSide() {
        val g = field(1080f, 2400f)

        assertTrue(g.longAxisIsVertical)

        // 比例尺 = 1080 / 68
        assertEquals(1080f / 68f, g.scale, 0.001f)
        // 球场短边正好等于屏幕短边
        assertEquals(1080f, g.drawnShort, 0.01f)
        // 长边按真实比例跟着算出来
        assertEquals(1080f / 68f * 105f, g.drawnLong, 0.01f)
        // 长边方向没到 80%，所以没用上第二条约束
        assertTrue(g.longFill < 0.8f)
        // 两端留的黑带相等
        assertEquals((2400f - g.drawnLong) / 2f, g.strip, 0.01f)
    }

    /** 手机竖屏但没那么细长（1080 × 1600）：长边铺满 80%，由第二条约束接管。 */
    @Test
    fun portrait_almostSquare_longSideCappedAt80Percent() {
        val g = field(1080f, 1600f)

        assertEquals(1600f * 0.8f / 105f, g.scale, 0.001f)
        assertEquals(1600f * 0.8f, g.drawnLong, 0.01f)
        // 长边最多占屏幕长边的 80%
        assertEquals(0.8f, g.longFill, 0.001f)
        // 短边方向必须塞得进屏幕
        assertTrue(g.drawnShort <= 1080f + 0.01f)
    }

    /** 正方形屏幕：长边 = 屏幕短边 × 0.8，短边按比例缩小。 */
    @Test
    fun squareScreen_longSideIs80PercentOfShortSide() {
        val g = field(1080f, 1080f)

        assertEquals(1080f * 0.8f, g.drawnLong, 0.01f)
        assertEquals(1080f * 0.8f / 105f * 68f, g.drawnShort, 0.01f)
        assertTrue(g.drawnShort < 1080f)
    }

    /** 平板横屏（1400 × 1080）：长边横着放，左右留黑带。 */
    @Test
    fun landscape_longAxisIsHorizontal() {
        val g = field(1400f, 1080f)

        assertFalse(g.longAxisIsVertical)
        assertEquals(1400f * 0.8f / 105f, g.scale, 0.001f)
        assertEquals(1400f * 0.8f, g.drawnLong, 0.01f)
        assertEquals(0.8f, g.longFill, 0.001f)
    }

    /** 球场坐标（米）→ 屏幕像素：竖屏时长轴映射到屏幕 y。 */
    @Test
    fun portrait_mapsLongAxisToScreenY() {
        val g = field(1080f, 2400f)

        // 球场中心 = 屏幕中心
        assertEquals(540f, g.screenX(0f, 0f), 0.01f)
        assertEquals(1200f, g.screenY(0f, 0f), 0.01f)

        // 长轴方向 ±52.5 米 = 球场两端，正好落在球场上下边界
        assertEquals(g.fieldTop, g.screenY(-52.5f, 0f), 0.01f)
        assertEquals(g.fieldBottom, g.screenY(52.5f, 0f), 0.01f)

        // 短轴方向 ±34 米 = 球场两边
        assertEquals(g.fieldLeft, g.screenX(0f, -34f), 0.01f)
        assertEquals(g.fieldRight, g.screenX(0f, 34f), 0.01f)
    }

    /** 横屏时长轴映射到屏幕 x。 */
    @Test
    fun landscape_mapsLongAxisToScreenX() {
        val g = field(1400f, 1080f)

        // 长轴（±52.5 米）落在左右边界
        assertEquals(g.fieldLeft, g.screenX(-52.5f, 0f), 0.05f)
        assertEquals(g.fieldRight, g.screenX(52.5f, 0f), 0.05f)
        // 短轴（±34 米）落在上下边界
        assertEquals(g.fieldTop, g.screenY(0f, -34f), 0.05f)
        assertEquals(g.fieldBottom, g.screenY(0f, 34f), 0.05f)
    }

    /**
     * 横屏手机（2400 × 1080）：屏幕长宽比 2.222 > 球场 1.544，所以还是「短边对齐」那条在起作用 ——
     * 球场短边竖着铺满屏幕短边，长边横着按真实比例算出来，左右各留一条黑带。
     */
    @Test
    fun landscape_longScreen_shortSideFillsScreenShortSide() {
        val g = field(2400f, 1080f)

        assertFalse(g.longAxisIsVertical)
        // 球场短边（68 米）正好等于屏幕短边（1080），长边按比例
        assertEquals(1080f, g.drawnShort, 0.01f)
        assertEquals(1080f / 68f * 105f, g.drawnLong, 0.01f)
        assertTrue(g.longFill < 0.8f)
        // 黑带在左右
        assertTrue(g.fieldLeft > 0f)
        assertEquals(g.fieldWidth, g.fieldRight - g.fieldLeft, 0.05f)
        assertEquals(0f, g.fieldTop, 0.05f)
    }

    /**
     * 同一个几何也接篮球场（28 × 15 米）。篮球场比足球场「方」（1.867），
     * 而手机竖屏是 2.222 —— 屏幕更细长时本来该由「短边对齐」接管，
     * 但这里 0.8 那条更紧（短边对齐会让球场长度超出屏幕），所以**改由 0.8 接管**：
     * 球场长边正好占屏幕长边的 80%，短边按比例缩小。
     *
     * 这就是这套规则的好处：换个项目、换个屏幕长宽比，两条约束自动切换，不用改代码。
     */
    @Test
    fun basketballCourtFallsBackToThe80PercentRule() {
        val g = CourtGeometry(1080f, 2400f, fieldLong = 28f, fieldShort = 15f)

        // 2400 × 0.8 / 28 = 68.57 < 1080 / 15 = 72 ⇒ 0.8 那条更紧
        assertEquals(2400f * 0.8f / 28f, g.scale, 0.001f)
        assertEquals(2400f * 0.8f, g.drawnLong, 0.01f)
        assertEquals(0.8f, g.longFill, 0.001f)
        // 短边跟着缩，所以左右也会留黑边
        assertEquals(2400f * 0.8f / 28f * 15f, g.drawnShort, 0.01f)
        assertTrue(g.drawnShort < 1080f)
        // 球场完整落在屏幕里
        assertTrue(g.fieldLeft >= -0.01f)
        assertTrue(g.fieldBottom <= 2400f + 0.01f)
    }

    /** 像素 → 球场坐标是上面那条的逆运算（两种方向都要成立）。 */
    @Test
    fun screenToFieldRoundTrip() {
        for (g in listOf(field(1080f, 2400f), field(1400f, 1080f))) {
            val x = 25f
            val y = -13f
            val px = g.screenX(x, y)
            val py = g.screenY(x, y)
            assertEquals(x, g.longAxisAt(px, py), 0.01f)
            assertEquals(y, g.shortAxisAt(px, py), 0.01f)
        }
    }

    /** 球场外是黑的：边界外一点点就不算在球场里。 */
    @Test
    fun outsideFieldIsNotInside() {
        val g = field(1080f, 2400f)

        assertTrue(g.isInsideField(g.viewWidth / 2f, g.viewHeight / 2f))
        assertTrue(g.isInsideField(g.fieldLeft, g.fieldTop))

        assertFalse(g.isInsideField(g.fieldLeft - 1f, g.viewHeight / 2f))
        assertFalse(g.isInsideField(g.fieldRight + 1f, g.viewHeight / 2f))
        assertFalse(g.isInsideField(g.viewWidth / 2f, g.fieldTop - 1f))
        assertFalse(g.isInsideField(g.viewWidth / 2f, g.fieldBottom + 1f))
        // 屏幕角落一定在球场外（黑区）
        assertFalse(g.isInsideField(0f, 0f))
    }

    /** 钳制：把一个越界的球场坐标拉回球场内。 */
    @Test
    fun clampKeepsCoordinatesOnTheField() {
        val g = field(1080f, 2400f)

        assertEquals(g.halfLong, g.clampLongAxis(999f), 0.01f)
        assertEquals(-g.halfLong, g.clampLongAxis(-999f), 0.01f)
        assertEquals(g.halfShort, g.clampShortAxis(999f), 0.01f)
        assertEquals(-g.halfShort, g.clampShortAxis(-999f), 0.01f)
        // 场内原样返回
        assertEquals(10f, g.clampLongAxis(10f), 0.001f)
    }

    /** 任何屏幕尺寸下，球场都必须完整落在屏幕里（不能溢出）。 */
    @Test
    fun fieldNeverOverflowsTheView() {
        val sizes = listOf(
            1080f to 2400f,
            1080f to 1920f,
            1080f to 1600f,
            1440f to 3120f,
            1080f to 1080f,
            1400f to 1080f,
            2400f to 1080f,
            800f to 1280f,
        )
        for ((w, h) in sizes) {
            val g = field(w, h)
            assertTrue("$w x $h: 左溢出", g.fieldLeft >= -0.01f)
            assertTrue("$w x $h: 右溢出", g.fieldRight <= w + 0.01f)
            assertTrue("$w x $h: 上溢出", g.fieldTop >= -0.01f)
            assertTrue("$w x $h: 下溢出", g.fieldBottom <= h + 0.01f)
            // 长边永远不超过屏幕长边的 80%
            assertTrue("$w x $h: 长边占比 ${g.longFill}", g.longFill <= 0.8f + 0.001f)
        }
    }
}
