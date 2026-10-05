package com.example.p2pnet.ui.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 自由层摆放规则的纯逻辑断言（不需要模拟器）：
 * ① 服务器卡片宽度占比（竖屏满宽 / 横屏半宽 / 正方形按竖屏）；
 * ② 「我」卡片默认中心 = 自由层中心；
 * ③ 拖动范围在新锚点下仍对称、两端可达，并且被服务器卡片往下压后仍合法；
 * ④ 任何卡片都不许盖住服务器卡片（A3）。
 */
class MeCardLayoutTest {

    // ── ① 服务器卡片宽度占比 ──

    @Test
    fun serverCardTakesFullWidthInPortrait() {
        // 高 > 宽（竖屏，例如 400x800）→ 满宽
        assertEquals(1f, serverCardWidthFraction(areaWidthPx = 400f, areaHeightPx = 800f), 0.0001f)
        println("[竖屏 400x800] 服务器卡片宽度占比 = ${serverCardWidthFraction(400f, 800f)} ✓")
    }

    @Test
    fun serverCardTakesHalfWidthCenteredInLandscape() {
        // 宽 > 高（横屏，例如 800x400）→ 半宽，且**水平居中**
        val fraction = serverCardWidthFraction(areaWidthPx = 800f, areaHeightPx = 400f)
        assertEquals(0.5f, fraction, 0.0001f)
        val cardW = 800f * fraction
        assertEquals("卡片宽 = 自由层宽的一半", 400f, cardW, 0.0001f)
        assertEquals(
            "居中 ⇒ 左边界 = (自由层宽 - 卡片宽)/2",
            (800f - cardW) / 2f,
            serverCardLeftPx(areaWidthPx = 800f, widthFraction = fraction),
            0.0001f
        )
        assertEquals(200f, serverCardLeftPx(800f, fraction), 0.0001f)
        // 竖屏满宽 ⇒ 左边界 0
        assertEquals(0f, serverCardLeftPx(400f, serverCardWidthFraction(400f, 800f)), 0.0001f)
        println("[横屏 800x400] 占比=0.5、卡片宽=400、左边界=${serverCardLeftPx(800f, 0.5f)}（居中）✓")
    }

    @Test
    fun serverCardSquareFallsBackToPortrait() {
        // 宽 == 高：定成"按竖屏处理"，即满宽（写进断言钉住）
        assertEquals(1f, serverCardWidthFraction(areaWidthPx = 600f, areaHeightPx = 600f), 0.0001f)
        println("[正方形 600x600] 占比 = ${serverCardWidthFraction(600f, 600f)}（按竖屏）✓")
    }

    // ── ② 默认中心 ──

    @Test
    fun meCardDefaultCenterIsFreeLayerCenter() {
        assertEquals("默认中心 = 自由层（整个内容区）中心", 400f, meCardDefaultCenterY(areaHeightPx = 800f), 0.0001f)
        assertEquals(250f, meCardDefaultCenterY(areaHeightPx = 500f), 0.0001f)
        println("[默认中心] areaH=800 → y=${meCardDefaultCenterY(800f)}；areaH=500 → y=${meCardDefaultCenterY(500f)} ✓")
    }

    // ── ③ 拖动范围：对称 + 两端可达 + 被服务器卡片下压 ──

    @Test
    fun dragRangeIsSymmetricAndReachesBothEnds() {
        val base = meCardDragRangePx(areaHeightPx = 1000f, cardHeightPx = 200f, marginPx = 0f)
        assertEquals("关于 0 对称（0 = 正中）", -base.endInclusive, base.start, 0.001f)
        assertTrue("默认位置 0 在范围内", 0f in base)
        assertEquals("上端可达：(areaH-cardH)/2", 400f, base.endInclusive, 0.001f)
        assertEquals("下端可达：-(areaH-cardH)/2", -400f, base.start, 0.001f)

        val withMargin = meCardDragRangePx(areaHeightPx = 1000f, cardHeightPx = 200f, marginPx = 20f)
        assertEquals(380f, withMargin.endInclusive, 0.001f)
        assertEquals(-380f, withMargin.start, 0.001f)
        println("[拖动范围] margin=0 → ${base.start}..${base.endInclusive}；margin=20 → ${withMargin.start}..${withMargin.endInclusive}（对称、两端可达）✓")
    }

    @Test
    fun tinyAreaDoesNotGoOutOfBounds() {
        val taller = meCardDragRangePx(areaHeightPx = 150f, cardHeightPx = 200f, marginPx = 0f)
        assertEquals(0f, taller.start, 0.001f)
        assertEquals(0f, taller.endInclusive, 0.001f)
        val noRoom = meCardDragRangePx(areaHeightPx = 240f, cardHeightPx = 200f, marginPx = 30f)
        assertEquals(0f, noRoom.start, 0.001f)
        assertEquals(0f, noRoom.endInclusive, 0.001f)
        println("[边界] 太矮时范围收成 0..0（不越界）✓")
    }

    @Test
    fun serverCardPushesDragTopEndDown() {
        // 自由层高 400、卡片高 120、无 margin：自由层内的对称范围是 -140..140（0 = 正中）
        val base = meCardDragRangePx(areaHeightPx = 400f, cardHeightPx = 120f, marginPx = 0f)
        assertEquals(140f, base.endInclusive, 0.001f)
        val centeredTop = 140f   // (400-120)/2

        // 服务器卡片下沿 150：居中的顶边 140 会压住它 → 上端被压到"贴住它下沿"（150）
        val pushed = clampRangeOverServerPx(base, centeredTopPx = centeredTop, minTopPx = 150f)
        assertEquals("上端 = 服务器卡片下沿 - 居中顶边", 10f, pushed.start, 0.001f)
        assertEquals("下端仍能到底", 140f, pushed.endInclusive, 0.001f)
        assertEquals("上端确实贴住服务器卡片下沿", 150f, pushed.start + centeredTop, 0.001f)
        assertFalse("【冲突优先级】正中会压住卡片 ⇒ 默认位置被下压（限位为准）", 0f in pushed)

        // 服务器卡片很矮（下沿 100）：上端只到 100（不会进到卡片里），但"正中"仍然合法
        val notPushed = clampRangeOverServerPx(base, centeredTopPx = centeredTop, minTopPx = 100f)
        assertEquals(-40f, notPushed.start, 0.001f)
        assertEquals("上端 = 100 - 140", 100f, notPushed.start + centeredTop, 0.001f)
        assertEquals(140f, notPushed.endInclusive, 0.001f)
        assertTrue("默认位置 0 仍在范围内 ⇒ 默认就是正中", 0f in notPushed)
        println("[避让] 服务器下沿150 → 范围 ${pushed.start}..${pushed.endInclusive}（默认被下压）；下沿100 → ${notPushed.start}..${notPushed.endInclusive}（默认仍正中）✓")
    }

    // ── ④ 卡片不许盖住服务器卡片（A3）──

    @Test
    fun portraitCardsArePushedBelowServerCard() {
        // 竖屏：服务器卡片满宽（左 4 / 右 396），卡片只能落到它下面
        val (x, y) = avoidServerRectPx(
            x = 50f, y = 10f, cardWidthPx = 100f, cardHeightPx = 80f,
            areaWidthPx = 400f, areaHeightPx = 800f,
            serverLeftPx = 4f, serverRightPx = 396f, serverBottomPx = 150f, gapPx = 8f
        )
        assertEquals(50f, x, 0.001f)
        assertEquals("竖屏：必须落到服务器卡片下方", 158f, y, 0.001f)
        println("[竖屏避让] (50,10) → ($x,$y)：卡片被压到服务器卡片下方 ✓")
    }

    @Test
    fun landscapeSideBandsMayUseTheTop() {
        // 横屏 800 宽、服务器卡片居中占一半 ⇒ 左边界 200、右边界 600，左右各 200 宽的空白带
        val serverLeft = 200f
        val serverRight = 600f

        // 左带（卡片右沿 ≤ 200-8）：纵向可以用到顶部
        val (xL, yL) = avoidServerRectPx(
            x = 40f, y = 8f, cardWidthPx = 100f, cardHeightPx = 80f,
            areaWidthPx = 800f, areaHeightPx = 400f,
            serverLeftPx = serverLeft, serverRightPx = serverRight, serverBottomPx = 150f, gapPx = 8f
        )
        assertEquals(40f, xL, 0.001f)
        assertEquals("左空白带可以用到顶部", 8f, yL, 0.001f)

        // 右带（卡片左沿 ≥ 600+8）：纵向也可以用顶部
        val (xR, yR) = avoidServerRectPx(
            x = 660f, y = 8f, cardWidthPx = 100f, cardHeightPx = 80f,
            areaWidthPx = 800f, areaHeightPx = 400f,
            serverLeftPx = serverLeft, serverRightPx = serverRight, serverBottomPx = 150f, gapPx = 8f
        )
        assertEquals(660f, xR, 0.001f)
        assertEquals("右空白带可以用到顶部", 8f, yR, 0.001f)

        // 中间那列（与服务器卡片横向重叠）仍然必须到它下方
        val (xM, yM) = avoidServerRectPx(
            x = 350f, y = 8f, cardWidthPx = 100f, cardHeightPx = 80f,
            areaWidthPx = 800f, areaHeightPx = 400f,
            serverLeftPx = serverLeft, serverRightPx = serverRight, serverBottomPx = 150f, gapPx = 8f
        )
        assertEquals(350f, xM, 0.001f)
        assertEquals(158f, yM, 0.001f)
        println("[横屏避让] 左带 (40)→y=$yL、右带 (660)→y=$yR 都可用顶部；中间 (350)→y=$yM 被压下 ✓")
    }

    @Test
    fun besideServerCardDetectsTheTwoBlankBands() {
        // 横屏：左带 [0,192]、右带 [608,800]，中间 [192,608] 不算"旁边"
        assertTrue(isBesideServerCardPx(0f, 190f, 200f, 600f, 8f))
        assertTrue(isBesideServerCardPx(608f, 100f, 200f, 600f, 8f))
        assertEquals(false, isBesideServerCardPx(300f, 100f, 200f, 600f, 8f))
        println("[空白带判定] 左带/右带=true，中间=false ✓")
    }

    @Test
    fun avoidServerRectKeepsCardInsideArea() {
        // 卡片比区域还大 / 放到负坐标：不能算出越界位置
        val (x, y) = avoidServerRectPx(
            x = -50f, y = -50f, cardWidthPx = 900f, cardHeightPx = 900f,
            areaWidthPx = 800f, areaHeightPx = 400f,
            serverLeftPx = 200f, serverRightPx = 600f, serverBottomPx = 150f, gapPx = 8f
        )
        assertTrue("x 不为负", x >= 0f)
        assertTrue("y 不为负", y >= 0f)
        assertEquals("x 被夹到 0", 0f, x, 0.001f)
        println("[边界避让] 超大卡片 (-50,-50) → ($x,$y)（不越界）✓")
    }
}
