package com.example.p2pnet.ui.login

/**
 * 自由层（= **整个内容区**）的摆放规则 —— 抽成纯函数（零 Android 依赖，可 JVM 单测）。
 *
 * 层级：服务器卡片**不再单独占一行**，而是自由层里顶部对齐的一个元素（不可拖动）。
 * 于是"自由层正中"就是**整个内容区的正中**（这正是用户要的"屏幕中心"）。
 */

/**
 * 服务器卡片宽度占自由层宽度的比例：
 * - **竖屏**（高 > 宽）→ `1.0`（满宽）
 * - **横屏**（宽 > 高）→ `0.5`（占一半，**水平居中**：见 [serverCardLeftPx]）
 * - **正方形**（宽 == 高）→ 按竖屏处理（`1.0`），这条写进单测钉住
 */
internal fun serverCardWidthFraction(areaWidthPx: Float, areaHeightPx: Float): Float =
    if (areaWidthPx > areaHeightPx) 0.5f else 1f

/**
 * 服务器卡片的左边界（px）：它**顶部对齐 + 水平居中**，所以
 * 满宽时 = 0；半宽时 = `(自由层宽 - 卡片宽) / 2`（横屏时左右各留 1/4 宽的空白带）。
 */
internal fun serverCardLeftPx(areaWidthPx: Float, widthFraction: Float): Float =
    (areaWidthPx * (1f - widthFraction)) / 2f

/**
 * 卡片是否**完全避开**服务器卡片的横向范围 —— 即落在左边或右边那条空白带里。
 * 落在这两条带里时，卡片纵向**可以一直用到顶部**（A3）。
 */
internal fun isBesideServerCardPx(
    cardLeftPx: Float,
    cardWidthPx: Float,
    serverLeftPx: Float,
    serverRightPx: Float,
    gapPx: Float
): Boolean =
    cardLeftPx + cardWidthPx <= serverLeftPx - gapPx || cardLeftPx >= serverRightPx + gapPx


/** 「我」卡片默认位置的中心 y = **自由层（整个内容区）的几何中心** */
internal fun meCardDefaultCenterY(areaHeightPx: Float): Float = areaHeightPx / 2f

/**
 * 「我」卡片相对"居中锚点"的可拖动纵向范围（px）：`0` = 正中。
 *
 * 这是**自由层内**的对称范围（上到顶、下到底，两边留同一个 `marginPx`）；
 * 服务器卡片那块由 [clampRangeOverServerPx] 再往下压。
 * 自由层太矮（卡片比可用高度还高，或扣掉 margin 没余量）时收成 `0..0`，不越界。
 */
internal fun meCardDragRangePx(
    areaHeightPx: Float,
    cardHeightPx: Float,
    marginPx: Float
): ClosedFloatingPointRange<Float> {
    val half = ((areaHeightPx - cardHeightPx) / 2f - marginPx).coerceAtLeast(0f)
    return -half..half
}

/**
 * 在"自由层对称范围"之上，再避开服务器卡片：
 * 卡片顶边不许高于 `minTopPx`（= 服务器卡片下沿 + margin），也就是把范围的下界往上抬。
 * 顺序乱掉就压成一个点，保证返回的范围始终合法。
 */
internal fun clampRangeOverServerPx(
    base: ClosedFloatingPointRange<Float>,
    centeredTopPx: Float,
    minTopPx: Float
): ClosedFloatingPointRange<Float> {
    val lo = maxOf(base.start, minTopPx - centeredTopPx)
    return lo..maxOf(lo, base.endInclusive)
}

/**
 * 把一张卡片从"服务器卡片矩形"里推出去（A3：任何卡片都不许盖住服务器卡片）。
 *
 * 规则（留 `gapPx`）：卡片**要么横向完全避开服务器卡片**（落在左边或右边的空白带里
 * = [isBesideServerCardPx]，此时纵向可以一直用到顶部），**要么完全在它下面**（`y >= serverBottom + gap`）。
 * 左上角越界时按这条夹回来；两条都不满足就把 y 压到服务器卡片下方。
 *
 * @return `(x, y)`：卡片左上角的合法位置（px）
 */
internal fun avoidServerRectPx(
    x: Float,
    y: Float,
    cardWidthPx: Float,
    cardHeightPx: Float,
    areaWidthPx: Float,
    areaHeightPx: Float,
    serverLeftPx: Float,
    serverRightPx: Float,
    serverBottomPx: Float,
    gapPx: Float
): Pair<Float, Float> {
    val maxX = (areaWidthPx - cardWidthPx).coerceAtLeast(0f)
    val nx = x.coerceIn(0f, maxX)
    val minY = if (isBesideServerCardPx(nx, cardWidthPx, serverLeftPx, serverRightPx, gapPx)) {
        gapPx
    } else {
        serverBottomPx + gapPx
    }
    val maxY = (areaHeightPx - cardHeightPx - gapPx).coerceAtLeast(minY)
    return nx to y.coerceIn(minY, maxY)
}
