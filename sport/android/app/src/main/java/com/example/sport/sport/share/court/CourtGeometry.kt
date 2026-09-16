package com.example.sport.sport.share.court

import kotlin.math.min

/**
 * 球场几何：把一块**真实尺寸的球场**放进屏幕里。纯 Kotlin，不依赖 Android，JVM 可单测。
 *
 * 规则照搬象棋棋盘那一套，只是「格子」换成了「米」：
 *
 *   比例尺 = min( 屏幕短边 / 球场短边 ,  屏幕长边 × 0.8 / 球场长边 )
 *
 *  - 第一条：**屏幕短边刚好对齐球场短边**。手机竖屏时屏幕特别细长，就是这条在起作用，
 *    球场短边铺满屏幕短边、长边按真实比例跟着算出来；
 *  - 第二条：**球场长边最多只占屏幕长边的 80%**（两端各留 10%）。屏幕越接近正方形，
 *    这条越紧，最后接管；那两条 10% 的黑带正好放队牌。
 *
 * 于是屏幕比球场更细长时用第一条，屏幕更方时用第二条 —— 跟象棋完全同构。
 *
 * 坐标约定（**跟屏幕方向无关**，这是关键）：
 *  - 球场坐标 `(x, y)` 单位是**米**，原点在球场正中心，x 沿球场**长边**、y 沿球场**短边**；
 *  - 屏幕方向只决定分量怎么映射：竖屏（高 ≥ 宽）时长边竖着放（x → 屏幕 y），
 *    横屏时长边横着放（x → 屏幕 x）。**不做 90° 旋转** —— 球场转了球门就跑边线上去了。
 *
 * 所以调用方永远只说「球场坐标」，由这里负责落到屏幕上。
 */
class CourtGeometry(
    val viewWidth: Float,
    val viewHeight: Float,
    /** 球场真实长度（米），足球 = 105。 */
    val fieldLong: Float,
    /** 球场真实宽度（米），足球 = 68。 */
    val fieldShort: Float,
) {

    companion object {
        /** 球场长边两端各留的比例：0.1 → 长边最多占屏幕长边的 80%（棋盘里的 COMPACT_FILL）。 */
        const val STRIP = 0.1f
    }

    /** true：屏幕是竖的（或正方形）→ 球场长边竖着放。 */
    val longAxisIsVertical: Boolean = viewHeight >= viewWidth

    /** 屏幕短边 / 长边。 */
    private val screenShort = min(viewWidth, viewHeight)

    private val screenLong = if (longAxisIsVertical) viewHeight else viewWidth

    /**
     * 比例尺（像素 / 米）= min(短边铺满，长边只占 80%)。
     *
     * 两条约束各管一段、不打架：第一条把球场**短边**顶到屏幕短边，
     * 而这个尺寸显然塞得进短边方向；越接近正方形的屏幕，第二条越紧，最终由它接管
     * （此时球场长边正好等于屏幕短边的 80%）。
     */
    val scale: Float = min(
        screenShort / fieldShort,
        screenLong * (1f - 2f * STRIP) / fieldLong,
    )

    /** 球场画出来的像素尺寸。 */
    val drawnLong: Float = fieldLong * scale
    val drawnShort: Float = fieldShort * scale

    /** 球场长边方向占屏幕长边的比例（封顶 0.8）。 */
    val longFill: Float = drawnLong / screenLong

    /** 屏幕长边两端各留下的黑带宽度（放队牌的地方）。 */
    val strip: Float = (screenLong - drawnLong) / 2f

    // ------------------------------------------------------------------ 坐标换算

    /**
     * 球场坐标（米）→ 屏幕像素。
     * [longAxisMeters] 沿球场长边、[shortAxisMeters] 沿球场短边，映射到哪一维由屏幕方向决定。
     */
    fun screenX(longAxisMeters: Float, shortAxisMeters: Float): Float =
        if (longAxisIsVertical) {
            viewWidth / 2f + shortAxisMeters * scale
        } else {
            viewWidth / 2f + longAxisMeters * scale
        }

    fun screenY(longAxisMeters: Float, shortAxisMeters: Float): Float =
        if (longAxisIsVertical) {
            viewHeight / 2f + longAxisMeters * scale
        } else {
            viewHeight / 2f + shortAxisMeters * scale
        }

    /** 屏幕像素 → 球场长轴坐标（米）。 */
    fun longAxisAt(screenX: Float, screenY: Float): Float =
        if (longAxisIsVertical) {
            (screenY - viewHeight / 2f) / scale
        } else {
            (screenX - viewWidth / 2f) / scale
        }

    /** 屏幕像素 → 球场短轴坐标（米）。 */
    fun shortAxisAt(screenX: Float, screenY: Float): Float =
        if (longAxisIsVertical) {
            (screenX - viewWidth / 2f) / scale
        } else {
            (screenY - viewHeight / 2f) / scale
        }

    // ------------------------------------------------------------------ 屏幕边界

    /**
     * 球场矩形在屏幕上的四条边。
     *
     * 注意：长边在屏幕上是横是竖由 [longAxisIsVertical] 决定，所以左右边要用**横向那一维**
     * 的长度算（竖屏是 [drawnShort]、横屏是 [drawnLong]），否则横屏会算错。
     */
    val fieldLeft: Float get() = viewWidth / 2f - fieldWidth / 2f
    val fieldRight: Float get() = viewWidth / 2f + fieldWidth / 2f
    val fieldTop: Float get() = viewHeight / 2f - fieldHeight / 2f
    val fieldBottom: Float get() = viewHeight / 2f + fieldHeight / 2f

    /** 球场在屏幕横向 / 纵向上占的像素。 */
    val fieldWidth: Float get() = if (longAxisIsVertical) drawnShort else drawnLong

    val fieldHeight: Float get() = if (longAxisIsVertical) drawnLong else drawnShort

    /** 黑带的厚度：竖屏时在上下，横屏时在左右。 */
    val stripAlongLongAxis: Float get() = strip

    // ------------------------------------------------------------------ 判定与钳制

    /** 这个屏幕点是不是落在球场里（含边线）。 */
    fun isInsideField(screenX: Float, screenY: Float): Boolean =
        screenX >= fieldLeft && screenX <= fieldRight &&
            screenY >= fieldTop && screenY <= fieldBottom

    /** 球场长轴方向的可用半长（米）。 */
    val halfLong: Float get() = fieldLong / 2f

    /** 球场短轴方向的可用半宽（米）。 */
    val halfShort: Float get() = fieldShort / 2f

    /** 把球场长轴坐标钳在球场内，边界各留 [marginMeters] 余量。 */
    fun clampLongAxis(meters: Float, marginMeters: Float = 0f): Float =
        meters.coerceIn(-halfLong + marginMeters, halfLong - marginMeters)

    /** 把球场短轴坐标钳在球场内，边界各留 [marginMeters] 余量。 */
    fun clampShortAxis(meters: Float, marginMeters: Float = 0f): Float =
        meters.coerceIn(-halfShort + marginMeters, halfShort - marginMeters)
}
