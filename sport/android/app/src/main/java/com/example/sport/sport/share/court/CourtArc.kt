package com.example.sport.sport.share.court

/**
 * 画弧时的角度计算。纯 Kotlin，不依赖 Android，JVM 可单测（见 CourtArcTest）。
 *
 * 只解决一件事：**从 A 绕到 B，该顺时针还是逆时针**。
 *
 * 光看两端是定不下来的 —— 从 A 到 B 有两条路（一条短的、一条绕大半圈的），
 * 三分线要走的就是那条 241° 的长弧，角球弧走的是 90° 的短弧，而球场长边在屏幕上
 * 可能竖着（上下半场），球场坐标下的角度还会跟着转 90°。
 *
 * 所以这里换一种说法：给一个**鼓出的方向**，试两种扫法，取中点方向跟它最贴合的。
 * 方向用向量给（不是点），因为弧心本身常常就是想要的那个方向的起点：
 * 角球弧的弧心顶在角点上，要鼓的方向就是「角点 → 场地中心」的斜对角 ——
 * 用点的话就得额外挑一个中间的点了。
 *
 * 注意比的是**方向夹角**，不是「中点离某点的距离」：角球弧的圆心离场地中心很远，
 * 用距离去比的话两条候选路径几乎一样近，四个角里会挑反两个。
 */
object CourtArc {

    /** 判「两个方向的贴合程度是否一样」用的容差。 */
    private const val TIE_EPSILON = 1e-4f

    /**
     * 一段弧：起始角 + 扫过角度，直接喂给 `Canvas.drawArc`（0° 朝右、顺时针为正）。
     *
     * @param cx / [cy] 圆心
     * @param fromX / [fromY] 弧的一端
     * @param toX / [toY] 弧的另一端
     * @param bulgeDx / [bulgeDy] 弧要鼓向的那一侧的**方向**（不是点，不需要归一化，不能是零向量）
     * @return 起始角与扫过角度；参数退化（圆心与端点重合、方向为零）时返回 null，调用方跳过这次绘制
     */
    fun angles(
        cx: Float,
        cy: Float,
        fromX: Float,
        fromY: Float,
        toX: Float,
        toY: Float,
        bulgeDx: Float,
        bulgeDy: Float,
    ): Pair<Float, Float>? {
        val startDx = fromX - cx
        val startDy = fromY - cy
        val endDx = toX - cx
        val endDy = toY - cy

        // 圆心跟端点重合、或者没给方向 ⇒ 角度没有意义
        if (isZero(startDx, startDy) || isZero(endDx, endDy) || isZero(bulgeDx, bulgeDy)) return null

        val start = angleDeg(startDx, startDy)
        val end = angleDeg(endDx, endDy)
        val target = Math.toRadians(angleDeg(bulgeDx, bulgeDy).toDouble())

        val targetCos = kotlin.math.cos(target)
        val targetSin = kotlin.math.sin(target)

        // 两种扫法（顺时针 / 逆时针）外加一整圈，取中点方向跟 bulge 方向最贴合的那个
        val candidates = floatArrayOf(end - start, end - start + 360f, end - start - 360f)
        var best = candidates[0]
        var bestScore = -Float.MAX_VALUE
        for (sweep in candidates) {
            val score = midDirectionScore(start, sweep, targetCos, targetSin)
            // 平分时取扫过角度更小的那个：扫 360° 和扫 0°、扫 90° 和扫 -270° 的中点方向
            // 完全一样（得分都是 1.0），得靠这条挑出「那条短的弧」，
            // 否则三分线会被画成绕场地一圈的 478°。
            val better = score > bestScore + TIE_EPSILON ||
                (kotlin.math.abs(score - bestScore) <= TIE_EPSILON &&
                    kotlin.math.abs(sweep) < kotlin.math.abs(best))
            if (better) {
                bestScore = score
                best = sweep
            }
        }
        return start to best
    }

    /** 这段弧的中点方向与 bulge 方向的贴合程度（点积，1 = 完全一致）。 */
    fun midDirectionScore(start: Float, sweep: Float, targetCos: Double, targetSin: Double): Float {
        val mid = Math.toRadians((start + sweep / 2f).toDouble())
        return (kotlin.math.cos(mid) * targetCos + kotlin.math.sin(mid) * targetSin).toFloat()
    }

    /** 屏幕坐标（y 向下）下的角度：0° 朝右、顺时针为正。 */
    fun angleDeg(dx: Float, dy: Float): Float =
        Math.toDegrees(kotlin.math.atan2(dy.toDouble(), dx.toDouble())).toFloat()

    private fun isZero(dx: Float, dy: Float) = dx == 0f && dy == 0f
}
