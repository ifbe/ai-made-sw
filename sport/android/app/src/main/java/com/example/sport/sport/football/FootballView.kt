package com.example.sport.sport.football

import android.content.Context
import android.graphics.Canvas
import android.util.AttributeSet
import com.example.sport.sport.share.court.CourtGeometry
import com.example.sport.sport.share.court.CourtSpec
import com.example.sport.sport.share.court.CourtView
import com.example.sport.sport.share.court.PlayerToken
import com.example.sport.sport.share.protocol.SportKind
import kotlin.math.sqrt

/**
 * 足球页。**只画 + 只报手势**，没有任何规则判断（不判越位、出界、进球，不记分）。
 *
 * 场地和共用逻辑在 [CourtView] 里（底色、外框、中线、中圈、令牌、球、拖动），
 * 这里只负责足球场特有的线：
 *
 *  - 两侧大禁区（16.5 × 40.32 米）、小禁区（5.5 × 18.32 米）；
 *  - 罚球点 + 罚球弧（以罚球点为心、半径 9.15 米，只画禁区外那一段）；
 *  - 四个角球弧（半径 1 米）；
 *  - 两侧球门（画在端线外侧的小矩形）。
 *
 * 尺寸全部是真实米数，见 [FootballCourt]。
 */
class FootballView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : CourtView(context, attrs, defStyleAttr) {

    companion object {
        /** 草皮绿。 */
        private const val COLOR_TURF = 0xFF1E7A34.toInt()

        /** 主队：红。 */
        private const val COLOR_HOME = 0xFFE23B3B.toInt()

        /** 客队：白。 */
        private const val COLOR_AWAY = 0xFFF2F2F2.toInt()

        /** 球外面那圈环：亮黄（跟红、白都区分得开）。 */
        private const val COLOR_BALL_RING = 0xFFFFC61A.toInt()
    }

    /**
     * 只返回常量，**不读任何字段** —— 这是基类构造时就要用的（见 [CourtView.spec]）。
     */
    override fun spec(): CourtSpec = CourtSpec(
        fieldLong = FootballCourt.LENGTH,
        fieldShort = FootballCourt.WIDTH,
        lineWidthMeters = FootballCourt.LINE_WIDTH,
        playerTokenDiameter = FootballCourt.PLAYER_TOKEN_DIAMETER,
        ballDiameter = FootballCourt.BALL_DIAMETER,
        centerCircleRadius = FootballCourt.CENTER_CIRCLE_R,
        surfaceColor = COLOR_TURF,
        homeColor = COLOR_HOME,
        awayColor = COLOR_AWAY,
        ballRingColor = COLOR_BALL_RING,
        ballStartLong = FootballFormation.BALL_X,
        ballStartShort = FootballFormation.BALL_Y,
    )

    override fun sportKind(): SportKind = SportKind.FOOTBALL

    override fun initialPlayers(): List<PlayerToken> = FootballFormation.players()

    // ------------------------------------------------------------------ 足球场特有的线

    override fun drawMarkings(canvas: Canvas, g: CourtGeometry) {
        for (side in intArrayOf(-1, 1)) {
            drawPenaltyAreas(canvas, g, side)
            drawPenaltyArc(canvas, g, side)
        }
        drawCornerArcs(canvas, g)
        drawGoals(canvas, g)
    }

    /** 大禁区 + 小禁区 + 罚球点。 */
    private fun drawPenaltyAreas(canvas: Canvas, g: CourtGeometry, side: Int) {
        val goalLine = FootballCourt.goalLineX(side)

        // 大禁区：从端线往里 16.5 米，宽 40.32 米
        val penaltyBack = goalLine - side * FootballCourt.PENALTY_AREA_DEPTH
        val penaltyHalf = FootballCourt.PENALTY_AREA_WIDTH / 2f
        drawFieldRect(canvas, g, goalLine, -penaltyHalf, penaltyBack, penaltyHalf)

        // 小禁区：从端线往里 5.5 米，宽 18.32 米
        val goalAreaBack = goalLine - side * FootballCourt.GOAL_AREA_DEPTH
        val goalAreaHalf = FootballCourt.GOAL_AREA_WIDTH / 2f
        drawFieldRect(canvas, g, goalLine, -goalAreaHalf, goalAreaBack, goalAreaHalf)

        // 罚球点
        val spotX = goalLine - side * FootballCourt.PENALTY_SPOT_FROM_LINE
        drawSpot(canvas, g, spotX, 0f, FootballCourt.CENTER_SPOT_R)
    }

    /**
     * 罚球弧：以罚球点为心、半径 9.15 米，**只画大禁区外面那一段**。
     *
     * 弧与禁区线的交点在「罚球点往端线方向 16.5 - 11 = 5.5 米、往两侧 √(9.15² - 5.5²) = 7.5 米」处。
     * 直接算出这两个点，再让 [CourtView.drawArcThrough] 决定往哪边鼓 ——
     * 这里要往球门那一侧鼓，所以方向给「罚球点 → 球门线」。
     */
    private fun drawPenaltyArc(canvas: Canvas, g: CourtGeometry, side: Int) {
        val spotX = FootballCourt.goalLineX(side) - side * FootballCourt.PENALTY_SPOT_FROM_LINE
        val back = FootballCourt.PENALTY_AREA_DEPTH - FootballCourt.PENALTY_SPOT_FROM_LINE // = 5.5
        val dy = sqrt(FootballCourt.PENALTY_ARC_R * FootballCourt.PENALTY_ARC_R - back * back) // = 7.5
        val cornerX = spotX - side * back

        drawArcThrough(
            canvas = canvas,
            g = g,
            x = spotX,
            y = 0f,
            radiusMeters = FootballCourt.PENALTY_ARC_R,
            from = Pair(cornerX, -dy),
            to = Pair(cornerX, dy),
            bulgeLong = FootballCourt.goalLineX(side) - spotX,
            bulgeShort = 0f,
        )
    }

    /**
     * 四个角球弧：半径 1 米，从一条边线转到另一条边线，朝场内鼓。
     *
     * 鼓出方向给「角点 → 场地中心」这条斜对角 —— 它正好是四分之一圆的中分线。
     * （不能给「中点离场地中心的距离」那种判断：弧心顶在角点上、离场地中心很远，
     * 两条候选路径几乎一样近，四个角里会挑反两个。）
     */
    private fun drawCornerArcs(canvas: Canvas, g: CourtGeometry) {
        val halfLong = g.halfLong
        val halfShort = g.halfShort

        for (signX in intArrayOf(-1, 1)) {
            for (signY in intArrayOf(-1, 1)) {
                val cornerLong = signX * halfLong
                val cornerShort = signY * halfShort
                // 圆心就是角点；起点在长边方向的边线上，终点在短边方向的边线上
                drawArcThrough(
                    canvas = canvas,
                    g = g,
                    x = cornerLong,
                    y = cornerShort,
                    radiusMeters = FootballCourt.CORNER_ARC_R,
                    from = Pair(signX * (halfLong - FootballCourt.CORNER_ARC_R), cornerShort),
                    to = Pair(cornerLong, signY * (halfShort - FootballCourt.CORNER_ARC_R)),
                    bulgeLong = -cornerLong,
                    bulgeShort = -cornerShort,
                )
            }
        }
    }

    /** 两侧球门：画在端线**外侧**的小矩形（长轴方向伸出 2 米，短轴方向 7.32 米宽）。 */
    private fun drawGoals(canvas: Canvas, g: CourtGeometry) {
        val half = FootballCourt.GOAL_WIDTH / 2f
        withLineWidth(lineWidth(g) * 1.6f) {
            for (side in intArrayOf(-1, 1)) {
                val lineX = FootballCourt.goalLineX(side)
                val outX = lineX + side * FootballCourt.GOAL_DEPTH
                drawFieldRect(canvas, g, lineX, -half, outX, half)
            }
        }
    }
}
