package com.example.sport.sport.basketball

import android.content.Context
import android.graphics.Canvas
import android.util.AttributeSet
import com.example.sport.sport.share.court.CourtGeometry
import com.example.sport.sport.share.court.CourtSpec
import com.example.sport.sport.share.court.CourtView
import com.example.sport.sport.share.court.PlayerToken
import com.example.sport.sport.share.protocol.SportKind

/**
 * 篮球页。**只画 + 只报手势**，没有任何规则判断（不判走步、不判 24 秒、不记分）。
 *
 * 场地和共用逻辑在 [CourtView] 里（底色、外框、中线、中圈、令牌、球、拖动），
 * 这里只负责篮球场特有的线：
 *
 *  - 两侧限制区（三秒区）+ 罚球线 + 罚球圈（靠端线那半个实线、靠中场那半个虚线）；
 *  - 三分线：两条底角直线 + 一段 6.75 米的弧；
 *  - 合理冲撞区（篮下 1.25 米的小半圆）；
 *  - 篮板 + 篮筐；
 *  - 篮板正面的宽度标记（篮板两端那两条短线）。
 *
 * 尺寸全是 FIBA 标准，见 [BasketballCourt]。
 */
class BasketballView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : CourtView(context, attrs, defStyleAttr) {

    companion object {
        /** 木地板色。 */
        private const val COLOR_FLOOR = 0xFFB07A3C.toInt()

        /** 主队：深红。 */
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
        fieldLong = BasketballCourt.LENGTH,
        fieldShort = BasketballCourt.WIDTH,
        lineWidthMeters = 0.1f,
        playerTokenDiameter = BasketballCourt.PLAYER_TOKEN_DIAMETER,
        ballDiameter = BasketballCourt.BALL_DIAMETER,
        centerCircleRadius = BasketballCourt.CENTER_CIRCLE_R,
        surfaceColor = COLOR_FLOOR,
        homeColor = COLOR_HOME,
        awayColor = COLOR_AWAY,
        ballRingColor = COLOR_BALL_RING,
        ballStartLong = BasketballFormation.BALL_X,
        ballStartShort = BasketballFormation.BALL_Y,
    )

    override fun sportKind(): SportKind = SportKind.BASKETBALL

    override fun initialPlayers(): List<PlayerToken> = BasketballFormation.players()

    // ------------------------------------------------------------------ 篮球场特有的线

    override fun drawMarkings(canvas: Canvas, g: CourtGeometry) {
        for (side in intArrayOf(-1, 1)) {
            drawLane(canvas, g, side)
            drawThreePointLine(canvas, g, side)
            drawRestrictedArea(canvas, g, side)
            drawBasket(canvas, g, side)
        }
    }

    /** 限制区（三秒区）：一个 4.9 × 5.8 米的矩形 + 罚球线 + 罚球圈。 */
    private fun drawLane(canvas: Canvas, g: CourtGeometry, side: Int) {
        val baseline = BasketballCourt.baselineX(side)
        val freeThrowLine = BasketballCourt.freeThrowLineX(side)
        val halfLane = BasketballCourt.LANE_WIDTH / 2f

        drawFieldRect(canvas, g, baseline, -halfLane, freeThrowLine, halfLane)

        // 罚球圈：靠端线那半个是实线，靠中场那半个是虚线。
        //
        // 两端隔着 180°，是**半圆** —— 一个「往哪边鼓」的方向判不出来，所以用 drawArc 明说。
        // 又因为两个半圆是「左右对开」的，两端必须在**上下**（垂直于对开方向）：
        // 端点放在罚球线上、中场那一侧的点，弧正好穿过端线那一侧。
        val r = BasketballCourt.FREE_THROW_CIRCLE_R

        // 靠端线那半个：实线
        drawArc(
            canvas = canvas,
            g = g,
            x = freeThrowLine,
            y = 0f,
            radiusMeters = r,
            fromX = freeThrowLine,
            fromY = -r,
            sweep = 180f * side,
        )

        // 靠中场那半个：虚线
        withDashedLine {
            drawArc(
                canvas = canvas,
                g = g,
                x = freeThrowLine,
                y = 0f,
                radiusMeters = r,
                fromX = freeThrowLine,
                fromY = -r,
                sweep = -180f * side,
            )
        }
    }

    /**
     * 三分线：两条底角直线（离边线 0.9 米）+ 一段以篮筐为心、半径 6.75 米的弧。
     * 弧的两端正好落在底角直线的端点上。
     */
    private fun drawThreePointLine(canvas: Canvas, g: CourtGeometry, side: Int) {
        val baseline = BasketballCourt.baselineX(side)
        val cornerX = BasketballCourt.threePointCornerX(side)

        for (edge in intArrayOf(-1, 1)) {
            val y = BasketballCourt.cornerThreeY(edge)
            // 底角直线：从端线到弧的起点
            drawSegment(canvas, g, baseline, y, cornerX, y)
        }

        // 弧：从一侧底角绕到另一侧底角，往中圈方向鼓出去（方向 = 篮筐 → 场地中心）
        drawArcThrough(
            canvas = canvas,
            g = g,
            x = BasketballCourt.basketX(side),
            y = 0f,
            radiusMeters = BasketballCourt.THREE_POINT_R,
            from = Pair(cornerX, BasketballCourt.cornerThreeY(-1)),
            to = Pair(cornerX, BasketballCourt.cornerThreeY(1)),
            bulgeLong = -BasketballCourt.basketX(side),
            bulgeShort = 0f,
        )
    }

    /**
     * 合理冲撞区：篮下 1.25 米的半圆，两端接在限制区的两条线上，**开口朝端线**
     * （所以弧的中点落在「篮筐 → 罚球线」那一侧，远离端线）。
     *
     * 两端隔着 180°，是**半圆**，没法用「往哪边鼓」判方向，所以用 drawArc 明说扫哪 180°。
     */
    private fun drawRestrictedArea(canvas: Canvas, g: CourtGeometry, side: Int) {
        val basket = BasketballCourt.basketX(side)
        val r = BasketballCourt.RESTRICTED_AREA_R

        drawArc(
            canvas = canvas,
            g = g,
            x = basket,
            y = 0f,
            radiusMeters = r,
            // 从「靠端线那一侧」的那一端出发
            fromX = basket,
            fromY = -r,
            // 扫 180°：side = -1（左半场）时顺时针、+1 时逆时针，中点都落在远端那一侧
            sweep = 180f * side,
        )
    }

    /** 篮板 + 篮筐：篮板是端线里侧的一小段粗线，篮筐是它的正前方一个小圆。 */
    private fun drawBasket(canvas: Canvas, g: CourtGeometry, side: Int) {
        val backboard = BasketballCourt.backboardX(side)
        val halfBackboard = BasketballCourt.BACKBOARD_WIDTH / 2f

        // 篮板：短轴方向的一小段，画粗一点
        withLineWidth(lineWidth(g) * 2.2f) {
            drawSegment(canvas, g, backboard, -halfBackboard, backboard, halfBackboard)
        }

        // 篮筐：圆心在篮筐中心，半径 0.225 米
        drawCircle(canvas, g, BasketballCourt.basketX(side), 0f, BasketballCourt.HOOP_R)
    }
}
