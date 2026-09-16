package com.example.sport.sport.share.court

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.util.TypedValue
import android.view.MotionEvent
import android.view.View
import com.example.sport.sport.share.protocol.BoardReset
import com.example.sport.sport.share.protocol.Coord
import com.example.sport.sport.share.protocol.CourtState
import com.example.sport.sport.share.protocol.DragEnded
import com.example.sport.sport.share.protocol.DragMoved
import com.example.sport.sport.share.protocol.DragStarted
import com.example.sport.sport.share.protocol.PlayerRef
import com.example.sport.sport.share.protocol.SportEvent
import com.example.sport.sport.share.protocol.SportEventSink
import com.example.sport.sport.share.protocol.SportKind
import com.example.sport.sport.share.protocol.StateChanged
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

/**
 * 本地手势。View 负责把**像素**换算成**球场坐标（米）**，再交给 [onGesture]；
 * 所以事件层既不认识 Android，也不认识像素，纯 Kotlin 就能测。
 */
sealed interface Gesture {
    /** 拿起了场上一个人 / 球（[from] = 它原来在哪儿）。 */
    data class PickUp(val ref: PlayerRef, val from: Coord) : Gesture

    /** 拖动中。 */
    data class DragTo(val ref: PlayerRef, val pos: Coord) : Gesture

    /** 松手。[committed] = false 表示拖动被打断（系统 cancel）。 */
    data class Drop(val ref: PlayerRef, val pos: Coord, val committed: Boolean) : Gesture
}

/**
 * 所有球类页面共用的底座：**只画 + 只报手势**，没有任何规则判断。
 *
 * 子类只要提供一个 [CourtSpec]（场地真实尺寸 / 颜色 / 球和人的大小）并实现
 * [drawMarkings]（这个项目特有的线），其余全在这里：
 *
 *  - 草皮 / 木地板底色 + 球场外框 + 中线 + 中圈；
 *  - 22 个（或 10 个、12 个）球员令牌 + 一颗球，客队号码转 180°；
 *  - 黑带上的主队 / 客队牌子；
 *  - 拖动：拿起最近的球员或球，松手停在哪儿就是哪儿。
 *
 * 几何见 [CourtGeometry]：竖屏时长边竖着放、横屏时横着放，比例尺按
 * 「屏幕短边对齐球场短边 / 球场长边最多占屏幕长边的 80%」算，所以球场外永远是黑的。
 *
 * 约定：这里**不 import log 包**，也不 import net 包 —— 拿起 / 放下只通过
 * [dragListener] 往外报一行文字，往哪儿写由 Activity 决定。
 */
abstract class CourtView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    /** 开局站位。 */
    protected abstract fun initialPlayers(): List<PlayerToken>

    /**
     * 画这个项目特有的线。用 [g] 把球场坐标（米）换成像素，或者直接用 [g] 提供的
     * [CourtGeometry.screenX] / [CourtGeometry.screenY]，配合
     * [drawLineBetween] / [drawSegment] / [drawArcAt] 这些帮手。
     *
     * 底色、外框、中线、中圈已经画好了，这里不用重复。
     */
    protected abstract fun drawMarkings(canvas: Canvas, g: CourtGeometry)

    /**
     * 这个项目的场地与配色。
     *
     * **是函数不是属性**：基类构造的时候就要用（底下那些画笔和球的初始位置都靠它），
     * 而 Kotlin 里「子类属性」要等基类构造完才初始化 —— 写成 `override val spec` 的话，
     * 基类构造时读到的是 null，一进页面就 NPE。
     *
     * 实现里只返回常量就行，**别去读子类自己的属性/字段**（那时候它们也还没初始化）。
     */
    protected abstract fun spec(): CourtSpec

    /**
     * 这个页面是哪种球，事件里要带上它。
     * **公开**的：MainActivity 要按球种把对端事件分发给对应页面。
     */
    abstract fun sportKind(): SportKind

    /** 球场线的颜色。 */
    private val lineColor = 0xE6FFFFFF.toInt()

    /** 号码颜色：主队令牌是深红底 → 白字；客队是白底 → 深字。 */
    private val numberColorHome = 0xFFFFFFFF.toInt()
    private val numberColorAway = 0xFF23282D.toInt()

    // ------------------------------------------------------------------ 数据（无逻辑，只有位置）

    /** 双方球员，开局站位见各项目的 Formation。 */
    protected val players: MutableList<PlayerToken> = initialPlayers().toMutableList()

    /** 球的位置（球场坐标，米）。 */
    protected var ballX: Float = spec().ballStartLong
    protected var ballY: Float = spec().ballStartShort

    /**
     * 拿起 / 放下时的回调，给「app 内日志」用。
     * View 自己不写日志（不 import log 包），由 MainActivity 挂上去。
     */
    var dragListener: ((String) -> Unit)? = null

    /**
     * 本地事件的出口：联机时把 WebSocket 的 Session 接到这里（跟象棋的 `eventSink` 同款）。
     * View 自己不 import net 包，只管把事件交出去。
     */
    var eventSink: SportEventSink? = null

    /** 拖动时手指与令牌中心的最大距离（dp），超了就抓不到。 */
    private var grabSlopDp = 26f

    // ------------------------------------------------------------------ 几何

    private var geo: CourtGeometry? = null

    // ------------------------------------------------------------------ 拖动状态

    private enum class Grabbed { NONE, PLAYER, BALL }

    private var grabbed = Grabbed.NONE

    /** 被拖的球员在 [players] 里的下标；[grabbed] 不是 PLAYER 时无意义。 */
    private var grabbedPlayer = -1

    /** 拖动前的原位，用来在球场上留一个半透明影子。 */
    private var originX = 0f
    private var originY = 0f

    // ------------------------------------------------------------------ 联机

    /** 事件序号：发送方自己递增，用于去重 / 丢弃过期包。 */
    private var seq = 0L

    /**
     * **对端**正在拖的东西：`(它原来在哪儿, 现在到哪儿了)`，没有则 null。
     * 渲染时把令牌画到「现在到哪儿」，并在「原来在哪儿」留个影子 —— 也就是「看见对方乱动」。
     */
    private var remoteDrag: Triple<PlayerRef, Coord, Coord>? = null

    // ------------------------------------------------------------------ 画笔

    private val density = resources.displayMetrics.density

    private val surfacePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = spec().surfaceColor
    }
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = lineColor
        strokeCap = Paint.Cap.ROUND
    }
    private val spotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = lineColor
    }
    private val homePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = spec().homeColor
    }
    private val awayPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = spec().awayColor
    }
    private val ballPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = spec().awayColor
    }

    /** 球外面那圈环：实心圆画在球的边界之外，所以不动球本身的直径。 */
    private val ballRingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = spec().ballRingColor
    }

    /** 拖动球时留在原位的那圈影子轮廓。 */
    private val shadowRingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0x80FFFFFF.toInt()
    }
    private val tokenRingPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0x66000000
    }
    private val shadowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x40FFFFFF
    }
    private val homeNumberPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = numberColorHome
        textAlign = Paint.Align.CENTER
        isFakeBoldText = true
    }
    private val awayNumberPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = numberColorAway
        textAlign = Paint.Align.CENTER
        isFakeBoldText = true
    }
    private val badgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        isFakeBoldText = true
    }

    /** 复用同一个矩形，避免每次绘制都 new。 */
    private val rect = RectF()

    // ------------------------------------------------------------------ 给子类用的绘制帮手

    /**
     * 一段线 / 一段圆弧的粗细。真实线宽是 0.1 米左右，在这个比例尺下只有两三个像素，
     * 所以兜一个下限，保证看得见。
     */
    protected fun lineWidth(g: CourtGeometry): Float =
        max(dp(1.5f), spec().lineWidthMeters * g.scale)

    /** 画一个球场坐标下的圆点（中圈圆心、罚球点这类）。 */
    protected fun drawSpot(canvas: Canvas, g: CourtGeometry, x: Float, y: Float, radiusMeters: Float) {
        spotPaint.alpha = 255
        canvas.drawCircle(
            g.screenX(x, y),
            g.screenY(x, y),
            max(dp(1.5f), radiusMeters * g.scale),
            spotPaint,
        )
    }

    /** 画一个球场坐标下的空心圆。 */
    protected fun drawCircle(canvas: Canvas, g: CourtGeometry, x: Float, y: Float, radiusMeters: Float) {
        canvas.drawCircle(
            g.screenX(x, y),
            g.screenY(x, y),
            radiusMeters * g.scale,
            linePaint,
        )
    }

    /** 用球场坐标画一条线段。 */
    protected fun drawSegment(
        canvas: Canvas,
        g: CourtGeometry,
        x1: Float,
        y1: Float,
        x2: Float,
        y2: Float,
    ) {
        canvas.drawLine(
            g.screenX(x1, y1),
            g.screenY(x1, y1),
            g.screenX(x2, y2),
            g.screenY(x2, y2),
            linePaint,
        )
    }

    /** 用球场坐标画一个矩形（两条长轴位置 + 两条短轴位置，顺序无所谓）。 */
    protected fun drawFieldRect(
        canvas: Canvas,
        g: CourtGeometry,
        x1: Float,
        y1: Float,
        x2: Float,
        y2: Float,
    ) {
        val a = g.screenX(x1, y1) to g.screenY(x1, y1)
        val b = g.screenX(x2, y2) to g.screenY(x2, y2)
        rect.set(
            min(a.first, b.first),
            min(a.second, b.second),
            max(a.first, b.first),
            max(a.second, b.second),
        )
        canvas.drawRect(rect, linePaint)
    }

    /**
     * 画一段**从 A 绕到 B** 的弧，方向由 [bulgeLong] / [bulgeShort] 决定：
     * 弧会往那个方向鼓出去。
     *
     * 为什么不直接给角度：球场长边在屏幕上可能是竖的（上下半场），球场坐标下的角度会跟着转，
     * 而且「从 A 顺时针还是逆时针到 B」光看两头很容易搞反（三分线是个 241° 的大弧，
     * 角球弧又贴在角上）。所以这里只给「从哪到哪、往哪个方向鼓」，方向在这里算：
     * 试两种扫法，取**中点方向**与鼓出方向夹角更小的那种。
     *
     * 方向用**向量**而不是点：角球弧的弧心就顶在角点上，「角点 → 场地中心」的方向
     * 没法用一个跟弧心不同的点表示（给了也是同一个点）。
     *
     * 注意这里是比**方向**而不是比距离 —— 弧心可能就在场地边上，
     * 拿「中点离某个点的距离」去比，两条候选路径几乎一样近，会挑反。
     *
     * @param x / [y] 圆心（球场坐标，米）
     * @param radiusMeters 半径（米）
     * @param from / [to] 弧的两端（球场坐标）
     * @param bulgeLong / [bulgeShort] 弧要鼓向的方向（球场坐标下的向量，不用归一化）。
     *   比如角球弧给「角点 → 场地中心」、三分线给「篮筐 → 场地中心」。
     */
    protected fun drawArcThrough(
        canvas: Canvas,
        g: CourtGeometry,
        x: Float,
        y: Float,
        radiusMeters: Float,
        from: Pair<Float, Float>,
        to: Pair<Float, Float>,
        bulgeLong: Float,
        bulgeShort: Float,
    ) {
        val cx = g.screenX(x, y)
        val cy = g.screenY(x, y)
        val r = radiusMeters * g.scale

        // 方向向量也要换成屏幕坐标（长边可能是横着的那一维）
        val originX = g.screenX(0f, 0f)
        val originY = g.screenY(0f, 0f)
        val tipX = g.screenX(bulgeLong, bulgeShort)
        val tipY = g.screenY(bulgeLong, bulgeShort)

        // 全部换算成屏幕坐标之后再交给 CourtArc —— 长边在屏幕上是竖着的话，角度跟着转
        val angles = CourtArc.angles(
            cx = cx,
            cy = cy,
            fromX = g.screenX(from.first, from.second),
            fromY = g.screenY(from.first, from.second),
            toX = g.screenX(to.first, to.second),
            toY = g.screenY(to.first, to.second),
            bulgeDx = tipX - originX,
            bulgeDy = tipY - originY,
        ) ?: return

        rect.set(cx - r, cy - r, cx + r, cy + r)
        canvas.drawArc(rect, angles.first, angles.second, false, linePaint)
    }

    /**
     * 直接指定「起始方向 + 扫过角度」画弧，用于**半圆**。
     *
     * 为什么不走 [drawArcThrough]：半圆的两端正好隔着 180°，两条候选路径的中点方向
     * 是垂直的 —— 只给一个「往哪边鼓」的方向，数学上分不出要哪半个。
     * 所以半圆一律用这个函数明说。
     *
     * @param fromX / [fromY] 半圆的起点（球场坐标）；角度取「圆心 → 起点」的屏幕方向
     * @param sweep 顺时针扫过的角度；`180` = 屏幕上的顺时针那半，`-180` = 逆时针那半
     */
    protected fun drawArc(
        canvas: Canvas,
        g: CourtGeometry,
        x: Float,
        y: Float,
        radiusMeters: Float,
        fromX: Float,
        fromY: Float,
        sweep: Float,
    ) {
        val cx = g.screenX(x, y)
        val cy = g.screenY(x, y)
        val r = radiusMeters * g.scale
        val start = CourtArc.angleDeg(
            g.screenX(fromX, fromY) - cx,
            g.screenY(fromX, fromY) - cy,
        )
        rect.set(cx - r, cy - r, cx + r, cy + r)
        canvas.drawArc(rect, start, sweep, false, linePaint)
    }

    /** 用虚线画一段圆（罚球圈靠中场那半个在 FIBA 里就是虚线）。 */
    private val dashEffect = android.graphics.DashPathEffect(floatArrayOf(14f, 12f), 0f)

    protected fun withDashedLine(block: () -> Unit) {
        val saved = linePaint.pathEffect
        linePaint.pathEffect = dashEffect
        block()
        linePaint.pathEffect = saved
    }

    /** 粗细单独指定（画球门这种要更粗的框）。 */
    protected fun withLineWidth(width: Float, block: () -> Unit) {
        val saved = linePaint.strokeWidth
        linePaint.strokeWidth = width
        block()
        linePaint.strokeWidth = saved
    }

    // ------------------------------------------------------------------ 尺寸

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return

        val g = CourtGeometry(
            viewWidth = w.toFloat(),
            viewHeight = h.toFloat(),
            fieldLong = spec().fieldLong,
            fieldShort = spec().fieldShort,
        )
        geo = g

        linePaint.strokeWidth = lineWidth(g)

        val tokenRadius = spec().playerTokenDiameter / 2f * g.scale
        tokenRingPaint.strokeWidth = max(dp(1f), tokenRadius * 0.16f)

        shadowRingPaint.strokeWidth = ballRingWidth(g)

        homeNumberPaint.textSize = tokenRadius * 1.1f
        awayNumberPaint.textSize = tokenRadius * 1.1f

        val strip = g.strip
        badgePaint.textSize = min(sp(18f), max(sp(11f), strip * 0.34f))
    }

    private fun dp(value: Float) = value * density

    private fun sp(value: Float) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, value, resources.displayMetrics)

    /**
     * 球外面那圈环的粗细：跟着球半径走，但夹在 2dp ~ 6dp 之间 ——
     * 小屏别细到看不见，大屏别粗成一个呼啦圈。画球和画影子都用它。
     */
    private fun ballRingWidth(g: CourtGeometry): Float {
        val radius = spec().ballDiameter / 2f * g.scale
        return min(dp(6f), max(dp(2f), radius * 0.45f))
    }

    /** 把球员 / 球摆回开球站位（右上角「重置」用）。 */
    fun resetFormation() {
        players.clear()
        players += initialPlayers()
        ballX = spec().ballStartLong
        ballY = spec().ballStartShort
        grabbed = Grabbed.NONE
        grabbedPlayer = -1
        remoteDrag = null
        invalidate()
    }

    /**
     * 「把大家摆回开球站位」这条事件，序号由 [CourtView] 自己盖章。
     * 重置是 Activity 触发的（本地状态已经改了），所以这里只负责产出事件。
     */
    fun resetEvent(): SportEvent = BoardReset(sportKind(), ++seq)

    // ------------------------------------------------------------------ 联机：本地手势 → 事件

    /**
     * 本地手势 → 要广播出去的事件（本地状态可能已经改了）。
     *
     * 跟象棋的 `Game.onGesture` 一个套路：**先改本地，再把事件交出去**。
     * 拿到 / 放下会额外发一条全量状态 —— 那是唯一权威，对端照抄即可；
     * 拖动过程中的位置只是装饰，丢了也不影响结果。
     */
    private fun onLocalGesture(gesture: Gesture): List<SportEvent> {
        val sport = sportKind()
        return when (gesture) {
            is Gesture.PickUp -> listOf(DragStarted(sport, ++seq, gesture.ref, gesture.from))

            is Gesture.DragTo -> listOf(DragMoved(sport, ++seq, gesture.ref, gesture.pos))

            is Gesture.Drop -> {
                val events = ArrayList<SportEvent>(2)
                events += DragEnded(sport, ++seq, gesture.ref, gesture.pos, gesture.committed)
                // 落位之后立刻同步全量状态，对端不需要自己算
                if (gesture.committed) events += StateChanged(sport, ++seq, snapshot())
                events
            }
        }
    }

    private fun emit(events: List<SportEvent>) {
        if (events.isEmpty()) return
        eventSink?.onLocalEvents(events)
    }

    /** 当前场上的全量状态（所有人 + 球）。 */
    fun snapshot(): CourtState = CourtState(
        players = players.associate { refOf(it) to Coord.ofMeters(it.x, it.y) },
        ball = Coord.ofMeters(ballX, ballY),
    )

    /** 收到对端事件 → 改本地状态。**对端来的事件不会再触发手势 / 再广播回去**。 */
    fun submitRemote(event: SportEvent) {
        if (event.sport != sportKind()) return

        when (event) {
            is DragStarted -> {
                // 对端拿起了东西：记下原位，渲染时在那儿留个影子
                remoteDrag = Triple(event.ref, event.from, event.from)
            }

            is DragMoved -> {
                val current = remoteDrag
                if (current != null && current.first == event.ref) {
                    remoteDrag = Triple(event.ref, current.second, event.pos)
                } else {
                    remoteDrag = Triple(event.ref, event.pos, event.pos)
                }
                moveLocal(event.ref, event.pos)
            }

            is DragEnded -> {
                if (event.committed) {
                    moveLocal(event.ref, event.pos)
                    dragListener?.invoke("对端放下${event.ref.label()}")
                }
                remoteDrag = null
            }

            is StateChanged -> {
                applyState(event.state)
                remoteDrag = null
                dragListener?.invoke("收到对端状态：${event.state.players.size} 人 + 球")
            }

            is BoardReset -> {
                resetFormation()
                dragListener?.invoke("对端重置了站位")
            }
        }
        invalidateIfVisible()
    }

    /** 直接照抄对端给的坐标，不做任何计算。 */
    private fun applyState(state: CourtState) {
        for (player in players) {
            state.players[refOf(player)]?.let { pos ->
                player.x = pos.metersX
                player.y = pos.metersY
            }
        }
        ballX = state.ball.metersX
        ballY = state.ball.metersY
    }

    /** 把场上某个球员（或球）挪到指定位置。 */
    private fun moveLocal(ref: PlayerRef, pos: Coord) {
        if (ref.isBall) {
            ballX = pos.metersX
            ballY = pos.metersY
            return
        }
        players.firstOrNull { samePlayer(it, ref) }?.let { player ->
            player.x = pos.metersX
            player.y = pos.metersY
        }
    }

    /** 本地令牌 → 上线用的 ref。 */
    protected fun refOf(token: PlayerToken): PlayerRef = if (token.side == 0) {
        PlayerRef.home(token.number, token.id)
    } else {
        PlayerRef.away(token.number, token.id)
    }

    /** 球员身份只认 `(side, 号码)` —— 对端的阵型顺序不必跟本机一样。 */
    private fun samePlayer(token: PlayerToken, ref: PlayerRef): Boolean =
        !ref.isBall && token.side == ref.side && token.number == ref.number

    /** 隐藏的页面不用重绘（它本来就不显示）。 */
    private fun invalidateIfVisible() {
        if (isShown) invalidate()
    }

    // ------------------------------------------------------------------ 绘制

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val g = geo ?: return

        // 底色 + 外框
        rect.set(g.fieldLeft, g.fieldTop, g.fieldRight, g.fieldBottom)
        canvas.drawRect(rect, surfacePaint)
        canvas.drawRect(rect, linePaint)

        // 中线 + 中圈 + 圆心点
        drawSegment(canvas, g, 0f, -g.halfShort, 0f, g.halfShort)
        drawCircle(canvas, g, 0f, 0f, spec().centerCircleRadius)
        drawSpot(canvas, g, 0f, 0f, 0.15f)

        // 这个项目特有的线
        drawMarkings(canvas, g)

        drawPlayers(canvas, g)
        drawBall(canvas, g)
        drawBadges(canvas, g)
    }

    /** 球员令牌。客队的号码转 180°，坐在对面的人也看得正。 */
    private fun drawPlayers(canvas: Canvas, g: CourtGeometry) {
        val radius = spec().playerTokenDiameter / 2f * g.scale

        for ((index, player) in players.withIndex()) {
            // 正在拖的那个人：原位留一个影子
            if (grabbed == Grabbed.PLAYER && index == grabbedPlayer) {
                canvas.drawCircle(
                    g.screenX(originX, originY),
                    g.screenY(originX, originY),
                    radius,
                    shadowPaint,
                )
                continue
            }

            // 对端正在拖这个人：令牌跟着他走，原位留个影子。
            // 影子画在「他开始拖的时候在哪儿」，令牌画在当前位置（也就是 player.x/y）。
            val remote = remoteDrag
            if (remote != null && remote.first == refOf(player)) {
                canvas.drawCircle(
                    g.screenX(remote.second.metersX, remote.second.metersY),
                    g.screenY(remote.second.metersX, remote.second.metersY),
                    radius,
                    shadowPaint,
                )
            }

            val cx = g.screenX(player.x, player.y)
            val cy = g.screenY(player.x, player.y)
            drawPlayer(canvas, cx, cy, radius, player)
        }
    }

    private fun drawPlayer(canvas: Canvas, cx: Float, cy: Float, radius: Float, player: PlayerToken) {
        val home = player.side == 0
        canvas.drawCircle(cx, cy, radius, if (home) homePaint else awayPaint)
        canvas.drawCircle(cx, cy, radius - tokenRingPaint.strokeWidth / 2f, tokenRingPaint)

        val paint = if (home) homeNumberPaint else awayNumberPaint
        val metrics = paint.fontMetrics
        val baseline = cy - (metrics.ascent + metrics.descent) / 2f

        if (home) {
            canvas.drawText(player.number.toString(), cx, baseline, paint)
        } else {
            // 客队在屏幕另一端，号码转 180° 朝对面
            canvas.save()
            canvas.rotate(180f, cx, cy)
            canvas.drawText(player.number.toString(), cx, baseline, paint)
            canvas.restore()
        }
    }

    /**
     * 球。**球本身的直径不动**（真实尺寸折算过来只有十来个像素，太小看不见），
     * 在它外面套一圈醒目的环：环画在球的边界**之外**，所以球还是原来那么大。
     */
    private fun drawBall(canvas: Canvas, g: CourtGeometry) {
        val radius = spec().ballDiameter / 2f * g.scale
        val ring = ballRingWidth(g)
        val cx = g.screenX(ballX, ballY)
        val cy = g.screenY(ballX, ballY)

        // 自己正在拖 或者 对端正在拖：都在原位描一圈影子
        val localDrag = grabbed == Grabbed.BALL
        val remote = remoteDrag?.takeIf { it.first.isBall }
        if (localDrag || remote != null) {
            val shadow = if (localDrag) Pair(originX, originY) else {
                Pair(remote!!.second.metersX, remote.second.metersY)
            }
            drawBallWithRing(
                canvas,
                g.screenX(shadow.first, shadow.second),
                g.screenY(shadow.first, shadow.second),
                radius,
                ring,
                shadowed = true,
            )
        }
        drawBallWithRing(canvas, cx, cy, radius, ring, shadowed = false)
    }

    /** 一圈球：底色球 + 深色分隔线 + 外面那圈醒目的环。 */
    private fun drawBallWithRing(
        canvas: Canvas,
        cx: Float,
        cy: Float,
        radius: Float,
        ring: Float,
        shadowed: Boolean,
    ) {
        if (shadowed) {
            // 影子只描个轮廓：跟真球同样大，但不抢眼
            canvas.drawCircle(cx, cy, radius + ring / 2f, shadowRingPaint)
            return
        }
        canvas.drawCircle(cx, cy, radius + ring, ballRingPaint)
        canvas.drawCircle(cx, cy, radius, tokenRingPaint)
        canvas.drawCircle(cx, cy, radius, ballPaint)
    }

    /**
     * 黑带上的队牌：屏幕**上方**是客队、**下方**是主队（面对面坐时各自朝自己那一端）。
     * 黑带太窄就不画，免得糊成一团。
     */
    private fun drawBadges(canvas: Canvas, g: CourtGeometry) {
        val strip = g.strip
        if (strip < dp(18f)) return

        val awayY = strip * 0.5f
        val homeY = g.viewHeight - strip * 0.5f

        if (g.longAxisIsVertical) {
            badgePaint.color = spec().awayColor
            drawCenteredText(canvas, "客队", g.viewWidth / 2f, awayY, badgePaint)
            badgePaint.color = spec().homeColor
            drawCenteredText(canvas, "主队", g.viewWidth / 2f, homeY, badgePaint)
        } else {
            // 横屏：黑带在左右两侧，客队在左、主队在右
            badgePaint.color = spec().awayColor
            drawCenteredText(canvas, "客队", g.fieldLeft / 2f, awayY, badgePaint)
            badgePaint.color = spec().homeColor
            drawCenteredText(canvas, "主队", (g.viewWidth + g.fieldRight) / 2f, homeY, badgePaint)
        }

        // 对端正在拖东西时，在最下面那条黑带上说一句（联机时才用得上）
        val remote = remoteDrag
        if (remote != null && strip > dp(40f)) {
            badgePaint.color = 0xB3FFFFFF.toInt()
            drawCenteredText(
                canvas,
                "对端正在拖${remote.first.label()}",
                g.viewWidth / 2f,
                g.viewHeight - strip - dp(10f),
                badgePaint,
            )
        }
    }

    private fun drawCenteredText(canvas: Canvas, text: String, cx: Float, cy: Float, paint: Paint) {
        val metrics = paint.fontMetrics
        canvas.drawText(text, cx, cy - (metrics.ascent + metrics.descent) / 2f, paint)
    }

    // ------------------------------------------------------------------ 触摸：只拖动，不判断

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        val g = geo ?: return false
        val x = event.x
        val y = event.y

        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                if (!grab(x, y, g)) return false
                // 本地状态已经在 grab 里改了；这里只把「拿起了什么」广播出去
                emit(onLocalGesture(Gesture.PickUp(grabbedRef()!!, Coord.ofMeters(originX, originY))))
                parent?.requestDisallowInterceptTouchEvent(true)
                invalidate()
                return true
            }

            MotionEvent.ACTION_MOVE -> {
                if (grabbed == Grabbed.NONE) return false
                moveTo(x, y, g)
                emit(
                    onLocalGesture(
                        Gesture.DragTo(grabbedRef()!!, Coord.ofMeters(g.longAxisAt(x, y), g.shortAxisAt(x, y))),
                    ),
                )
                return true
            }

            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                if (grabbed == Grabbed.NONE) return false
                // 松手停在哪儿就是哪儿：不做任何吸附 / 归位
                val cancelled = event.actionMasked == MotionEvent.ACTION_CANCEL
                val current = grabbedRef()!!
                val pos = if (current.isBall) {
                    Coord.ofMeters(ballX, ballY)
                } else {
                    val player = players[grabbedPlayer]
                    Coord.ofMeters(player.x, player.y)
                }
                msgDrop(cancelled)
                emit(onLocalGesture(Gesture.Drop(current, pos, committed = !cancelled)))
                grabbed = Grabbed.NONE
                grabbedPlayer = -1
                invalidate()
                return true
            }
        }
        return super.onTouchEvent(event)
    }

    /** 抓最近的球员或球（球优先一点，因为它小、容易被球员压住）。 */
    private fun grab(px: Float, py: Float, g: CourtGeometry): Boolean {
        val slop = dp(grabSlopDp)
        val ballRadius = spec().ballDiameter / 2f * g.scale
        val tokenRadius = spec().playerTokenDiameter / 2f * g.scale

        val ballDistance = distance(px, py, g.screenX(ballX, ballY), g.screenY(ballX, ballY))
        if (ballDistance <= max(slop, ballRadius)) {
            grabbed = Grabbed.BALL
            originX = ballX
            originY = ballY
            dragListener?.invoke("拿起球")
            return true
        }

        var bestIndex = -1
        var bestDistance = Float.MAX_VALUE
        for ((index, player) in players.withIndex()) {
            val d = distance(px, py, g.screenX(player.x, player.y), g.screenY(player.x, player.y))
            if (d < bestDistance) {
                bestDistance = d
                bestIndex = index
            }
        }
        if (bestIndex < 0 || bestDistance > max(slop, tokenRadius)) return false

        grabbed = Grabbed.PLAYER
        grabbedPlayer = bestIndex
        originX = players[bestIndex].x
        originY = players[bestIndex].y
        val player = players[bestIndex]
        dragListener?.invoke("拿起${sideName(player.side)}${player.number} 号")
        return true
    }

    /** 当前拎在手上的东西（没在拖就是 null）。 */
    private fun grabbedRef(): PlayerRef? = when (grabbed) {
        Grabbed.PLAYER -> players.getOrNull(grabbedPlayer)?.let { refOf(it) }
        Grabbed.BALL -> PlayerRef.BALL_REF
        Grabbed.NONE -> null
    }

    private fun moveTo(px: Float, py: Float, g: CourtGeometry) {
        val longAxis = g.longAxisAt(px, py)
        val shortAxis = g.shortAxisAt(px, py)
        when (grabbed) {
            Grabbed.BALL -> {
                ballX = longAxis
                ballY = shortAxis
            }

            Grabbed.PLAYER -> {
                val player = players[grabbedPlayer]
                player.x = longAxis
                player.y = shortAxis
            }

            Grabbed.NONE -> return
        }
        invalidate()
    }

    /** 松手时把「谁落在哪儿」报给日志（球场坐标，米）。 */
    private fun msgDrop(cancelled: Boolean) {
        val prefix = if (cancelled) "拖动被打断" else "放下"
        when (grabbed) {
            Grabbed.PLAYER -> {
                // 位置是「松手时」的，不是 origin（origin 只用来画影子）
                val player = players[grabbedPlayer]
                dragListener?.invoke(
                    "${prefix}${sideName(player.side)}${player.number} 号 → " +
                        "(${format(player.x)}, ${format(player.y)}) m",
                )
            }

            Grabbed.BALL -> dragListener?.invoke(
                "${prefix}球 → (${format(ballX)}, ${format(ballY)}) m",
            )

            Grabbed.NONE -> Unit
        }
    }

    /** 球员队伍的中文名：side 0 = 主队、1 = 客队。 */
    private fun sideName(side: Int) = if (side == 0) "主队" else "客队"

    private fun format(value: Float) = String.format(java.util.Locale.US, "%.1f", value)

    private fun distance(x1: Float, y1: Float, x2: Float, y2: Float): Float {
        val dx = x1 - x2
        val dy = y1 - y2
        return sqrt(dx * dx + dy * dy)
    }
}
