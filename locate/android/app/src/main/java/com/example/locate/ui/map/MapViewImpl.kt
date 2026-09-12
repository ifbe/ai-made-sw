package com.example.locate.ui.map

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.text.TextPaint
import android.text.TextUtils
import android.util.AttributeSet
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import com.example.locate.domain.model.User
import com.example.locate.util.AppLog
import org.json.JSONObject
import kotlin.math.pow

private const val LOG_PANEL_WIDTH_DP = 300          // 展开后的默认宽度
private const val LOG_PANEL_TAB_MIN_WIDTH_DP = 40   // 折叠小方块的最小宽度（箭头 + 日志N）
private const val LOG_PANEL_ROW_DP = 14             // 每行日志的行距
private const val LOG_PANEL_STRIP_DP = 30           // 底部把手条高度（折叠时只有它）
private const val LOG_PANEL_ROWS_TOP_DP = 3
private const val LOG_PANEL_MIN_ROWS = 3            // 可拖出来的最小行数
private const val LOG_PANEL_MAX_ROWS_CAP = 30       // 可拖出来的最大行数
private const val LOG_PANEL_RESIZE_ZONE_DP = 26     // 右上角缩放热区大小
private const val LOGOUT_LABEL = "退出登录"          // 本地面板标题行右侧的退出入口

/**
 * 手写定点格式化。
 * 十字线和四角坐标每帧都要拼字符串，String.format 每次都会新建 Formatter + StringBuilder，
 * 拖地图时是白白的分配和 GC 压力。
 */
private fun fmtFixed(value: Double, decimals: Int): String {
    if (!value.isFinite()) return "--"
    val sb = StringBuilder(16)
    var v = value
    if (v < 0) {
        sb.append('-')
        v = -v
    }
    val scale = when (decimals) {
        1 -> 10L
        4 -> 10000L
        else -> 1000000L
    }
    val scaled = Math.round(v * scale)
    sb.append(scaled / scale)
    sb.append('.')
    val frac = scaled % scale
    var divisor = scale / 10
    while (divisor > 1 && frac < divisor) {
        sb.append('0')
        divisor /= 10
    }
    sb.append(frac)
    return sb.toString()
}

class MapViewImpl @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : FrameLayout(context, attrs, defStyleAttr), MapView {

    private val webView: WebView
    private val overlay: FrameLayout

    // 箭头 / 目标点 / 目标虚线都由 Leaflet 画（见 assets/html/map.html），
    // 这一侧只把"谁在哪、目标在哪"发过去，不再自己算屏幕坐标。
    private var mapReady = false
    private val pendingJs = mutableListOf<String>()

    // 手指没松开（或缩放动画没停）时为 true。这期间不重画 HUD，
    // 因为十字线和四角坐标都是全屏 View，重画一次＝整屏重新光栅化。
    @Volatile
    private var mapMoving = false

    private var clickListener: ((Double, Double) -> Unit)? = null
    private var mapViewWidth = 0      // CSS 像素，来自 JS
    private var mapViewHeight = 0     // CSS 像素，来自 JS
    private var currentZoom = 15.0
    private var currentCenterLat = 0.0
    private var currentCenterLng = 0.0
    private var currentAltitude: Double? = null
    private var crosshairView: CrosshairView? = null
    private var cornerCoordsView: CornerCoordsView? = null
    private var logPanel: LogPanel? = null
    private var localSettingsPanel: LocalSettingsPanel? = null
    private var userListPanel: UserListPanel? = null
    private var localSettingsClickListener: ((String, Double, Double) -> Unit)? = null
    private var userListClickListener: ((String, User) -> Unit)? = null

    // 四角坐标（每次 onCenterAndZoom 时更新）
    private var cornerTopLeft: Pair<Double, Double>? = null    // (lat, lng)
    private var cornerTopRight: Pair<Double, Double>? = null   // (lat, lng)
    private var cornerBottomLeft: Pair<Double, Double>? = null // (lat, lng)
    private var cornerBottomRight: Pair<Double, Double>? = null // (lat, lng)

    init {
        // dpr = context.resources.displayMetrics.density  // removed, using CSS pixels directly

        webView = WebView(context).apply {
            // 注意：这里以前是 setLayerType(LAYER_TYPE_SOFTWARE)，会让 WebView 走 CPU 软渲染，
            // 拖地图时每一帧都要把整屏内容重新光栅化，是卡顿的主要来源。默认的硬件加速交给
            // Chromium 自己在 GPU 上合成瓦片图层，才能跟手。
            setBackgroundColor(0xFFFFFFFF.toInt())
            layoutParams = LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT)
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                databaseEnabled = true
                loadWithOverviewMode = true
                useWideViewPort = true
                builtInZoomControls = false
                displayZoomControls = false
                cacheMode = WebSettings.LOAD_DEFAULT
                mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                allowFileAccess = true
                allowContentAccess = true
            }
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    onMapPageReady()
                    requestCenterAndZoom()
                }
            }
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(msg: android.webkit.ConsoleMessage?): Boolean = true
            }
        }
        addView(webView)

        overlay = FrameLayout(context).apply {
            layoutParams = LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT)
            clipChildren = false
            clipToPadding = false
        }
        addView(overlay)
        // 允许子视图绘制到边界外
        this.clipChildren = false
        this.clipToPadding = false

        // 十字线（屏幕正中心，用于设置目标点）
        crosshairView = CrosshairView(context)
        overlay.addView(crosshairView!!, FrameLayout.LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))

        // 四角坐标视图（盖在地图最上层）
        cornerCoordsView = CornerCoordsView(context)
        overlay.addView(cornerCoordsView!!, FrameLayout.LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))

        // 左下角：日志面板（折叠时只有一个小三角）
        logPanel = LogPanel(context)
        overlay.addView(logPanel!!, FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT).apply {
            gravity = android.view.Gravity.BOTTOM or android.view.Gravity.START
            bottomMargin = 32
            marginStart = 20
        })

        // 左上角：本地设置面板
        localSettingsPanel = LocalSettingsPanel(context)
        localSettingsPanel?.setOnClickListener { type ->
            localSettingsClickListener?.invoke(type, currentCenterLat, currentCenterLng)
        }
        overlay.addView(localSettingsPanel!!, FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT).apply {
            gravity = android.view.Gravity.TOP or android.view.Gravity.START
            topMargin = 60
            marginStart = 16
        })

        // 右上角：队友列表面板
        userListPanel = UserListPanel(context)
        userListPanel?.setOnClickListener { action, user ->
            userListClickListener?.invoke(action, user)
        }
        overlay.addView(userListPanel!!, FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT).apply {
            gravity = android.view.Gravity.TOP or android.view.Gravity.END
            topMargin = 60
            marginEnd = 16
        })



        // 未登录时两个角面板都不显示，登录成功后由 ViewModel 打开
        setCornerPanelsVisible(false)

        webView.addJavascriptInterface(JsInterface(), "Android")
        webView.loadUrl("file:///android_asset/html/map.html")

        // 定时轮询地图中心（每500ms），解决后台时 evaluateJavascript 不执行的问题
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(object : Runnable {
            override fun run() {
                if (mapReady) postJs("MapInterface.getCenterAndZoom()")
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(this, 500)
            }
        }, 500)
    }

    private fun getScreenWidth(): Int = context.resources.displayMetrics.widthPixels
    private fun getScreenHeight(): Int = context.resources.displayMetrics.heightPixels

    fun getView(): View = this

    // ─── MapView interface ───────────────────────────────────────────

    override fun showUser(lat: Double, lng: Double, heading: Float) {
        if (lat == 0.0 && lng == 0.0) return
        postJs("MapInterface.setSelf($lat, $lng, ${deg(heading)})")
    }

    override fun showOtherUser(user: User) {
        val key = jsQuote(user.username)
        // 还没上报过坐标的人不画，否则所有标记都会堆在地图左上角
        if (user.lat == 0.0 && user.lng == 0.0) {
            postJs("MapInterface.removeUser($key)")
            return
        }
        val label = user.nickname?.takeIf { it.isNotBlank() } ?: user.username
        postJs(
            "MapInterface.setUser($key, ${user.lat}, ${user.lng}, ${deg(user.heading)}, ${jsQuote(label)})"
        )

        val targetLat = user.targetLat
        val targetLng = user.targetLng
        if (targetLat != null && targetLng != null && !(targetLat == 0.0 && targetLng == 0.0)) {
            postJs("MapInterface.setUserTarget($key, $targetLat, $targetLng)")
        } else {
            postJs("MapInterface.clearUserTarget($key)")
        }
    }

    override fun removeOtherUser(username: String) {
        postJs("MapInterface.removeUser(${jsQuote(username)})")
    }

    override fun showOtherUsers(users: List<User>) {
        // 这一侧不缓存任何标记状态：让 JS 侧按 key 清掉已经不在列表里的人
        val keys = users.joinToString(prefix = "[", postfix = "]", separator = ",") {
            jsQuote(it.username)
        }
        postJs("MapInterface.retainUsers($keys)")
        users.forEach { showOtherUser(it) }
    }

    override fun showTarget(lat: Double, lng: Double) {
        postJs("MapInterface.setSelfTarget($lat, $lng)")
    }

    override fun clearTarget() {
        postJs("MapInterface.clearSelfTarget()")
    }

    override fun moveTo(lat: Double, lng: Double, zoom: Double) {
        postJs("MapInterface.moveTo($lat, $lng, $zoom)")
    }


    override fun setOnMapClickListener(listener: (Double, Double) -> Unit) {
        clickListener = listener
    }

    override fun setCornerPanelsVisible(visible: Boolean) {
        post {
            val state = if (visible) View.VISIBLE else View.GONE
            localSettingsPanel?.visibility = state
            userListPanel?.visibility = state
        }
    }

    override fun updateTargetButton(hasTarget: Boolean) {
        post {
            localSettingsPanel?.setHasTarget(hasTarget)
        }
    }

    override fun setOnTargetButtonClickListener(listener: (Double, Double) -> Unit) {
        localSettingsClickListener = { type, lat, lng ->
            if (type == "target") listener(lat, lng)
        }
    }

    override fun updateUserList(users: List<User>) {
        post { userListPanel?.updateUsers(users) }
    }

    override fun updateAltitude(altitude: Double?) {
        currentAltitude = altitude
        post { crosshairView?.invalidate() }
    }

    override fun setOnLocalSettingsClickListener(listener: (String, Double, Double) -> Unit) {
        localSettingsClickListener = listener
    }

    override fun setOnUserListClickListener(listener: (String, User) -> Unit) {
        userListClickListener = listener
    }

    override fun onDestroy() {
        logPanel?.dispose()
        webView.destroy()
    }

    // ─── 发给 Leaflet 的指令 ──────────────────────────────────────────

    /** JS 字符串字面量：用户名/昵称可能带引号 */
    private fun jsQuote(value: String): String = JSONObject.quote(value)

    /** 朝向只在 0~360 有意义；NaN/Infinity 会让 JS 里的 rotate() 失效 */
    private fun deg(heading: Float): Float = if (heading.isFinite()) heading else 0f

    private fun requestCenterAndZoom() {
        postJs("MapInterface.getCenterAndZoom()")
    }

    /**
     * 页面加载完成前 evaluateJavascript 是发给空白页的，会直接丢掉。
     * 所以标记指令先排队，页面就绪（onPageFinished / onMapReady）时一起发。
     */
    @SuppressLint("SetJavaScriptEnabled")
    private fun postJs(code: String) {
        if (!mapReady) {
            if (pendingJs.size < 128) pendingJs.add(code)
            return
        }
        webView.post { webView.evaluateJavascript(code, null) }
    }

    private fun onMapPageReady() {
        mapReady = true
        if (pendingJs.isEmpty()) return
        val queued = pendingJs.toList()
        pendingJs.clear()
        webView.post {
            queued.forEach { webView.evaluateJavascript(it, null) }
        }
    }

    // ─── JS Bridge ───────────────────────────────────────────────────

    inner class JsInterface {
        @JavascriptInterface
        fun onMapClick(lat: Double, lng: Double) {
            android.util.Log.d("MapDebug", "onMapClick: $lat, $lng")
            clickListener?.invoke(lat, lng)
        }

        @JavascriptInterface
        fun onMapReady() {
            // 页面脚本已跑起来（Leaflet 已建好），早先排队的标记指令现在可以发了
            onMapPageReady()
            postJs("MapInterface.getCenterAndZoom()")
        }

        @JavascriptInterface
        fun onMapMoving(moving: Boolean) {
            mapMoving = moving
        }

        @JavascriptInterface
        fun onCenterAndZoom(zoom: Double, centerLat: Double, centerLng: Double, cssWidth: Int, cssHeight: Int) {
            val wasInitialized = mapViewWidth > 0 && mapViewHeight > 0
            // 值没变就别重画（空闲时每 500ms 一次轮询，本来全是白画）
            val changed = cssWidth != mapViewWidth || cssHeight != mapViewHeight ||
                zoom != currentZoom || centerLat != currentCenterLat || centerLng != currentCenterLng
            // 保持 CSS 像素原始值，用于十字线旁的墨卡托投影计算
            mapViewWidth = cssWidth
            mapViewHeight = cssHeight
            currentZoom = zoom
            currentCenterLat = centerLat
            currentCenterLng = centerLng

            if (!wasInitialized && cssWidth > 0 && cssHeight > 0) {
                onFirstMapReady?.invoke()
            }

            // 拖拽/缩放动画进行中：数值照记（设目标要用地图中心），但不重画
            if (mapMoving || !changed) return

            post {
                crosshairView?.invalidate()
                cornerCoordsView?.invalidate()
            }
        }
    }

    private var onFirstMapReady: (() -> Unit)? = null
    fun setOnFirstMapReadyListener(listener: () -> Unit) {
        android.util.Log.d("MapDebug", "setOnFirstMapReadyListener registered, current callback=${onFirstMapReady != null}")
        onFirstMapReady = listener
        // 如果地图已经初始化过了，立即触发
        if (mapViewWidth > 0 && mapViewHeight > 0) {
            android.util.Log.d("MapDebug", "Map already ready, triggering immediately")
            onFirstMapReady?.invoke()
        }
    }

    // ─── Corner Coordinates View ─────────────────────────────────────

    inner class CornerCoordsView @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF444444.toInt()
            textSize = 22f
        }
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xBBFFFFFF.toInt()
        }
        // 这两个以前是在 onDraw 里 new 出来的，每帧都在分配
        private val debugPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF00AA00.toInt()
            textSize = 20f
            textAlign = Paint.Align.CENTER
        }
        private val debugBgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xBB000000.toInt()
        }
        private var debugText = ""
        private var debugWidth = 0f

        override fun onDraw(canvas: Canvas) {
            // 直接用 canvas 的实际尺寸，不用 mapViewWidth/Height
            val w = canvas.width.toFloat()
            val h = canvas.height.toFloat()
            if (w <= 0 || h <= 0) return

            val pad = 10f
            val lineH = 28f

            // 四个角写死在屏幕真正的角落
            // 左上: 文字基线在 (pad, pad+lineH)
            // 右上: 文字基线在 (w-pad, pad+lineH)，右对齐
            // 左下: 文字基线在 (pad, h-pad)
            // 右下: 文字基线在 (w-pad, h-pad)，右对齐
            drawCorner(canvas, pad,      pad + lineH,  "左上", true)
            drawCorner(canvas, w - pad,  pad + lineH,  "右上", false)
            drawCorner(canvas, pad,      h - pad,      "左下", true)
            drawCorner(canvas, w - pad,  h - pad,      "右下", false)

            // Debug: 屏幕尺寸（顶部居中）。尺寸不会变，量一次就够
            if (debugText.isEmpty()) {
                debugText = "屏幕:${w.toInt()}x${h.toInt()}"
                debugWidth = debugPaint.measureText(debugText)
            }
            val debugX = w / 2
            val debugY = 20f
            val debugH = 28f
            canvas.drawRoundRect(debugX - debugWidth / 2 - 8f, debugY - debugH + 4f, debugX + debugWidth / 2 + 8f, debugY + 4f, 8f, 8f, debugBgPaint)
            canvas.drawText(debugText, debugX, debugY, debugPaint)
        }

        private fun drawCorner(canvas: Canvas, sx: Float, sy: Float, name: String, alignLeft: Boolean) {
            val dx = (sx - canvas.width / 2).toDouble()
            val dy = (canvas.height / 2 - sy).toDouble()
            val lat = cornerLat(dy)
            val lng = cornerLng(dx)
            val text = "$name ${fmt(lat)}, ${fmt(lng)}"
            val textW = textPaint.measureText(text)
            val bx = if (alignLeft) sx else sx - textW
            val lineH = 28f
            canvas.drawRect(bx - 4f, sy - lineH + 4f, bx + textW + 4f, sy + 4f, bgPaint)
            canvas.drawText(text, bx, sy, textPaint)
        }


        // dy: screen pixels from center. dy>0=above center(north), dy<0=below center(south)
        private fun cornerLat(dy: Double): Double {
            val scale = 256.0 * 2.0.pow(currentZoom)
            // worldY/halfScale = 0.5 - ln(tan(latRad) + 1/cos(latRad)) / (2π)
            val centerLatRad = Math.toRadians(currentCenterLat)
            val centerWorldY = (0.5 - kotlin.math.ln(kotlin.math.tan(centerLatRad) + 1.0 / kotlin.math.cos(centerLatRad)) / (2.0 * Math.PI)) * scale * 0.5
            val worldY = centerWorldY - dy
            val worldYFrac = worldY / (scale * 0.5)
            // Inverse: lat = 2*atan(exp(π*(1-2*worldYFrac))) - π/2
            val latRad = 2.0 * kotlin.math.atan(kotlin.math.exp(Math.PI * (1.0 - 2.0 * worldYFrac))) - Math.PI / 2.0
            return Math.toDegrees(latRad)
        }

        private fun cornerLng(dx: Double): Double {
            val scale = 256.0 * 2.0.pow(currentZoom)
            val centerWorldX = (currentCenterLng + 180.0) / 360.0 * scale
            val worldX = centerWorldX + dx
            return worldX / scale * 360.0 - 180.0
        }

        private fun fmt(v: Double) = fmtFixed(v, 4)
    }

    // ─── Crosshair View ─────────────────────────────────────────────

    inner class CrosshairView @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFF0000.toInt()
            strokeWidth = 3f
            style = Paint.Style.STROKE
        }
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFF0000.toInt()
            textSize = 24f
            textAlign = Paint.Align.LEFT
        }
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFFFFFF.toInt()
            style = Paint.Style.FILL
        }
        private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFF0000.toInt()
            style = Paint.Style.STROKE
            strokeWidth = 2f
        }

        override fun onDraw(canvas: Canvas) {
            val cx = width / 2f
            val cy = height / 2f
            val size = 40f

            // 十字线
            paint.strokeWidth = 3f
            canvas.drawLine(cx - size, cy, cx + size, cy, paint)
            canvas.drawLine(cx, cy - size, cx, cy + size, paint)
            canvas.drawCircle(cx, cy, 8f, paint)

            // 坐标文字（在十字线上方，三行，位置抬高不挡十字星）
            val line1 = "经度: " + fmtFixed(currentCenterLng, 6)
            val line2 = "纬度: " + fmtFixed(currentCenterLat, 6)
            val altitude = currentAltitude
            val altText = if (altitude != null) "海拔: " + fmtFixed(altitude, 1) + " m" else "海拔: -- m"
            val lineH = 28f

            // 背景框在十字星上方，不遮挡
            val textW = maxOf(textPaint.measureText(line1), textPaint.measureText(line2), textPaint.measureText(altText))
            val textX = cx - textW / 2 - 8f
            val textY = cy - size - 120f  // 抬高到十字线上方，不挡中心
            val bgW = textW + 16f
            val bgH = lineH * 3 + 12f
            canvas.drawRect(textX, textY, textX + bgW, textY + bgH, bgPaint)
            canvas.drawRect(textX, textY, textX + bgW, textY + bgH, borderPaint)

            textPaint.textAlign = Paint.Align.LEFT
            canvas.drawText(line1, textX + 8f, textY + lineH, textPaint)
            canvas.drawText(line2, textX + 8f, textY + lineH * 2, textPaint)
            canvas.drawText(altText, textX + 8f, textY + lineH * 3, textPaint)
        }
    }

    // ─── Log Panel (bottom-left) ──────────────────────────────────────

    /**
     * 应用内日志矩形。左下角那个点固定不动，卡片往右上长。
     *
     * - 底部是始终可见的把手条：折叠时只有它（▲ 日志N），展开后日志行画在它上方（▼）
     * - 只有点把手条才切换展开/折叠，点日志行不会收起
     * - 日志行区域上下拖动翻历史，长按清空
     * - 拖右上角可以自己改宽高（左下角固定，所以往右上拖）
     * - 右侧竖条是滚动条，显示当前这一段在全部日志里的位置
     */
    inner class LogPanel @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {

        private var entries: List<AppLog.Entry> = emptyList()
        private var expanded = AppLog.panelExpanded
        private var scrollLines = 0        // 距最新一行上滚了多少行，0 = 贴住最新
        private var visibleRows = AppLog.panelRows
        private var customWidthPx = 0      // 0 = 用默认宽度
        private var resizing = false
        private var downTime = 0L
        private var downY = 0f
        private var lastY = 0f
        private var dragging = false
        private val touchSlop = android.view.ViewConfiguration.get(context).scaledTouchSlop
        private val locationOnScreen = IntArray(2)

        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xF0FFFFFF.toInt(); style = Paint.Style.FILL
        }
        private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0x33000000.toInt(); style = Paint.Style.STROKE; strokeWidth = 1f
        }
        private val headerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF888888.toInt() }
        private val dividerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x22000000 }
        private val timePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF9E9E9E.toInt() }
        private val textPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF000000.toInt() }
        private val trianglePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF666666.toInt(); style = Paint.Style.FILL
        }
        private val trianglePath = Path()
        private val gripPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0x55000000; style = Paint.Style.STROKE
        }
        private val scrollTrackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x14000000 }
        private val scrollThumbPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x66000000 }

        private val logListener: (List<AppLog.Entry>) -> Unit = { list ->
            val oldSize = entries.size
            entries = list
            // 正在翻历史时来了新日志：滚动量一起前推，视口保持不动
            if (scrollLines > 0 && list.size > oldSize) scrollLines += list.size - oldSize
            scrollLines = scrollLines.coerceIn(0, maxScrollLines())
            if (expanded) requestLayout()
            invalidate()
        }

        init {
            setWillNotDraw(false)
            // 恢复上次拖出来的宽度（Activity 重建后不丢）
            if (AppLog.panelWidthDp > 0) customWidthPx = dp(AppLog.panelWidthDp)
        }

        override fun onAttachedToWindow() {
            super.onAttachedToWindow()
            AppLog.addListener(logListener)
        }

        override fun onDetachedFromWindow() {
            super.onDetachedFromWindow()
            AppLog.removeListener(logListener)
        }

        fun dispose() {
            AppLog.removeListener(logListener)
        }

        // ─── 尺寸 ────────────────────────────────────────────────────

        private fun defaultPanelWidth(): Int = minOf(dp(LOG_PANEL_WIDTH_DP), getScreenWidth() - dp(48))

        private fun panelWidth(): Int = if (customWidthPx > 0) customWidthPx else defaultPanelWidth()

        private fun minPanelWidth(): Int = dp(140)

        private fun maxPanelWidth(): Int = getScreenWidth() - dp(16)

        /** 高度最多占屏幕一半，换算成能放几行 */
        private fun maxRowCapacity(): Int {
            val usable = getScreenHeight() / 2 - dp(LOG_PANEL_STRIP_DP + LOG_PANEL_ROWS_TOP_DP + 1)
            return (usable / dp(LOG_PANEL_ROW_DP)).coerceIn(LOG_PANEL_MIN_ROWS, LOG_PANEL_MAX_ROWS_CAP)
        }

        private fun rowCapacity(): Int = visibleRows.coerceIn(LOG_PANEL_MIN_ROWS, maxRowCapacity())

        private fun maxScrollLines(): Int = (entries.size - rowCapacity()).coerceAtLeast(0)

        private fun rowPitchPx(): Float = dp(LOG_PANEL_ROW_DP).toFloat()

        /** 当前视口里的日志：末尾是 entries.size - scrollLines */
        private fun visibleEntries(): List<AppLog.Entry> {
            val end = (entries.size - scrollLines).coerceIn(0, entries.size)
            val start = (end - rowCapacity()).coerceAtLeast(0)
            return entries.subList(start, end)
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            var h = LOG_PANEL_STRIP_DP
            if (expanded) {
                // 展开后是个固定行数的窗口（像终端），行数由拖拽决定
                h += LOG_PANEL_ROWS_TOP_DP + rowCapacity() * LOG_PANEL_ROW_DP + 1
            }
            // 折叠态是个小方块（箭头 + 日志N），展开才变宽
            val w = if (expanded) panelWidth() else tabWidth()
            setMeasuredDimension(w, dp(h))
        }

        private fun stripText(): String = "日志 ${entries.size}"

        /** 折叠态宽度：按把手条文字实测，仍比展开时短得多 */
        private fun tabWidth(): Int {
            headerPaint.textSize = dp(10).toFloat()
            val textWidth = headerPaint.measureText(stripText())
            return maxOf(dp(LOG_PANEL_TAB_MIN_WIDTH_DP), (dp(24) + textWidth + dp(10)).toInt())
        }

        // ─── 绘制 ────────────────────────────────────────────────────

        override fun onDraw(canvas: Canvas) {
            headerPaint.textSize = dp(10).toFloat()
            timePaint.textSize = dp(8).toFloat()
            textPaint.textSize = dp(10).toFloat()

            val r = dp(10).toFloat()
            canvas.drawRoundRect(0f, 0f, width.toFloat(), height.toFloat(), r, r, bgPaint)
            canvas.drawRoundRect(0f, 0f, width.toFloat(), height.toFloat(), r, r, borderPaint)

            // 把手条永远贴着底边，展开只是往上长
            val stripTop = height - dp(LOG_PANEL_STRIP_DP)

            if (expanded) {
                val capacity = rowCapacity()
                val visible = visibleEntries()
                val rowsTop = dp(LOG_PANEL_ROWS_TOP_DP)

                if (visible.isEmpty()) {
                    canvas.drawText("暂无日志", dp(8).toFloat(), (rowsTop + dp(10)).toFloat(), headerPaint)
                }
                var baseline = rowsTop + dp(10)
                for (entry in visible) {
                    canvas.drawText(entry.time, dp(6).toFloat(), baseline.toFloat(), timePaint)
                    textPaint.color = when (entry.level) {
                        AppLog.Level.WARN -> 0xFFEF6C00.toInt()
                        AppLog.Level.ERROR -> 0xFFD32F2F.toInt()
                        else -> 0xFF000000.toInt()
                    }
                    // 右侧留出滚动条的位置
                    val text = TextUtils.ellipsize(
                        entry.text,
                        textPaint,
                        (width - dp(42) - dp(16)).toFloat(),
                        TextUtils.TruncateAt.END
                    ).toString()
                    canvas.drawText(text, dp(42).toFloat(), baseline.toFloat(), textPaint)
                    baseline += dp(LOG_PANEL_ROW_DP)
                }

                drawScrollBar(canvas, stripTop, capacity)
                drawResizeGrip(canvas)

                canvas.drawLine(
                    dp(4).toFloat(), stripTop.toFloat(),
                    (width - dp(4)).toFloat(), stripTop.toFloat(),
                    dividerPaint
                )
            }

            // 把手条：箭头永远在最左边；展开/折叠文字完全一样，只有矩形长度不同
            headerPaint.color = if (expanded && scrollLines > 0) 0xFFEF6C00.toInt() else 0xFF888888.toInt()
            canvas.drawText(stripText(), dp(24).toFloat(), (stripTop + dp(19)).toFloat(), headerPaint)
            headerPaint.color = 0xFF888888.toInt()

            val cx = dp(13).toFloat()
            val cy = (stripTop + dp(15)).toFloat()
            trianglePath.reset()
            if (expanded) {
                // 向下 = 点击折叠
                trianglePath.moveTo(cx - dp(6), cy - dp(4))
                trianglePath.lineTo(cx + dp(6), cy - dp(4))
                trianglePath.lineTo(cx, cy + dp(5))
            } else {
                // 向上 = 点击展开
                trianglePath.moveTo(cx, cy - dp(5))
                trianglePath.lineTo(cx - dp(6), cy + dp(4))
                trianglePath.lineTo(cx + dp(6), cy + dp(4))
            }
            trianglePath.close()
            canvas.drawPath(trianglePath, trianglePaint)
        }

        /** 终端式滚动条：显示当前窗口在全部日志里的位置 */
        private fun drawScrollBar(canvas: Canvas, stripTop: Int, capacity: Int) {
            if (entries.size <= capacity) return

            val trackTop = dp(LOG_PANEL_ROWS_TOP_DP)
            val trackBottom = stripTop - dp(3)
            val trackHeight = (trackBottom - trackTop).toFloat()
            if (trackHeight <= 0f) return

            val x = (width - dp(7)).toFloat()
            val barWidth = dp(3).toFloat()
            canvas.drawRect(x, trackTop.toFloat(), x + barWidth, trackBottom.toFloat(), scrollTrackPaint)

            val total = entries.size
            val end = (total - scrollLines).coerceIn(0, total)
            val start = (end - capacity).coerceAtLeast(0)
            val thumbHeight = maxOf(dp(10).toFloat(), trackHeight * capacity / total)
            val thumbTop = trackTop + trackHeight * start / total
            canvas.drawRect(x, thumbTop, x + barWidth, thumbTop + thumbHeight, scrollThumbPaint)
        }

        /** 右上角拖拽手柄（三条斜线） */
        private fun drawResizeGrip(canvas: Canvas) {
            gripPaint.strokeWidth = dp(1).toFloat()
            val right = (width - dp(3)).toFloat()
            val top = dp(3).toFloat()
            for (i in 0 until 3) {
                val offset = dp(i * 4).toFloat()
                canvas.drawLine(right - dp(10) + offset, top, right, top + dp(10) - offset, gripPaint)
            }
        }

        // ─── 触摸 ────────────────────────────────────────────────────

        override fun onTouchEvent(event: android.view.MotionEvent): Boolean {
            when (event.action) {
                android.view.MotionEvent.ACTION_DOWN -> {
                    downTime = event.eventTime
                    downY = event.y
                    lastY = event.y
                    dragging = false
                    // 右上角是缩放热区
                    resizing = expanded &&
                        event.x >= width - dp(LOG_PANEL_RESIZE_ZONE_DP) &&
                        event.y <= dp(LOG_PANEL_RESIZE_ZONE_DP)
                    parent?.requestDisallowInterceptTouchEvent(true)
                }
                android.view.MotionEvent.ACTION_MOVE -> {
                    if (resizing) {
                        applyResize(event)
                    } else {
                        if (!dragging && kotlin.math.abs(event.y - downY) > touchSlop) dragging = true
                        if (dragging && expanded) {
                            val pitch = rowPitchPx()
                            val lines = ((event.y - lastY) / pitch).toInt()
                            if (lines != 0) {
                                scrollLines = (scrollLines + lines).coerceIn(0, maxScrollLines())
                                lastY += lines * pitch
                                invalidate()
                            }
                        }
                    }
                }
                android.view.MotionEvent.ACTION_UP -> {
                    parent?.requestDisallowInterceptTouchEvent(false)
                    if (!resizing && !dragging) {
                        if (event.eventTime - downTime >= android.view.ViewConfiguration.getLongPressTimeout()) {
                            AppLog.clear()
                            scrollLines = 0
                        } else if (event.y >= height - dp(LOG_PANEL_STRIP_DP)) {
                            // 只有把手条切换展开/折叠，点日志行不会把它收起来
                            expanded = !expanded
                            AppLog.panelExpanded = expanded
                            if (!expanded) scrollLines = 0
                            requestLayout()
                            invalidate()
                        }
                    }
                    dragging = false
                    resizing = false
                }
                android.view.MotionEvent.ACTION_CANCEL -> {
                    parent?.requestDisallowInterceptTouchEvent(false)
                    dragging = false
                    resizing = false
                }
            }
            return true
        }

        /** 拖右上角改宽高：左下角固定，所以宽取到左边缘的距离、高取到底边的距离 */
        private fun applyResize(event: android.view.MotionEvent) {
            getLocationOnScreen(locationOnScreen)
            val left = locationOnScreen[0].toFloat()
            val bottom = locationOnScreen[1].toFloat() + height

            val newWidth = (event.rawX - left).toInt().coerceIn(minPanelWidth(), maxPanelWidth())
            val fixedHeight = dp(LOG_PANEL_STRIP_DP + LOG_PANEL_ROWS_TOP_DP) + 1
            val newRows = (((bottom - event.rawY).toInt() - fixedHeight) / dp(LOG_PANEL_ROW_DP))
                .coerceIn(LOG_PANEL_MIN_ROWS, maxRowCapacity())

            if (newWidth == customWidthPx && newRows == visibleRows) return

            customWidthPx = newWidth
            visibleRows = newRows
            AppLog.panelWidthDp = (newWidth / resources.displayMetrics.density).toInt()
            AppLog.panelRows = newRows
            scrollLines = scrollLines.coerceIn(0, maxScrollLines())
            requestLayout()
            invalidate()
        }

        private fun dp(px: Int): Int = (px * context.resources.displayMetrics.density).toInt()
    }

    // ─── Local Settings Panel (top-left) ───────────────────────────

    inner class LocalSettingsPanel @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private var hasTarget = false
        private var onClickListener: ((String) -> Unit)? = null
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xF5FFFFFF.toInt(); style = Paint.Style.FILL
        }
        private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0x33000000.toInt(); style = Paint.Style.STROKE; strokeWidth = 1f
        }
        private val headerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF888888.toInt(); textSize = 26f
        }
        private val dividerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x22000000 }
        private val rowBgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x0D000000 }
        private val rowIconPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val rowTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF000000.toInt(); textSize = 28f
        }
        // 标题行最右边的「退出登录」
        private val logoutPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFE53935.toInt(); textSize = 28f; textAlign = Paint.Align.RIGHT
        }

        init { setWillNotDraw(false) }

        fun setOnClickListener(listener: (String) -> Unit) { onClickListener = listener }
        fun setHasTarget(has: Boolean) { hasTarget = has; invalidate() }

        /** 「退出登录」文字的左边界，绘制和点击热区共用 */
        private fun logoutLeft(): Float =
            width - dp(10) - logoutPaint.measureText(LOGOUT_LABEL) - dp(6)

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            // 标题行(dp(30)) + 分隔线(dp(2)) + 2行内容(dp(24)每行) + padding(dp(8))
            val contentHeight = dp(30) + dp(2) + (dp(24) * 2) + dp(8)
            setMeasuredDimension(dp(130), contentHeight)
        }

        override fun onDraw(canvas: Canvas) {
            // solid background + border
            canvas.drawRoundRect(0f, 0f, width.toFloat(), height.toFloat(), dp(10).toFloat(), dp(10).toFloat(), bgPaint)
            canvas.drawRoundRect(0f, 0f, width.toFloat(), height.toFloat(), dp(10).toFloat(), dp(10).toFloat(), borderPaint)

            // header：左边「本地」，同一行最右边「退出登录」
            canvas.drawText("本地", dp(10).toFloat(), dp(20).toFloat(), headerPaint)
            canvas.drawText(LOGOUT_LABEL, (width - dp(10)).toFloat(), dp(20).toFloat(), logoutPaint)
            canvas.drawLine(dp(4).toFloat(), dp(30).toFloat(), (width - dp(4)).toFloat(), dp(30).toFloat(), dividerPaint)

            // rows at y=36, 60 (24dp spacing)
            val rowY1 = dp(36)
            val rowY2 = dp(60)

            // 我的位置 row
            canvas.drawRect(dp(4).toFloat(), rowY1.toFloat() - dp(3), (width - dp(4)).toFloat(), (rowY1 + dp(20)).toFloat(), rowBgPaint)
            rowIconPaint.color = 0xFFFFD700.toInt()
            canvas.drawText("⬡", dp(10).toFloat(), (rowY1 + dp(13)).toFloat(), rowIconPaint)
            canvas.drawText("我的位置", dp(28).toFloat(), (rowY1 + dp(13)).toFloat(), rowTextPaint)

            // 我的目标 row
            canvas.drawRect(dp(4).toFloat(), rowY2.toFloat() - dp(3), (width - dp(4)).toFloat(), (rowY2 + dp(20)).toFloat(), rowBgPaint)
            rowIconPaint.color = if (hasTarget) 0xFFFF9800.toInt() else 0xFF2196F3.toInt()
            canvas.drawText("◎", dp(10).toFloat(), (rowY2 + dp(13)).toFloat(), rowIconPaint)
            rowTextPaint.color = if (hasTarget) 0xFFFF9800.toInt() else 0xFF2196F3.toInt()
            canvas.drawText(if (hasTarget) "取消目标" else "设目标", dp(28).toFloat(), (rowY2 + dp(13)).toFloat(), rowTextPaint)
            rowTextPaint.color = 0xFF000000.toInt()
        }

        override fun onTouchEvent(event: android.view.MotionEvent): Boolean {
            if (event.action == android.view.MotionEvent.ACTION_UP) {
                parent?.requestDisallowInterceptTouchEvent(true)
                val x = event.x
                val y = event.y
                val rowY1 = dp(36)
                val rowY2 = dp(60)
                when {
                    // 标题行右侧那块就是退出登录
                    y <= dp(30) && x >= logoutLeft() -> onClickListener?.invoke("logout")
                    y >= (rowY1 - dp(3)) && y <= (rowY1 + dp(20)) -> onClickListener?.invoke("location")
                    y >= (rowY2 - dp(3)) && y <= (rowY2 + dp(20)) -> onClickListener?.invoke("target")
                }
            }
            return true
        }

        private fun dp(px: Int): Int = (px * context.resources.displayMetrics.density).toInt()
    }

    // ─── User List Panel (top-right) ─────────────────────────────────

    inner class UserListPanel @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private var users: List<User> = emptyList()
        private var selfUsername: String = ""
        private var onClickListener: ((String, User) -> Unit)? = null
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xF0FFFFFF.toInt(); style = Paint.Style.FILL
        }
        private val headerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF888888.toInt(); textSize = 28f
        }
        private val dividerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x33000000 }
        private val rowBgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x11000000 }
        private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val namePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF000000.toInt(); textSize = 28f
        }
        private val targetPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xCCAAAAAA.toInt(); textSize = 26f
        }
        private val targetActivePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFF9800.toInt(); textSize = 26f
        }
        private val scrollPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0x33000000; strokeWidth = 1f
        }
        private val colors = listOf(
            0xFF2196F3.toInt(), 0xFF9C27B0.toInt(), 0xFF00BCD4.toInt(),
            0xFFE91E63.toInt(), 0xFF00BCD4.toInt(), 0xFFFF9800.toInt(),
            0xFF795548.toInt(), 0xFF9E9E9E.toInt()
        )

        init { setWillNotDraw(false) }

        fun updateUsers(list: List<User>) { users = list; requestLayout(); invalidate() }
        fun setOnClickListener(listener: (String, User) -> Unit) { onClickListener = listener }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            // 标题区(dp(32)) + 分隔线(dp(4)) + 用户行(n * dp(24)) + 底边距(dp(4))
            val totalHeight = dp(32) + dp(4) + users.size * dp(24) + dp(4)
            setMeasuredDimension(dp(120), totalHeight)
        }

        override fun onDraw(canvas: Canvas) {
            canvas.drawRoundRect(0f, 0f, width.toFloat(), height.toFloat(), dp(10).toFloat(), dp(10).toFloat(), bgPaint)
            canvas.drawText("同服人数：${users.size}", dp(8).toFloat(), dp(22).toFloat(), headerPaint)
            canvas.drawLine(dp(4).toFloat(), dp(32).toFloat(), (width - dp(4)).toFloat(), dp(32).toFloat(), dividerPaint)

            var y = dp(38)
            for (user in users) {
                val color = colors[Math.abs(user.username.hashCode()) % colors.size]
                val hasTarget = user.targetLat != null
                val name = user.nickname ?: user.username
                drawRow(canvas, name, color, hasTarget, y)
                y += dp(24)
            }
        }

        private fun drawRow(canvas: Canvas, name: String, color: Int, hasTarget: Boolean, y: Int) {
            // bg
            canvas.drawRect(dp(3).toFloat(), (y - dp(3)).toFloat(), (width - dp(3)).toFloat(), (y + dp(20)).toFloat(), rowBgPaint)
            // dot
            dotPaint.color = color
            canvas.drawCircle(dp(12).toFloat(), (y + dp(9)).toFloat(), dp(4).toFloat(), dotPaint)
            // name
            namePaint.color = 0xFF000000.toInt()
            namePaint.textSize = 24f
            canvas.drawText(name, dp(22).toFloat(), (y + dp(14)).toFloat(), namePaint)
            // target icon (right side, only if has target)
            if (hasTarget) {
                targetActivePaint.textSize = 22f
                canvas.drawText("⊕", (width - dp(16)).toFloat(), (y + dp(14)).toFloat(), targetActivePaint)
            }
        }

        override fun onTouchEvent(event: android.view.MotionEvent): Boolean {
            if (event.action == android.view.MotionEvent.ACTION_UP) {
                parent?.requestDisallowInterceptTouchEvent(true)
                val y = event.y
                var rowY = dp(38)
                for (user in users) {
                    if (y >= (rowY - dp(3)) && y <= (rowY + dp(20))) {
                        val x = event.x
                        android.util.Log.d("MapDebug", "UserListPanel click: user=${user.username} x=$x width=${width} targetLat=${user.targetLat}")
                        if (x < width / 2) {
                            android.util.Log.d("MapDebug", "  -> action=user, fly to ${user.lat},${user.lng}")
                            onClickListener?.invoke("user", user)
                        } else if (user.targetLat != null && user.targetLat != 0.0) {
                            android.util.Log.d("MapDebug", "  -> action=target, fly to target ${user.targetLat},${user.targetLng}")
                            onClickListener?.invoke("target", user)
                        } else {
                            android.util.Log.d("MapDebug", "  -> fallback, fly to ${user.lat},${user.lng}")
                            onClickListener?.invoke("user", user)
                        }
                        break
                    }
                    rowY += dp(24)
                }
            }
            return true
        }

        private fun dp(px: Int): Int = (px * context.resources.displayMetrics.density).toInt()
    }
}
