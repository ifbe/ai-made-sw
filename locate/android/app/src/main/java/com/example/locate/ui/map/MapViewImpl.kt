package com.example.locate.ui.map

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import com.example.locate.domain.model.User
import kotlin.math.cos
import kotlin.math.ln
import kotlin.math.pow
import kotlin.math.tan

/**
 * Hybrid Map Implementation:
 * - WebView renders Leaflet map tiles (base layer)
 * - Native Android views render markers, arrows, target lines (overlay)
 */
class MapViewImpl @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : FrameLayout(context, attrs, defStyleAttr), MapView {

    private val webView: WebView
    private val overlay: FrameLayout
    private val markerViews = mutableMapOf<String, MarkerView>()
    private var myMarker: MarkerView? = null
    private var myTargetMarker: MarkerView? = null
    private var myTargetLineView: TargetLineView? = null

    private var clickListener: ((Double, Double) -> Unit)? = null
    private var mapViewWidth = 0      // physical pixels from JS
    private var mapViewHeight = 0    // physical pixels from JS
    private var currentZoom = 15.0
    private var currentCenterLat = 0.0
    private var currentCenterLng = 0.0
    private var crosshairView: CrosshairView? = null
    private var cornerCoordsView: CornerCoordsView? = null

    private val pendingPositions = mutableMapOf<String, PendingUpdate>()

    private data class PendingUpdate(val lat: Double, val lng: Double, val heading: Float = 0f)

    init {
        // dpr = context.resources.displayMetrics.density  // removed, using CSS pixels directly

        webView = WebView(context).apply {
            setLayerType(View.LAYER_TYPE_SOFTWARE, null)
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

        // 调试：固定用户标记（固定在十字线上方30px）
        val debugLp = FrameLayout.LayoutParams(80, 80).apply {
            leftMargin = (375 / 2 - 40)  // CSS pixels
            topMargin = (778 / 2 - 40 - 30)
        }
        val debugUser = MarkerView(context)
        overlay.addView(debugUser, debugLp)
        debugUser.update(0.0, 0.0, 0f, isSelf = true, isTarget = false)

        android.util.Log.d("MapDebug", "Overlay ready, debug marker at ${debugLp.leftMargin},${debugLp.topMargin}")

        webView.addJavascriptInterface(JsInterface(), "Android")
        webView.loadUrl("file:///android_asset/html/map.html")

        // 定时轮询地图中心（每500ms），解决后台时 evaluateJavascript 不执行的问题
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(object : Runnable {
            override fun run() {
                postJs("MapInterface.getCenterAndZoom()")
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(this, 500)
            }
        }, 500)
    }

    private fun getScreenWidth(): Int = context.resources.displayMetrics.widthPixels
    private fun getScreenHeight(): Int = context.resources.displayMetrics.heightPixels

    fun getView(): View = this

    // ─── MapView interface ───────────────────────────────────────────

    override fun showUser(lat: Double, lng: Double, heading: Float) {
        android.util.Log.d("MapDebug", "showUser: lat=$lat lng=$lng heading=$heading mapCenter=($currentCenterLat,$currentCenterLng) zoom=$currentZoom")
        pendingPositions["__self__"] = PendingUpdate(lat, lng, heading)
        if (myMarker == null) {
            myMarker = MarkerView(context)
            overlay.addView(myMarker, FrameLayout.LayoutParams(80, 80))
        }
        // 立即计算位置，不依赖 pending 刷新
        updateMarkerPosition(myMarker!!, lat, lng, heading, isSelf = true)
    }

    override fun showOtherUser(user: User) {
        pendingPositions[user.username] = PendingUpdate(user.lat, user.lng, user.heading)
        if (markerViews[user.username] == null) {
            markerViews[user.username] = MarkerView(context)
            overlay.addView(markerViews[user.username], FrameLayout.LayoutParams(80, 80))
        }
        updateMarkerPosition(markerViews[user.username]!!, user.lat, user.lng, user.heading, isSelf = false)
    }

    override fun removeOtherUser(username: String) {
        pendingPositions.remove(username)
        markerViews[username]?.let {
            overlay.removeView(it)
            markerViews.remove(username)
        }
    }

    override fun showOtherUsers(users: List<User>) {
        val usernames = users.map { it.username }.toSet()
        markerViews.keys.toList().forEach { name ->
            if (name !in usernames) removeOtherUser(name)
        }
        users.forEach { showOtherUser(it) }
    }

    override fun showTarget(lat: Double, lng: Double) {
        pendingPositions["__myTarget__"] = PendingUpdate(lat, lng)
        if (myTargetMarker == null) {
            myTargetMarker = MarkerView(context)
            overlay.addView(myTargetMarker, FrameLayout.LayoutParams(60, 30))
        }
        updateMarkerPosition(myTargetMarker!!, lat, lng, 0f, isTarget = true)
    }

    override fun clearTarget() {
        pendingPositions.remove("__myTarget__")
        myTargetMarker?.let {
            overlay.removeView(it)
            myTargetMarker = null
        }
        myTargetLineView?.let {
            overlay.removeView(it)
            myTargetLineView = null
        }
    }

    override fun moveTo(lat: Double, lng: Double, zoom: Double) {
        postJs("MapInterface.moveTo($lat, $lng, $zoom)")
    }

    override fun setOnMapClickListener(listener: (Double, Double) -> Unit) {
        clickListener = listener
    }

    override fun onDestroy() {
        webView.destroy()
    }

    // ─── Position conversion ──────────────────────────────────────────
    // JS reports CSS pixel dimensions, but Android uses physical pixels.
    // We multiply by dpr to get physical pixels for layout.

    private fun latLngToScreen(lat: Double, lng: Double): Pair<Float, Float>? {
        if (mapViewWidth == 0 || mapViewHeight == 0) {
            android.util.Log.d("MapDebug", "latLngToScreen: size not ready $mapViewWidth x $mapViewHeight")
            return null
        }
        val scale = 256.0 * 2.0.pow(currentZoom)
        val worldX = (lng + 180.0) / 360.0 * scale
        val centerWorldX = (currentCenterLng + 180.0) / 360.0 * scale
        val latRad = Math.toRadians(lat)
        val centerLatRad = Math.toRadians(currentCenterLat)
        val worldY = (0.5 - ln(tan(latRad) + 1.0 / cos(latRad)) / (2.0 * Math.PI)) * scale * 0.5
        val centerWorldY = (0.5 - ln(tan(centerLatRad) + 1.0 / cos(centerLatRad)) / (2.0 * Math.PI)) * scale * 0.5
        // mapViewWidth/Height from JS are already in physical pixels
        val x = (worldX - centerWorldX + mapViewWidth / 2.0).toFloat()
        val y = (worldY - centerWorldY + mapViewHeight / 2.0).toFloat()
        return Pair(x, y)
    }

    private fun updateMarkerPosition(view: MarkerView, lat: Double, lng: Double, heading: Float, isSelf: Boolean = false, isTarget: Boolean = false) {
        val pos = latLngToScreen(lat, lng)
        android.util.Log.d("MapDebug", "updateMarker: lat=$lat lng=$lng => $pos")
        pos?.let { (x, y) ->
            val size = if (isTarget) 60 else 80
            val h = if (isTarget) 30 else size
            view.layoutParams = LayoutParams(size, h).apply {
                leftMargin = (x - size / 2).toInt()
                topMargin = (y - h / 2).toInt()
            }
            view.update(lat, lng, heading, isSelf, isTarget)
            view.requestLayout()

            if (isSelf && !isTarget) {
                val targetPos = pendingPositions["__myTarget__"]
                if (targetPos != null) {
                    val targetScreen = latLngToScreen(targetPos.lat, targetPos.lng)
                    if (targetScreen != null) {
                        if (myTargetLineView == null) {
                            myTargetLineView = TargetLineView(context).also {
                                overlay.addView(it, 0)
                            }
                        }
                        myTargetLineView?.setLine(x, y, targetScreen.first, targetScreen.second)
                    }
                }
            }
        }
    }

    private fun refreshAllMarkers() {
        android.util.Log.d("MapDebug", "refreshAllMarkers: pending=${pendingPositions.size}")
        pendingPositions.forEach { (key, update) ->
            when (key) {
                "__self__" -> myMarker?.let { updateMarkerPosition(it, update.lat, update.lng, update.heading, isSelf = true) }
                "__myTarget__" -> myTargetMarker?.let { updateMarkerPosition(it, update.lat, update.lng, 0f, isTarget = true) }
                else -> markerViews[key]?.let { updateMarkerPosition(it, update.lat, update.lng, update.heading) }
            }
        }
    }

    private fun requestCenterAndZoom() {
        postJs("MapInterface.getCenterAndZoom()")
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun postJs(code: String) {
        webView.post { webView.evaluateJavascript(code, null) }
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
            android.util.Log.d("MapDebug", "Map ready")
            postJs("MapInterface.getCenterAndZoom()")
        }

        @JavascriptInterface
        fun onCenterAndZoom(zoom: Double, centerLat: Double, centerLng: Double, cssWidth: Int, cssHeight: Int) {
            val wasInitialized = mapViewWidth > 0 && mapViewHeight > 0
            // JS reports CSS pixels; Android needs physical pixels
            mapViewWidth = cssWidth
            mapViewHeight = cssHeight
            currentZoom = zoom
            currentCenterLat = centerLat
            currentCenterLng = centerLng
            android.util.Log.d("MapDebug", "onCenterAndZoom: zoom=$zoom center=($centerLat,$centerLng) css=${cssWidth}x${cssHeight} phys=${mapViewWidth}x${mapViewHeight} pending=${pendingPositions.size}")
            // 确保在 UI 线程执行 layout 和 invalidate
            post {
                crosshairView?.invalidate()
                cornerCoordsView?.invalidate()
                refreshAllMarkers()
            }
            if (!wasInitialized && cssWidth > 0 && cssHeight > 0) {
                android.util.Log.d("MapDebug", "First map ready, triggering callback")
                onFirstMapReady?.invoke()
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
        // Same formula as latLngToScreen for worldY
        private fun cornerLat(dy: Double): Double {
            val scale = 256.0 * 2.0.pow(currentZoom)
            // Use SAME formula as latLngToScreen for worldY:
            // worldY/halfScale = 0.5 - ln(tan(latRad) + 1/cos(latRad)) / (2π)
            val centerLatRad = Math.toRadians(currentCenterLat)
            val centerWorldY = (0.5 - ln(tan(centerLatRad) + 1.0 / cos(centerLatRad)) / (2.0 * Math.PI)) * scale * 0.5
            val worldY = centerWorldY - dy
            val worldYFrac = worldY / (scale * 0.5)
            // Inverse: lat = 2*atan(exp(π*(1-2*worldYFrac))) - π/2  (same as latLngToScreen inverse)
            val latRad = 2.0 * kotlin.math.atan(kotlin.math.exp(Math.PI * (1.0 - 2.0 * worldYFrac))) - Math.PI / 2.0
            return Math.toDegrees(latRad)
        }

        private fun cornerLng(dx: Double): Double {
            val scale = 256.0 * 2.0.pow(currentZoom)
            val centerWorldX = (currentCenterLng + 180.0) / 360.0 * scale
            val worldX = centerWorldX + dx
            return worldX / scale * 360.0 - 180.0
        }

        private fun fmt(v: Double) = String.format("%.4f", v)
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
            textSize = 28f
            textAlign = Paint.Align.CENTER
        }
        override fun onDraw(canvas: Canvas) {
            val cx = width / 2f
            val cy = height / 2f
            val size = 40f
            // 十字线
            canvas.drawLine(cx - size, cy, cx + size, cy, paint)
            canvas.drawLine(cx, cy - size, cx, cy + size, paint)
            canvas.drawCircle(cx, cy, 8f, paint)
            // 坐标文字（在十字线上方）
            val coordText = String.format("%.4f, %.4f", currentCenterLat, currentCenterLng)
            canvas.drawText(coordText, cx, cy - size - 8, textPaint)
        }
    }

    // ─── Marker View ─────────────────────────────────────────────────

    // ─── Marker View ─────────────────────────────────────────────────

    inner class MarkerView @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private var label: String = ""
        private var heading: Float = 0f
        private var isSelf: Boolean = false
        private var isTarget: Boolean = false
        private var markerLat: Double = 0.0
        private var markerLng: Double = 0.0
        private val arrowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val coordTextPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val arrowPath = Path()

        init { setWillNotDraw(false) }

        fun update(lat: Double, lng: Double, heading: Float = 0f, isSelf: Boolean = false, isTarget: Boolean = false) {
            android.util.Log.d("MapDebug", "MarkerView.update: isSelf=$isSelf isTarget=$isTarget size=${width}x${height} lat=$lat lng=$lng")
            this.label = if (isTarget) "🎯" else if (isSelf) "我" else (markerViews.entries.find { it.value == this }?.key ?: "")
            this.heading = heading
            this.isSelf = isSelf
            this.isTarget = isTarget
            this.markerLat = lat
            this.markerLng = lng
            invalidate()
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            setMeasuredDimension(80, 80)
        }

        override fun onDraw(canvas: Canvas) {
            val w = width.toFloat()
            val h = height.toFloat()
            if (w <= 0 || h <= 0) return
            val cx = w / 2
            val cy = h / 2

            if (isTarget) {
                bgPaint.color = 0xFFFF9800.toInt()
                canvas.drawRoundRect(0f, 0f, w, h, 8f, 8f, bgPaint)
                textPaint.color = 0xFFFFFFFF.toInt()
                textPaint.textSize = h * 0.6f
                textPaint.textAlign = Paint.Align.CENTER
                canvas.drawText("🎯", cx, cy + textPaint.textSize / 3, textPaint)
                return
            }

            bgPaint.color = if (isSelf) 0xFFD4A500.toInt() else 0xFF1E6EB5.toInt()
            canvas.drawRoundRect(0f, 0f, w, h, 12f, 12f, bgPaint)
            textPaint.color = 0xFFFFFFFF.toInt()
            textPaint.textSize = h * 0.3f
            textPaint.textAlign = Paint.Align.CENTER
            canvas.drawText(label, cx, h * 0.35f, textPaint)

            canvas.save()
            canvas.rotate(heading, cx, cy + h * 0.15f)
            arrowPaint.color = if (isSelf) 0xFFFFDF7E.toInt() else 0xFF7EC8FF.toInt()
            arrowPath.reset()
            arrowPath.moveTo(cx, cy - h * 0.35f)
            arrowPath.lineTo(cx - w * 0.25f, cy + h * 0.1f)
            arrowPath.lineTo(cx + w * 0.25f, cy + h * 0.1f)
            arrowPath.close()
            canvas.drawPath(arrowPath, arrowPaint)
            canvas.restore()

            // 坐标文字显示在标记右上方（超出视图范围，clipChildren=false时可见）
            coordTextPaint.color = if (isSelf) 0xFFD4A500.toInt() else 0xFF1E6EB5.toInt()
            coordTextPaint.textSize = 20f
            coordTextPaint.textAlign = Paint.Align.LEFT
            val coordLine1 = String.format("%.4f", markerLat)
            val coordLine2 = String.format("%.4f", markerLng)
            // 绘制在视图右边缘外侧
            canvas.drawText(coordLine1, w + 4f, h * 0.35f, coordTextPaint)
            canvas.drawText(coordLine2, w + 4f, h * 0.55f, coordTextPaint)
        }
    }

    // ─── Target Line View ───────────────────────────────────────────

    inner class TargetLineView @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private var x1 = 0f; private var y1 = 0f; private var x2 = 0f; private var y2 = 0f
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xCCFF9800.toInt()
            strokeWidth = 6f
            style = Paint.Style.STROKE
            pathEffect = android.graphics.DashPathEffect(floatArrayOf(24f, 12f), 0f)
        }
        fun setLine(x1: Float, y1: Float, x2: Float, y2: Float) {
            this.x1 = x1; this.y1 = y1; this.x2 = x2; this.y2 = y2
            invalidate()
        }
        override fun onDraw(canvas: Canvas) {
            canvas.drawLine(x1, y1, x2, y2, paint)
        }
    }
}
