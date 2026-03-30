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
import org.json.JSONObject
import kotlin.math.pow
import kotlin.math.ln
import kotlin.math.tan
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.atan

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
    private var myServerMarker: MarkerView? = null  // 服务器广播回来的位置（调试用）
    private var myTargetLineView: TargetLineView? = null

    // 其他用户的 target 标记
    private val targetMarkers = mutableMapOf<String, MarkerView>()
    private val targetLines = mutableMapOf<String, TargetLineView>()

    private var clickListener: ((Double, Double) -> Unit)? = null
    private var mapViewWidth = 0      // physical pixels from JS
    private var mapViewHeight = 0    // physical pixels from JS
    private var currentZoom = 15.0
    private var currentCenterLat = 0.0
    private var currentCenterLng = 0.0
    private var crosshairView: CrosshairView? = null
    private var cornerCoordsView: CornerCoordsView? = null
    private var connectionStatusView: ConnectionStatusView? = null
    private var targetButtonView: TargetButtonView? = null
    private var targetButtonClickListener: ((Double, Double) -> Unit)? = null

    // 四角坐标（每次 onCenterAndZoom 时更新）
    private var cornerTopLeft: Pair<Double, Double>? = null    // (lat, lng)
    private var cornerTopRight: Pair<Double, Double>? = null   // (lat, lng)
    private var cornerBottomLeft: Pair<Double, Double>? = null // (lat, lng)
    private var cornerBottomRight: Pair<Double, Double>? = null // (lat, lng)

    private val pendingPositions = mutableMapOf<String, PendingUpdate>()

    private data class PendingUpdate(val lat: Double, val lng: Double, val heading: Float = 0f, val targetLat: Double? = null, val targetLng: Double? = null)

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

        // 连接状态图标（右上角）
        connectionStatusView = ConnectionStatusView(context)
        connectionStatusView?.setStatus(0)  // 初始=连接中(橙)
        android.util.Log.d("MapDebug", "Adding connectionStatusView to overlay")
        overlay.addView(connectionStatusView!!, FrameLayout.LayoutParams(72, 72).apply {
            gravity = android.view.Gravity.TOP or android.view.Gravity.END
            topMargin = 60
            marginEnd = 20
        })

        // 目标设置按钮（连接图标下方）
        targetButtonView = TargetButtonView(context)

        // 服务器位置标记（调试用，绿色和本地金色对比）
        myServerMarker = MarkerView(context)
        myServerMarker?.update(0.0, 0.0, 0f, isSelf = false, isServerPos = true)
        overlay.addView(myServerMarker, FrameLayout.LayoutParams(80, 100))
        targetButtonView?.setOnClickListener {
            android.util.Log.d("MapDebug", "TargetButton clicked, currentCenter=${currentCenterLat},${currentCenterLng}")
            targetButtonClickListener?.invoke(currentCenterLat, currentCenterLng)
        }
        overlay.addView(targetButtonView!!, FrameLayout.LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT).apply {
            gravity = android.view.Gravity.TOP or android.view.Gravity.END
            topMargin = 60 + 72 + 8
            marginEnd = 20
        })



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
            post { overlay.addView(myMarker, FrameLayout.LayoutParams(80, 100)) }
        }
        // 立即计算位置，不依赖 pending 刷新
        updateMarkerPosition(myMarker!!, lat, lng, heading, isSelf = true)
    }

    override fun showOtherUser(user: User) {
        android.util.Log.d("MapDebug", "showOtherUser: ${user.username} lat=${user.lat} lng=${user.lng} targetLat=${user.targetLat} existingMarker=${markerViews[user.username] != null}")
        pendingPositions[user.username] = PendingUpdate(user.lat, user.lng, user.heading, user.targetLat, user.targetLng)
        if (markerViews[user.username] == null) {
            android.util.Log.d("MapDebug", "Creating new MarkerView for ${user.username}")
            markerViews[user.username] = MarkerView(context)
            post { overlay.addView(markerViews[user.username], FrameLayout.LayoutParams(80, 100)) }
        }
        updateMarkerPosition(markerViews[user.username]!!, user.lat, user.lng, user.heading, isSelf = false)
        // 处理该用户的 target
        if (user.targetLat != null && user.targetLng != null) {
            if (targetMarkers[user.username] == null) {
                targetMarkers[user.username] = MarkerView(context)
                targetLines[user.username] = TargetLineView(context)
                post {
                    overlay.addView(targetMarkers[user.username], FrameLayout.LayoutParams(60, 30))
                    overlay.addView(targetLines[user.username], FrameLayout.LayoutParams(1, 1))
                }
            }
            updateMarkerPosition(targetMarkers[user.username]!!, user.targetLat, user.targetLng, 0f, isTarget = true)
            // 目标点和位置之间的连线等位置算出来再更新
            val marker = markerViews[user.username]
            if (marker != null) {
                latLngToScreen(user.lat, user.lng) { pos ->
                    if (pos != null) {
                        val px = pos.first
                        val py = pos.second
                        latLngToScreen(user.targetLat, user.targetLng) { targetPos ->
                            if (targetPos != null) {
                                post {
                                    targetLines[user.username]?.setLine(px, py, targetPos.first, targetPos.second)
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // 无 target 则移除
            targetMarkers[user.username]?.let { overlay.removeView(it) }
            targetMarkers.remove(user.username)
            targetLines[user.username]?.let { overlay.removeView(it) }
            targetLines.remove(user.username)
            // 清除 pendingPositions 中的 target 坐标，防止 refreshAllMarkers 再次画出旧位置
            pendingPositions[user.username] = pendingPositions[user.username]?.copy(targetLat = null, targetLng = null)
                ?: PendingUpdate(user.lat, user.lng, user.heading, null, null)
        }
    }

    override fun removeOtherUser(username: String) {
        android.util.Log.d("MapDebug", "removeOtherUser: $username")
        pendingPositions.remove(username)
        markerViews[username]?.let {
            overlay.removeView(it)
            markerViews.remove(username)
        }
        targetMarkers[username]?.let {
            overlay.removeView(it)
            targetMarkers.remove(username)
        }
        targetLines[username]?.let {
            overlay.removeView(it)
            targetLines.remove(username)
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

    override fun showServerPosition(lat: Double, lng: Double, heading: Float) {
        android.util.Log.d("MapDebug", "showServerPosition: lat=$lat lng=$lng heading=$heading")
        if (lat == 0.0 && lng == 0.0) return
        myServerMarker?.let { marker ->
            if (marker.parent != null) {
                android.util.Log.d("MapDebug", "showServerPosition: updating myServerMarker")
                updateMarkerPosition(marker, lat, lng, heading, isSelf = false, isServerPos = true)
            } else {
                android.util.Log.d("MapDebug", "showServerPosition: myServerMarker not in overlay yet")
            }
        } ?: android.util.Log.d("MapDebug", "showServerPosition: myServerMarker is null")
    }

    override fun setOnMapClickListener(listener: (Double, Double) -> Unit) {
        clickListener = listener
    }

    override fun setConnectionStatus(status: Int, onlineCount: Int) {
        post { connectionStatusView?.setStatus(status, onlineCount) }
    }

    override fun updateTargetButton(hasTarget: Boolean) {
        post { targetButtonView?.setHasTarget(hasTarget) }
    }

    override fun setOnTargetButtonClickListener(listener: (Double, Double) -> Unit) {
        targetButtonClickListener = listener
    }

    override fun onDestroy() {
        webView.destroy()
    }

    // ─── Position conversion ──────────────────────────────────────────
    // 用 Leaflet 原生 latLngToContainerPoint 做坐标转换

    private fun updateCorners() {
        if (mapViewWidth == 0 || mapViewHeight == 0) return
        android.util.Log.d("MapDebug", "updateCorners: css=${mapViewWidth}x${mapViewHeight}")
    }

    // 调用 Leaflet 的 latLngToContainerPoint 获取屏幕像素
    // WebView 方法必须在主线程调用，用 webView.post{}
    private fun latLngToScreen(lat: Double, lng: Double, callback: (Pair<Float, Float>?) -> Unit) {
        if (mapViewWidth == 0 || mapViewHeight == 0) {
            callback(null)
            return
        }
        val js = "MapInterface.latLngToScreen($lat, $lng)"
        webView.post {
            webView.evaluateJavascript(js) { result ->
            android.util.Log.d("MapDebug", "latLngToScreen JS result: $result")
            if (result == "null") {
                callback(null)
                return@evaluateJavascript
            }
            try {
                // result 格式: {"x":123.4,"y":567.8}
                val json = JSONObject(result)
                val x = json.getDouble("x").toFloat()
                val y = json.getDouble("y").toFloat()
                // Leaflet 返回的是 CSS 像素，需要转物理像素
                val dpr = context.resources.displayMetrics.density
                val physX = x * dpr
                val physY = y * dpr
                android.util.Log.d("MapDebug", "latLngToScreen: ($lat, $lng) => CSS($x,$y) phys($physX,$physY) dpr=$dpr")
                callback(Pair(physX, physY))
            } catch (e: Exception) {
                android.util.Log.d("MapDebug", "latLngToScreen parse error: $e")
                callback(null)
            }
        }
        }
    }

    private fun updateMarkerPosition(view: MarkerView, lat: Double, lng: Double, heading: Float, isSelf: Boolean = false, isTarget: Boolean = false, isServerPos: Boolean = false, key: String = "") {
        // 过滤无效 GPS 坐标
        if (lat == 0.0 && lng == 0.0) {
            android.util.Log.d("MapDebug", "updateMarker: skipped invalid (0,0)")
            return
        }
        latLngToScreen(lat, lng) { pos ->
            if (pos == null) {
                android.util.Log.d("MapDebug", "updateMarker: pos is null")
                return@latLngToScreen
            }
            val (x, y) = pos
            android.util.Log.d("MapDebug", "updateMarker: lat=$lat lng=$lng => ($x, $y)")
            val size = if (isTarget) 60 else 80
            val h = if (isTarget) 30 else if (isServerPos) 100 else size
            post {
                view.layoutParams = LayoutParams(size, h).apply {
                    leftMargin = (x - size / 2).toInt()
                    topMargin = (y - h / 2).toInt()
                }
                view.update(lat, lng, heading, isSelf, isTarget, isServerPos)
                view.requestLayout()
            }

            if (isSelf && !isTarget) {
                val targetPos = pendingPositions["__myTarget__"]
                if (targetPos != null) {
                    latLngToScreen(targetPos.lat, targetPos.lng) { targetScreen ->
                        if (targetScreen != null) {
                            post {
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
            } else if (!isTarget && key.isNotEmpty()) {
                // 其他用户的 target 连线
                val userPending = pendingPositions[key]
                if (userPending?.targetLat != null && userPending.targetLng != null) {
                    val tx = x
                    val ty = y
                    latLngToScreen(userPending.targetLat, userPending.targetLng) { targetScreen ->
                        if (targetScreen != null) {
                            post {
                                targetLines[key]?.setLine(tx, ty, targetScreen.first, targetScreen.second)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun refreshAllMarkers() {
        android.util.Log.d("MapDebug", "refreshAllMarkers: pending=${pendingPositions.size} markers=${markerViews.size} targets=${targetMarkers.size}")
        pendingPositions.forEach { (key, update) ->
            when (key) {
                "__self__" -> myMarker?.let { updateMarkerPosition(it, update.lat, update.lng, update.heading, isSelf = true) }
                "__myTarget__" -> myTargetMarker?.let { updateMarkerPosition(it, update.lat, update.lng, 0f, isTarget = true) }
                else -> {
                    markerViews[key]?.let { updateMarkerPosition(it, update.lat, update.lng, update.heading, isSelf = false, key = key) }
                    // 该用户有 target 时刷新 target 标记和连线
                    if (update.targetLat != null && update.targetLng != null) {
                        if (targetMarkers[key] == null) {
                            targetMarkers[key] = MarkerView(context)
                            targetLines[key] = TargetLineView(context)
                            post {
                                overlay.addView(targetMarkers[key], FrameLayout.LayoutParams(60, 30))
                                overlay.addView(targetLines[key], FrameLayout.LayoutParams(1, 1))
                            }
                        }
                        targetMarkers[key]?.let { updateMarkerPosition(it, update.targetLat, update.targetLng, 0f, isTarget = true) }
                    } else {
                        // 无 target 则移除
                        targetMarkers[key]?.let { overlay.removeView(it) }
                        targetMarkers.remove(key)
                        targetLines[key]?.let { overlay.removeView(it) }
                        targetLines.remove(key)
                    }
                }
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
            // 保持 CSS 像素原始值，用于 Mercator 投影计算
            mapViewWidth = cssWidth
            mapViewHeight = cssHeight
            currentZoom = zoom
            currentCenterLat = centerLat
            currentCenterLng = centerLng
            android.util.Log.d("MapDebug", "onCenterAndZoom: zoom=$zoom center=($centerLat,$centerLng) css=${cssWidth}x${cssHeight} pending=${pendingPositions.size}")
            // 确保在 UI 线程执行 layout 和 invalidate
            post {
                updateCorners()
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

            // Debug: 屏幕尺寸（顶部居中）
            val debugText = "屏幕:${w.toInt()}x${h.toInt()}"
            val debugPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = 0xFF00AA00.toInt()
                textSize = 20f
            }
            val debugBgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = 0xBB000000.toInt()
            }
            val debugX = w / 2
            val debugY = 20f
            val debugW = debugPaint.measureText(debugText)
            val debugH = 28f
            canvas.drawRoundRect(debugX - debugW / 2 - 8f, debugY - debugH + 4f, debugX + debugW / 2 + 8f, debugY + 4f, 8f, 8f, debugBgPaint)
            debugPaint.textAlign = Paint.Align.CENTER
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
        // Same formula as latLngToScreen for worldY
        private fun cornerLat(dy: Double): Double {
            val scale = 256.0 * 2.0.pow(currentZoom)
            // Use SAME formula as latLngToScreen for worldY:
            // worldY/halfScale = 0.5 - ln(tan(latRad) + 1/cos(latRad)) / (2π)
            val centerLatRad = Math.toRadians(currentCenterLat)
            val centerWorldY = (0.5 - kotlin.math.ln(kotlin.math.tan(centerLatRad) + 1.0 / kotlin.math.cos(centerLatRad)) / (2.0 * Math.PI)) * scale * 0.5
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
        private var isServerPos: Boolean = false
        private var markerLat: Double = 0.0
        private var markerLng: Double = 0.0
        private val arrowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val coordTextPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val arrowPath = Path()

        init { setWillNotDraw(false) }

        fun update(lat: Double, lng: Double, heading: Float = 0f, isSelf: Boolean = false, isTarget: Boolean = false, isServerPos: Boolean = false) {
            android.util.Log.d("MapDebug", "MarkerView.update: isSelf=$isSelf isTarget=$isTarget isServerPos=$isServerPos size=${width}x${height} lat=$lat lng=$lng")
            this.label = if (isTarget) "🎯" else if (isSelf) "我" else if (isServerPos) "云" else (markerViews.entries.find { it.value == this }?.key ?: "")
            this.heading = heading
            this.isSelf = isSelf
            this.isTarget = isTarget
            this.isServerPos = isServerPos
            this.markerLat = lat
            this.markerLng = lng
            invalidate()
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            setMeasuredDimension(80, 100)
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
                canvas.drawText("T", cx, cy + textPaint.textSize / 3, textPaint)
                return
            }

            // 箭头"↑"，旋转角度=heading（0°指北，顺时针）
            canvas.save()
            canvas.rotate(heading, cx, cy)
            textPaint.color = when {
                isServerPos -> 0xFF4CAF50.toInt()  // 绿色-服务器位置
                isSelf -> 0xFFFFD700.toInt()        // 金色-自己本地GPS
                else -> 0xFF2196F3.toInt()           // 蓝色-队友
            }
            textPaint.textSize = h * 0.8f
            textPaint.textAlign = Paint.Align.CENTER
            canvas.drawText("↑", cx, cy + textPaint.textSize / 3, textPaint)
            canvas.restore()

            // 昵称（箭头下方）
            if (label.isNotEmpty()) {
                textPaint.color = 0xFFFFFFFF.toInt()
                textPaint.textSize = 18f
                textPaint.textAlign = Paint.Align.CENTER
                canvas.drawText(label, cx, h + 20f, textPaint)
            }
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

    // ─── Connection Status Icon ───────────────────────────────────────

    inner class ConnectionStatusView @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        // 0=连接中(橙), 1=已连接(绿), 2=断开(红)
        private var status = 2
        private var onlineCount = 0
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
        private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = 3f
            color = 0x99FFFFFF.toInt()
        }
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFFFFFF.toInt()
            textAlign = Paint.Align.CENTER
        }
        private val warnPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFFFFFF.toInt()
            textAlign = Paint.Align.CENTER
            isFakeBoldText = true
        }

        init { setWillNotDraw(false) }

        fun setStatus(s: Int, count: Int = 0) {
            status = s
            onlineCount = count
            invalidate()
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            setMeasuredDimension(72, 72)
        }

        override fun onDraw(canvas: Canvas) {
            val cx = width / 2f
            val cy = height / 2f
            val radius = 34f

            paint.color = when (status) {
                0 -> 0xFFFF9800.toInt()  // 橙色-连接中
                1 -> 0xFF4CAF50.toInt() // 绿色-已连接
                else -> 0xFFF44336.toInt() // 红色-断开
            }
            canvas.drawCircle(cx, cy, radius, paint)
            canvas.drawCircle(cx, cy, radius, borderPaint)

            when (status) {
                1 -> {
                    // 绿色: 显示在线人数
                    textPaint.textSize = 28f
                    canvas.drawText(onlineCount.toString(), cx, cy + textPaint.textSize / 3 - 1, textPaint)
                }
                2 -> {
                    // 红色: 显示警告感叹号
                    warnPaint.textSize = 38f
                    canvas.drawText("!", cx, cy + warnPaint.textSize / 3 - 1, warnPaint)
                }
                else -> {
                    // 橙色: 空白
                }
            }
        }
    }

    // ─── Target Button ────────────────────────────────────────────────

    inner class TargetButtonView @JvmOverloads constructor(
        ctx: Context,
        attrs: AttributeSet? = null,
        defStyleAttr: Int = 0
    ) : View(ctx, attrs, defStyleAttr) {
        private var hasTarget = false
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFFFFFFF.toInt()
            textSize = 24f
            textAlign = Paint.Align.CENTER
        }
        private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = 2f
            color = 0x99FFFFFF.toInt()
        }

        init { setWillNotDraw(false) }

        fun setHasTarget(has: Boolean) {
            hasTarget = has
            invalidate()
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            val text = if (hasTarget) "已设目标，点我取消" else "未设目标，点我设置"
            val tw = textPaint.measureText(text)
            setMeasuredDimension(tw.toInt() + 40, 64)
        }

        override fun onDraw(canvas: Canvas) {
            val cx = width / 2f
            val cy = height / 2f
            val rx = (width / 2f) - 4f
            val ry = (height / 2f) - 4f

            bgPaint.color = if (hasTarget) 0xFFFF9800.toInt() else 0xCC1E88E5.toInt()
            canvas.drawRoundRect(4f, 4f, width - 4f, height - 4f, 12f, 12f, bgPaint)
            canvas.drawRoundRect(4f, 4f, width - 4f, height - 4f, 12f, 12f, borderPaint)

            val text = if (hasTarget) "已设目标，点我取消" else "未设目标，点我设置"
            canvas.drawText(text, cx, cy + textPaint.textSize / 3 - 2, textPaint)
        }
    }
}
