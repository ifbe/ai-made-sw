package com.example.locate.ui.map.osm

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Environment
import android.view.View
import androidx.core.content.ContextCompat
import com.example.locate.R
import com.example.locate.domain.model.User
import com.example.locate.ui.map.MapView
import org.osmdroid.config.Configuration
import org.osmdroid.tileprovider.tilesource.TileSourceFactory
import org.osmdroid.tileprovider.tilesource.XYTileSource
import org.osmdroid.util.GeoPoint
import org.osmdroid.views.MapView as OsmMapViewBase
import org.osmdroid.views.overlay.Marker
import org.osmdroid.views.overlay.mylocation.GpsMyLocationProvider
import org.osmdroid.views.overlay.mylocation.MyLocationNewOverlay
import java.io.File

/**
 * OSMDroid 实现
 * 基于 OpenStreetMap，免费无需 API Key
 */
class OsmMapView(private val context: Context) : MapView {

    private val mapView: OsmMapViewBase
    private var myLocationOverlay: MyLocationNewOverlay? = null
    private val userMarkers = mutableMapOf<String, Marker>()
    private var myTargetMarker: Marker? = null
    private var otherTargetMarkers = mutableMapOf<String, Marker>()
    private var clickListener: ((Double, Double) -> Unit)? = null

    init {
        // 初始化 OSMDroid 配置
        Configuration.getInstance().userAgentValue = context.packageName

        // 配置瓦片缓存路径（支持 Android 10+ scoped storage）
        val basePath = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.getExternalFilesDir(null) ?: context.filesDir
        } else {
            @Suppress("DEPRECATION")
            Environment.getExternalStorageDirectory()
        }
        val tileCache = File(basePath, "osmdroid/tiles")
        Configuration.getInstance().osmdroidTileCache = tileCache
        Configuration.getInstance().osmdroidBasePath = basePath

        // 高德瓦片
        // MapTileIndex encoding (MAX_ZOOM=29): tileKey = (x << 58) | (y << 29) | zoom
        // zoom: bits 58-63 (6 bits), y: bits 29-57 (29 bits), x: bits 0-28 (29 bits)
        val gaodeTileSource = object : XYTileSource(
            "Gaode", 1, 18, 256, ".png",
            arrayOf("https://webrd01.is.autonavi.com/appmaptile?lang=zh_cn&size=1&style=8")
        ) {
            override fun getTileURLString(tileKey: Long): String {
                val zoom = ((tileKey shr 58) and 0x3FL).toInt()
                val x = ((tileKey shr 29) and 0x1FFFFFFF).toInt()
                val y = (tileKey and 0x1FFFFFFF).toInt()
                return "https://webrd01.is.autonavi.com/appmaptile?lang=zh_cn&size=1&style=8&x=$x&y=$y&z=$zoom"
            }
        }

        mapView = OsmMapViewBase(context).apply {
            setTileSource(gaodeTileSource)
            setMultiTouchControls(true)
            controller.setZoom(15.0)

            // 默认显示中国区域
            controller.setCenter(GeoPoint(35.0, 105.0))

            // 地图点击事件
            setOnClickListener {
                // noop — 用 overlay 来处理
            }

            overlays.add(object : org.osmdroid.views.overlay.Overlay() {
                override fun onSingleTapConfirmed(e: android.view.MotionEvent?, mapView: OsmMapViewBase?): Boolean {
                    e?.let { me ->
                        val projection = mapView?.projection
                        val geoPoint = projection?.fromPixels(me.x.toInt(), me.y.toInt()) as? GeoPoint
                        geoPoint?.let { gp ->
                            clickListener?.invoke(gp.latitude, gp.longitude)
                        }
                    }
                    return true
                }
            })
        }
    }

    fun getView(): View = mapView

    fun getMapCenter(): GeoPoint? = mapView.mapCenter as? GeoPoint

    override fun showUser(lat: Double, lng: Double, heading: Float) {
        val geoPoint = GeoPoint(lat, lng)

        if (myLocationOverlay == null) {
            myLocationOverlay = MyLocationNewOverlay(GpsMyLocationProvider(context), mapView).apply {
                enableMyLocation()
            }
            mapView.overlays.add(myLocationOverlay)
        }

        mapView.controller.animateTo(geoPoint)
    }

    override fun showOtherUser(user: User) {
        val geoPoint = GeoPoint(user.lat, user.lng)

        val marker = userMarkers.getOrPut(user.username) {
            Marker(mapView).apply {
                setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_BOTTOM)
                title = user.username
                icon = getUserIcon()
            }.also { mapView.overlays.add(it) }
        }

        marker.position = geoPoint
        marker.rotation = user.heading
        marker.title = user.username
        mapView.invalidate()
    }

    override fun removeOtherUser(username: String) {
        userMarkers.remove(username)?.let {
            mapView.overlays.remove(it)
        }
        otherTargetMarkers.remove(username)?.let {
            mapView.overlays.remove(it)
        }
        mapView.invalidate()
    }

    override fun showOtherUsers(users: List<User>) {
        // 清空旧标记
        userMarkers.keys.toList().forEach { removeOtherUser(it) }

        users.forEach { user ->
            showOtherUser(user)
            // 显示目标点
            if (user.targetLat != null && user.targetLng != null) {
                showOtherTarget(user.username, user.targetLat, user.targetLng)
            }
        }
    }

    override fun showTarget(lat: Double, lng: Double) {
        val geoPoint = GeoPoint(lat, lng)

        val marker = myTargetMarker ?: Marker(mapView).apply {
            setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_CENTER)
            icon = getTargetIcon()
            title = "目标"
        }.also {
            myTargetMarker = it
            mapView.overlays.add(it)
        }

        marker.position = geoPoint
        mapView.invalidate()
    }

    private fun showOtherTarget(username: String, lat: Double, lng: Double) {
        val geoPoint = GeoPoint(lat, lng)

        val marker = otherTargetMarkers.getOrPut(username) {
            Marker(mapView).apply {
                setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_CENTER)
                icon = getOtherTargetIcon()
                title = "$username 的目标"
            }.also { mapView.overlays.add(it) }
        }

        marker.position = geoPoint
        mapView.invalidate()
    }

    override fun clearTarget() {
        myTargetMarker?.let {
            mapView.overlays.remove(it)
            myTargetMarker = null
        }
        mapView.invalidate()
    }

    override fun moveTo(lat: Double, lng: Double, zoom: Double) {
        mapView.controller.setZoom(zoom)
        mapView.controller.animateTo(GeoPoint(lat, lng))
    }

    override fun setOnMapClickListener(listener: (Double, Double) -> Unit) {
        clickListener = listener
    }

    override fun onDestroy() {
        myLocationOverlay?.disableMyLocation()
        mapView.onDetach()
    }

    private fun getUserIcon(): Drawable? {
        return ContextCompat.getDrawable(context, android.R.drawable.ic_menu_myplaces)
    }

    private fun getTargetIcon(): Drawable? {
        return ContextCompat.getDrawable(context, android.R.drawable.ic_menu_add)
    }

    private fun getOtherTargetIcon(): Drawable? {
        return ContextCompat.getDrawable(context, android.R.drawable.ic_menu_directions)
    }
}
