package com.example.locate.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.example.locate.data.remote.ApiClient
import com.example.locate.domain.model.Position
import com.example.locate.ui.map.MapActivity
import com.example.locate.util.Constants
import com.google.android.gms.location.*

/**
 * 息屏时持续获取位置和方向的前台服务
 */
class LocationTrackerService : Service(), SensorEventListener {

    private lateinit var fusedLocationClient: FusedLocationProviderClient
    private lateinit var sensorManager: SensorManager
    private lateinit var wakeLock: PowerManager.WakeLock

    private var apiClient: ApiClient? = null
    private var currentPosition: Position? = null
    private var currentHeading: Float = 0f
    private var mapView: com.example.locate.ui.map.MapView? = null
    private var hasMovedToSelf = false

    private val binder = LocalBinder()

    inner class LocalBinder : Binder() {
        fun getService(): LocationTrackerService = this@LocationTrackerService
    }

    override fun onCreate() {
        super.onCreate()
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
        sensorManager = getSystemService(Context.SENSOR_SERVICE) as SensorManager
        wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Locate:LocationWakeLock")

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) {
            // 没有位置权限，不启动前台服务
            return START_NOT_STICKY
        }
        startForeground()
        startLocationUpdates()
        startSensorUpdates()
        wakeLock.acquire(10 * 60 * 1000L) // 10分钟防止休眠
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onDestroy() {
        super.onDestroy()
        stopLocationUpdates()
        stopSensorUpdates()
        if (wakeLock.isHeld) wakeLock.release()
    }

    fun setApiClient(client: ApiClient) {
        this.apiClient = client
    }

    private fun startForeground() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                Constants.NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
            )
        } else {
            startForeground(Constants.NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MapActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, Constants.NOTIFICATION_CHANNEL_ID)
            .setContentTitle("位置追踪中")
            .setContentText("正在分享你的位置")
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            Constants.NOTIFICATION_CHANNEL_ID,
            "位置追踪",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "息屏时持续分享位置"
        }
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(channel)
    }

    private fun startLocationUpdates() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) return

        val locationRequest = LocationRequest.Builder(
            Priority.PRIORITY_HIGH_ACCURACY,
            Constants.LOCATION_UPDATE_INTERVAL_MS
        ).apply {
            setMinUpdateIntervalMillis(Constants.LOCATION_FASTEST_INTERVAL_MS)
            setWaitForAccurateLocation(false)
        }.build()

        fusedLocationClient.requestLocationUpdates(
            locationRequest,
            locationCallback,
            mainLooper
        )
    }

    private val locationCallback = object : LocationCallback() {
        override fun onLocationResult(result: LocationResult) {
            result.lastLocation?.let { location ->
                currentPosition = Position(
                    lat = location.latitude,
                    lng = location.longitude,
                    accuracy = location.accuracy,
                    altitude = location.altitude,
                    speed = location.speed,
                    bearing = location.bearing
                )
                sendUpdate()
            }
        }
    }

    private fun stopLocationUpdates() {
        fusedLocationClient.removeLocationUpdates(locationCallback)
    }

    /**
     * 注册方向传感器（加速度 + 地磁）
     */
    private fun startSensorUpdates() {
        val accelSensor = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val magneticSensor = sensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)

        accelSensor?.let {
            sensorManager.registerListener(this, it, SensorManager.SENSOR_DELAY_UI)
        }
        magneticSensor?.let {
            sensorManager.registerListener(this, it, SensorManager.SENSOR_DELAY_UI)
        }
    }

    private fun stopSensorUpdates() {
        sensorManager.unregisterListener(this)
    }

    private val accelerometerReading = FloatArray(3)
    private val magnetometerReading = FloatArray(3)
    private val rotationMatrix = FloatArray(9)
    private val orientationAngles = FloatArray(3)

    override fun onSensorChanged(event: SensorEvent) {
        when (event.sensor.type) {
            Sensor.TYPE_ACCELEROMETER -> {
                System.arraycopy(event.values, 0, accelerometerReading, 0, accelerometerReading.size)
            }
            Sensor.TYPE_MAGNETIC_FIELD -> {
                System.arraycopy(event.values, 0, magnetometerReading, 0, magnetometerReading.size)
            }
        }

        if (SensorManager.getRotationMatrix(rotationMatrix, null, accelerometerReading, magnetometerReading)) {
            SensorManager.getOrientation(rotationMatrix, orientationAngles)
            // orientationAngles[0] 是方位角（弧度），转为度
            var azimuth = Math.toDegrees(orientationAngles[0].toDouble()).toFloat()
            if (azimuth < 0) azimuth += 360f
            currentHeading = azimuth
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    fun getCurrentPosition(): Position? = currentPosition
    fun getCurrentGcj02Position(): Position? {
        val pos = currentPosition ?: return null
        val (gcjLat, gcjLng) = wgs84ToGcj02(pos.lat, pos.lng)
        return Position(gcjLat, gcjLng, pos.accuracy, pos.altitude, pos.speed, pos.bearing)
    }
    fun getCurrentHeading(): Float = currentHeading
    fun setMapView(view: com.example.locate.ui.map.MapView?) { this.mapView = view }

    private fun sendUpdate() {
        val pos = currentPosition ?: return
        val (gcjLat, gcjLng) = wgs84ToGcj02(pos.lat, pos.lng)
        // 第一次 GPS 到达时，把地图飞到自己的位置
        if (!hasMovedToSelf && mapView != null) {
            hasMovedToSelf = true
            mapView?.moveTo(gcjLat, gcjLng, 17.0)
        }
        mapView?.updateAltitude(pos.altitude)
        apiClient?.sendPosition(gcjLat, gcjLng, currentHeading)
        android.util.Log.d("GPS", "sendPosition: wgs84(${pos.lat},${pos.lng}) => gcj02($gcjLat,$gcjLng) accuracy=${pos.accuracy}m")
    }

    /**
     * WGS84 转 GCJ-02（国测局坐标）
     * 用于修正国产手机 GPS 返回 WGS84 导致的位置偏移
     */
    private fun wgs84ToGcj02(wgsLat: Double, wgsLng: Double): Pair<Double, Double> {
        var dLat = transformLat(wgsLng - 105.0, wgsLat - 35.0)
        var dLng = transformLng(wgsLng - 105.0, wgsLat - 35.0)
        val radLat = wgsLat / 180.0 * Math.PI
        var magic = kotlin.math.sin(radLat * Math.PI)
        magic = 1 - 0.006693421622965839 * magic * magic
        val sqrtMagic = kotlin.math.sqrt(magic)
        dLat = (dLat * 180.0) / ((6378245.0 / sqrtMagic) * Math.PI * (1 - 0.006693421622965839) / (magic * sqrtMagic))
        dLng = (dLng * 180.0) / (6378245.0 / sqrtMagic * kotlin.math.cos(radLat) * Math.PI)
        return Pair(wgsLat + dLat, wgsLng + dLng)
    }

    private fun transformLat(x: Double, y: Double): Double {
        var ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * kotlin.math.sqrt(kotlin.math.abs(x))
        ret += (20.0 * kotlin.math.sin(6.0 * x * Math.PI) + 20.0 * kotlin.math.sin(2.0 * x * Math.PI)) * 2.0 / 3.0
        ret += (20.0 * kotlin.math.sin(y * Math.PI) + 40.0 * kotlin.math.sin(y / 3.0 * Math.PI)) * 2.0 / 3.0
        ret += (160.0 * kotlin.math.sin(y / 12.0 * Math.PI) + 320.0 * kotlin.math.sin(y / 30.0 * Math.PI)) * 2.0 / 3.0
        return ret
    }

    private fun transformLng(x: Double, y: Double): Double {
        var ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * kotlin.math.sqrt(kotlin.math.abs(x))
        ret += (20.0 * kotlin.math.sin(6.0 * x * Math.PI) + 20.0 * kotlin.math.sin(2.0 * x * Math.PI)) * 2.0 / 3.0
        ret += (20.0 * kotlin.math.sin(x * Math.PI) + 40.0 * kotlin.math.sin(x / 3.0 * Math.PI)) * 2.0 / 3.0
        ret += (150.0 * kotlin.math.sin(x / 12.0 * Math.PI) + 300.0 * kotlin.math.sin(x / 30.0 * Math.PI)) * 2.0 / 3.0
        return ret
    }
}
