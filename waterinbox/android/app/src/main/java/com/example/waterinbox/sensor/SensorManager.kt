package com.example.waterinbox.sensor

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import com.example.waterinbox.math.BoxMath
import com.example.waterinbox.math.FusionConfig
import com.example.waterinbox.socket.SocketManager
import com.example.waterinbox.math.fuse_madgwick
import com.example.waterinbox.math.fuse_mahony3
import com.example.waterinbox.math.fuse_mahony6
import com.example.waterinbox.math.fuse_ekf
import kotlin.math.sqrt

data class SensorData(
    val gyro: FloatArray = floatArrayOf(0f, 0f, 0f),
    val accel: FloatArray = floatArrayOf(0f, 0f, 0f),
    val magnet: FloatArray = floatArrayOf(0f, 0f, 0f),

    val accelCorr: FloatArray = floatArrayOf(0f, 0f, 0f),
    val gyroCorr: FloatArray = floatArrayOf(0f, 0f, 0f),
    val magnetCorr: FloatArray = floatArrayOf(0f, 0f, 0f),

    val quaternion: FloatArray = floatArrayOf(0f, 0f, 0f, 1f),  // [qx,qy,qz,qw]
    val euler: FloatArray = floatArrayOf(0f, 0f, 0f),
    val axisAngle: FloatArray = floatArrayOf(0f, 0f, 0f, 0f),  // (axisX, axisY, axisZ, angleDeg)

    val accelRaw: FloatArray = floatArrayOf(0f, 0f, 0f),  // raw accelerometer (positive = anti-gravity)
    val gravity: FloatArray = floatArrayOf(0f, 0f, -1f),  // world gravity in box space, from quaternion
    val dt: Float = 0f,            // time step in seconds
    val waterPoly: List<FloatArray> = emptyList(),  // intersection polygon debug points
    val algoParams: FloatArray = floatArrayOf(0f, 0f, 0f),  // algorithm-specific params (displayed in UI)
    // World axis vectors rotated by quaternion into body space (for debug rendering)
    val worldAxisX: FloatArray = floatArrayOf(1f, 0f, 0f),  // [x,y,z] world X+ → body
    val worldAxisY: FloatArray = floatArrayOf(0f, 1f, 0f),  // [x,y,z] world Y+ → body
    val worldAxisZ: FloatArray = floatArrayOf(0f, 0f, 1f),  // [x,y,z] world Z+ → body
    val boatVertices: FloatArray = floatArrayOf(0f),  // 8 boat corner positions [x,y,z]×8, computed in BoxSpace.drawBoat
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SensorData
        return gyro.contentEquals(other.gyro) && accel.contentEquals(other.accel) &&
                magnet.contentEquals(other.magnet) && quaternion.contentEquals(other.quaternion) &&
                euler.contentEquals(other.euler) && axisAngle.contentEquals(other.axisAngle) &&
                gravity.contentEquals(other.gravity) &&
                kotlin.math.abs(dt - other.dt) < 1e-6f
    }

    override fun hashCode(): Int {
        var result = gyro.contentHashCode()
        result = 31 * result + accel.contentHashCode()
        result = 31 * result + magnet.contentHashCode()
        result = 31 * result + quaternion.contentHashCode()
        result = 31 * result + euler.contentHashCode()
        result = 31 * result + axisAngle.contentHashCode()
        result = 31 * result + gravity.contentHashCode()
        result = 31 * result + dt.hashCode()
        return result
    }
}

class SensorProbe(context: Context) : SensorEventListener {

    private val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private val gyro = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE)!!
    private val accel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)!!
    private val magnet = sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)

    // Box dimensions matching WaterRenderer (using screen pixels)
    private val metrics = context.resources.displayMetrics
    private val boxW = metrics.widthPixels.toFloat()
    private val boxH = metrics.heightPixels.toFloat()
    private val boxD = minOf(boxW, boxH) / 2f
    private val boxMath = BoxMath(boxW / 2f, boxH / 2f, boxD)

    private val _data = MutableStateFlow(SensorData())
    val data: StateFlow<SensorData> = _data.asStateFlow()

    // Quaternion state (updated by fusion)
    private var qW = 1f
    private var qX = 0f
    private var qY = 0f
    private var qZ = 0f

    private var lastGyrTimestamp = 0L
    private var lastDt = 0f

    // Sensor values (raw Android)
    private var gX = 0f; private var gY = 0f; private var gZ = 0f
    private var aX = 0f; private var aY = 0f; private var aZ = 0f
    private var mX = 0f; private var mY = 0f; private var mZ = 0f
    private var fixAX = 0f; private var fixAY = 0f; private var fixAZ = 0f  // negated accel = gravity dir
    private var fixGX = 0f; private var fixGY = 0f; private var fixGZ = 0f
    private var fixMX = 0f; private var fixMY = 0f; private var fixMZ = 0f

    fun start() {
        sm.registerListener(this, gyro, SensorManager.SENSOR_DELAY_GAME)
        sm.registerListener(this, accel, SensorManager.SENSOR_DELAY_GAME)
        sm.registerListener(this, magnet, SensorManager.SENSOR_DELAY_GAME)
    }

    fun stop() {
        sm.unregisterListener(this)
    }

    override fun onSensorChanged(event: SensorEvent) {
        when (event.sensor.type) {
            Sensor.TYPE_GYROSCOPE -> {
                val gyrTs = event.timestamp  // nanoseconds since boot (sensor time base)
                gX = event.values[0]; gY = event.values[1]; gZ = event.values[2]
                fixGX = gX; fixGY = gY; fixGZ = gZ

                if (lastGyrTimestamp != 0L) {
                    lastDt = ((gyrTs - lastGyrTimestamp) * 1e-9f).coerceIn(0.001f, 0.1f)
                    val result = when (FusionConfig.algorithm) {
                        "madgwick"  -> fuse_madgwick(fixGX, fixGY, fixGZ, fixAX, fixAY, fixAZ, qW, qX, qY, qZ, lastDt)
                        "mahony3"   -> fuse_mahony3(fixGX, fixGY, fixGZ, qW, qX, qY, qZ, lastDt)
                        "ekf"       -> fuse_ekf(fixGX, fixGY, fixGZ, fixAX, fixAY, fixAZ, qW, qX, qY, qZ, lastDt)
                        else        -> fuse_mahony6(fixGX, fixGY, fixGZ, fixAX, fixAY, fixAZ, qW, qX, qY, qZ, lastDt)
                    }
                    qX = result[0]; qY = result[1]; qZ = result[2]; qW = result[3]
                }
                lastGyrTimestamp = gyrTs

                emit(lastDt, gyrTs)
            }
            Sensor.TYPE_ACCELEROMETER -> {
                aX = event.values[0]; aY = event.values[1]; aZ = event.values[2]
                fixAX = -aX; fixAY = -aY; fixAZ = -aZ
            }
            Sensor.TYPE_MAGNETIC_FIELD -> {
                mX = event.values[0]; mY = event.values[1]; mZ = event.values[2]
                fixMX = mX; fixMY = mY; fixMZ = mZ
            }
        }
    }

    private fun emit(dt: Float, gyroTimestampNs: Long) {
        // ── 1. 欧拉角 (ZYX, C code convention) ──
        // e[0]=roll(around X), e[1]=pitch(around Y), e[2]=yaw(around Z)
        val test = qY * qW - qX * qZ  // different from YXZ!
        val roll: Float
        val pitch: Float
        val yaw: Float

        if (test > 0.499f) {
            roll = (Math.PI / 2f).toFloat()
            pitch = (-2f * kotlin.math.atan2(qX, qW)).toFloat()
            yaw = 0f
        } else if (test < -0.499f) {
            roll = (-Math.PI / 2f).toFloat()
            pitch = (2f * kotlin.math.atan2(qX, qW)).toFloat()
            yaw = 0f
        } else {
            val qx2 = qX * qX
            val qy2 = qY * qY
            val qz2 = qZ * qZ
            // roll: atan2(2(xw+yz), 1-2(x²+y²))
            roll = (kotlin.math.atan2(2f * (qX * qW + qY * qZ), 1f - 2f * (qx2 + qy2))).toFloat()
            // pitch: asin(2(yw-xz))
            pitch = (kotlin.math.asin(2f * test)).toFloat()
            // yaw: atan2(2(zw+xy), 1-2(y²+z²))
            yaw = (kotlin.math.atan2(2f * (qZ * qW + qX * qY), 1f - 2f * (qy2 + qz2))).toFloat()
        }

        // ── 2. 轴角 (C quaternion2axisandangle convention) ──
        // If qw < 0, negate vector part to get canonical form for display:
        // equivalent rotation with angle in [0°, 180°]
        val qx_d = if (qW < 0f) -qX else qX
        val qy_d = if (qW < 0f) -qY else qY
        val qz_d = if (qW < 0f) -qZ else qZ
        val qvLen = sqrt(qx_d * qx_d + qy_d * qy_d + qz_d * qz_d)
        val angleDeg: Float
        val axisX: Float
        val axisY: Float
        val axisZ: Float
        if (qvLen > 1e-6f) {
            angleDeg = (kotlin.math.acos(qW.toDouble().coerceIn(-1.0, 1.0)) * 2.0 * 180.0 / Math.PI).toFloat()
            val invLen = 1.0f / qvLen
            axisX = qx_d * invLen
            axisY = qy_d * invLen
            axisZ = qz_d * invLen
        } else {
            angleDeg = 0f
            axisX = 0f; axisY = 0f; axisZ = 1f
        }

        // ── 3. 重力向量 (四元数逆旋 from world to body) ──
        val gravityLocalX =  2f * (qW * qY - qZ * qX)
        val gravityLocalY = -2f * (qY * qZ + qW * qX)
        val gravityLocalZ = -1f + 2f * (qX * qX + qY * qY)

        // World axis vectors — exact port of C quaternion2bodyspaceworldaxis(qx,qy,qz,qw)
        // r=worldX+, f=worldY+, t=worldZ+ in body space
        val wxX =  1f - 2f*(qY*qY + qZ*qZ)
        val wxY =  2f * (qX*qY - qZ*qW)
        val wxZ =  2f * (qX*qZ + qY*qW)
        val wyX =  2f * (qX*qY + qZ*qW)
        val wyY =  1f - 2f*(qX*qX + qZ*qZ)
        val wyZ =  2f * (qY*qZ - qX*qW)
        val wzX =  2f * (qX*qZ - qY*qW)
        val wzY =  2f * (qY*qZ + qX*qW)
        val wzZ =  1f - 2f*(qX*qX + qY*qY)

        // ── 5. 推送 ──
        _data.value = SensorData(
            gyro = floatArrayOf(gX, gY, gZ),
            accel = floatArrayOf(aX, aY, aZ),
            magnet = floatArrayOf(mX, mY, mZ),
            gyroCorr = floatArrayOf(fixGX, fixGY, fixGZ),
            accelCorr = floatArrayOf(fixAX, fixAY, fixAZ),
            magnetCorr = floatArrayOf(fixMX, fixMY, fixMZ),
            quaternion = floatArrayOf(qX, qY, qZ, qW),
            euler = floatArrayOf(
                Math.toDegrees(roll.toDouble()).toFloat(),
                Math.toDegrees(pitch.toDouble()).toFloat(),
                Math.toDegrees(yaw.toDouble()).toFloat()
            ),
            axisAngle = floatArrayOf(axisX, axisY, axisZ, angleDeg),
            accelRaw = floatArrayOf(aX, aY, aZ),
            gravity = floatArrayOf(gravityLocalX, gravityLocalY, gravityLocalZ),
            dt = dt,
            waterPoly = boxMath.solveWaterPlane(floatArrayOf(gravityLocalX, gravityLocalY, gravityLocalZ)).polygon,
            worldAxisX = floatArrayOf(wxX, wxY, wxZ),
            worldAxisY = floatArrayOf(wyX, wyY, wyZ),
            worldAxisZ = floatArrayOf(wzX, wzY, wzZ),
            algoParams = when (FusionConfig.algorithm) {
                "madgwick" -> floatArrayOf(FusionConfig.madgwickBeta, 0f, 0f)
                "mahony6"  -> floatArrayOf(FusionConfig.mahonyKp, FusionConfig.mahonyKi, 0f)
                else       -> floatArrayOf(0f, 0f, 0f)
            },
        )
        // ── 6. Socket output ──
        SocketManager.onSensorData(
            qX, qY, qZ, qW,
            fixGX, fixGY, fixGZ,   // gyroC (corrected)
            fixAX, fixAY, fixAZ,    // accelC (corrected, negated)
            fixMX, fixMY, fixMZ,    // magC (corrected)
            gyroTimestampNs,
        )
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}
