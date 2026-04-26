package com.example.waterinbox.math

import kotlin.math.sqrt

/** Fast inverse square root, matching the C implementation exactly. */
private fun invSqrt(x: Float): Float {
    val xhalf = 0.5f * x
    var i = java.lang.Float.floatToIntBits(x)
    i = 0x5f3759df - (i shr 1)
    var y = java.lang.Float.intBitsToFloat(i)
    y = y * (1.5f - xhalf * y * y)
    return y
}

/**
 * Madgwick AHRS sensor fusion — accelerometer + gyroscope only.
 * C-code exact port: madgwickupdate6() from ahrs.madgwick.c.
 * Input: NED坐标系 (gyro/accel)，输出: NED坐标系四元数
 * Internal quaternion order: [qx, qy, qz, qw].
 * Beta read from FusionConfig.madgwickBeta.
 */
//NED
fun fuse_madgwick(
    gx_ned: Float, gy_ned: Float, gz_ned: Float,
    ax_ned: Float, ay_ned: Float, az_ned: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
): FloatArray {
    // C convention: per->q = [qx, qy, qz, qw]
    val gx = gx_ned; val gy = gy_ned; val gz = gz_ned
    val ax = ax_ned; val ay = ay_ned; val az = az_ned
    var qx = qX; var qy = qY; var qz = qZ; var qw = qW

    // Rate of change of quaternion from gyroscope
    val qDot1 = 0.5f * (-qx * gx - qy * gy - qz * gz)
    val qDot2 = 0.5f * (qw * gx + qy * gz - qz * gy)
    val qDot3 = 0.5f * (qw * gy - qx * gz + qz * gx)
    val qDot4 = 0.5f * (qw * gz + qx * gy - qy * gx)

    // Normalise accelerometer — local vars (params are val in Kotlin)
    var recipNorm = invSqrt(ax * ax + ay * ay + az * az)
    val ax_n = ax * recipNorm
    val ay_n = ay * recipNorm
    val az_n = az * recipNorm

    // Auxiliary variables — C code: float
    val _2qw = 2.0f * qw
    val _2qx = 2.0f * qx
    val _2qy = 2.0f * qy
    val _2qz = 2.0f * qz
    val _4qw = 4.0f * qw
    val _4qx = 4.0f * qx
    val _4qy = 4.0f * qy
    val _8qx = 8.0f * qx
    val _8qy = 8.0f * qy
    val qwqw = qw * qw
    val qxqx = qx * qx
    val qyqy = qy * qy
    val qzqz = qz * qz

    // Gradient descent algorithm corrective step — exact C port
//    val s0 = _4qw * qyqy + _2qy * ax_n + _4qw * qxqx - _2qx * ay_n
//    val s1 = _4qx * qzqz - _2qz * ax_n + 4.0f * qwqw * qx - _2qw * ay_n - _4qx + _8qx * qxqx + _8qx * qyqy + _4qx * az_n
//    val s2 = 4.0f * qwqw * qy + _2qw * ax_n + _4qy * qzqz - _2qz * ay_n - _4qy + _8qy * qxqx + _8qy * qyqy + _4qy * az_n
//    val s3 = 4.0f * qxqx * qz - _2qx * ax_n + 4.0f * qyqy * qz - _2qy * ay_n
    // ENU 坐标系下的梯度计算
    val s0 = _4qw * qyqy - _2qy * ax_n + _4qw * qxqx + _2qx * ay_n
    val s1 = _4qx * qzqz + _2qz * ax_n + 4.0f * qwqw * qx + _2qw * ay_n - _4qx + _8qx * qxqx + _8qx * qyqy - _4qx * az_n
    val s2 = 4.0f * qwqw * qy - _2qw * ax_n + _4qy * qzqz + _2qz * ay_n - _4qy + _8qy * qxqx + _8qy * qyqy - _4qy * az_n
    val s3 = 4.0f * qxqx * qz + _2qx * ax_n + 4.0f * qyqy * qz + _2qy * ay_n
    recipNorm = invSqrt(s0 * s0 + s1 * s1 + s2 * s2 + s3 * s3)
    val ns0 = s0 * recipNorm
    val ns1 = s1 * recipNorm
    val ns2 = s2 * recipNorm
    val ns3 = s3 * recipNorm

    // Apply feedback step — C: beta * normalized_gradient
    val qDot1_c = qDot1 - FusionConfig.madgwickBeta * ns0
    val qDot2_c = qDot2 - FusionConfig.madgwickBeta * ns1
    val qDot3_c = qDot3 - FusionConfig.madgwickBeta * ns2
    val qDot4_c = qDot4 - FusionConfig.madgwickBeta * ns3

    // Integrate
    qw += qDot1_c * dt
    qx += qDot2_c * dt
    qy += qDot3_c * dt
    qz += qDot4_c * dt

    // Normalise quaternion
    recipNorm = invSqrt(qw * qw + qx * qx + qy * qy + qz * qz)
    qw *= recipNorm
    qx *= recipNorm
    qy *= recipNorm
    qz *= recipNorm

    // Return [qx, qy, qz, qw] for Kotlin callers
    return floatArrayOf(qx, qy, qz, qw)
}

/**
 * Gyro-only quaternion integration — exact C port of mahonyupdate3().
 * Hamilton product: qDot = 0.5 * q ⊗ [0, gx, gy, gz]
 * C state: qx,qy,qz,qw (static array written in-place).
 * Returns [qx, qy, qz, qw] to match callers' expectation.
 */
fun fuse_mahony3(
    gx: Float, gy: Float, gz: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
): FloatArray {
    var qw = qW; var qx = qX; var qy = qY; var qz = qZ

    val gxScaled = gx * (0.5f * dt)
    val gyScaled = gy * (0.5f * dt)
    val gzScaled = gz * (0.5f * dt)

    val pw = qw; val px = qx; val py = qy; val pz = qz
    qx += (  0f * px + gzScaled * py - gyScaled * pz + gxScaled * pw)
    qy += (-gzScaled * px +  0f * py + gxScaled * pz + gyScaled * pw)
    qz += ( gyScaled * px - gxScaled * py +  0f * pz + gzScaled * pw)
    qw += (-gxScaled * px - gyScaled * py - gzScaled * pz +  0f * pw)

    val invnorm = invSqrt(qw * qw + qx * qx + qy * qy + qz * qz)
    qw *= invnorm; qx *= invnorm; qy *= invnorm; qz *= invnorm

    return floatArrayOf(qx, qy, qz, qw)
}

/**
 * Mahony AHRS — C-code exact port: mahonyupdate6() calling mahonyupdate3().
 * Internal quaternion: [qx,qy,qz,qw] (C convention).
 * twoKp/twoKi from FusionConfig.mahonyKp / .mahonyKi.
 * Returns [qw,qx,qy,qz]. Integral state in FusionState singleton.
 */
fun fuse_mahony6(
    gx: Float, gy: Float, gz: Float,
    ax: Float, ay: Float, az: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
): FloatArray {
    var qx = qX; var qy = qY; var qz = qZ; var qw = qW
    var ax = ax; var ay = ay; var az = az
    var gx = gx; var gy = gy; var gz = gz

    val avalid = (ax != 0.0f) || (ay != 0.0f) || (az != 0.0f)
    if (avalid) {
        var recipNorm: Float
        var halfvx: Float
        var halfvy: Float
        var halfvz: Float
        var halfex: Float
        var halfey: Float
        var halfez: Float

        // bodyspace measure_grav_dir
        recipNorm = invSqrt(ax * ax + ay * ay + az * az)
        ax *= recipNorm
        ay *= recipNorm
        az *= recipNorm

        // bodyspace predict_grav_dir
        halfvx = -(qx * qz - qw * qy)
        halfvy = -(qw * qx + qy * qz)
        halfvz = -(qw * qw + qz * qz - 0.5f);

        // bodyspace grav_error = cross(measure_grav_dir, predict_grav_dir)
        halfex = (ay * halfvz - az * halfvy)
        halfey = (az * halfvx - ax * halfvz)
        halfez = (ax * halfvy - ay * halfvx)

        // Compute and apply integral feedback if enabled
        if (FusionConfig.mahonyKi > 0.0f) {
            FusionState.integralX += FusionConfig.mahonyKi * halfex * dt
            FusionState.integralY += FusionConfig.mahonyKi * halfey * dt
            FusionState.integralZ += FusionConfig.mahonyKi * halfez * dt
            // Anti-windup: clamp integral terms
            val maxIntegral = 0.5f
            if (FusionState.integralX >  maxIntegral) FusionState.integralX =  maxIntegral
            if (FusionState.integralX < -maxIntegral) FusionState.integralX = -maxIntegral
            if (FusionState.integralY >  maxIntegral) FusionState.integralY =  maxIntegral
            if (FusionState.integralY < -maxIntegral) FusionState.integralY = -maxIntegral
            if (FusionState.integralZ >  maxIntegral) FusionState.integralZ =  maxIntegral
            if (FusionState.integralZ < -maxIntegral) FusionState.integralZ = -maxIntegral
            gx += FusionState.integralX
            gy += FusionState.integralY
            gz += FusionState.integralZ
        } else {
            FusionState.integralX = 0.0f
            FusionState.integralY = 0.0f
            FusionState.integralZ = 0.0f
        }

        // Apply proportional feedback (twoKp = 2*Kp)
        gx += 2.0f * FusionConfig.mahonyKp * halfex
        gy += 2.0f * FusionConfig.mahonyKp * halfey
        gz += 2.0f * FusionConfig.mahonyKp * halfez
    }

    // Second integration: mahonyupdate3 with corrected gyro, calling fuse_mahony3
    // fuse_mahony3 returns [qx, qy, qz, qw]
    val result2 = fuse_mahony3(gx, gy, gz, qw, qx, qy, qz, dt)
    qx = result2[0]; qy = result2[1]; qz = result2[2]; qw = result2[3]

    return floatArrayOf(qx, qy, qz, qw)
}

/**
 * EKF (Extended Kalman Filter) for IMU attitude estimation — placeholder.
 * State: quaternion(4) + gyro_bias(3) = 7-dim
 * Process model: quaternion kinematic driven by corrected gyro
 * Measurement: accel (gravity) — TODO: magnetometer for yaw absolute reference
 *
 * Currently a stub: falls back to gyro-only integration (same as fuse_mahony3).
 * TODO: implement full EKF predict/update cycle with proper covariance propagation.
 */
fun fuse_ekf(
    gx: Float, gy: Float, gz: Float,
    ax: Float, ay: Float, az: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
): FloatArray {
    // TODO: implement EKF
    // For now, gyro-only integration (no accel correction, no mag correction)
    return fuse_mahony3(gx, gy, gz, qW, qX, qY, qZ, dt)
}

/**
 * Mahony fusion integral state — stored as singleton so callers don't manage it.
 * Not thread-safe: must only be used from the sensor thread (SensorManager).
 */
object FusionState {
    var integralX = 0f
    var integralY = 0f
    var integralZ = 0f

    fun reset() {
        integralX = 0f; integralY = 0f; integralZ = 0f
    }
}

/**
 * Fusion algorithm selection and tuning — all in one place.
 * Switch algorithm here: "mahony3" | "mahony6" | "madgwick"
 */
object FusionConfig {
    var algorithm = "mahony6"
    const val madgwickBeta = 0.5f
    const val mahonyKp = 1.0f
    const val mahonyKi = 0.0f
}

/**
 * Box in local coordinates:
 *   x ∈ [-W/2, W/2]
 *   y ∈ [-H/2, H/2]
 *   z ∈ [-D/2, D/2]  (screen at z=+D/2, back at z=-D/2, center at z=0)
 *
 * Gravity in local coords = -normalized accelerometer.
 * Water surface is perpendicular to gravity (horizontal in world space).
 */
class BoxMath(
    val hw: Float,
    val hh: Float,
    val d: Float
) {
    private data class Edge(val p1: FloatArray, val p2: FloatArray)

    private val edges: List<Edge>

    init {
        val hd = d / 2f
        edges = listOf(
            // Front face (z = +D/2)
            Edge(floatArrayOf(-hw, -hh,  hd), floatArrayOf( hw, -hh,  hd)),
            Edge(floatArrayOf( hw, -hh,  hd), floatArrayOf( hw,  hh,  hd)),
            Edge(floatArrayOf( hw,  hh,  hd), floatArrayOf(-hw,  hh,  hd)),
            Edge(floatArrayOf(-hw,  hh,  hd), floatArrayOf(-hw, -hh,  hd)),
            // Back face (z = -D/2)
            Edge(floatArrayOf(-hw, -hh, -hd), floatArrayOf( hw, -hh, -hd)),
            Edge(floatArrayOf( hw, -hh, -hd), floatArrayOf( hw,  hh, -hd)),
            Edge(floatArrayOf( hw,  hh, -hd), floatArrayOf(-hw,  hh, -hd)),
            Edge(floatArrayOf(-hw,  hh, -hd), floatArrayOf(-hw, -hh, -hd)),
            // Vertical edges
            Edge(floatArrayOf(-hw, -hh, -hd), floatArrayOf(-hw, -hh,  hd)),
            Edge(floatArrayOf( hw, -hh, -hd), floatArrayOf( hw, -hh,  hd)),
            Edge(floatArrayOf( hw,  hh, -hd), floatArrayOf( hw,  hh,  hd)),
            Edge(floatArrayOf(-hw,  hh, -hd), floatArrayOf(-hw,  hh,  hd)),
        )
    }

    /**
     * Find the 3D intersection polygon between the water plane and the box.
     * Points are sorted counter-clockwise around the polygon's centroid.
     */
    fun intersectPlaneWithBox(nx: Float, ny: Float, nz: Float, c: Float): List<FloatArray> {
        val pts = mutableListOf<FloatArray>()
        for (edge in edges) {
            val its = linePlaneIntersection(edge, nx, ny, nz, c) ?: continue
            pts.add(its)
        }
        if (pts.size < 3) return emptyList()

        val cx = pts.sumOf { it[0].toDouble() } / pts.size
        val cy = pts.sumOf { it[1].toDouble() } / pts.size
        pts.sortBy { kotlin.math.atan2(it[1] - cy, it[0] - cx) }
        return pts
    }

    private fun linePlaneIntersection(edge: Edge, nx: Float, ny: Float, nz: Float, c: Float): FloatArray? {
        val (p1, p2) = edge
        val d1 = nx * p1[0] + ny * p1[1] + nz * p1[2] - c
        val d2 = nx * p2[0] + ny * p2[1] + nz * p2[2] - c
        if (d1 * d2 > 0f) return null
        if (d1 == 0f && d2 == 0f) return null
        val t = d1 / (d1 - d2)
        if (t < 0f || t > 1f) return null
        return floatArrayOf(
            p1[0] + t * (p2[0] - p1[0]),
            p1[1] + t * (p2[1] - p1[1]),
            p1[2] + t * (p2[2] - p1[2])
        )
    }

    /**
     * Given gravity direction in local coords, compute water plane and intersection polygon.
     * Water plane passes through box center (c=0), perpendicular to gravity.
     */
    fun solveWaterPlane(gravityLocal: FloatArray): WaterPlaneResult {
        val gLen = sqrt(gravityLocal[0] * gravityLocal[0] + gravityLocal[1] * gravityLocal[1] + gravityLocal[2] * gravityLocal[2])
        if (gLen < 1e-6f) {
            return WaterPlaneResult(floatArrayOf(0f, 0f, 1f), 0f, 0f, emptyList(), false)
        }

        val nx = gravityLocal[0] / gLen
        val ny = gravityLocal[1] / gLen
        val nz = gravityLocal[2] / gLen

        // Water plane passes through box center at c=0
        val c = 0f
        val polygon = intersectPlaneWithBox(nx, ny, nz, c)

        return WaterPlaneResult(
            normal = floatArrayOf(nx, ny, nz),
            c = c,
            volume = 0f,
            polygon = polygon,
            isWaterVisible = polygon.size >= 3
        )
    }

    data class WaterPlaneResult(
        val normal: FloatArray,
        val c: Float,
        val volume: Float,
        val polygon: List<FloatArray>,
        val isWaterVisible: Boolean
    )
}
