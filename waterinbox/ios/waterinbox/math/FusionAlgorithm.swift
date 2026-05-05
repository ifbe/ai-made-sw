import Foundation

class FusionConfig {
    static var algorithm = "ios"
    static var yawAlgorithm = "none"
    static let madgwickBeta: Float = 0.5
    static let mahonyKp: Float = 1.0
    static let mahonyKi: Float = 0.0

    static var accelX: Float = 0
    static var accelY: Float = 0
    static var accelZ: Float = 0

    static var magX: Float = 0
    static var magY: Float = 0
    static var magZ: Float = 0
}

class FusionState {
    static var integralX: Float = 0
    static var integralY: Float = 0
    static var integralZ: Float = 0

    static func reset() {
        integralX = 0
        integralY = 0
        integralZ = 0
    }
}

func invSqrt(_ x: Float) -> Float {
    let xhalf = 0.5 * x
    var i: UInt32 = xhalf.bitPattern
    i = 0x5f3759df - (i >> 1)
    var y = Float(bitPattern: i)
    y = y * (1.5 - xhalf * y * y)
    return y
}

func fuse_mahony6(
    gx: Float, gy: Float, gz: Float,
    ax: Float, ay: Float, az: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
) -> [Float] {
    var qx = qX
    var qy = qY
    var qz = qZ
    var qw = qW

    var gx = gx
    var gy = gy
    var gz = gz

    var ax = ax
    var ay = ay
    var az = az

    let avalid = ax != 0 || ay != 0 || az != 0

    if avalid {
        var recipNorm: Float
        var halfvx: Float
        var halfvy: Float
        var halfvz: Float
        var halfex: Float
        var halfey: Float
        var halfez: Float

        recipNorm = invSqrt(ax * ax + ay * ay + az * az)
        ax *= recipNorm
        ay *= recipNorm
        az *= recipNorm

        halfvx = -(qx * qz - qw * qy)
        halfvy = -(qw * qx + qy * qz)
        halfvz = -(qw * qw + qz * qz - 0.5)

        halfex = (ay * halfvz - az * halfvy)
        halfey = (az * halfvx - ax * halfvz)
        halfez = (ax * halfvy - ay * halfvx)

        if FusionConfig.mahonyKi > 0 {
            FusionState.integralX += FusionConfig.mahonyKi * halfex * dt
            FusionState.integralY += FusionConfig.mahonyKi * halfey * dt
            FusionState.integralZ += FusionConfig.mahonyKi * halfez * dt

            let maxIntegral: Float = 0.5
            if FusionState.integralX > maxIntegral { FusionState.integralX = maxIntegral }
            if FusionState.integralX < -maxIntegral { FusionState.integralX = -maxIntegral }
            if FusionState.integralY > maxIntegral { FusionState.integralY = maxIntegral }
            if FusionState.integralY < -maxIntegral { FusionState.integralY = -maxIntegral }
            if FusionState.integralZ > maxIntegral { FusionState.integralZ = maxIntegral }
            if FusionState.integralZ < -maxIntegral { FusionState.integralZ = -maxIntegral }

            gx += FusionState.integralX
            gy += FusionState.integralY
            gz += FusionState.integralZ
        }

        gx += 2.0 * FusionConfig.mahonyKp * halfex
        gy += 2.0 * FusionConfig.mahonyKp * halfey
        gz += 2.0 * FusionConfig.mahonyKp * halfez
    }

    let gxScaled = gx * (0.5 * dt)
    let gyScaled = gy * (0.5 * dt)
    let gzScaled = gz * (0.5 * dt)

    let pw = qw
    let px = qx
    let py = qy
    let pz = qz

    qx += (0 * px + gzScaled * py - gyScaled * pz + gxScaled * pw)
    qy += (-gzScaled * px + 0 * py + gxScaled * pz + gyScaled * pw)
    qz += (gyScaled * px - gxScaled * py + 0 * pz + gzScaled * pw)
    qw += (-gxScaled * px - gyScaled * py - gzScaled * pz + 0 * pw)

    let invnorm = invSqrt(qw * qw + qx * qx + qy * qy + qz * qz)
    qw *= invnorm
    qx *= invnorm
    qy *= invnorm
    qz *= invnorm

    return [qx, qy, qz, qw]
}

func fuse_mahony3(
    gx: Float, gy: Float, gz: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
) -> [Float] {
    var qw = qW
    var qx = qX
    var qy = qY
    var qz = qZ

    let gxScaled = gx * (0.5 * dt)
    let gyScaled = gy * (0.5 * dt)
    let gzScaled = gz * (0.5 * dt)

    let pw = qw
    let px = qx
    let py = qy
    let pz = qz

    qx += (0 * px + gzScaled * py - gyScaled * pz + gxScaled * pw)
    qy += (-gzScaled * px + 0 * py + gxScaled * pz + gyScaled * pw)
    qz += (gyScaled * px - gxScaled * py + 0 * pz + gzScaled * pw)
    qw += (-gxScaled * px - gyScaled * py - gzScaled * pz + 0 * pw)

    let invnorm = invSqrt(qw * qw + qx * qx + qy * qy + qz * qz)
    qw *= invnorm
    qx *= invnorm
    qy *= invnorm
    qz *= invnorm

    return [qx, qy, qz, qw]
}

func fuse_madgwick(
    gx: Float, gy: Float, gz: Float,
    ax: Float, ay: Float, az: Float,
    qW: Float, qX: Float, qY: Float, qZ: Float,
    dt: Float
) -> [Float] {
    var qx = qX
    var qy = qY
    var qz = qZ
    var qw = qW

    let qDot1 = 0.5 * (-qx * gx - qy * gy - qz * gz)
    let qDot2 = 0.5 * (qw * gx + qy * gz - qz * gy)
    let qDot3 = 0.5 * (qw * gy - qx * gz + qz * gx)
    let qDot4 = 0.5 * (qw * gz + qx * gy - qy * gx)

    var recipNorm = invSqrt(ax * ax + ay * ay + az * az)
    let ax_n = ax * recipNorm
    let ay_n = ay * recipNorm
    let az_n = az * recipNorm

    let _2qw = 2.0 * qw
    let _2qx = 2.0 * qx
    let _2qy = 2.0 * qy
    let _2qz = 2.0 * qz
    let _4qw = 4.0 * qw
    let _4qx = 4.0 * qx
    let _4qy = 4.0 * qy
    let _8qx = 8.0 * qx
    let _8qy = 8.0 * qy
    let qwqw = qw * qw
    let qxqx = qx * qx
    let qyqy = qy * qy
    let qzqz = qz * qz

    // ENU coordinate system
    let s0 = _4qw * qyqy - _2qy * ax_n + _4qw * qxqx + _2qx * ay_n
    let s1 = _4qx * qzqz + _2qz * ax_n + 4.0 * qwqw * qx + _2qw * ay_n - _4qx + _8qx * qxqx + _8qx * qyqy - _4qx * az_n
    let s2 = 4.0 * qwqw * qy - _2qw * ax_n + _4qy * qzqz + _2qz * ay_n - _4qy + _8qy * qxqx + _8qy * qyqy - _4qy * az_n
    let s3 = 4.0 * qxqx * qz + _2qx * ax_n + 4.0 * qyqy * qz + _2qy * ay_n

    recipNorm = invSqrt(s0 * s0 + s1 * s1 + s2 * s2 + s3 * s3)
    let ns0 = s0 * recipNorm
    let ns1 = s1 * recipNorm
    let ns2 = s2 * recipNorm
    let ns3 = s3 * recipNorm

    let qDot1_c = qDot1 - FusionConfig.madgwickBeta * ns0
    let qDot2_c = qDot2 - FusionConfig.madgwickBeta * ns1
    let qDot3_c = qDot3 - FusionConfig.madgwickBeta * ns2
    let qDot4_c = qDot4 - FusionConfig.madgwickBeta * ns3

    qw += qDot1_c * dt
    qx += qDot2_c * dt
    qy += qDot3_c * dt
    qz += qDot4_c * dt

    recipNorm = invSqrt(qw * qw + qx * qx + qy * qy + qz * qz)
    qw *= recipNorm
    qx *= recipNorm
    qy *= recipNorm
    qz *= recipNorm

    return [qx, qy, qz, qw]
}

func fixYaw(qx: Float, qy: Float, qz: Float, qw: Float) -> [Float] {
    switch FusionConfig.yawAlgorithm {
    case "none":
        return [qx, qy, qz, qw]
    case "mag":
        return applyMagYawCorrection(qx: qx, qy: qy, qz: qz, qw: qw)
    default:
        return [qx, qy, qz, qw]
    }
}

private func applyMagYawCorrection(qx: Float, qy: Float, qz: Float, qw: Float) -> [Float] {
    let test = qy * qw - qx * qz
    let curYaw: Float
    if test > 0.499 || test < -0.499 {
        curYaw = 0
    } else {
        curYaw = atan2(2 * (qz * qw + qx * qy), 1 - 2 * (qy * qy + qz * qz))
    }

    let mLen = sqrt(FusionConfig.magX * FusionConfig.magX + FusionConfig.magY * FusionConfig.magY)
    if mLen < 1e-6 {
        return [qx, qy, qz, qw]
    }

    let refYaw = atan2(FusionConfig.magY / mLen, FusionConfig.magX / mLen)

    var dYaw = refYaw - curYaw
    while dYaw > Float.pi { dYaw -= 2 * Float.pi }
    while dYaw < -Float.pi { dYaw += 2 * Float.pi }

    if abs(dYaw) < 1e-4 {
        return [qx, qy, qz, qw]
    }

    let half = dYaw * 0.5
    let qhz = sin(half)
    let qhw = cos(half)

    let qhz_x = 0 as Float
    let qhz_y = 0 as Float

    let newQx = qhw * qx + qhz * qhz_x
    let newQy = qhw * qy + qhz * qhz_y
    let newQz = qhw * qz + qhz * 1
    let newQw = qhw * qw - qhz * 0

    return [newQx, newQy, newQz, newQw]
}