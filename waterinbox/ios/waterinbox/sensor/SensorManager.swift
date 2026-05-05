import Foundation
import CoreMotion
import Combine
import UIKit

class RenderState: ObservableObject {
    static let shared = RenderState()

    @Published var drawWorldAxes: Bool = true
    @Published var drawGravityArrow: Bool = true
    @Published var drawMagnetArrow: Bool = true
    @Published var drawBoat: Bool = true
    @Published var drawWaterSurface: Bool = true
    @Published var drawWaterBody: Bool = true

    private init() {}
}

class SensorManager: ObservableObject {
    static let shared = SensorManager()

    private let motionManager = CMMotionManager()
    private var lastGyrTimestamp: TimeInterval = 0
    private var lastDt: Float = 0

    // Quaternion state
//    @Published var qX: Float = 0
//    @Published var qY: Float = 0
//    @Published var qZ: Float = 0
//    @Published var qW: Float = 1

    @Published var data = SensorData()

    // Accelerometer reading (for arrow display)
    @Published var accelX: Float = 0
    @Published var accelY: Float = 0
    @Published var accelZ: Float = 0

    // Magnetometer reading (for arrow display)
    @Published var magX: Float = 0
    @Published var magY: Float = 0
    @Published var magZ: Float = 0

    private var qW_f: Float = 1
    private var qX_f: Float = 0
    private var qY_f: Float = 0
    private var qZ_f: Float = 0

    // Boat vertices updated by MetalViewController after each draw
    var latestBoatVertices: [Float] = Array(repeating: 0, count: 24)

    // BoxMath for water polygon computation
    private var boxMath: BoxMath!

    private init() {
        // Initialize boxMath with screen dimensions
        let screenScale = Float(UIScreen.main.scale)
        let screenBounds = UIScreen.main.bounds
        let hw = Float(screenBounds.width) * screenScale
        let hh = Float(screenBounds.height) * screenScale
        let boxD = min(hw, hh) / 2
        self.boxMath = BoxMath(hw: hw, hh: hh, d: boxD)
    }

    func start() {
        guard motionManager.isDeviceMotionAvailable else {
            print("Device motion not available")
            return
        }

        // Use device motion (fused sensor data)
        motionManager.deviceMotionUpdateInterval = 1.0 / 60.0
        motionManager.startDeviceMotionUpdates(to: .main) { [weak self] motion, error in
            guard let self = self, let motion = motion else { return }
            self.processMotion(motion)
        }
    }

    func stop() {
        motionManager.stopDeviceMotionUpdates()
    }

    private func processMotion(_ motion: CMDeviceMotion) {
        // Update sensor data
        let gx = Float(motion.rotationRate.x)
        let gy = Float(motion.rotationRate.y)
        let gz = Float(motion.rotationRate.z)

        let ax = Float(motion.userAcceleration.x)
        let ay = Float(motion.userAcceleration.y)
        let az = Float(motion.userAcceleration.z)

        let mx = Float(motion.magneticField.field.x)
        let my = Float(motion.magneticField.field.y)
        let mz = Float(motion.magneticField.field.z)

        // Gravity direction (normalized) for water surface calculation
        let grav = motion.gravity
        // userAcceleration + gravity = actual acceleration (in g, ~1.0 when stationary)
        let actualAccelX = Float(motion.userAcceleration.x) + Float(grav.x)
        let actualAccelY = Float(motion.userAcceleration.y) + Float(grav.y)
        let actualAccelZ = Float(motion.userAcceleration.z) + Float(grav.z)

        // Update config for arrow display (use actual acceleration, not normalized)
        FusionConfig.accelX = actualAccelX
        FusionConfig.accelY = actualAccelY
        FusionConfig.accelZ = actualAccelZ
        FusionConfig.magX = mx
        FusionConfig.magY = my
        FusionConfig.magZ = mz

        // Store for gravity arrow
        accelX = actualAccelX
        accelY = actualAccelY
        accelZ = actualAccelZ
    
        // Apply custom fusion algorithm using raw (unfused) gyro/accel + previous state
        let timestamp = motion.timestamp
        let dt = Float(timestamp - lastGyrTimestamp)
        lastGyrTimestamp = timestamp
        if dt <= 0 || dt > 1.0 { lastDt = 1.0 / 60.0 } else { lastDt = dt }

        // rawQ is always from iOS CMDeviceMotion (system-fused)
        let quat = motion.attitude.quaternion
        let rawQ: [Float] = [Float(quat.x), Float(quat.y), Float(quat.z), Float(quat.w)]

        // fusion
        var fusedQ: [Float] = rawQ
        if FusionConfig.algorithm != "ios" {
            let (qx, qy, qz, qw) = (qX_f, qY_f, qZ_f, qW_f)
            switch FusionConfig.algorithm {
            case "mahony3":
                let r = fuse_mahony3(gx: gx, gy: gy, gz: gz, qW: qw, qX: qx, qY: qy, qZ: qz, dt: lastDt)
                qX_f = r[0]; qY_f = r[1]; qZ_f = r[2]; qW_f = r[3]
                fusedQ = r
            case "mahony6":
                let r = fuse_mahony6(gx: gx, gy: gy, gz: gz, ax: -ax, ay: -ay, az: -az, qW: qw, qX: qx, qY: qy, qZ: qz, dt: lastDt)
                qX_f = r[0]; qY_f = r[1]; qZ_f = r[2]; qW_f = r[3]
                fusedQ = r
            case "madgwick":
                let r = fuse_madgwick(gx: gx, gy: gy, gz: gz, ax: -ax, ay: -ay, az: -az, qW: qw, qX: qx, qY: qy, qZ: qz, dt: lastDt)
                qX_f = r[0]; qY_f = r[1]; qZ_f = r[2]; qW_f = r[3]
                fusedQ = r
            case "ekf":
                let r = fuse_mahony3(gx: gx, gy: gy, gz: gz, qW: qw, qX: qx, qY: qy, qZ: qz, dt: lastDt)
                qX_f = r[0]; qY_f = r[1]; qZ_f = r[2]; qW_f = r[3]
                fusedQ = r
            default:
                break
            }
        }

        //fix yaw
        let fixedQ: [Float] = fixYaw(qx: fusedQ[0], qy: fusedQ[1], qz: fusedQ[2], qw: fusedQ[3])

        // Compute gravity in local box space from quaternion
        let fX = fixedQ[0]
        let fY = fixedQ[1]
        let fZ = fixedQ[2]
        let fW = fixedQ[3]

        let gravityLocalX =  2 * (fW * fY - fZ * fX)
        let gravityLocalY = -2 * (fY * fZ + fW * fX)
        let gravityLocalZ = -1 + 2 * (fX * fX + fY * fY)

        // Compute world axes
        let wxX =  1 - 2*(fY*fY + fZ*fZ)
        let wxY =  2 * (fX*fY - fZ*fW)
        let wxZ =  2 * (fX*fZ + fY*fW)
        let wyX =  2 * (fX*fY + fZ*fW)
        let wyY =  1 - 2*(fX*fX + fZ*fZ)
        let wyZ =  2 * (fY*fZ - fX*fW)
        let wzX =  2 * (fX*fZ - fY*fW)
        let wzY =  2 * (fY*fZ + fX*fW)
        let wzZ =  1 - 2*(fX*fX + fY*fY)

        // Compute Euler angles
        let test = fY * fW - fX * fZ
        var roll: Float = 0
        var pitch: Float = 0
        var yaw: Float = 0

        if test > 0.499 {
            roll = Float.pi / 2
            pitch = -2 * atan2(fX, fW)
            yaw = 0
        } else if test < -0.499 {
            roll = -Float.pi / 2
            pitch = 2 * atan2(fX, fW)
            yaw = 0
        } else {
            let qx2 = fX * fX
            let qy2 = fY * fY
            let qz2 = fZ * fZ
            roll = atan2(2 * (fX * fW + fY * fZ), 1 - 2 * (qx2 + qy2))
            pitch = asin(2 * test)
            yaw = atan2(2 * (fZ * fW + fX * fY), 1 - 2 * (qy2 + qz2))
        }

        // Axis-angle (canonical form)
        let qx_d = fW < 0 ? -fX : fX
        let qy_d = fW < 0 ? -fY : fY
        let qz_d = fW < 0 ? -fZ : fZ
        let qvLen = sqrt(qx_d * qx_d + qy_d * qy_d + qz_d * qz_d)

        var angleDeg: Float = 0
        var axisX: Float = 0, axisY: Float = 0, axisZ: Float = 1

        if qvLen > 1e-6 {
            angleDeg = Float(acos(Double(fW).clamped(to: -1...1))) * 2 * 180 / Float.pi
            let invLen = 1.0 / qvLen
            axisX = qx_d * invLen
            axisY = qy_d * invLen
            axisZ = qz_d * invLen
        }

        // Update SensorData
        // quatFixed = fused output (custom algo or iOS raw), quatFused = iOS raw
        let waterPoly = boxMath.solveWaterPlane(gravity: [gravityLocalX, gravityLocalY, gravityLocalZ]).polygon
        DispatchQueue.main.async {
            self.data = SensorData(
                gyro: [gx, gy, gz],
                accel: [ax, ay, az],
                magnet: [mx, my, mz],
                gyroCorr: [gx, gy, gz],
                accelCorr: [-ax, -ay, -az],
                magnetCorr: [mx, my, mz],
                quatFused: fusedQ,
                quatFixed: fixedQ,
                euler: [roll * 180 / Float.pi, pitch * 180 / Float.pi, yaw * 180 / Float.pi],
                axisAngle: [axisX, axisY, axisZ, angleDeg],
                accelRaw: [ax, ay, az],
                gravity: [gravityLocalX, gravityLocalY, gravityLocalZ],
                dt: self.lastDt,
                waterPoly: waterPoly,
                worldAxisX: [wxX, wxY, wxZ],
                worldAxisY: [wyX, wyY, wyZ],
                worldAxisZ: [wzX, wzY, wzZ],
                boatVertices: self.latestBoatVertices,
                algoParams: self.getAlgoParams()
            )
        }
    }

    func computeBoatVertices() -> [Float] {
        return latestBoatVertices
    }

    func getAlgoParams() -> [Float] {
        switch FusionConfig.algorithm {
        case "madgwick":
            return [FusionConfig.madgwickBeta, 0, 0]
        case "mahony6":
            return [FusionConfig.mahonyKp, FusionConfig.mahonyKi, 0]
        default:
            return [0, 0, 0]
        }
    }
}

struct SensorData {
    var gyro: [Float] = [0, 0, 0]
    var accel: [Float] = [0, 0, 0]
    var magnet: [Float] = [0, 0, 0]
    var gyroCorr: [Float] = [0, 0, 0]
    var accelCorr: [Float] = [0, 0, 0]
    var magnetCorr: [Float] = [0, 0, 0]
    var quatFused: [Float] = [0, 0, 0, 1]
    var quatFixed: [Float] = [0, 0, 0, 1]
    var euler: [Float] = [0, 0, 0]
    var axisAngle: [Float] = [0, 0, 0, 0]
    var accelRaw: [Float] = [0, 0, 0]
    var gravity: [Float] = [0, 0, -1]
    var dt: Float = 0
    var waterPoly: [[Float]] = []
    var worldAxisX: [Float] = [1, 0, 0]
    var worldAxisY: [Float] = [0, 1, 0]
    var worldAxisZ: [Float] = [0, 0, 1]
    var boatVertices: [Float] = Array(repeating: 0, count: 24)
    var algoParams: [Float] = [0, 0, 0]
}

extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self {
        return min(max(self, range.lowerBound), range.upperBound)
    }
}
