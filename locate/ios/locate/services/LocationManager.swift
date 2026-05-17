import Foundation
import CoreLocation
import CoreMotion

protocol LocationManagerDelegate: AnyObject {
    func didUpdateLocation(lat: Double, lng: Double, heading: Float)
}

/// GPS + 地磁方向管理
/// 对应 Android 的 LocationTrackerService
final class LocationManager: NSObject {
    weak var delegate: LocationManagerDelegate?

    private let clLocationManager = CLLocationManager()
    private let motionManager = CMMotionManager()

    private(set) var currentPosition: Position?
    private(set) var currentHeading: Float = 0

    // 是否在中国大陆需要坐标转换
    private var needsGcj02Conversion: Bool {
        let region = Locale.current.regionCode ?? ""
        return Constants.cnRegions.contains(region)
    }

    override init() {
        super.init()
        setupLocationManager()
        setupMotionManager()
    }

    private func setupLocationManager() {
        clLocationManager.delegate = self
        clLocationManager.desiredAccuracy = kCLLocationAccuracyBest
        clLocationManager.distanceFilter = 5 // 移动5米以上才更新
        clLocationManager.pausesLocationUpdatesAutomatically = false
    }

    private func setupMotionManager() {
        guard motionManager.isDeviceMotionAvailable else { return }
        motionManager.deviceMotionUpdateInterval = 0.1

        motionManager.startDeviceMotionUpdates(to: .main) { [weak self] motion, error in
            guard let motion = motion else { return }
            self?.processDeviceMotion(motion)
        }
    }

    private func processDeviceMotion(_ motion: CMDeviceMotion) {
        let gravity = motion.gravity
        var azimuth = atan2(gravity.x, gravity.y) * 180 / .pi
        if azimuth < 0 { azimuth += 360 }
        currentHeading = Float(azimuth)
    }

    func requestPermission() {
        clLocationManager.requestWhenInUseAuthorization()
    }

    func start() {
        clLocationManager.startUpdatingLocation()
        if !motionManager.isDeviceMotionActive {
            motionManager.startDeviceMotionUpdates()
        }
    }

    func stop() {
        clLocationManager.stopUpdatingLocation()
        motionManager.stopDeviceMotionUpdates()
    }

    func getCurrentHeading() -> Float {
        return currentHeading
    }

    func getCurrentPosition() -> Position? {
        return currentPosition
    }

    /// WGS84 → GCJ02 转换（中国大陆区域）
    /// 和 Android LocationTrackerService 的算法完全一致
    func gcj02Convert(wgsLat: Double, wgsLng: Double) -> (Double, Double) {
        guard needsGcj02Conversion else { return (wgsLat, wgsLng) }

        var dLat = transformLat(wgsLng - 105.0, wgsLat - 35.0)
        var dLng = transformLng(wgsLng - 105.0, wgsLat - 35.0)

        let radLat = wgsLat / 180.0 * .pi
        var magic = sin(radLat)
        magic = 1 - 0.006693421622965839 * magic * magic
        let sqrtMagic = sqrt(magic)

        dLat = (dLat * 180.0) / ((6378245.0 / sqrtMagic) * .pi * (1 - 0.006693421622965839) / (magic * sqrtMagic))
        dLng = (dLng * 180.0) / (6378245.0 / sqrtMagic * cos(radLat) * .pi)

        return (wgsLat + dLat, wgsLng + dLng)
    }

    private func transformLat(_ x: Double, _ y: Double) -> Double {
        var ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * sqrt(abs(x))
        ret += (20.0 * sin(6.0 * x * .pi) + 20.0 * sin(2.0 * x * .pi)) * 2.0 / 3.0
        ret += (20.0 * sin(y * .pi) + 40.0 * sin(y / 3.0 * .pi)) * 2.0 / 3.0
        ret += (160.0 * sin(y / 12.0 * .pi) + 320.0 * sin(y / 30.0 * .pi)) * 2.0 / 3.0
        return ret
    }

    private func transformLng(_ x: Double, _ y: Double) -> Double {
        var ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * sqrt(abs(x))
        ret += (20.0 * sin(6.0 * x * .pi) + 20.0 * sin(2.0 * x * .pi)) * 2.0 / 3.0
        ret += (20.0 * sin(x * .pi) + 40.0 * sin(x / 3.0 * .pi)) * 2.0 / 3.0
        ret += (150.0 * sin(x / 12.0 * .pi) + 300.0 * sin(x / 30.0 * .pi)) * 2.0 / 3.0
        return ret
    }
}

extension LocationManager: CLLocationManagerDelegate {
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last else { return }

        currentPosition = Position(
            lat: location.coordinate.latitude,
            lng: location.coordinate.longitude,
            accuracy: Float(location.horizontalAccuracy),
            altitude: location.altitude,
            speed: Float(location.speed),
            bearing: Float(location.course)
        )

        // 转换坐标后通知
        let (gcjLat, gcjLng) = gcj02Convert(
            wgsLat: location.coordinate.latitude,
            wgsLng: location.coordinate.longitude
        )
        delegate?.didUpdateLocation(lat: gcjLat, lng: gcjLng, heading: currentHeading)
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        print("Location error: \(error)")
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways:
            start()
        case .denied, .restricted:
            print("位置权限被拒绝")
        default:
            break
        }
    }
}