import Foundation
import MapKit

/// 用户标注（其他用户或自己）
class UserAnnotation: NSObject, MKAnnotation {
    dynamic var coordinate: CLLocationCoordinate2D
    var title: String?
    var subtitle: String?
    var heading: Float
    var isSelf: Bool

    init(username: String, lat: Double, lng: Double, heading: Float, isSelf: Bool = false) {
        self.coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lng)
        self.title = username
        self.heading = heading
        self.isSelf = isSelf
        super.init()
    }

    func update(lat: Double, lng: Double, heading: Float) {
        self.coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lng)
        self.heading = heading
    }
}

/// 目标点标注
class TargetAnnotation: NSObject, MKAnnotation {
    dynamic var coordinate: CLLocationCoordinate2D
    var title: String? = "目标"

    init(coordinate: CLLocationCoordinate2D) {
        self.coordinate = coordinate
        super.init()
    }

    convenience init(lat: Double, lng: Double) {
        self.init(coordinate: CLLocationCoordinate2D(latitude: lat, longitude: lng))
    }

    func update(lat: Double, lng: Double) {
        self.coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lng)
    }
}