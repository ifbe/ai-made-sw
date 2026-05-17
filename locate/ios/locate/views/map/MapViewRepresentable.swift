import SwiftUI
import MapKit

/// MKMapView 的 SwiftUI 包装器
struct MapViewRepresentable: UIViewRepresentable {
    @Binding var centerCoordinate: CLLocationCoordinate2D
    @Binding var region: MKCoordinateRegion

    var userAnnotations: [User] = []
    var targetCoord: CLLocationCoordinate2D?
    var userLocationCoord: CLLocationCoordinate2D?
    var serverPositionCoord: CLLocationCoordinate2D?

    var onMapReady: (() -> Void)?
    var onMapClick: ((Double, Double) -> Void)?
    var onRegionChange: ((Double, Double, Double) -> Void)?

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> MKMapView {
        let mapView = MKMapView()
        mapView.delegate = context.coordinator
        mapView.showsUserLocation = true
        mapView.showsUserLocation = false  // 用自定义标注，不用默认蓝点
        mapView.showsCompass = false
        mapView.showsScale = false
        mapView.isRotateEnabled = false

        mapView.register(UserAnnotationView.self, forAnnotationViewWithReuseIdentifier: UserAnnotationView.reuseIdentifier)
        mapView.register(TargetAnnotationView.self, forAnnotationViewWithReuseIdentifier: TargetAnnotationView.reuseIdentifier)

        // Initial region
        mapView.setRegion(region, animated: false)
        context.coordinator.lastRegion = region

        let tapGesture = UITapGestureRecognizer(target: context.coordinator, action: #selector(Coordinator.handleTap(_:)))
        mapView.addGestureRecognizer(tapGesture)

        context.coordinator.mapView = mapView

        DispatchQueue.main.async {
            context.coordinator.notifyMapReady()
        }

        return mapView
    }

    func updateUIView(_ mapView: MKMapView, context: Context) {
        // 只在 region 实际变化时同步（避免循环锁死地图拖动）
        if abs(context.coordinator.lastRegion.center.latitude - region.center.latitude) > 1e-6 ||
           abs(context.coordinator.lastRegion.center.longitude - region.center.longitude) > 1e-6 {
            mapView.setRegion(region, animated: true)
            context.coordinator.lastRegion = region
        }
        context.coordinator.updateUserAnnotations(users: userAnnotations)
        context.coordinator.updateTargetAnnotation(coord: targetCoord, userLocation: userLocationCoord)
        context.coordinator.updateServerAnnotation(coord: serverPositionCoord)
        context.coordinator.updateSelfLocationAnnotation(coord: userLocationCoord)
    }

    class Coordinator: NSObject, MKMapViewDelegate {
        var parent: MapViewRepresentable
        weak var mapView: MKMapView?
        private var mapReadyCallback: (() -> Void)?
        private var userAnnotationMap: [String: UserAnnotation] = [:]
        private var myTargetLine: MKPolyline?
        private var userTargetLines: [String: MKPolyline] = [:]
        private var serverPositionAnnotation: UserAnnotation?
        private var selfLocationAnnotation: UserAnnotation?
        var lastRegion: MKCoordinateRegion = MKCoordinateRegion()  // 防止循环更新

        init(_ parent: MapViewRepresentable) {
            self.parent = parent
            super.init()
        }

        func notifyMapReady() { parent.onMapReady?() }

        @objc func handleTap(_ gesture: UITapGestureRecognizer) {
            guard let mapView = gesture.view as? MKMapView else { return }
            let point = gesture.location(in: mapView)
            let coord = mapView.convert(point, toCoordinateFrom: mapView)
            parent.onMapClick?(coord.latitude, coord.longitude)
        }

        func mapView(_ mapView: MKMapView, regionDidChangeAnimated animated: Bool) {
            let center = mapView.centerCoordinate
            let region = mapView.region
            let zoom = log2(360.0 / region.span.longitudeDelta)
            parent.onRegionChange?(zoom, center.latitude, center.longitude)
        }

        func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
            if annotation is MKUserLocation { return nil }
            if let userAnnotation = annotation as? UserAnnotation {
                return mapView.dequeueReusableAnnotationView(withIdentifier: UserAnnotationView.reuseIdentifier, for: annotation) as? UserAnnotationView
                    ?? UserAnnotationView(annotation: annotation, reuseIdentifier: UserAnnotationView.reuseIdentifier)
            }
            if annotation is TargetAnnotation {
                return mapView.dequeueReusableAnnotationView(withIdentifier: TargetAnnotationView.reuseIdentifier, for: annotation) as? TargetAnnotationView
                    ?? TargetAnnotationView(annotation: annotation, reuseIdentifier: TargetAnnotationView.reuseIdentifier)
            }
            return nil
        }

        func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
            if let polyline = overlay as? MKPolyline {
                return TargetLineRenderer(overlay: polyline)
            }
            return MKOverlayRenderer(overlay: overlay)
        }

        func updateUserAnnotations(users: [User]) {
            guard let mapView = mapView else { return }
            let currentUsernames = Set(users.map { $0.username })
            let existingUsernames = Set(userAnnotationMap.keys)

            // 移除离开的用户（包括其目标线和标记）
            for username in existingUsernames.subtracting(currentUsernames) {
                if let annotation = userAnnotationMap[username] {
                    mapView.removeAnnotation(annotation)
                    userAnnotationMap.removeValue(forKey: username)
                }
                if let line = userTargetLines[username] {
                    mapView.removeOverlay(line)
                    userTargetLines.removeValue(forKey: username)
                }
            }

            for user in users {
                if let existing = userAnnotationMap[user.username] {
                    existing.coordinate = CLLocationCoordinate2D(latitude: user.lat, longitude: user.lng)
                    existing.heading = user.heading
                    existing.title = user.nickname ?? user.username
                } else {
                    let annotation = UserAnnotation(
                        username: user.username,
                        lat: user.lat,
                        lng: user.lng,
                        heading: user.heading,
                        isSelf: false
                    )
                    annotation.title = user.nickname ?? user.username
                    userAnnotationMap[user.username] = annotation
                    mapView.addAnnotation(annotation)
                }

                // 用户→目标 的连线
                if let targetLat = user.targetLat, let targetLng = user.targetLng {
                    // 移除旧的该用户目标线
                    if let oldLine = userTargetLines[user.username] {
                        mapView.removeOverlay(oldLine)
                    }
                    let userCoord = CLLocationCoordinate2D(latitude: user.lat, longitude: user.lng)
                    let targetCoord = CLLocationCoordinate2D(latitude: targetLat, longitude: targetLng)
                    let line = makeTargetLine(from: userCoord, to: targetCoord)
                    userTargetLines[user.username] = line
                    mapView.addOverlay(line)
                } else {
                    // 无目标则移除该用户的连线
                    if let oldLine = userTargetLines[user.username] {
                        mapView.removeOverlay(oldLine)
                        userTargetLines.removeValue(forKey: user.username)
                    }
                }
            }
        }

        func updateTargetAnnotation(coord: CLLocationCoordinate2D?, userLocation: CLLocationCoordinate2D?) {
            guard let mapView = mapView else { return }

            // 移除目标标注
            let existingTargets = mapView.annotations.filter { $0 is TargetAnnotation }
            mapView.removeAnnotations(existingTargets)

            // 移除我的目标连线
            if let line = myTargetLine {
                mapView.removeOverlay(line)
                myTargetLine = nil
            }

            if let coord = coord {
                let annotation = TargetAnnotation(coordinate: coord)
                mapView.addAnnotation(annotation)

                // 我的位置→目标 的连线
                if let userLoc = userLocation {
                    let line = makeTargetLine(from: userLoc, to: coord)
                    myTargetLine = line
                    mapView.addOverlay(line)
                }
            }
        }

        func updateServerAnnotation(coord: CLLocationCoordinate2D?) {
            guard let mapView = mapView else { return }
            if let existing = serverPositionAnnotation {
                mapView.removeAnnotation(existing)
                serverPositionAnnotation = nil
            }
            if let coord = coord {
                let annotation = UserAnnotation(
                    username: "服务器",
                    lat: coord.latitude,
                    lng: coord.longitude,
                    heading: 0,
                    isSelf: false
                )
                annotation.title = "服务器"
                serverPositionAnnotation = annotation
                mapView.addAnnotation(annotation)
            }
        }

        func updateSelfLocationAnnotation(coord: CLLocationCoordinate2D?) {
            guard let mapView = mapView else { return }
            if let existing = selfLocationAnnotation {
                mapView.removeAnnotation(existing)
                selfLocationAnnotation = nil
            }
            if let coord = coord {
                let annotation = UserAnnotation(
                    username: "本地位置",
                    lat: coord.latitude,
                    lng: coord.longitude,
                    heading: 0,
                    isSelf: true
                )
                annotation.title = "本地"
                selfLocationAnnotation = annotation
                mapView.addAnnotation(annotation)
            }
        }
    }
}