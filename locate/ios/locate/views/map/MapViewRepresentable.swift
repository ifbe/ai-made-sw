import SwiftUI
import MapKit

private func sameCoordinate(_ lhs: CLLocationCoordinate2D?, _ rhs: CLLocationCoordinate2D?) -> Bool {
    switch (lhs, rhs) {
    case (nil, nil):
        return true
    case let (l?, r?):
        return abs(l.latitude - r.latitude) < 1e-9 && abs(l.longitude - r.longitude) < 1e-9
    default:
        return false
    }
}

/// 一条目标线的端点签名：端点没变就不重建 polyline
private struct TargetLineKey: Equatable {
    let lat: Double
    let lng: Double
    let targetLat: Double
    let targetLng: Double
}

/// MKMapView 的 SwiftUI 包装器
struct MapViewRepresentable: UIViewRepresentable {
    @Binding var centerCoordinate: CLLocationCoordinate2D
    @Binding var region: MKCoordinateRegion

    var userAnnotations: [User] = []
    var targetCoord: CLLocationCoordinate2D?
    var userLocationCoord: CLLocationCoordinate2D?
    /// 本地罗盘朝向（0=北，顺时针），金色三角要跟着转
    var selfHeading: Float = 0
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
        let coordinator = context.coordinator
        coordinator.parent = self

        // 只在 region 实际变化时同步（避免循环锁死地图拖动）
        if abs(coordinator.lastRegion.center.latitude - region.center.latitude) > 1e-6 ||
           abs(coordinator.lastRegion.center.longitude - region.center.longitude) > 1e-6 {
            mapView.setRegion(region, animated: true)
            coordinator.lastRegion = region
        }

        // SwiftUI 每次重算 body 都会走到这里，拖地图时一秒几十次。
        // 下面几个方法都会增删 MapKit 的标注/覆盖物（最贵的一步），
        // 所以输入没变就直接返回，一个都不碰。
        guard coordinator.annotationInputsChanged(
            users: userAnnotations,
            target: targetCoord,
            userLocation: userLocationCoord,
            server: serverPositionCoord,
            selfHeading: selfHeading
        ) else { return }

        coordinator.updateUserAnnotations(users: userAnnotations)
        coordinator.updateTargetAnnotation(coord: targetCoord, userLocation: userLocationCoord)
        coordinator.updateServerAnnotation(coord: serverPositionCoord)
        coordinator.updateSelfLocationAnnotation(coord: userLocationCoord, heading: selfHeading)
    }

    class Coordinator: NSObject, MKMapViewDelegate {
        var parent: MapViewRepresentable
        weak var mapView: MKMapView?
        private var mapReadyCallback: (() -> Void)?
        private var userAnnotationMap: [String: UserAnnotation] = [:]
        private var userLineKeys: [String: TargetLineKey] = [:]
        private var userTargetLines: [String: MKPolyline] = [:]
        private var myTargetLine: MKPolyline?
        private var myTargetKey: TargetLineKey?
        private var targetAnnotation: TargetAnnotation?
        private var serverPositionAnnotation: UserAnnotation?
        private var selfLocationAnnotation: UserAnnotation?
        var lastRegion: MKCoordinateRegion = MKCoordinateRegion()  // 防止循环更新

        // 上一次的输入快照，用来判断有没有必要动 MapKit
        private var lastUsers: [User] = []
        private var lastTarget: CLLocationCoordinate2D?
        private var lastSelf: CLLocationCoordinate2D?
        private var lastServer: CLLocationCoordinate2D?
        private var lastSelfHeadingDegree = 0
        private var hasSnapshot = false

        init(_ parent: MapViewRepresentable) {
            self.parent = parent
            super.init()
        }

        /// 标注相关的输入有没有变。没变的话 updateUIView 后面那几步全都可以省掉。
        func annotationInputsChanged(
            users: [User],
            target: CLLocationCoordinate2D?,
            userLocation: CLLocationCoordinate2D?,
            server: CLLocationCoordinate2D?,
            selfHeading: Float
        ) -> Bool {
            // 朝向按 1° 量化：罗盘读数一直在抖，不量化的话每帧都要重画箭头
            let headingDegree = Int(selfHeading.rounded())
            if hasSnapshot,
               users == lastUsers,
               sameCoordinate(target, lastTarget),
               sameCoordinate(userLocation, lastSelf),
               sameCoordinate(server, lastServer),
               headingDegree == lastSelfHeadingDegree {
                return false
            }
            hasSnapshot = true
            lastUsers = users
            lastTarget = target
            lastSelf = userLocation
            lastServer = server
            lastSelfHeadingDegree = headingDegree
            return true
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

        // MARK: - 标注同步
        // 一律"原地改"，不再 remove + add：增删标注会让 MapKit 重建标注视图并重跑动画，
        // 拖动时每秒几十次的话必卡。

        func updateUserAnnotations(users: [User]) {
            guard let mapView = mapView else { return }
            let currentUsernames = Set(users.map { $0.username })

            // 移除离开的用户（包括其目标线和标记）
            for username in Set(userAnnotationMap.keys).subtracting(currentUsernames) {
                if let annotation = userAnnotationMap.removeValue(forKey: username) {
                    mapView.removeAnnotation(annotation)
                }
                removeUserLine(username)
                userLineKeys.removeValue(forKey: username)
            }

            for user in users {
                // 还没上报过坐标的人（服务器上还是 0,0）不画箭头：
                // 否则会在几内亚湾堆一个标记，点队友列表也会飞过去
                if user.lat == 0 && user.lng == 0 {
                    if let annotation = userAnnotationMap.removeValue(forKey: user.username) {
                        mapView.removeAnnotation(annotation)
                    }
                    removeUserLine(user.username)
                    userLineKeys.removeValue(forKey: user.username)
                    continue
                }

                if let existing = userAnnotationMap[user.username] {
                    existing.coordinate = CLLocationCoordinate2D(latitude: user.lat, longitude: user.lng)
                    existing.title = user.nickname ?? user.username
                    if existing.heading != user.heading {
                        existing.heading = user.heading
                        // heading 不是 KVO 属性，改了得手动让箭头重画
                        mapView.view(for: existing)?.setNeedsDisplay()
                    }
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

                updateUserLine(for: user)
            }
        }

        /// 用户→目标 的连线：只有端点变了才重建
        private func updateUserLine(for user: User) {
            guard let mapView = mapView else { return }

            let key: TargetLineKey?
            if let targetLat = user.targetLat, let targetLng = user.targetLng {
                key = TargetLineKey(lat: user.lat, lng: user.lng, targetLat: targetLat, targetLng: targetLng)
            } else {
                key = nil
            }

            guard userLineKeys[user.username] != key else { return }
            userLineKeys[user.username] = key

            removeUserLine(user.username)
            if let key = key {
                let line = makeTargetLine(
                    from: CLLocationCoordinate2D(latitude: key.lat, longitude: key.lng),
                    to: CLLocationCoordinate2D(latitude: key.targetLat, longitude: key.targetLng)
                )
                userTargetLines[user.username] = line
                mapView.addOverlay(line)
            }
        }

        private func removeUserLine(_ username: String) {
            guard let mapView = mapView else { return }
            if let line = userTargetLines.removeValue(forKey: username) {
                mapView.removeOverlay(line)
            }
        }

        func updateTargetAnnotation(coord: CLLocationCoordinate2D?, userLocation: CLLocationCoordinate2D?) {
            guard let mapView = mapView else { return }

            if let coord = coord {
                if let existing = targetAnnotation {
                    existing.coordinate = coord
                } else {
                    let annotation = TargetAnnotation(coordinate: coord)
                    targetAnnotation = annotation
                    mapView.addAnnotation(annotation)
                }
            } else if let existing = targetAnnotation {
                mapView.removeAnnotation(existing)
                targetAnnotation = nil
            }

            // 我的位置→目标 的连线：端点没变就不动
            let key: TargetLineKey?
            if let coord = coord, let userLoc = userLocation {
                key = TargetLineKey(
                    lat: userLoc.latitude,
                    lng: userLoc.longitude,
                    targetLat: coord.latitude,
                    targetLng: coord.longitude
                )
            } else {
                key = nil
            }
            guard myTargetKey != key else { return }
            myTargetKey = key

            if let line = myTargetLine {
                mapView.removeOverlay(line)
                myTargetLine = nil
            }
            if let key = key {
                let line = makeTargetLine(
                    from: CLLocationCoordinate2D(latitude: key.lat, longitude: key.lng),
                    to: CLLocationCoordinate2D(latitude: key.targetLat, longitude: key.targetLng)
                )
                myTargetLine = line
                mapView.addOverlay(line)
            }
        }

        func updateServerAnnotation(coord: CLLocationCoordinate2D?) {
            guard let mapView = mapView else { return }

            if let coord = coord {
                if let existing = serverPositionAnnotation {
                    existing.coordinate = coord
                } else {
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
            } else if let existing = serverPositionAnnotation {
                mapView.removeAnnotation(existing)
                serverPositionAnnotation = nil
            }
        }

        func updateSelfLocationAnnotation(coord: CLLocationCoordinate2D?, heading: Float) {
            guard let mapView = mapView else { return }

            if let coord = coord {
                if let existing = selfLocationAnnotation {
                    existing.coordinate = coord
                    if existing.heading != heading {
                        existing.heading = heading
                        // heading 不是 KVO 属性，改了得手动让三角重画
                        mapView.view(for: existing)?.setNeedsDisplay()
                    }
                } else {
                    let annotation = UserAnnotation(
                        username: "本地位置",
                        lat: coord.latitude,
                        lng: coord.longitude,
                        heading: heading,
                        isSelf: true
                    )
                    annotation.title = "本地"
                    selfLocationAnnotation = annotation
                    mapView.addAnnotation(annotation)
                }
            } else if let existing = selfLocationAnnotation {
                mapView.removeAnnotation(existing)
                selfLocationAnnotation = nil
            }
        }
    }
}
