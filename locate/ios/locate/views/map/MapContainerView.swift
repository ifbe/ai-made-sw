import SwiftUI
import MapKit
import Combine

struct CornerCoordinates {
    let topLeft: (lat: Double, lng: Double)
    let topRight: (lat: Double, lng: Double)
    let bottomLeft: (lat: Double, lng: Double)
    let bottomRight: (lat: Double, lng: Double)
}

/// 地图主视图（MapKit + Overlay 层）
/// 对应 Android 的 MapActivity + MapViewImpl
struct MapContainerView: View {
    @StateObject var viewModel: MapViewModel
    var onLogout: () -> Void

    @State private var region = MKCoordinateRegion(
        center: CLLocationCoordinate2D(latitude: 31.9, longitude: 118.8),
        span: MKCoordinateSpan(latitudeDelta: 0.01, longitudeDelta: 0.01)
    )
    @State private var centerLat: Double = 31.9
    @State private var centerLng: Double = 118.8
    @State private var currentAltitude: Double?
    @State private var corners: CornerCoordinates = CornerCoordinates(
        topLeft: (0, 0), topRight: (0, 0),
        bottomLeft: (0, 0), bottomRight: (0, 0)
    )
    @State private var hasTarget: Bool = false
    @State private var userLocation: CLLocationCoordinate2D?
    @State private var userListWidth: CGFloat = 100

    var body: some View {
        ZStack {
            MapViewRepresentable(
                centerCoordinate: .constant(region.center),
                region: $region,
                userAnnotations: viewModel.otherUsers,
                targetCoord: viewModel.uiState.targetLat != nil ?
                    CLLocationCoordinate2D(latitude: viewModel.uiState.targetLat!, longitude: viewModel.uiState.targetLng!) : nil,
                userLocationCoord: userLocation,
                serverPositionCoord: nil,
                onMapReady: {
                    viewModel.onFirstMapReady()
                },
                onMapClick: { lat, lng in
                    // 地图层只显示，不响应点击
                },
                onRegionChange: { zoom, lat, lng in
                    centerLat = lat
                    centerLng = lng
                    currentAltitude = self.viewModel.locationManager?.getCurrentPosition()?.altitude
                    updateCorners(span: zoom)
                }
            )
            .ignoresSafeArea()

            // 四角坐标十字丝
            CrosshairOverlay(
                centerLat: centerLat,
                centerLng: centerLng,
                altitude: currentAltitude,
                corners: corners
            )

            // 右上角：队友列表面板
            VStack {
                HStack {
                    Spacer()
                    UserListPanel(
                        otherUsers: viewModel.otherUsers,
                        panelWidth: userListWidth,
                        onSelectUser: { coord in
                            print("DEBUG: onSelectUser tapped, coord=\(coord.latitude),\(coord.longitude)")
                            let currentSpan = region.span
                            region = MKCoordinateRegion(center: coord, span: currentSpan)
                        },
                        onSelectTarget: { coord in
                            print("DEBUG: onSelectTarget tapped, coord=\(coord.latitude),\(coord.longitude)")
                            let currentSpan = region.span
                            region = MKCoordinateRegion(center: coord, span: currentSpan)
                        }
                    )
                    .frame(width: userListWidth, height: nil)
                }
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
            .padding(.trailing, 16)
            .padding(.top, 60)

            // 左上角：本地设置面板
            VStack {
                HStack {
                    LocalSettingsPanel(
                        localPosition: userLocation,
                        hasTarget: hasTarget,
                        onTapMyLocation: {
                            print("DEBUG: onTapMyLocation tapped, userLocation=\(String(describing: userLocation))")
                            if let loc = userLocation {
                                let currentSpan = self.region.span
                                self.region = MKCoordinateRegion(center: loc, span: currentSpan)
                            } else if let pos = self.viewModel.locationManager?.getCurrentPosition() {
                                print("DEBUG: userLocation nil, fallback to getCurrentPosition: \(pos.lat),\(pos.lng)")
                                let (gcjLat, gcjLng) = self.viewModel.locationManager!.gcj02Convert(wgsLat: pos.lat, wgsLng: pos.lng)
                                let coord = CLLocationCoordinate2D(latitude: gcjLat, longitude: gcjLng)
                                let currentSpan = self.region.span
                                self.region = MKCoordinateRegion(center: coord, span: currentSpan)
                            }
                        },
                        onTapMyTarget: {
                            print("DEBUG: onTapMyTarget tapped, hasTarget=\(hasTarget)")
                            if hasTarget {
                                self.viewModel.clearTarget()
                                hasTarget = false
                            } else {
                                self.viewModel.setTarget(lat: centerLat, lng: centerLng)
                                hasTarget = true
                            }
                        }
                    )
                    .frame(width: userListWidth)
                    .padding(.leading, 16)
                    .padding(.top, 60)
                    Spacer()
                }
                Spacer()
            }

            // 左下角：连接状态（点它退出）
            VStack {
                Spacer()
                HStack {
                    Button(action: onLogout) {
                        ConnectionStatusView(
                            status: viewModel.connectionStatus,
                            onlineCount: viewModel.onlineCount
                        )
                    }
                    .buttonStyle(.plain)
                    .padding(.leading, 16)
                    .padding(.bottom, 32)
                    Spacer()
                }
            }

            // 自动登录中
            if viewModel.uiState.autoLoggingIn {
                ProgressView()
                    .scaleEffect(1.5)
            }
        }
        .onAppear {
            viewModel.onMapReady = { [self] in
                if let pos = viewModel.locationManager?.getCurrentPosition() {
                    let coord = CLLocationCoordinate2D(latitude: pos.lat, longitude: pos.lng)
                    userLocation = coord
                    withAnimation(.easeInOut(duration: 0.5)) { region.center = coord }
                    centerLat = pos.lat
                    centerLng = pos.lng
                    let zoom = log2(360.0 / region.span.longitudeDelta)
                    updateCorners(span: zoom)
                }
            }
            viewModel.onSelfLocationUpdate = { lat, lng in
                userLocation = CLLocationCoordinate2D(latitude: lat, longitude: lng)
            }
            viewModel.onServerPositionUpdate = { lat, lng, heading in
                // 不再需要
            }
        }
        .onChange(of: viewModel.uiState.targetLat) { newTargetLat in
            hasTarget = newTargetLat != nil
        }
        .alert("错误", isPresented: .constant(viewModel.uiState.error != nil)) {
            Button("确定") { viewModel.clearError() }
        } message: {
            Text(viewModel.uiState.error ?? "")
        }
    }

    private func updateCorners(span: Double) {
        // zoom = log2(360.0 / longitudeDelta) → longitudeDelta = 360.0 / 2^zoom
        // latitudeDelta 按屏幕宽高比近似计算
        let lngDelta = 360.0 / pow(2.0, span)
        let latDelta = lngDelta * (UIScreen.main.bounds.height / UIScreen.main.bounds.width)
        let halfLat = latDelta / 2
        let halfLng = lngDelta / 2
        corners = CornerCoordinates(
            topLeft: (centerLat + halfLat, centerLng - halfLng),
            topRight: (centerLat + halfLat, centerLng + halfLng),
            bottomLeft: (centerLat - halfLat, centerLng - halfLng),
            bottomRight: (centerLat - halfLat, centerLng + halfLng)
        )
    }
}