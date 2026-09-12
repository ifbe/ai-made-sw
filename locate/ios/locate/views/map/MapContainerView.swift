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
    @State private var localPanelWidth: CGFloat = 120

    var body: some View {
        ZStack {
            MapViewRepresentable(
                centerCoordinate: .constant(region.center),
                region: $region,
                userAnnotations: viewModel.otherUsers,
                targetCoord: viewModel.uiState.targetLat != nil ?
                    CLLocationCoordinate2D(latitude: viewModel.uiState.targetLat!, longitude: viewModel.uiState.targetLng!) : nil,
                userLocationCoord: userLocation,
                selfHeading: viewModel.locationManager?.getCurrentHeading() ?? 0,
                serverPositionCoord: nil,
                onMapReady: {
                    viewModel.onFirstMapReady()
                },
                onMapClick: { lat, lng in
                    // 地图层只显示，不响应点击
                },
                onRegionChange: { zoom, lat, lng in
                    // 拖动时这个回调一秒来几十次，值没变就别写 @State：
                    // 每写一次整个页面（连 MapKit 包装器）都要重算一遍
                    let roundedLat = (lat * 1_000_000).rounded() / 1_000_000
                    let roundedLng = (lng * 1_000_000).rounded() / 1_000_000
                    guard roundedLat != centerLat || roundedLng != centerLng else { return }
                    centerLat = roundedLat
                    centerLng = roundedLng
                    let altitude = self.viewModel.locationManager?.getCurrentPosition()?.altitude
                    if altitude != currentAltitude {
                        currentAltitude = altitude
                    }
                    updateCorners(span: zoom)
                }
            )
            .ignoresSafeArea()

            // 中心十字星：必须和地图一样铺满全屏，否则它的中心比地图中心低十几点，
            // 飞到某个点以后十字星就和该点不重合
            CrosshairOverlay(
                centerLat: centerLat,
                centerLng: centerLng,
                altitude: currentAltitude
            )
            .ignoresSafeArea()

            // 四角坐标（留在安全区内，别钻到刘海底下）
            CornerCoordsOverlay(corners: corners)

            // 未登录 / 自动登录中：顶部悬浮的登录矩形（悬浮着，不把地图顶下去）
            if !viewModel.uiState.loggedIn {
                VStack {
                    LoginCard(viewModel: viewModel)
                        .padding(.horizontal, 16)
                        .padding(.top, 12)
                    Spacer()
                }
            }

            // 登录后：左上角「本地」+ 右上角「同服人数」
            if viewModel.uiState.loggedIn {
                cornerPanels
            }

            // 左下角：日志矩形
            VStack {
                Spacer()
                HStack {
                    LogPanel()
                        .padding(.leading, 20)
                        .padding(.bottom, 32)
                    Spacer()
                }
            }
        }
        .onAppear {
            viewModel.onMapReady = { [self] in
                if let pos = viewModel.locationManager?.getCurrentPosition() {
                    // getCurrentPosition() 是原始 WGS-84，地图是 GCJ-02：
                    // 直接拿来用在国内会差 300~600 米，必须转一次
                    let (gcjLat, gcjLng) = viewModel.locationManager!.gcj02Convert(wgsLat: pos.lat, wgsLng: pos.lng)
                    let coord = CLLocationCoordinate2D(latitude: gcjLat, longitude: gcjLng)
                    userLocation = coord
                    withAnimation(.easeInOut(duration: 0.5)) { region.center = coord }
                    centerLat = gcjLat
                    centerLng = gcjLng
                    let zoom = log2(360.0 / region.span.longitudeDelta)
                    updateCorners(span: zoom)
                }
            }
            viewModel.onSelfLocationUpdate = { lat, lng in
                userLocation = CLLocationCoordinate2D(latitude: lat, longitude: lng)
            }
            viewModel.onServerPositionUpdate = { _, _, _ in
                // 不再需要
            }
        }
        .onChange(of: viewModel.uiState.targetLat) { newTargetLat in
            hasTarget = newTargetLat != nil
        }
        .alert("错误", isPresented: .constant(viewModel.uiState.error != nil && viewModel.uiState.loggedIn)) {
            Button("确定") { viewModel.clearError() }
        } message: {
            Text(viewModel.uiState.error ?? "")
        }
    }

    /// 左上角本地面板 + 右上角队友列表（只在登录后显示）
    @ViewBuilder
    private var cornerPanels: some View {
        // 右上角：队友列表面板
        VStack {
            HStack {
                Spacer()
                UserListPanel(
                    otherUsers: viewModel.otherUsers,
                    selfUsername: viewModel.loginUsername ?? viewModel.uiState.username,
                    selfCoordinate: userLocation,
                    panelWidth: userListWidth,
                    onSelectUser: { coord in
                        let currentSpan = region.span
                        region = MKCoordinateRegion(center: coord, span: currentSpan)
                    },
                    onSelectTarget: { coord in
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
        .padding(.top, 44)

        // 左上角：本地设置面板（右上角带「退出登录」）
        VStack {
            HStack {
                LocalSettingsPanel(
                    localPosition: userLocation,
                    hasTarget: hasTarget,
                    onTapMyLocation: {
                        if let loc = userLocation {
                            let currentSpan = self.region.span
                            self.region = MKCoordinateRegion(center: loc, span: currentSpan)
                        } else if let pos = self.viewModel.locationManager?.getCurrentPosition() {
                            let (gcjLat, gcjLng) = self.viewModel.locationManager!.gcj02Convert(wgsLat: pos.lat, wgsLng: pos.lng)
                            let coord = CLLocationCoordinate2D(latitude: gcjLat, longitude: gcjLng)
                            let currentSpan = self.region.span
                            self.region = MKCoordinateRegion(center: coord, span: currentSpan)
                        }
                    },
                    onTapMyTarget: {
                        if hasTarget {
                            self.viewModel.clearTarget()
                            hasTarget = false
                        } else {
                            self.viewModel.setTarget(lat: centerLat, lng: centerLng)
                            hasTarget = true
                        }
                    },
                    onTapLogout: {
                        self.viewModel.logout()
                    }
                )
                .frame(width: localPanelWidth)
                .padding(.leading, 16)
                .padding(.top, 44)
                Spacer()
            }
            Spacer()
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
