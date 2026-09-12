import SwiftUI

/// 屏幕中心十字星 + 中心坐标。
///
/// ⚠️ 调用方必须给它 `.ignoresSafeArea()`：地图（MKMapView）是全屏的，它的中心
/// 就是屏幕中心；如果十字星被安全区往内挤十几点，它的"中心"就会比地图中心低，
/// 看起来就是"飞到某个点以后，十字星和那个点不重合"。
struct CrosshairOverlay: View {
    let centerLat: Double
    let centerLng: Double
    let altitude: Double?

    var body: some View {
        GeometryReader { geometry in
            let cx = geometry.size.width / 2
            let cy = geometry.size.height / 2

            ZStack {
                // 十字丝（红色）
                Path { path in
                    path.move(to: CGPoint(x: cx - 20, y: cy))
                    path.addLine(to: CGPoint(x: cx + 20, y: cy))
                    path.move(to: CGPoint(x: cx, y: cy - 20))
                    path.addLine(to: CGPoint(x: cx, y: cy + 20))
                }
                .stroke(Color.red.opacity(0.8), lineWidth: 1)

                // 中心小方块
                Path { path in
                    path.addRect(CGRect(x: cx - 4, y: cy - 4, width: 8, height: 8))
                }
                .stroke(Color.red.opacity(0.8), lineWidth: 1)

                // ─── 中心坐标大字（红框背景）──────────────────
                VStack(alignment: .leading, spacing: 0) {
                    Text(String(format: "经度: %.6f", centerLng))
                    Text(String(format: "纬度: %.6f", centerLat))
                    Text(String(format: "海拔: %.1f m", altitude ?? 0))
                }
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.red)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.white)
                        .overlay(
                            RoundedRectangle(cornerRadius: 4)
                                .stroke(Color.red, lineWidth: 1)
                        )
                )
                .offset(y: -60)  // 十字丝上方
            }
        }
        .allowsHitTesting(false)
    }
}

/// 四角坐标（白底黑字）。
/// 这个留在安全区内 —— 顶到刘海/状态栏底下就看不清了。
struct CornerCoordsOverlay: View {
    let corners: CornerCoordinates

    var body: some View {
        VStack {
            HStack {
                coordLabel(lat: corners.topLeft.lat, lng: corners.topLeft.lng)
                Spacer()
                coordLabel(lat: corners.topRight.lat, lng: corners.topRight.lng)
            }
            Spacer()
            HStack {
                coordLabel(lat: corners.bottomLeft.lat, lng: corners.bottomLeft.lng)
                Spacer()
                coordLabel(lat: corners.bottomRight.lat, lng: corners.bottomRight.lng)
            }
        }
        .padding(4)
        .allowsHitTesting(false)
    }

    private func coordLabel(lat: Double, lng: Double) -> some View {
        HStack(spacing: 2) {
            Text(String(format: "%.5f", lat))
                .font(.system(size: 9, design: .monospaced))
            Text(String(format: "%.5f", lng))
                .font(.system(size: 9, design: .monospaced))
        }
        .foregroundColor(.black)
        .padding(.horizontal, 3)
        .padding(.vertical, 2)
        .background(Color.white.opacity(0.7))
        .cornerRadius(3)
    }
}
