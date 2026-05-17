import SwiftUI

struct CrosshairOverlay: View {
    let centerLat: Double
    let centerLng: Double
    let altitude: Double?
    let corners: CornerCoordinates

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

                // ─── 中心坐标大字（Android 样式，红框背景）──────────────────
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

                // ─── 四角坐标（白底黑字）──────────────────────────────────
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
            }
        }
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