import SwiftUI

/// 气泡形状，支持每角不同半径（实现 Android 的气泡 tail 效果）
struct BubbleShape: Shape {
    let style: BubbleStyle

    func path(in rect: CGRect) -> Path {
        var path = Path()

        switch style {
        case .left:
            // topLeft=4, topRight=18, bottomLeft=18, bottomRight=18
            // Android left bubble 的 tail 在左下，用 topLeft=4 实现
            path.move(to: CGPoint(x: 4, y: 0))
            path.addLine(to: CGPoint(x: rect.width - 18, y: 0))
            path.addArc(
                center: CGPoint(x: rect.width - 18, y: 18),
                radius: 18,
                startAngle: .degrees(-90),
                endAngle: .degrees(0),
                clockwise: false
            )
            path.addLine(to: CGPoint(x: rect.width, y: rect.height - 18))
            path.addArc(
                center: CGPoint(x: rect.width - 18, y: rect.height - 18),
                radius: 18,
                startAngle: .degrees(0),
                endAngle: .degrees(90),
                clockwise: false
            )
            path.addLine(to: CGPoint(x: 18, y: rect.height))
            path.addArc(
                center: CGPoint(x: 18, y: rect.height - 18),
                radius: 18,
                startAngle: .degrees(90),
                endAngle: .degrees(180),
                clockwise: false
            )
            path.addLine(to: CGPoint(x: 0, y: 4))
            path.addArc(
                center: CGPoint(x: 4, y: 4),
                radius: 4,
                startAngle: .degrees(180),
                endAngle: .degrees(270),
                clockwise: false
            )
            path.closeSubpath()

        case .right:
            // topLeft=18, topRight=4, bottomLeft=18, bottomRight=18
            // Android right bubble 的 tail 在右下，用 topRight=4 实现
            path.move(to: CGPoint(x: 18, y: 0))
            path.addLine(to: CGPoint(x: rect.width - 4, y: 0))
            path.addArc(
                center: CGPoint(x: rect.width - 4, y: 4),
                radius: 4,
                startAngle: .degrees(-90),
                endAngle: .degrees(0),
                clockwise: false
            )
            path.addLine(to: CGPoint(x: rect.width, y: rect.height - 18))
            path.addArc(
                center: CGPoint(x: rect.width - 18, y: rect.height - 18),
                radius: 18,
                startAngle: .degrees(0),
                endAngle: .degrees(90),
                clockwise: false
            )
            path.addLine(to: CGPoint(x: 18, y: rect.height))
            path.addArc(
                center: CGPoint(x: 18, y: rect.height - 18),
                radius: 18,
                startAngle: .degrees(90),
                endAngle: .degrees(180),
                clockwise: false
            )
            path.addLine(to: CGPoint(x: 0, y: 18))
            path.addArc(
                center: CGPoint(x: 18, y: 18),
                radius: 18,
                startAngle: .degrees(180),
                endAngle: .degrees(270),
                clockwise: false
            )
            path.closeSubpath()
        }

        return path
    }
}

/// 气泡方向
enum BubbleStyle {
    case left
    case right
}
