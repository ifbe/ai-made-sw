import SwiftUI
import UIKit

/// 3D 坐标轴视图（对应 Android AxisView）
/// 红=X，绿=Y，蓝=Z，Z轴斜向45度，6个旋转按钮点击发送 X+/X-/Y+/Y-/Z+/Z-
struct AxisView: UIViewRepresentable {
    var onAxisRotation: ((String) -> Void)?

    func makeUIView(context: Context) -> AxisUIView {
        let view = AxisUIView()
        view.onRotation = onAxisRotation
        return view
    }

    func updateUIView(_ uiView: AxisUIView, context: Context) {
        uiView.onRotation = onAxisRotation
    }
}

/// 内部 UIView 实现
class AxisUIView: UIView {

    var onRotation: ((String) -> Void)?

    // 颜色
    private let xColor = UIColor(red: 1.0, green: 0.267, blue: 0.267, alpha: 1.0)       // #FF4444
    private let yColor = UIColor(red: 0.267, green: 0.667, blue: 0.267, alpha: 1.0)   // #44AA44
    private let zColor = UIColor(red: 0.267, green: 0.267, blue: 1.0, alpha: 1.0)    // #4444FF

    private let axisPaint = UIBezierPath()
    private let fillPaint = UIColor.clear
    private let labelFont = UIFont.systemFont(ofSize: 12)
    private let btnTextFont = UIFont.systemFont(ofSize: 14)
    private let btnRadius: CGFloat = 16

    // 6个按钮区域 [x1, y1, x2, y2]（iOS CGRect 坐标 y 从上到下）
    // 顺序：0=X+按钮，1=X-按钮，2=Y+按钮，3=Y-按钮，4=Z+按钮，5=Z-按钮
    private var btnRects: [CGRect] = []

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        backgroundColor = .clear
    }

    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }
        let w = rect.width
        let h = rect.height
        guard w > 0, h > 0 else { return }

        let cx = w / 2
        let cy = h / 2
        let len = min(w, h) * 0.28
        let r = min(w, h) * 0.07

        // 重置按钮区域
        btnRects = []

        // === X轴（红）===
        ctx.setStrokeColor(xColor.cgColor)
        ctx.setLineWidth(2.5)
        ctx.move(to: CGPoint(x: cx - len, y: cy))
        ctx.addLine(to: CGPoint(x: cx + len, y: cy))
        ctx.strokePath()

        // X+ 箭头
        drawArrow(ctx: ctx, x: cx + len, y: cy, angle: 0, color: xColor)

        // X+ 按钮
        let bx = cx + len + r + 4
        let bxRect = CGRect(x: bx - r, y: cy - r, width: r * 2, height: r * 2)
        btnRects.append(bxRect)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(bxRect)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(bxRect)
        drawBtnText(ctx: ctx, text: "⟳", x: bx, y: cy, color: xColor)

        // X- 按钮
        let bx2 = cx - len - r - 4
        let bxRect2 = CGRect(x: bx2 - r, y: cy - r, width: r * 2, height: r * 2)
        btnRects.append(bxRect2)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(bxRect2)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(bxRect2)
        drawBtnText(ctx: ctx, text: "⟲", x: bx2, y: cy, color: xColor)

        // === Y轴（绿）===
        ctx.setStrokeColor(yColor.cgColor)
        ctx.setLineWidth(2.5)
        ctx.move(to: CGPoint(x: cx, y: cy - len))
        ctx.addLine(to: CGPoint(x: cx, y: cy + len))
        ctx.strokePath()

        // Y+ 箭头（向上，-90度）
        drawArrow(ctx: ctx, x: cx, y: cy - len, angle: -.pi / 2, color: yColor)

        // Y+ 按钮
        let by = cy - len - r - 4
        let byRect = CGRect(x: cx - r, y: by - r, width: r * 2, height: r * 2)
        btnRects.append(byRect)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(byRect)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(byRect)
        drawBtnText(ctx: ctx, text: "⟳", x: cx, y: by, color: yColor)

        // Y- 按钮
        let by2 = cy + len + r + 4
        let byRect2 = CGRect(x: cx - r, y: by2 - r, width: r * 2, height: r * 2)
        btnRects.append(byRect2)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(byRect2)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(byRect2)
        drawBtnText(ctx: ctx, text: "⟲", x: cx, y: by2, color: yColor)

        // === Z轴（蓝）：斜向 45度 ===
        let dz = len * 0.4
        ctx.setStrokeColor(zColor.cgColor)
        ctx.setLineWidth(2.5)
        ctx.move(to: CGPoint(x: cx - dz, y: cy - dz))
        ctx.addLine(to: CGPoint(x: cx + dz, y: cy + dz))
        ctx.strokePath()

        // Z+ 箭头
        drawArrow(ctx: ctx, x: cx + dz, y: cy + dz, angle: .pi / 4, color: zColor)

        // Z+ 按钮（斜向 0.7r 偏移）
        let bzx = cx + dz + r * 0.7
        let bzy = cy + dz + r * 0.7
        let bzxRect = CGRect(x: bzx - r, y: bzy - r, width: r * 2, height: r * 2)
        btnRects.append(bzxRect)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(bzxRect)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(bzxRect)
        drawBtnText(ctx: ctx, text: "⟲", x: bzx, y: bzy, color: zColor)

        // Z- 按钮
        let bzx2 = cx - dz - r * 0.7
        let bzy2 = cy - dz - r * 0.7
        let bzxRect2 = CGRect(x: bzx2 - r, y: bzy2 - r, width: r * 2, height: r * 2)
        btnRects.append(bzxRect2)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(bzxRect2)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(bzxRect2)
        drawBtnText(ctx: ctx, text: "⟳", x: bzx2, y: bzy2, color: zColor)

        // 轴标签
        let smallFont = UIFont.systemFont(ofSize: 14)
        let attrs: [NSAttributedString.Key: Any] = [.font: smallFont, .foregroundColor: xColor]
        "X".draw(at: CGPoint(x: cx + len + 2, y: cy - 4), withAttributes: attrs)
        let attrsY: [NSAttributedString.Key: Any] = [.font: smallFont, .foregroundColor: yColor]
        "Y".draw(at: CGPoint(x: cx + 5, y: cy - len - 2), withAttributes: attrsY)
        let attrsZ: [NSAttributedString.Key: Any] = [.font: smallFont, .foregroundColor: zColor]
        "Z".draw(at: CGPoint(x: cx + dz + 4, y: cy + dz + 5), withAttributes: attrsZ)

        // 中心点
        ctx.setFillColor(UIColor(red: 0.2, green: 0.2, blue: 0.2, alpha: 1.0).cgColor)
        ctx.fillEllipse(in: CGRect(x: cx - 3, y: cy - 3, width: 6, height: 6))
    }

    private func drawArrow(ctx: CGContext, x: CGFloat, y: CGFloat, angle: CGFloat, color: UIColor) {
        let size = min(bounds.width, bounds.height) * 0.05
        ctx.saveGState()
        ctx.translateBy(x: x, y: y)
        ctx.rotate(by: angle)
        ctx.setFillColor(color.cgColor)
        ctx.move(to: CGPoint(x: size, y: 0))
        ctx.addLine(to: CGPoint(x: size * 0.5, y: size * 0.5 * tan(.pi / 2.5)))
        ctx.addLine(to: CGPoint(x: size * 0.5, y: -size * 0.5 * tan(.pi / 2.5)))
        ctx.closePath()
        ctx.fillPath()
        ctx.restoreGState()
    }

    private func drawBtnText(ctx: CGContext, text: String, x: CGFloat, y: CGFloat, color: UIColor) {
        let attrs: [NSAttributedString.Key: Any] = [
            .font: btnTextFont,
            .foregroundColor: color
        ]
        let size = text.size(withAttributes: attrs)
        let textRect = CGRect(
            x: x - size.width / 2,
            y: y - size.height / 2,
            width: size.width,
            height: size.height
        )
        text.draw(in: textRect, withAttributes: attrs)
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard let touch = touches.first else { return }
        let pt = touch.location(in: self)

        for (i, rect) in btnRects.enumerated() {
            if rect.contains(pt) {
                let cmd: String
                switch i {
                case 0: cmd = "X+⟳"
                case 1: cmd = "X-⟲"
                case 2: cmd = "Y+⟳"
                case 3: cmd = "Y-⟲"
                case 4: cmd = "Z+⟲"
                case 5: cmd = "Z-⟳"
                default: return
                }
                onRotation?(cmd)
                return
            }
        }
    }
}
