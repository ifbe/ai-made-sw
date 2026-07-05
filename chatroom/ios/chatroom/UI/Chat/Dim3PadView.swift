import SwiftUI
import UIKit

/// 三维模式（dim3）专用控件合集。
/// 之前拆成 `ArrowPadView.swift` + `AxisView.swift` 两个文件，合并在这里：
/// - 都是 dim3 模式才用
/// - 都是「左侧 3×3 网格 + 右侧坐标轴」的视觉关系
/// 放一起便于一起 review / 改整体样式。

// MARK: - ArrowPadView

/// 三维模式专用的方向键 3×3 网格（iOS 端镜像 Android `inputBarDim3` 的 `leftSideDim3`）。
/// 与 `DirectionPadView`（qwe 遥控器）的区别：**显示箭头符号** ↖↑↗←◉→↙↓↘，
/// 外加上下两块「+」「-」按钮。
///
/// 布局：
/// ```
///       [ + ]
///   ↖   ↑   ↗
///   ←   ◉   →     ← 中间 3×3 网格占父容器剩余空间（cells 正方形）
///   ↙   ↓   ↘
///       [ - ]
/// ```
///
/// 大小策略：父容器是 HStack 的 weight=1 部分。`+`/`-` 按钮固定高度，
/// 中间 3×3 网格用 GeometryReader 算出 cell 边长 = min(可用 w, 可用 h) / 3，
/// 保证正方形 cells。
struct ArrowPadView: View {
    let onTap: (String) -> Void

    /// 3×3，从上到下、从左到右：
    /// ↖  ↑  ↗
    /// ←  ◉  →
    /// ↙  ↓  ↘
    private let arrows: [(String, String)] = [
        ("↖", "btnDim3UpLeft"),
        ("↑", "btnDim3Up2"),
        ("↗", "btnDim3UpRight"),
        ("←", "btnDim3Left"),
        ("◉", "btnDim3Center"),
        ("→", "btnDim3Right"),
        ("↙", "btnDim3DownLeft"),
        ("↓", "btnDim3Down"),
        ("↘", "btnDim3DownRight")
    ]

    /// +/- 按钮的尺寸策略（2026-07-05 跟用户定下）。
/// - 高度：父容器（ArrowPadView）较小边的 1/8（但减 4pt 抵消 grid 间距）：
///   `btnH = (min(W, H) - 4) / 8`，让 cluster = min(W, H) 严格贴满，
///   竖屏有 spacer 余量，横屏刚好填满。
/// - 宽度：父容器宽的 50% (`.sideButtonWidthRatio`)
    private let sideButtonWidthRatio: CGFloat = 0.5

    var body: some View {
        // 外层 GeometryReader 拿父容器 (ArrowPadView) 的 W、H。
        GeometryReader { outerGeo in
            let W = outerGeo.size.width
            let H = outerGeo.size.height
            let minSide = min(W, H)
            let cell = max(0, (minSide - 4) / 4)
            let btnH = max(0, (minSide - 4) / 8)
            let btnW = W * sideButtonWidthRatio
            let gridSide = cell * 3 + 4

            // VStack spacing = 0：+/- 紧贴 9 宫格，中间不空白。
            // 上下两个 Spacer(minLength: 0)：当 ArrowPadView 比 cluster 高时，
            // 多余纵向空间平均分到顶部和底部（9 宫格 + +/- 作为一个整体强制居中）。
            // VStack 默认 .center 对齐：9 宫格是宽者，+/- 按钮也跟着居中。
            VStack(spacing: 0) {
                Spacer(minLength: 0)

                // 顶部 "+" 实心按钮
                solidButton(label: "+") {
                    onTap("+")
                }
                .frame(width: btnW, height: btnH)

                // 中间 3×3 箭头网格（强制居中，正方形）
                VStack(spacing: 2) {
                    ForEach(0..<3, id: \.self) { row in
                        HStack(spacing: 2) {
                            ForEach(0..<3, id: \.self) { col in
                                let index = row * 3 + col
                                let (arrow, _) = arrows[index]
                                RemoteButton(
                                    label: arrow,
                                    fontSize: cell * 0.5,
                                    color: Color(hex: "#2196F3")
                                ) {
                                    onTap(arrow)
                                }
                                .frame(width: cell, height: cell)
                            }
                        }
                    }
                }
                .frame(width: gridSide, height: gridSide)

                // 底部 "-" 实心按钮
                solidButton(label: "-") {
                    onTap("-")
                }
                .frame(width: btnW, height: btnH)

                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 实心按钮：白字 + 蓝底（与 Android `bg_remote_btn_solid` 一致）
    /// **不**自带尺寸，尺寸由外层 `.frame(width:height:)` 决定——方便上下两处按需调整。
    @ViewBuilder
    private func solidButton(label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 22, weight: .bold))
                .foregroundColor(.white)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color(hex: "#2196F3"))
                )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - AxisView

/// 3D 坐标轴视图（对应 Android AxisView）
/// 红=X，绿=Y，蓝=Z，Z轴斜向45度，6个旋转按钮：
/// 显示文字 x+/x-/y+/y-/z+/z-，回调发送 x/X/y/Y/z/Z
/// （iOS 镜像 Android 2026-07 改动，去掉 ⟲/⟳ 符号）
///
/// 与 `ArrowPadView` 一起是 dim3 模式右半边的视图，所以放在同一个文件。
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
    /// 2 字符按钮文字（x+/x-/y+/y-/z+/z-）的字号，Android 端从 48 降到 28，这里同步
    private let btnTextFont = UIFont.systemFont(ofSize: 14)
    private let btnRadius: CGFloat = 16

    // 6个按钮区域 [x1, y1, x2, y2]（iOS CGRect 坐标 y 从上到下）
    // 顺序：0=X+, 1=X-, 2=Y+, 3=Y-, 4=Z+, 5=Z-
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

        btnRects = []

        // === X轴（红）===
        ctx.setStrokeColor(xColor.cgColor)
        ctx.setLineWidth(2.5)
        ctx.move(to: CGPoint(x: cx - len, y: cy))
        ctx.addLine(to: CGPoint(x: cx + len, y: cy))
        ctx.strokePath()

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
        drawBtnText(ctx: ctx, text: "x+", x: bx, y: cy, color: xColor)

        // X- 按钮
        let bx2 = cx - len - r - 4
        let bxRect2 = CGRect(x: bx2 - r, y: cy - r, width: r * 2, height: r * 2)
        btnRects.append(bxRect2)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(bxRect2)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(bxRect2)
        drawBtnText(ctx: ctx, text: "x-", x: bx2, y: cy, color: xColor)

        // === Y轴（绿）===
        ctx.setStrokeColor(yColor.cgColor)
        ctx.setLineWidth(2.5)
        ctx.move(to: CGPoint(x: cx, y: cy - len))
        ctx.addLine(to: CGPoint(x: cx, y: cy + len))
        ctx.strokePath()

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
        drawBtnText(ctx: ctx, text: "y+", x: cx, y: by, color: yColor)

        // Y- 按钮
        let by2 = cy + len + r + 4
        let byRect2 = CGRect(x: cx - r, y: by2 - r, width: r * 2, height: r * 2)
        btnRects.append(byRect2)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(byRect2)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(byRect2)
        drawBtnText(ctx: ctx, text: "y-", x: cx, y: by2, color: yColor)

        // === Z轴（蓝）：斜向 45度 ===
        let dz = len * 0.4
        ctx.setStrokeColor(zColor.cgColor)
        ctx.setLineWidth(2.5)
        ctx.move(to: CGPoint(x: cx - dz, y: cy - dz))
        ctx.addLine(to: CGPoint(x: cx + dz, y: cy + dz))
        ctx.strokePath()

        drawArrow(ctx: ctx, x: cx + dz, y: cy + dz, angle: .pi / 4, color: zColor)

        // Z+ 按钮
        let bzx = cx + dz + r * 0.7
        let bzy = cy + dz + r * 0.7
        let bzxRect = CGRect(x: bzx - r, y: bzy - r, width: r * 2, height: r * 2)
        btnRects.append(bzxRect)
        ctx.setFillColor(fillPaint.cgColor)
        ctx.fill(bzxRect)
        ctx.setStrokeColor(UIColor.gray.cgColor)
        ctx.setLineWidth(1.5)
        ctx.stroke(bzxRect)
        drawBtnText(ctx: ctx, text: "z+", x: bzx, y: bzy, color: zColor)

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
        drawBtnText(ctx: ctx, text: "z-", x: bzx2, y: bzy2, color: zColor)

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

        // 与 Android 对齐：小写 = 正方向 CW，大写 = 反方向 CCW
        // （Android 修复了原 AxisView 把 onZRotateCW 画成 ⟲ 的 swapped bug）
        let cmds = ["x", "X", "y", "Y", "z", "Z"]
        for (i, rect) in btnRects.enumerated() where i < cmds.count {
            if rect.contains(pt) {
                onRotation?(cmds[i])
                return
            }
        }
    }
}