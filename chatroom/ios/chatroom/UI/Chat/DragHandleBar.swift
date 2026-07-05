import SwiftUI
import UIKit

/// 拖拽条（对应 Android `handleLabel`）——**走 UIKit 手势，不走 SwiftUI 手势系统**。
///
/// 背景：`ChatView` 被 `TabView(.page(indexDisplayMode: .never))` 包着，TabView 自己有水平的
/// page-swipe 手势。SwiftUI 的 `DragGesture` 跟 TabView 的 swipe 在同一个 gesture-arbitration
/// 队列里仲裁，iOS 17+ 上多次观测到「子层 .highPriorityGesture / simultaneousGesture 仍卡死整个 app」
/// 的情况——这正是我们之前 .gesture 路径死锁的根因。
///
/// 方案：用 `UIPanGestureRecognizer` 包在 UIView 里，UIKit 的手势系统**独立于 SwiftUI 的手势仲裁**，
/// 跟 TabView 的 swipe 可以共存，不会死锁。这是 Apple 自家 framework 之间的标准协作方式。
///
/// 行为：
/// - 向上拖（手指向屏幕顶部）= `inputHeight` 增大（chat 区域变小）
/// - 向下拖 = `inputHeight` 减小（chat 区域变大）
/// - 拖拽范围 clamp 在 [minHeight, maxHeight]
/// - isMaximized 时整个 view `.isUserInteractionEnabled = false`，手势不响应
struct DragHandleBar: UIViewRepresentable {
    /// 当前输入区高度（绑定到外部 @State）
    @Binding var inputHeight: CGFloat
    /// 当前模式的最小输入区高度（含 handle 36pt）
    var minHeight: CGFloat
    /// 拖拽上限（chat 区域至少留 60pt 的换算上限）
    var maxHeight: CGFloat
    /// 全屏模式时禁用拖拽
    var isMaximized: Bool

    func makeUIView(context: Context) -> DragHandleUIView {
        let v = DragHandleUIView()
        v.label.text = "拖拽"
        v.bind(inputHeight: $inputHeight, minHeight: minHeight, maxHeight: maxHeight, isMaximized: isMaximized)
        return v
    }

    func updateUIView(_ uiView: DragHandleUIView, context: Context) {
        // 每次 body 重评估都同步最新 min/max/isMaximized（min/max 跟当前模式/布局有关）。
        // @Binding 自动追踪——closure 无需重建。
        uiView.bind(
            inputHeight: $inputHeight,
            minHeight: minHeight,
            maxHeight: maxHeight,
            isMaximized: isMaximized
        )
    }
}

/// 实际承载 `UIPanGestureRecognizer` 的 UIView。
/// 不参与 SwiftUI 响应式（自身不存任何会被 SwiftUI 读的状态），纯 UIKit 手势处理。
final class DragHandleUIView: UIView {

    let label = UILabel()
    private var inputHeightBinding: Binding<CGFloat>?
    private var minHeight: CGFloat = 0
    private var maxHeight: CGFloat = 0
    private var isMaximized: Bool = false

    /// 拖拽起始时输入区高度（`.began` 捕获，`.ended`/`.cancelled` 置回 nil）。
    /// `.changed` 里 `next = startHeight - t.y`，t.y 是 UIPanGestureRecognizer 自带的
    /// **cumulative translation since gesture began**（不需要自己 setTranslation 重置）。
    ///
    /// ⚠️ 旧实现坑位：「`setTranslation(.zero)` + `lastTranslationY` 增量」的写法
    /// 在 `setTranslation` 之后下一帧 `t.y` 从 0 重新累加，导致
    /// `delta = t.y - lastTranslationY` 从第二帧开始恒为 0——表现为拖拽只动几个像素。
    private var startHeight: CGFloat?

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        isUserInteractionEnabled = true

        // "拖拽" label
        label.text = "拖拽"
        label.font = .systemFont(ofSize: 12)
        label.textColor = .gray
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: leadingAnchor),
            label.trailingAnchor.constraint(equalTo: trailingAnchor),
            label.topAnchor.constraint(equalTo: topAnchor),
            label.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])

        // UIPanGestureRecognizer —— UIKit 手势，独立于 SwiftUI 的 gesture-arbitration
        let pan = UIPanGestureRecognizer(target: self, action: #selector(handlePan(_:)))
        pan.minimumNumberOfTouches = 1
        pan.maximumNumberOfTouches = 1
        // 不设 maximumNumberOfTouches > 1；单指拖拽
        addGestureRecognizer(pan)
    }

    required init?(coder: NSCoder) {
        fatalError("not implemented")
    }

    /// SwiftUI 在 body 重评估时反复调用此方法同步最新状态。
    func bind(inputHeight: Binding<CGFloat>, minHeight: CGFloat, maxHeight: CGFloat, isMaximized: Bool) {
        self.inputHeightBinding = inputHeight
        self.minHeight = minHeight
        self.maxHeight = maxHeight
        self.isMaximized = isMaximized
        alpha = isMaximized ? 0.4 : 1.0
        isUserInteractionEnabled = !isMaximized
    }

    @objc private func handlePan(_ gr: UIPanGestureRecognizer) {
        guard let binding = inputHeightBinding, !isMaximized else { return }

        switch gr.state {
        case .began:
            // 拍下当前高度作为基准。后续 .changed 全部从这个基准 + cumulative t.y 算新高度。
            startHeight = binding.wrappedValue

        case .changed:
            guard let h0 = startHeight else { return }
            let t = gr.translation(in: self)
            // t.y 是 gesture 开始以来**累计** translation（在 self 坐标系）。
            // 手指向上拖 → t.y 减小（负值） → inputHeight 应该增大。
            // 直接 h0 - t.y：
            //   - t.y < 0 (向上)  → h0 - (-n) = h0 + n（增大）
            //   - t.y > 0 (向下)  → h0 - (+n) = h0 - n（减小）
            let next = h0 - t.y
            binding.wrappedValue = min(max(next, minHeight), maxHeight)

        case .ended, .cancelled, .failed:
            // 释放 startHeight 让下次 .began 能干净地重新捕获。
            startHeight = nil

        default:
            break
        }
    }
}
