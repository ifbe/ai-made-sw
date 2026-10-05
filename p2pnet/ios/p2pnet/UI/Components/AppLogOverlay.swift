import SwiftUI

/// App 内日志浮层：**应用级**，悬浮在所有页面之上（不属于某一个页面）。
///
/// 折叠时只剩右下角一颗「日志」按钮；点开是一个 90% 的矩形，
/// 以右下角为原点从按钮放大 / 缩回（`scaleEffect(anchor: .bottomTrailing)` + 遮罩淡入）。
///
/// 由 `MainScreen` 放在**页面内容之上**渲染，所以切到任何 tab 都能看到、都能点开；
/// 位置在 Scaffold 的内容层里，**不盖住底部 tab 栏**。
///
/// ⚠️ 折叠时必须不吞触摸：iOS 这套写法的面板是一直存在的（缩到 0.06 + 透明），
/// 所以遮罩和面板都要 `.allowsHitTesting(expanded)` —— 否则折叠时整页都点不动。
/// （Android 那边是 `if (progress > 0.001f)` 才组合面板，等价效果。）
struct AppLogOverlay: View {
    let messages: [MessageItem]
    let onClear: () -> Void

    /// false = 折叠（只剩右下角按钮），true = 展开（90% 屏幕）
    @State private var expanded = false

    private static let animation: Animation = .easeInOut(duration: 0.26)
    private static let buttonColor = Color(hex: 0x6650a4)
    private static let buttonActiveColor = Color(hex: 0x7D5260)

    var body: some View {
        GeometryReader { geo in
            ZStack {
                // ── 展开时才把「遮罩 + 面板」插进视图树（折叠时整块不存在）──
                // 这么写有两个好处：
                //  1. 折叠时不可能吞触摸（比 `.allowsHitTesting(false)` 更彻底）；
                //  2. 折叠时那个 ScrollView（里面每行都有 GeometryReader + PreferenceKey + scrollTo）
                //     **完全不参与布局**，不会在拖动卡片时被反复重算 —— 这也是 Android 的做法
                //     （`if (progress > 0.001f) { 遮罩 + AppLogPanel }`）。
                if expanded {
                    // 遮罩：展开时铺满、吞掉所有触摸（避免误点/误拖下面的卡片）
                    Color.black.opacity(0.55)
                        .transition(.opacity)

                    AppLogPanel(
                        messages: messages,
                        onClear: onClear,
                        onClose: { toggle() }
                    )
                    .frame(width: geo.size.width * 0.9, height: geo.size.height * 0.9)
                    // 以面板右下角（≈ 屏幕右下角按钮）为锚点：从按钮位置放大 / 缩回按钮
                    .transition(
                        .scale(scale: 0.06, anchor: .bottomTrailing).combined(with: .opacity)
                    )
                }

                // ── 右下角「日志」按钮：折叠或展开时始终显示 ──
                logButton
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
                    .padding(16)
            }
        }
    }

    private var logButton: some View {
        Button(action: { toggle() }) {
            Text("日志")
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(.white)
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
                .background(
                    Capsule().fill(expanded ? Self.buttonActiveColor : Self.buttonColor)
                )
                .shadow(color: .black.opacity(0.4), radius: 8, y: 2)
        }
        .buttonStyle(.plain)
    }

    private func toggle() {
        withAnimation(Self.animation) {
            expanded.toggle()
        }
    }
}

// MARK: - 日志面板本体（90% 矩形）

/// 展开后的面板：标题 + 清空/📋复制/✕ + 消息列表（复用 `LogCard`，自带跟随底部和 JSON 折行处理）。
struct AppLogPanel: View {
    let messages: [MessageItem]
    let onClear: () -> Void
    let onClose: () -> Void

    var body: some View {
        LogCard(
            title: "App 内日志",
            lines: LogLine.fromMessages(messages),
            listHorizontalPadding: 12,
            listBottomPadding: 56,     // 别被右下角「日志」按钮挡住
            onClear: onClear,
            onClose: onClose
        )
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(hex: 0xFF2B2B2B))
        )
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color.white.opacity(0.12), lineWidth: 1)
        )
    }
}
