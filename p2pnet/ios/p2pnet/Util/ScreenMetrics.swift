import CoreGraphics

#if canImport(UIKit)
import UIKit
#endif

/// 屏幕/窗口尺寸小工具。
///
/// 用它是为了画「屏幕几何中心的横线」：Android 那边用
/// `WindowManager.currentWindowMetrics.bounds` 拿到整个窗口（含状态栏、含底部 tab 栏），
/// iOS 的对应物是 key window 的 bounds。
/// 不用 `UIScreen.main`（iOS 16 起已废弃，会带 deprecation 警告）。
///
/// 注意：`UIApplication.shared` / `UIWindowScene.windows` 都是 **MainActor 隔离**的，
/// 所以这里不能标 `nonisolated`；调用方（View 的 onAppear）本来就在主线程，
/// 而且要把结果缓存进 @State，别在 Canvas 每帧绘制里读。
enum ScreenMetrics {

#if canImport(UIKit)
    /// 窗口高度（整个屏幕，不是安全区内的可用高度）；拿不到返回 0（调用方据此跳过画线）
    static var windowHeight: CGFloat {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        for scene in scenes {
            if let window = scene.windows.first(where: { $0.isKeyWindow }) {
                return window.bounds.height
            }
        }
        for scene in scenes {
            if let window = scene.windows.first {
                return window.bounds.height
            }
        }
        return 0
    }
#endif
}

// MARK: - 内容区布局（服务器卡片进自由层之后的几何；纯计算，可单独 swiftc 编译断言）

/// 服务器卡片在**自由层**里的位置与宽度规则：
///  - **高度 > 宽度**（竖屏，含相等）→ 占满整个内容宽（两侧各留 `padding`）；
///  - **宽度 > 高度**（横屏）→ 只占一半宽，且**水平居中**（左右各留 1/4 宽的空白带）。
/// 自由层填满整个内容区，服务器卡片是它内部顶部对齐的元素 —— 所以"自由层正中"就是整个内容区的正中。
nonisolated enum ContentLayout {

    /// 服务器卡片的宽度（只看内容区宽高比，尺寸变一次算一次，天然随旋转/改窗口实时变化）
    static func serverCardWidth(content: CGSize) -> CGFloat {
        return isWide(content) ? content.width / 2 : content.width
    }

    /// 是否按"横屏"处理：**严格** width > height；相等时按竖屏（占满）
    static func isWide(_ content: CGSize) -> Bool {
        return content.width > content.height
    }

    /// 服务器卡片的实际矩形（**顶部对齐**；横屏**水平居中**占一半）。高度由卡片自己撑开，这里先给 0。
    /// - Parameter padding: 水平内边距（A4：**竖屏**沿用原来的 4pt；横屏是居中半宽，用不到 padding）
    static func serverCardFrame(content: CGSize, padding: CGFloat = 4) -> CGRect {
        if isWide(content) {
            let width = max(0, content.width / 2)
            return CGRect(x: (content.width - width) / 2, y: 0, width: width, height: 0)   // 居中
        }
        let width = max(0, content.width - padding * 2)
        return CGRect(x: padding, y: 0, width: width, height: 0)
    }

    /// 卡片（不含服务器卡片自己）的**上沿下限**：与服务器卡片水平相交 → 服务器卡片下沿 + margin；
    /// 不相交（例如横屏时卡片整体在右半区）→ 0，即**纵向可以一直用到顶部**（A3）。
    static func minTopY(cardSize: CGSize, cardLeft: CGFloat, serverRect: CGRect, margin: CGFloat = 0) -> CGFloat {
        guard serverRect.width > 0, serverRect.height > 0 else { return margin }
        let cardRight = cardLeft + cardSize.width
        let overlaps = cardRight > serverRect.minX && cardLeft < serverRect.maxX
        return overlaps ? serverRect.maxY + margin : margin
    }

    /// 把一张卡片的**左上角**夹进自由层（右侧/下侧不出界；上侧按 `minTopY` 躲开服务器卡片）
    static func clampTopLeft(
        _ topLeft: CGPoint,
        cardSize: CGSize,
        area: CGSize,
        serverRect: CGRect,
        margin: CGFloat = 0
    ) -> CGPoint {
        let maxX = max(0, area.width - cardSize.width)
        let minY = minTopY(cardSize: cardSize, cardLeft: topLeft.x, serverRect: serverRect, margin: margin)
        let maxY = max(minY, area.height - cardSize.height)
        return CGPoint(
            x: min(max(topLeft.x, 0), maxX),
            y: min(max(topLeft.y, minY), maxY)
        )
    }
}

/// 「我」卡片的拖动几何（纯计算，Foundation-only，可单独 swiftc 编译断言）
///
/// 锚点规则：默认落在**自由层正中**（自由层现在含服务器卡片那块 → 就是整个内容区的正中）；
/// 拖动位移相对这个中心锚点对称，向上受服务器卡片下沿限制（水平相交时）、向下能到自由层底边。
nonisolated enum MeCardGeometry {

    /// 横向可用位移：±(可用宽 − 卡片宽)/2 − margin；卡片比可用区还宽时返回 0（保持正中溢出）
    static func maxDx(area: CGSize, meSize: CGSize, margin: CGFloat = 0) -> CGFloat {
        return max(0, (area.width - meSize.width) / 2 - margin)
    }

    /// 纵向位移范围（相对**中心**锚点）：
    ///  - 上界：卡片上沿 ≥ `minTopY`（与服务器卡片水平相交时就是服务器卡片下沿 + margin）；
    ///  - 下界：卡片下沿 ≤ area.height − margin；
    ///  - **卡片比可用区还高时返回 `0...0`**：不做纵向夹取，默认中心仍是自由层正中（对称溢出）。
    static func dyRange(
        area: CGSize,
        meSize: CGSize,
        centerX: CGFloat,
        serverRect: CGRect = .zero,
        margin: CGFloat = 0
    ) -> ClosedRange<CGFloat> {
        let half = meSize.height / 2
        let topLimit = ContentLayout.minTopY(
            cardSize: meSize,
            cardLeft: centerX - meSize.width / 2,
            serverRect: serverRect,
            margin: margin
        )
        let lower = topLimit + half - area.height / 2      // 上沿 ≥ topLimit
        let upper = area.height / 2 - margin - half        // 下沿 ≤ area.height − margin
        if lower > upper {
            // 纵向装不下（例如横屏窗口很矮）：**以"不许盖住服务器卡片"的限位为准** ——
            // 卡片顶到服务器卡片下沿、允许下沿越界；没有服务器卡片时保持正中（不夹取）
            return serverRect.height > 0 ? lower...lower : 0...0
        }
        return lower...upper
    }

    /// 未叠加拖动位移时的默认中心：水平居中、**垂直居中**（= 自由层正中）
    static func baseCenter(area: CGSize) -> CGPoint {
        return CGPoint(x: area.width / 2, y: area.height / 2)
    }

    /// 夹取后的拖动位移
    static func clamp(
        drag: CGSize,
        area: CGSize,
        meSize: CGSize,
        serverRect: CGRect = .zero,
        margin: CGFloat = 0
    ) -> CGSize {
        let dxMax = maxDx(area: area, meSize: meSize, margin: margin)
        let dx = min(max(drag.width, -dxMax), dxMax)
        let centerX = area.width / 2 + dx
        let range = dyRange(area: area, meSize: meSize, centerX: centerX, serverRect: serverRect, margin: margin)
        return CGSize(
            width: dx,
            height: min(max(drag.height, range.lowerBound), range.upperBound)
        )
    }

    /// 卡片最终中心 = 默认中心（居中）+ 夹取后的拖动位移
    static func center(
        area: CGSize,
        meSize: CGSize,
        drag: CGSize,
        serverRect: CGRect = .zero,
        margin: CGFloat = 0
    ) -> CGPoint {
        let base = baseCenter(area: area)
        let d = clamp(drag: drag, area: area, meSize: meSize, serverRect: serverRect, margin: margin)
        return CGPoint(x: base.x + d.width, y: base.y + d.height)
    }
}
