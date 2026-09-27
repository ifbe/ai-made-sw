//
//  Layout.swift
//  chess
//
//  四角控件 + 安全区处理（对照 design.md §4.2）。
//
//  Android 侧是在 `setOnApplyWindowInsetsListener` 里给 margin 加安全区；
//  iOS 这边：**棋盘**全屏画（`.ignoresSafeArea()`），四角控件放在不忽略安全区的层里，
//  于是它们天然就在「安全区 + 12pt」的位置上。
//
//  ⚠️ 结构上刻意保持朴素（ZStack + 一个撑满屏的 `Color.clear` 尺寸锚点 + 四个 frame 定位）：
//  这是已经实机验证过能正常显示的形状，不要再"优化"成 `.background {}` / overlay 之类的写法。
//

import SwiftUI

enum Layout {

    /// 四角控件离屏幕边缘的距离（安全区之外再加这么多）。
    static let cornerMargin = Theme.cornerMargin
}

/// 四个角控件的容器：左上标签栏 / 右上重置 / 左下联机条 / 右下日志。
/// 自己处在安全区里，四角各再加 `12pt`。
///
/// 键盘避让**不要自己做**：键盘弹出时系统会把根视图的底部安全区抬高，
/// 这一层跟着缩小、下面那一行就自动移到键盘上方了（§14.6）。
/// 之前额外加了一层手算的键盘高度，结果抬了两次、地址栏飞到屏幕中上部。
struct CornerControls<TopLeading: View, TopTrailing: View, BottomLeading: View, BottomTrailing: View>: View {

    @ViewBuilder var topLeading: () -> TopLeading
    @ViewBuilder var topTrailing: () -> TopTrailing
    @ViewBuilder var bottomLeading: () -> BottomLeading
    @ViewBuilder var bottomTrailing: () -> BottomTrailing

    var body: some View {
        ZStack {
            // 只用来「把这个 ZStack 撑满整屏」的尺寸锚点。
            // 注意：`Color` 是**会绘制**的视图，命中区域就是整块矩形！不关掉命中测试的话，
            // 它会把全屏的触摸都吃掉，底下的棋盘就彻底拖不动了。
            Color.clear
                .allowsHitTesting(false)

            topLeading()
                .padding(insets(top: true, leading: true))
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            topTrailing()
                .padding(insets(top: true, trailing: true))
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)

            bottomLeading()
                .padding(insets(bottom: true, leading: true))
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomLeading)

            bottomTrailing()
                .padding(insets(bottom: true, trailing: true))
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
        }
    }

    /// 四角各自要留的边距：基础 12pt。
    private func insets(
        top: Bool = false,
        bottom: Bool = false,
        leading: Bool = false,
        trailing: Bool = false
    ) -> EdgeInsets {
        EdgeInsets(
            top: top ? Layout.cornerMargin : 0,
            leading: leading ? Layout.cornerMargin : 0,
            bottom: bottom ? Layout.cornerMargin : 0,
            trailing: trailing ? Layout.cornerMargin : 0
        )
    }
}
