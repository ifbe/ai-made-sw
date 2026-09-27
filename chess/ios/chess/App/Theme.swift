//
//  Theme.swift
//  chess
//
//  全部配色 / 圆角 / 字号 / 内边距常量（对照 design.md §5 与 Android 的
//  res/values/{themes,dimens}.xml、res/drawable/*.xml、res/layout/activity_main.xml）。
//

import SwiftUI

extension Color {
    /// 按 Android 的 `#AARRGGBB` 顺序构造（例如 `0xE61A1A1A`）。
    init(argb: UInt32) {
        let a = Double((argb >> 24) & 0xFF) / 255
        let r = Double((argb >> 16) & 0xFF) / 255
        let g = Double((argb >> 8) & 0xFF) / 255
        let b = Double(argb & 0xFF) / 255
        self.init(.sRGB, red: r, green: g, blue: b, opacity: a)
    }
}

enum Theme {

    // MARK: - 界面配色（§5.1）

    /// 页面底色。
    static let pageBackground = Color(argb: 0xFF000000)
    /// 小按钮底。
    static let tabBackground = Color(argb: 0xE61A1A1A)
    /// 小按钮边。
    static let tabBorder = Color(argb: 0x4DFFFFFF)
    /// 小按钮字（非当前）。
    static let tabText = Color(argb: 0xFFF0F0F0)
    /// 当前标签底。
    static let tabActiveBackground = Color(argb: 0xFFE6B24C)
    /// 当前标签字。
    static let tabActiveText = Color(argb: 0xFF2A2110)
    /// 重置按钮字。
    static let resetText = Color(argb: 0xFFEF9A9A)
    /// 强调色（轮到谁走的黄框、悬停提示、日志框边）。
    static let accent = Color(argb: 0xFFE6B24C)
    /// 地址框占位色。
    static let placeholder = Color(argb: 0x80FFFFFF)
    /// 日志面板底。
    static let logPanelBackground = Color(argb: 0xE6101418)
    /// 日志面板边。
    static let logPanelBorder = Color(argb: 0x66E6B24C)
    /// 日志正文。
    static let logText = Color(argb: 0xFFD8E8FF)

    // MARK: - 象棋配色（§5.2）

    static let xiangqiBoardFill = Color(argb: 0xFFFFE999)
    static let xiangqiBoardStroke = Color(argb: 0xFFE0C67E)
    static let xiangqiLine = Color(argb: 0xFF3A3226)
    static let xiangqiRiverText = Color(argb: 0xFF8A7748)
    static let xiangqiPieceFill = Color(argb: 0xFFFFFBF0)
    static let xiangqiRed = Color(argb: 0xFFC0392B)
    static let xiangqiBlack = Color(argb: 0xFF1F1F1F)
    static let xiangqiHoverOk = Color(argb: 0xFF3A3226)
    static let xiangqiHoverBad = Color(argb: 0xFFC62828)

    // MARK: - 国际象棋配色（§5.3）

    static let intlLightSquare = Color(argb: 0xFFF0D9B5)
    static let intlDarkSquare = Color(argb: 0xFFB58863)
    static let intlBoardBorder = Color(argb: 0xFF6B4A2F)
    static let intlWhiteGlyph = Color(argb: 0xFFFFFFFF)
    static let intlWhiteGlyphStroke = Color(argb: 0xFF3A3226)
    static let intlBlackGlyph = Color(argb: 0xFF1B1B1B)
    static let intlBlackGlyphStroke = Color(argb: 0xFFEFE6D5)
    static let intlHoverOk = Color(argb: 0x40E6B24C)
    static let intlHoverBad = Color(argb: 0x40C62828)

    // MARK: - 围棋 / 五子棋配色（§5.4）

    static let stoneBoardFill = Color(argb: 0xFFFFE999)
    static let stoneBoardStroke = Color(argb: 0xFFE0C67E)
    static let stoneLine = Color(argb: 0xFF3A3226)
    static let stoneBlackFill = Color(argb: 0xFF0A0A0A)
    static let stoneBlackStroke = Color(argb: 0xFF3A3A3A)
    static let stoneWhiteFill = Color(argb: 0xFFF2F2F2)
    static let stoneWhiteStroke = Color(argb: 0xFF9E9E9E)
    static let stoneCountText = Color(argb: 0xFFFFFFFF)
    static let stoneHoverOk = Color(argb: 0xFF3A3226)
    static let stoneHoverBad = Color(argb: 0xFFC62828)

    // MARK: - 尺寸（§4、§7.2）

    /// 四角控件的基础外边距（再各自加上安全区）。
    static let cornerMargin: CGFloat = 12

    /// 小按钮：左右 10pt、上下 7pt、字号 13pt、圆角 18pt、间距 4pt。
    static let tabPaddingH: CGFloat = 10
    static let tabPaddingV: CGFloat = 7
    static let tabFontSize: CGFloat = 13
    static let tabCornerRadius: CGFloat = 18
    static let tabSpacing: CGFloat = 4

    /// 重置按钮。
    static let resetPaddingH: CGFloat = 12
    static let resetPaddingV: CGFloat = 8
    static let resetFontSize: CGFloat = 14
    static let resetCornerRadius: CGFloat = 22

    /// 联机条。
    static let netSpacing: CGFloat = 6
    static let addressWidth: CGFloat = 130
    static let addressPaddingH: CGFloat = 10
    static let addressPaddingV: CGFloat = 7
    static let addressFontSize: CGFloat = 13

    /// 日志框。
    static let logPanelWidth: CGFloat = 280
    static let logPanelHeight: CGFloat = 170
    static let logPanelPadding: CGFloat = 8
    static let logPanelCornerRadius: CGFloat = 10
    static let logFontSize: CGFloat = 10
    static let logLineSpacing: CGFloat = 2
    static let logToggleGap: CGFloat = 6

    /// 「该谁走」黄框线宽。
    static let yellowFrameLineWidth: CGFloat = 2

    // MARK: - 文案（§5.5）

    enum Text {
        static let tabXiangqi = "象棋"
        static let tabIntlChess = "国际象棋"
        static let tabGo = "围棋"
        static let tabGomoku = "五子棋"
        static let reset = "↺ 重置"

        static let netModeServer = "服"
        static let netModeClient = "客"
        static let netStartServer = "开始服务"
        static let netStartClient = "开始连接"
        static let netStarting = "启动中…"
        static let netConnecting = "连接中…"
        static let netOnline = "已连接"
        static let netFailed = "连接失败"
        static let netClosed = "已关闭"
        static let netDisconnected = "连接已断开"
        static let netBadAddress = "地址不对"
        static let netNoPermission = "缺少本地网络权限"
        static let netServerError = "服务出错"
        static let netHintServer = "192.168.1.7:8765"
        static let netHintClient = "对方地址，如 192.168.5.213:8765"

        static let logButton = "日志"
        static let logHide = "收起"

        /// 象棋两端牌子。
        static let sideBlack = "黑方"
        static let sideRed = "红方"
        /// 国际象棋两端牌子。
        static let sideWhite = "白方"

        static let riverRed = "楚 河"
        static let riverBlack = "汉 界"

        /// 托盘剩余数量：`x{n}`。
        static func trayCount(_ n: Int) -> String { "x\(n)" }
    }
}

/// 小按钮样式（Android 的 `TabButton` / `bg_tab` / `bg_tab_active`）。
struct TabButtonModifier: ViewModifier {
    var active: Bool

    func body(content: Content) -> some View {
        content
            .font(.system(size: Theme.tabFontSize))
            .foregroundColor(active ? Theme.tabActiveText : Theme.tabText)
            .padding(.horizontal, Theme.tabPaddingH)
            .padding(.vertical, Theme.tabPaddingV)
            .background(
                RoundedRectangle(cornerRadius: Theme.tabCornerRadius)
                    .fill(active ? Theme.tabActiveBackground : Theme.tabBackground)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Theme.tabCornerRadius)
                    .strokeBorder(Theme.tabBorder, lineWidth: active ? 0 : 1)
                    // 描边 `Shape` 的命中区域是**整个矩形**（不是那 1pt 线），
                    // 不关掉命中测试就会把底下控件（尤其是 TextField）的触摸全吃掉。
                    .allowsHitTesting(false)
            )
    }
}

extension View {
    /// 非当前页的小按钮：黑底 + 1pt 描边 + 浅色字。
    func tabButton() -> some View { modifier(TabButtonModifier(active: false)) }

    /// 当前页的小按钮：黄底 + 深色字、无边框。
    func tabButtonActive() -> some View { modifier(TabButtonModifier(active: true)) }
}
