import SwiftUI
import UIKit

/// 左下角的应用内日志矩形（对应 Android 的 LogPanel）。
///
/// - 底部是始终可见的把手条：折叠时只有它（▲ 日志N），展开后日志行画在它上方（▼）
/// - 只有点把手条才切换展开/折叠，点日志行不会收起
/// - 日志行区域上下拖动翻历史，长按清空
/// - 拖右上角可以自己改宽高（左下角固定，所以往右上拖）
/// - 右侧竖条是滚动条，显示当前这一段在全部日志里的位置
struct LogPanel: View {

    @ObservedObject private var log = AppLog.shared

    // 尺寸常量，和 Android 保持一致
    private let rowPitch: CGFloat = 14
    private let stripHeight: CGFloat = 30
    private let rowsTop: CGFloat = 3
    private let minRows = 3
    private let maxRowsCap = 30
    private let defaultWidth: CGFloat = 300
    private let minPanelWidth: CGFloat = 140
    private let resizeZone: CGFloat = 26
    private let longPressSeconds: TimeInterval = 0.6

    @State private var scrollLines = 0
    @State private var lastCount = 0
    @State private var resizing = false
    @State private var resizeStartWidth: CGFloat = 0
    @State private var resizeStartRows = 0
    @State private var stripPressStart: Date?
    @State private var rowPressStart: Date?
    @State private var rowDragLastY: CGFloat = 0
    @State private var rowDragging = false

    private var screenWidth: CGFloat { UIScreen.main.bounds.width }
    private var screenHeight: CGFloat { UIScreen.main.bounds.height }

    private var expanded: Bool { log.panelExpanded }

    /// 高度最多占屏幕一半，换算成能放几行
    private var maxRows: Int {
        let usable = screenHeight / 2 - (stripHeight + rowsTop + 1)
        return min(maxRowsCap, max(minRows, Int(usable / rowPitch)))
    }

    private var capacity: Int { min(max(log.panelRows, minRows), maxRows) }

    private var maxScroll: Int { max(0, log.entries.count - capacity) }

    private var panelWidth: CGFloat {
        if !expanded { return tabWidth }
        let stored = log.panelWidth > 0 ? log.panelWidth : min(defaultWidth, screenWidth - 48)
        return min(max(stored, minPanelWidth), screenWidth - 16)
    }

    /// 折叠态宽度：按把手条文字实测，仍比展开时短得多。
    /// 留够余量，否则「日志 6」会在中间的空格处折成两行。
    private var tabWidth: CGFloat {
        let text = stripText as NSString
        let width = text.size(withAttributes: [.font: UIFont.systemFont(ofSize: 10)]).width
        return max(48, 32 + width + 14)
    }

    private var stripText: String { "日志 \(log.entries.count)" }

    /// 当前视口里的日志：末尾是 entries.count - scrollLines
    private var visibleEntries: [AppLog.Entry] {
        let end = min(max(log.entries.count - scrollLines, 0), log.entries.count)
        let start = max(0, end - capacity)
        if start >= end { return [] }
        return Array(log.entries[start..<end])
    }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            if expanded {
                rowsArea
                    .frame(height: rowsTop + CGFloat(capacity) * rowPitch + 1)
                Rectangle()
                    .fill(Color.black.opacity(0.12))
                    .frame(height: 1)
            }
            handleStrip
        }
        .frame(width: panelWidth, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.white.opacity(0.94))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.black.opacity(0.12), lineWidth: 1)
        )
        .overlay(alignment: .topTrailing) {
            if expanded { resizeHandle }
        }
        .onReceive(log.$entries) { list in
            let newCount = list.count
            // 正在翻历史时来了新日志：滚动量一起前推，视口保持不动
            if scrollLines > 0 && newCount > lastCount {
                scrollLines += newCount - lastCount
            }
            lastCount = newCount
            scrollLines = min(max(scrollLines, 0), max(0, newCount - capacity))
        }
    }

    // MARK: - 日志行

    private var rowsArea: some View {
        ZStack(alignment: .topLeading) {
            VStack(alignment: .leading, spacing: 0) {
                if visibleEntries.isEmpty {
                    Text("暂无日志")
                        .font(.system(size: 10))
                        .foregroundColor(.gray)
                        .padding(.leading, 8)
                } else {
                    ForEach(visibleEntries) { entry in
                        rowView(entry)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.top, rowsTop)

            scrollBar
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .contentShape(Rectangle())
        .gesture(rowGesture)
    }

    private func rowView(_ entry: AppLog.Entry) -> some View {
        HStack(spacing: 0) {
            Text(entry.time)
                .font(.system(size: 8, design: .monospaced))
                .foregroundColor(Color(red: 0.62, green: 0.62, blue: 0.62))
                .frame(width: 36, alignment: .leading)
            Text(entry.text)
                .font(.system(size: 10))
                .foregroundColor(color(for: entry.level))
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(height: rowPitch)
        .padding(.leading, 6)
        .padding(.trailing, 16)   // 右侧给滚动条留位置
    }

    /// 终端式滚动条：显示当前窗口在全部日志里的位置
    private var scrollBar: some View {
        GeometryReader { geometry in
            let total = log.entries.count
            let height = geometry.size.height
            if total > capacity && height > 0 {
                let end = min(max(total - scrollLines, 0), total)
                let start = max(0, end - capacity)
                let thumbHeight = max(10, height * CGFloat(capacity) / CGFloat(total))
                let thumbTop = height * CGFloat(start) / CGFloat(total)
                ZStack(alignment: .top) {
                    Rectangle()
                        .fill(Color.black.opacity(0.08))
                    Rectangle()
                        .fill(Color.black.opacity(0.4))
                        .frame(height: thumbHeight)
                        .offset(y: thumbTop)
                }
            }
        }
        .frame(width: 3)
        .padding(.trailing, 4)
        .frame(maxWidth: .infinity, alignment: .trailing)
    }

    // MARK: - 底部把手条

    private var handleStrip: some View {
        HStack(spacing: 5) {
            TriangleShape(up: !expanded)
                .fill(Color(red: 0.4, green: 0.4, blue: 0.4))
                .frame(width: 12, height: 9)
            Text(stripText)
                .font(.system(size: 10))
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .foregroundColor(
                    expanded && scrollLines > 0
                        ? Color(red: 0.937, green: 0.424, blue: 0.0)
                        : Color(red: 0.53, green: 0.53, blue: 0.53)
                )
            Spacer(minLength: 0)
        }
        .padding(.leading, 7)
        .padding(.trailing, 8)
        .frame(height: stripHeight)
        .contentShape(Rectangle())
        .gesture(stripGesture)
    }

    /// 短按切换展开/折叠，长按清空
    private var stripGesture: some Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { _ in
                if stripPressStart == nil { stripPressStart = Date() }
            }
            .onEnded { value in
                let duration = Date().timeIntervalSince(stripPressStart ?? Date())
                stripPressStart = nil
                if duration >= longPressSeconds {
                    AppLog.clear()
                    scrollLines = 0
                } else if abs(value.translation.height) < 10 {
                    log.panelExpanded.toggle()
                    if !log.panelExpanded { scrollLines = 0 }
                }
            }
    }

    // MARK: - 拖动翻历史 / 长按清空

    private var rowGesture: some Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { value in
                if rowPressStart == nil {
                    rowPressStart = Date()
                    rowDragLastY = value.location.y
                    rowDragging = false
                }
                if !rowDragging && abs(value.translation.height) > 6 {
                    rowDragging = true
                }
                guard rowDragging else { return }
                let lines = Int((value.location.y - rowDragLastY) / rowPitch)
                if lines != 0 {
                    scrollLines = min(max(scrollLines + lines, 0), maxScroll)
                    rowDragLastY += CGFloat(lines) * rowPitch
                }
            }
            .onEnded { _ in
                let duration = Date().timeIntervalSince(rowPressStart ?? Date())
                let wasDragging = rowDragging
                rowPressStart = nil
                rowDragging = false
                if !wasDragging && duration >= longPressSeconds {
                    AppLog.clear()
                    scrollLines = 0
                }
            }
    }

    // MARK: - 右上角缩放

    /// 右上角那三条斜线就是缩放热区；左下角固定，所以往右上拖变大
    private var resizeHandle: some View {
        ResizeGripShape()
            .stroke(Color.black.opacity(0.32), lineWidth: 1)
            .frame(width: 10, height: 10)
            .padding(.top, 3)
            .padding(.trailing, 3)
            .frame(width: resizeZone, height: resizeZone, alignment: .topTrailing)
            .contentShape(Rectangle())
            .gesture(resizeGesture)
    }

    private var resizeGesture: some Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { value in
                if !resizing {
                    resizing = true
                    resizeStartWidth = panelWidth
                    resizeStartRows = capacity
                }
                let newWidth = min(max(resizeStartWidth + value.translation.width, minPanelWidth), screenWidth - 16)
                // 往上拖 = 变高 = 多显示几行
                let deltaRows = Int(-value.translation.height / rowPitch)
                let newRows = min(max(resizeStartRows + deltaRows, minRows), maxRows)

                log.panelWidth = newWidth
                log.panelRows = newRows
                scrollLines = min(scrollLines, max(0, log.entries.count - newRows))
            }
            .onEnded { _ in
                resizing = false
            }
    }

    private func color(for level: AppLog.Level) -> Color {
        switch level {
        case .warn:  return Color(red: 0.937, green: 0.424, blue: 0.0)   // EF6C00
        case .error: return Color(red: 0.827, green: 0.184, blue: 0.184) // D32F2F
        case .info:  return .black
        }
    }
}

/// 把手条上的三角：折叠时朝上（点它展开），展开时朝下（点它折叠）
private struct TriangleShape: Shape {
    let up: Bool

    func path(in rect: CGRect) -> Path {
        var path = Path()
        if up {
            path.move(to: CGPoint(x: rect.midX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        } else {
            path.move(to: CGPoint(x: rect.minX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        }
        path.closeSubpath()
        return path
    }
}

/// 右上角的三条斜线
private struct ResizeGripShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let size = min(rect.width, rect.height)
        for index in 0..<3 {
            let offset = CGFloat(index) * 4
            path.move(to: CGPoint(x: size - 10 + offset, y: rect.minY))
            path.addLine(to: CGPoint(x: size, y: rect.minY + 10 - offset))
        }
        return path
    }
}
