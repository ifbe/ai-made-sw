import SwiftUI

/// 一条日志行。App 内日志有方向标签，UDP / WG 的「消息历史」没有。
struct LogLine: Identifiable {
    let id: String
    /// 行首标签（App 内日志用："client:" / "ios:" …）
    let label: String?
    let labelColor: Color?
    /// 复制时用的前缀（App 内日志要保留原来的 "CLIENT: xxx" 格式）
    let copyPrefix: String?
    let text: String

    /// 纯文本日志（UdpTest / WG 的消息历史）：id 用下标（这两个列表只追加，不会乱）
    static func plain(_ texts: [String]) -> [LogLine] {
        texts.enumerated().map { index, text in
            LogLine(id: "\(index)", label: nil, labelColor: nil, copyPrefix: nil, text: text)
        }
    }

    /// App 内日志（带方向标签和配色）
    static func fromMessages(_ messages: [MessageItem]) -> [LogLine] {
        messages.map { item in
            LogLine(
                id: "\(item.id)",
                label: label(for: item.direction),
                labelColor: color(for: item.direction),
                copyPrefix: item.direction.rawValue,
                text: item.content
            )
        }
    }

    private static func label(for direction: Direction) -> String {
        switch direction {
        case .client: return "client:"
        case .server: return "server:"
        case .system: return "ios:"
        case .udpSend: return "→ "
        case .udpRecv: return "← "
        }
    }

    private static func color(for direction: Direction) -> Color {
        switch direction {
        case .client: return Color(hex: 0x6650a4)
        case .server: return Color(hex: 0x7D5260)
        case .system: return Color(hex: 0xFFB3261E)
        case .udpSend: return Color(hex: 0x6650a4)
        case .udpRecv: return Color(hex: 0x7D5260)
        }
    }
}

/// 统一的「消息历史」卡（对齐 Android 那边三处几乎一样的日志卡）：
/// 标题 + 清空/复制 + 消息列表。UdpTest 消息历史 / WG 消息历史 / App 内日志浮层三处共用。
///
/// 顺带统一两件事：
///  1. **自动跟随**：默认滚到最底；手指拖动时暂停跟随；拖完那一刻若已贴底就恢复跟随。
///     iOS 15.6 没有 `scrollPosition` / `onScrollGeometryChange` / `onScrollPhaseChange`，
///     所以用 `GeometryReader` + `PreferenceKey` 判「最后一行是否可见」，
///     并且**只在手动滚动停下那一刻**重新判断 —— 不能用行数判断：新消息一进来
///     「贴底」会瞬间变 false，跟随就再也回不来了。
///  2. 显示时给 JSON 插零宽空格（`logDisplayText`），复制仍用原文。
struct LogCard: View {
    let title: String
    let lines: [LogLine]
    /// 列表左右内边距。UdpTest 页要求 0（紧贴卡片边缘）；标题行和分割线始终留 12
    var listHorizontalPadding: CGFloat = 12
    /// 列表底部留白（App 内日志要留够，别被右下角「日志」按钮挡住）
    var listBottomPadding: CGFloat = 8
    /// 列表高度上限；nil = 占满剩余空间（UdpTest 页那套）
    var listHeight: CGFloat? = nil
    var fontSize: CGFloat = 10
    var emptyText: String = "暂无日志"
    var onClear: (() -> Void)? = nil
    var onClose: (() -> Void)? = nil

    @State private var followTail = true
    @State private var userScrolling = false
    @State private var lastRowBottom: CGFloat = 0
    @State private var viewportHeight: CGFloat = 0
    @State private var showingCopied = false

    private static let space = "p2pnet.logcard"

    private var atBottom: Bool {
        // 还没量到（lastRowBottom == 0）时按「贴底」算
        lastRowBottom <= viewportHeight + 8
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header
                .padding(.horizontal, 12)

            Divider()
                .padding(.horizontal, 12)

            if lines.isEmpty {
                VStack {
                    Spacer()
                    HStack {
                        Spacer()
                        Text(emptyText)
                            .font(.system(size: fontSize + 3))
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    Spacer()
                }
            } else {
                logList
            }
        }
    }

    // MARK: - 标题行

    private var header: some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.footnote)
                .fontWeight(.medium)
                .foregroundColor(.secondary)

            Spacer(minLength: 4)

            if let onClear = onClear, !lines.isEmpty {
                Button("清空", action: onClear)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }

            Button(action: copyAll) {
                Text("📋复制")
                    .font(.system(size: 10))
            }
            .foregroundColor(.secondary)
            .disabled(lines.isEmpty)

            if showingCopied {
                Text("已复制")
                    .font(.system(size: 10))
                    .foregroundColor(.blue)
            }

            if let onClose = onClose {
                Button(action: onClose) {
                    Text("✕").font(.system(size: 12))
                }
                .foregroundColor(.secondary)
            }
        }
    }

    // MARK: - 列表（自带跟随底部）

    private var logList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(lines) { line in
                        row(line)
                            .id(line.id)
                            .background(
                                GeometryReader { g in
                                    Color.clear.preference(
                                        key: LastRowBottomKey.self,
                                        value: g.frame(in: .named(Self.space)).maxY
                                    )
                                }
                            )
                    }
                }
                .padding(.horizontal, listHorizontalPadding)
                .padding(.bottom, listBottomPadding)
            }
            .coordinateSpace(name: Self.space)
            .background(
                GeometryReader { g in
                    Color.clear.preference(key: ViewportHeightKey.self, value: g.size.height)
                }
            )
            .onPreferenceChange(LastRowBottomKey.self) { lastRowBottom = $0 }
            .onPreferenceChange(ViewportHeightKey.self) { viewportHeight = $0 }
            // 手动拖动时暂停跟随；松手那一刻若已贴底就恢复（iOS 15 没有滚动阶段 API，用拖动手势代替）
            .simultaneousGesture(
                DragGesture(minimumDistance: 1)
                    .onChanged { _ in userScrolling = true }
                    .onEnded { _ in
                        userScrolling = false
                        followTail = atBottom
                    }
            )
            .onAppear {
                followTail = true
                scrollToBottom(proxy, animated: false)
            }
            .onChange(of: lines.count) { _ in
                if followTail && !userScrolling {
                    scrollToBottom(proxy, animated: true)
                }
            }
            .frame(height: listHeight)
        }
    }

    private func row(_ line: LogLine) -> some View {
        HStack(alignment: .top, spacing: 4) {
            if let label = line.label {
                Text(label)
                    .font(.system(size: fontSize, design: .monospaced))
                    .foregroundColor(line.labelColor ?? .secondary)
                    .frame(width: 52, alignment: .leading)
            }
            Text(logDisplayText(line.text))
                .font(.system(size: fontSize, design: .monospaced))
                .foregroundColor(.secondary)
            Spacer(minLength: 0)
        }
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy, animated: Bool) {
        guard let last = lines.last else { return }
        if animated {
            withAnimation(.linear(duration: 0.12)) {
                proxy.scrollTo(last.id, anchor: .bottom)
            }
        } else {
            proxy.scrollTo(last.id, anchor: .bottom)
        }
    }

    // MARK: - 复制（用原文，不带零宽字符）

    private func copyAll() {
        let text = lines.map { line -> String in
            if let prefix = line.copyPrefix {
                return "\(prefix): \(line.text)"
            }
            return line.text
        }.joined(separator: "\n")
        UIPasteboard.general.string = text
        showingCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            showingCopied = false
        }
    }
}

// MARK: - PreferenceKey

private struct LastRowBottomKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

private struct ViewportHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}
