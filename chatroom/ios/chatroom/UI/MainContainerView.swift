import SwiftUI

/// 主容器（对应 Android MainActivity）
/// 首页 + ViewPager + TabBar（模拟 Android SessionTabBar）
///
/// 单个 tab 的结构（从左到右）：
/// ```
/// [ⓘ]  名字  [×]
///  ↑          ↑
///  点它展开/收起重连面板   点它关闭该会话（首页 tab 没有 ⓘ 和 ×）
/// ```
/// tab 本体点击 = 切到该会话；名字是会话创建时间；未连接 / 链路失败时整个字串加删除线。
struct MainContainerView: View {
    @StateObject private var sessionManager = SessionManager.shared

    // Tab 状态
    @State private var selectedTab: String = "home"
    /// 已打开的会话 tab 顺序（= SessionManager.sessionOrder）
    @State private var chatSessions: [String] = []
    /// 当前展开了重连面板的会话
    @State private var openPanels: Set<String> = []
    @State private var didRestore = false

    var body: some View {
        VStack(spacing: 0) {
            // 页面内容：所有页面都常驻 view 树，只显示选中的那个。
            // 不需要 TabView：
            //   - TabView(.page) 有横向 swipe—误触
            //   - TabView 默认 .automatic 有底部系统 tab bar—多出一块灰白区域
            // ZStack + opacity/allowsHitTesting 是最干净的纯 SwiftUI 做法。
            ZStack {
                // 首页
                HomeView(onSessionCreated: { sessionId in
                    openSession(sessionId)
                })
                .opacity(selectedTab == "home" ? 1 : 0)
                .allowsHitTesting(selectedTab == "home")

                // 各 Chat 会话（常驻 view 树 → 切 tab 不重连 TCP）
                ForEach(chatSessions, id: \.self) { sessionId in
                    ChatView(sessionId: sessionId, showReconnectPanel: panelBinding(sessionId))
                        .opacity(selectedTab == sessionId ? 1 : 0)
                        .allowsHitTesting(selectedTab == sessionId)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            // 底部 TabBar
            tabBar
        }
        .onAppear(perform: restoreIfNeeded)
    }

    // MARK: - TabBar

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                // 首页 Tab（无 ⓘ、无 ×）
                TabButton(
                    name: "首页",
                    isSelected: selectedTab == "home",
                    isHome: true,
                    strikeThrough: false,
                    onTap: { selectedTab = "home" },
                    onInfo: nil,
                    onClose: nil
                )

                // Session Tabs
                ForEach(chatSessions, id: \.self) { sessionId in
                    TabButton(
                        name: Self.sessionTimeLabel(sessionId),
                        isSelected: selectedTab == sessionId,
                        isHome: false,
                        strikeThrough: !sessionManager.isSessionUp(sessionId),
                        onTap: { selectedTab = sessionId },
                        onInfo: { onInfoTap(sessionId) },
                        onClose: { closeSession(sessionId) }
                    )
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
        }
        .background(Color(hex: "#F5F5F5"))
    }

    // MARK: - Actions

    /// 启动恢复：把上次进程落盘的会话读回来（一律未连接），据此建 tab。
    /// 只做一次（onAppear 可能触发多次）。
    private func restoreIfNeeded() {
        guard !didRestore else { return }
        didRestore = true
        sessionManager.restoreFromStore()
        chatSessions = sessionManager.getSessionOrder()
    }

    private func openSession(_ sessionId: String) {
        if !chatSessions.contains(sessionId) {
            chatSessions.append(sessionId)
        }
        openPanels.remove(sessionId)
        selectedTab = sessionId
    }

    /// 点会话名左边的 ⓘ：展开 / 收起该会话的重连面板。
    /// 如果点的不是当前会话，先切过去（对应 Android `MainActivity.onSessionInfoClick`）。
    private func onInfoTap(_ sessionId: String) {
        if selectedTab != sessionId {
            selectedTab = sessionId
        }
        if openPanels.contains(sessionId) {
            openPanels.remove(sessionId)
        } else {
            openPanels.insert(sessionId)
        }
    }

    private func closeSession(_ sessionId: String) {
        // 先从 view 树移除：ChatView.onDisappear 会断开该会话的参与者
        chatSessions.removeAll { $0 == sessionId }
        openPanels.remove(sessionId)
        // 再清 SessionManager（同时从持久化里删掉，重启后不会再恢复）
        sessionManager.removeSession(sessionId)
        if selectedTab == sessionId {
            selectedTab = "home"
        }
    }

    /// 某会话面板的展开状态绑定
    private func panelBinding(_ sessionId: String) -> Binding<Bool> {
        Binding(
            get: { openPanels.contains(sessionId) },
            set: { open in
                if open {
                    openPanels.insert(sessionId)
                } else {
                    openPanels.remove(sessionId)
                }
            }
        )
    }

    /// tab 名字 = 会话创建时间 `YYMM-DDhh-mmss`（年月-日时-分秒，例 `2609-1301-2716`），纯文字、无 emoji。
    ///
    /// 从 sessionId 里的 epoch 毫秒解析（`SessionManager.createSession()` 生成的就是
    /// `session_<epochMillis>`）；解析不出来（理论上不会）就用 0。
    static func sessionTimeLabel(_ sessionId: String) -> String {
        let millis = SessionManager.createdAt(fromSessionId: sessionId)
        return timeLabelFormatter.string(from: Date(timeIntervalSince1970: Double(millis) / 1000.0))
    }

    private static let timeLabelFormatter: DateFormatter = {
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.dateFormat = "yyMM-ddHH-mmss"
        return fmt
    }()
}

// MARK: - Tab Button

private struct TabButton: View {
    let name: String
    let isSelected: Bool
    let isHome: Bool
    let strikeThrough: Bool
    let onTap: () -> Void
    let onInfo: (() -> Void)?
    let onClose: (() -> Void)?

    var body: some View {
        HStack(spacing: 4) {
            // 名字左边的 ⓘ：展开 / 收起重连面板（首页不显示）
            if !isHome, let onInfo {
                Button(action: onInfo) {
                    Text("ⓘ")
                        .font(.system(size: 15))
                        .foregroundColor(textColor)
                }
                .buttonStyle(.plain)
            }

            Text(name)
                .font(.system(size: 14))
                .strikethrough(strikeThrough, color: textColor)
                .foregroundColor(textColor)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)

            if !isHome, let onClose {
                Button(action: onClose) {
                    Text("×")
                        .font(.system(size: 16))
                        .foregroundColor(textColor)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        // tab 名是 14 字符的时间戳（YYMM-DDhh-mmss），比原来的 "💬 1" 长很多，
        // 这里放宽 padding / 最小宽度，保证加上 ⓘ 和 × 之后也不挤（对应 Android dp(128)）
        .frame(minWidth: 128)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isSelected ? Color(hex: "#2196F3") : Color(hex: "#E0E0E0"))
        )
        // tab 本体点击 = 切到该会话。用 contentShape + onTapGesture 而不是外层 Button：
        // Button 套 Button 在 iOS 上会让 ⓘ / × 的点击被外层吞掉
        .contentShape(RoundedRectangle(cornerRadius: 8))
        .onTapGesture(perform: onTap)
    }

    private var textColor: Color {
        isSelected ? .white : Color(hex: "#888888")
    }
}
