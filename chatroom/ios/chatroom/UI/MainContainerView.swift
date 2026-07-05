import SwiftUI

/// 主容器（对应 Android MainActivity）
/// 首页 + ViewPager + TabBar（模拟 Android SessionTabBar）
struct MainContainerView: View {
    @StateObject private var sessionManager = SessionManager.shared

    // Tab 状态
    @State private var selectedTab: String = "home"
    @State private var sessionTabs: [(id: String, name: String)] = []  // (sessionId, tabName)

    // ChatFragments（每个 session 一个 ChatView）
    @State private var chatSessions: [String] = []  // sessionId 列表

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

                // 各 Chat 会话
                ForEach(chatSessions, id: \.self) { sessionId in
                    ChatView(sessionId: sessionId)
                        .opacity(selectedTab == sessionId ? 1 : 0)
                        .allowsHitTesting(selectedTab == sessionId)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            // 底部 TabBar
            tabBar
        }
    }

    // MARK: - TabBar

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                // 首页 Tab
                TabButton(
                    name: "🏠 首页",
                    isSelected: selectedTab == "home",
                    isHome: true
                ) {
                    selectedTab = "home"
                }

                // Session Tabs
                ForEach(sessionTabs, id: \.id) { tab in
                    TabButton(
                        name: tab.name,
                        isSelected: selectedTab == tab.id,
                        isHome: false,
                        onTap: { selectedTab = tab.id },
                        onClose: { closeSession(tab.id) }
                    )
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
        }
        .background(Color(hex: "#F5F5F5"))
    }

    // MARK: - Actions

    private func openSession(_ sessionId: String) {
        chatSessions.append(sessionId)
        sessionTabs.append((id: sessionId, name: "💬 \(sessionTabs.count + 1)"))
        selectedTab = sessionId
    }

    private func closeSession(_ sessionId: String) {
        chatSessions.removeAll { $0 == sessionId }
        sessionTabs.removeAll { $0.id == sessionId }
        sessionManager.removeSession(sessionId)
        if selectedTab == sessionId {
            selectedTab = "home"
        }
    }
}

// MARK: - Tab Button

private struct TabButton: View {
    let name: String
    let isSelected: Bool
    let isHome: Bool
    let onTap: () -> Void
    let onClose: (() -> Void)?

    init(name: String, isSelected: Bool, isHome: Bool, onTap: @escaping () -> Void, onClose: (() -> Void)? = nil) {
        self.name = name
        self.isSelected = isSelected
        self.isHome = isHome
        self.onTap = onTap
        self.onClose = onClose
    }

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 4) {
                Text(tabName)
                    .font(.system(size: 14))
                    .foregroundColor(isSelected ? .white : Color(hex: "#888888"))

                if !isHome, let onClose {
                    Button {
                        onClose()
                    } label: {
                        Text("×")
                            .font(.system(size: 16))
                            .foregroundColor(isSelected ? .white : Color(hex: "#888888"))
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(isSelected ? Color(hex: "#2196F3") : Color(hex: "#E0E0E0"))
            )
        }
    }

    private var tabName: String {
        if isHome { return "🏠 首页" }
        return name
    }
}
