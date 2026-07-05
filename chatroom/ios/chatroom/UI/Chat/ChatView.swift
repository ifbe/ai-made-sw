import SwiftUI
import UIKit

/// 聊天界面主视图（对应 Android ChatFragment）
/// 2026-07 重构：与 Android 端对齐
/// - 顶部 handle 行（spinner + "拖拽" + ⤢）可调输入区高度
/// - ⤢ 按钮切换最大化（隐藏聊天列表，输入区占满）
/// - 6 种输入模式（empty/text/remote/dim3/voice/file）
struct ChatView: View {
    let sessionId: String

    @StateObject private var sessionManager = SessionManager.shared
    @State private var currentInputMode: ChatInputMode = .text
    @State private var inputText: String = ""
    @State private var messages: [Message] = []
    /// `Participant` 不是值类型，用普通 var + 回调，不参与 SwiftUI 响应式
    @State private var activeParticipants: [String: Participant] = [:]

    // === 拖拽 + 最大化 状态 ===
    @State private var inputHeight: CGFloat = 200     // 当前 inputArea 像素高度（含 handle）
    @State private var isMaximized: Bool = false
    @State private var lastNonMaximizedHeight: CGFloat = 200
    /// GeometryReader 给的容器高度（chat 页可用高度，扣状态栏/TabBar/底部 TabBar 之后）。
    /// **不**用 `UIScreen.main.bounds.height` 当上限基线——后者含状态栏、TabBar、Dynamic Island，
    /// 超出可用区时 inputArea 会冲破 VStack 容器，SwiftUI layout 要么 clip 要么进入 layout 振荡。
    @State private var availableHeight: CGFloat = 600

    private let handleHeight: CGFloat = 36
    /// 拖拽上限需要保证 chat 区域至少留一行 (≈60pt)，防止把 chat 挤没了
    private let chatMinReservedHeight: CGFloat = 60

    /// 各模式 inputBar **内容**的最小像素高度（不含顶部 handle 36pt）。
    /// 总 inputArea min = handleHeight(36) + 这里。
    ///
    /// 2026-07-05 跟用户定下：
    /// - empty = 0：可以完全隐藏，只剩 handle 行
    /// - text = 44：一行 TextField + Send 按钮高度（iOS tap-target 最小值）
    /// - remote = 120：两个 3×3 网格在窄屏仍可读
    /// - dim3 = 160：适配横屏（landscape TabView ≈ 300pt，216pt inputArea min 能装下）
    /// - voice / file = 44：最小可点（同 text）
    private let minHeightByMode: [ChatInputMode: CGFloat] = [
        .empty: 0, .text: 44, .remote: 120, .dim3: 160, .voice: 44, .file: 44
    ]

    // MARK: - Body

    var body: some View {
        GeometryReader { geo in
            VStack(spacing: 0) {
                if !isMaximized {
                    messagesList
                        .frame(height: max(0, geo.size.height - inputHeight))
                }
                inputArea
                    .frame(height: isMaximized ? geo.size.height : inputHeight)
            }
            .onAppear { availableHeight = geo.size.height }
            .onChange(of: geo.size.height) { newH in availableHeight = newH }
        }
        .background(Color(hex: "#F0F0F0"))
        .onAppear {
            loadMessages()
            connectParticipants()
        }
        .onDisappear {
            disconnectParticipants()
        }
    }

    // MARK: - 消息列表

    private var messagesList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(messages) { msg in
                        MessageRowView(message: msg).id(msg.id)
                    }

                    // 末尾 marker（用于 scrollTo 定位）
                    Color.clear.frame(height: 1).id("endMarker")
                }
                .padding(.horizontal, 4)
                .padding(.vertical, 4)
            }
            // iOS 17+：原生 sticky-bottom 粘底功能。仅靠该 modifier 即可让"少消息时贴底部显示"
            // 不再用 Spacer().frame(maxHeight: .infinity)——后者会在父高度快速变化（例如拖拽手把时
            // messagesList height 实时缩减/扩大）时让 SwiftUI layout 进入振荡、退化为卡死。
            // 项目 deployment target = 15.6，所以 iOS 17+ 才用这个；
            // iOS 15-16 仍退回到老的 Spacer.maxHeight（仅在 iOS 17+ 之后的运行环境才会拖拽，才会触发振荡）。
            .modifier(StickyBottomIfAvailable())
            .onAppear { proxy.scrollTo("endMarker", anchor: .bottom) }
            .onChange(of: messages.count) { _ in
                // iOS 上没有 OnScrollListener 这种机制做"贴底跟随 + 用户上滑暂停"
                // 简易实现：每次新消息都滚到底
                // （TODO: 想做严格贴底跟随，可加 DragGesture 检测 + 浮窗"↓ 跳到底"按钮）
                withAnimation(.easeOut(duration: 0.15)) {
                    proxy.scrollTo("endMarker", anchor: .bottom)
                }
            }
        }
    }

    // MARK: - 输入区（handle + content）

    private var inputArea: some View {
        VStack(spacing: 0) {
            handleRow
                .frame(height: handleHeight)

            currentInputContent
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Color.white)
        .clipped()
    }

    @ViewBuilder
    private var currentInputContent: some View {
        switch currentInputMode {
        case .empty: emptyInputBar
        case .text: textInputBar
        case .remote: remoteInputBar
        case .dim3: dim3InputBar
        case .voice: voiceInputBar
        case .file: fileInputBar
        }
    }

    // MARK: - Handle 行：spinner + 拖拽 + 最大化

    private var handleRow: some View {
        HStack(spacing: 4) {
            modeMenuButton
            dragHandle
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            maximizeButton
        }
        .padding(.horizontal, 4)
        .background(Color(hex: "#F5F5F5"))
    }

    private var modeMenuButton: some View {
        Menu {
            ForEach(ChatInputMode.allCases) { mode in
                Button {
                    switchMode(to: mode)
                } label: {
                    Text("\(mode.icon) \(mode.label)")
                }
            }
        } label: {
            HStack(spacing: 2) {
                Text(currentInputMode.icon).font(.system(size: 11))
                Text(currentInputMode.label).font(.system(size: 10))
            }
            .foregroundColor(Color(hex: "#2196F3"))
            .padding(.horizontal, 8)
            .frame(minWidth: 56, minHeight: 28)
            .background(Color(hex: "#E3F2FD"))
            .cornerRadius(8)
        }
        .frame(width: 88, height: 30)
    }

    /// "拖拽" label —— 走 UIKit 手势 (`UIPanGestureRecognizer`)，不参与 SwiftUI gesture-arbitration。
    ///
    /// 修复史：
    /// - 第一次（错）认为 SwiftUI `DragGesture` + `.highPriorityGesture` + `@GestureState` 能解决。→ 报仍然冻结。
    /// - 真正根因：`ChatView` 嵌在 `TabView(.page(...))` 里，SwiftUI DragGesture 与 TabView 的
    ///   page-swipe 手势争用同一个 gesture-arbitration 队列，iOS 17+ 出现**死锁型卡死**（不是 200ms
    ///   卡顿，是彻底无响应）。SwiftUI 没有完整 API 可干净绕开这个死锁。
    /// - 现在的方案：用 `UIPanGestureRecognizer` 包进 `UIViewRepresentable`。UIKit 手势**独立**于
    ///   SwiftUI 的 gesture-arbitration 队列，不会跟 TabView 的 page-swipe 冲突。这是 Apple 自家
    ///   framework 之间的标准协作方式。
    ///
    /// 配合改动：
    /// - `availableHeight`（@State）记录 GeometryReader 真实容器高度，**不用** UIScreen.main.bounds
    /// - `messagesList` 不再用 `Spacer().frame(maxHeight: .infinity)`（layout 振荡源）
    private var dragHandle: some View {
        DragHandleBar(
            inputHeight: $inputHeight,
            minHeight: handleHeight + (minHeightByMode[currentInputMode] ?? 80),
            maxHeight: max(availableHeight - chatMinReservedHeight, handleHeight + (minHeightByMode[currentInputMode] ?? 80)),
            isMaximized: isMaximized
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// maxInputHeight / currentScreenHeight 旧逻辑不再需要——高度直接由 `availableHeight`
    /// （GeometryReader 给的真实容器高度）算，避免 UIScreen.main.bounds 在刘海/灵动岛机型上超限。
    ///（保留占位避免别人误以为有这两函数仍存在，函数体已删除。）

    private var maximizeButton: some View {
        Button(action: toggleMaximize) {
            HStack(spacing: 4) {
                Text(isMaximized ? "⤡" : "⤢")
                Text(isMaximized ? "退出" : "全屏")
            }
            .font(.system(size: 13))
            .foregroundColor(isMaximized ? .gray : Color(hex: "#2196F3"))
            .padding(.horizontal, 10)
            .frame(width: 88, height: 30)
            .background(Color(hex: "#E3F2FD"))
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
    }

    // MARK: - 拖拽 / 最大化逻辑

    private func minHeightForCurrentMode() -> CGFloat {
        handleHeight + (minHeightByMode[currentInputMode] ?? 80)
    }

    private func toggleMaximize() {
        if isMaximized {
            // 还原
            isMaximized = false
            inputHeight = lastNonMaximizedHeight > 0 ? lastNonMaximizedHeight : minHeightForCurrentMode()
        } else {
            // 最大化
            lastNonMaximizedHeight = inputHeight
            isMaximized = true
        }
    }

    private func switchMode(to mode: ChatInputMode) {
        guard mode != currentInputMode else { return }
        currentInputMode = mode
        // 切到模式后如果当前 inputHeight 不足新模式最小值，自动撑大
        let minPx = minHeightForCurrentMode()
        if inputHeight < minPx {
            inputHeight = minPx
        }
    }

    // MARK: - 6 种 inputBar 内容

    private var emptyInputBar: some View {
        ZStack {
            Color.white
            // 实时显示当前 inputArea 的宽×高（pt 数）。与 Android 对齐：
            // 字体大、黑色、水平 + 垂直居中（之前是 `.secondary` 在白底上看不清、
            // size=18 偏小，Text 在 GeometryReader 里默认 top-left 不居中）。
            GeometryReader { geo in
                Text("\(Int(geo.size.width))pt × \(Int(geo.size.height))pt")
                    .font(.system(size: 28, weight: .medium))
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
                    .allowsHitTesting(false)
            }
        }
    }

    private var textInputBar: some View {
        HStack(spacing: 8) {
            TextField("输入消息...", text: $inputText)
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color(hex: "#F5F5F5"))
                .cornerRadius(20)
                .overlay(
                    RoundedRectangle(cornerRadius: 20)
                        .stroke(Color(hex: "#DDDDDD"), lineWidth: 1)
                )

            Button("发送") {
                sendTextMessage()
            }
            .foregroundColor(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(hex: "#2196F3"))
            .cornerRadius(20)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
        .background(Color.white)
    }

    private var remoteInputBar: some View {
        HStack(spacing: 4) {
            DirectionPadView { label in
                sendDirectionLabel(label)
            }

            Rectangle()
                .fill(Color(hex: "#CCCCCC"))
                .frame(width: 1)
                .padding(.horizontal, 4)

            NumPadView { label in
                sendDirectionLabel(label)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
        .background(Color.white)
    }

    private var dim3InputBar: some View {
        HStack(spacing: 4) {
            // 左侧：箭头 3×3 + +/- 按钮（与 Android `inputBarDim3`/`leftSideDim3` 对齐）
            // 与 `DirectionPadView`（qwe 遥控模式）不同：dim3 模式显示箭头，remote 模式才显示 qwe。
            ArrowPadView { label in
                sendDirectionLabel(label)
            }

            Rectangle()
                .fill(Color(hex: "#CCCCCC"))
                .frame(width: 1)
                .padding(.horizontal, 4)

            AxisView { cmd in
                sendDirectionLabel(cmd)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
        .background(Color.white)
    }

    private var voiceInputBar: some View {
        HStack {
            Text("语音模式（TODO）")
                .font(.system(size: 14))
                .foregroundColor(Color(hex: "#999999"))
            Spacer()
        }
        .padding()
        .background(Color.white)
    }

    private var fileInputBar: some View {
        HStack {
            Text("文件模式（TODO）")
                .font(.system(size: 14))
                .foregroundColor(Color(hex: "#999999"))
            Spacer()
        }
        .padding()
        .background(Color.white)
    }

    // MARK: - 消息发送

    private func loadMessages() {
        messages = sessionManager.getMessages(sessionId)
    }

    private func sendTextMessage() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }

        let bubble = Message(
            senderId: "self",
            senderType: .user,
            senderName: "我",
            content: text
        )
        let info = Message(
            senderId: "self",
            senderType: .user,
            senderName: "我",
            content: "📤 发送: \(text)",
            isInfo: true
        )

        sessionManager.addMessage(sessionId, message: bubble)
        sessionManager.addMessage(sessionId, message: info)
        messages = sessionManager.getMessages(sessionId)
        broadcastToParticipants(text)
        inputText = ""
    }

    private func sendDirectionLabel(_ label: String) {
        let bubble = Message(
            senderId: "self",
            senderType: .user,
            senderName: "我",
            content: label
        )
        let info = Message(
            senderId: "self",
            senderType: .user,
            senderName: "我",
            content: "📤 发送: \(label)",
            isInfo: true
        )

        sessionManager.addMessage(sessionId, message: bubble)
        sessionManager.addMessage(sessionId, message: info)
        messages = sessionManager.getMessages(sessionId)
        broadcastToParticipants(label)
    }

    // MARK: - Participants

    private func connectParticipants() {
        let configs = sessionManager.getParticipants(sessionId)
        if configs.isEmpty {
            let msg = Message(
                senderId: "system",
                senderType: .socket,
                senderName: "系统",
                content: "该会话没有任何参与者",
                isInfo: true
            )
            sessionManager.addMessage(sessionId, message: msg)
            messages = sessionManager.getMessages(sessionId)
            return
        }

        for config in configs {
            switch config.type {
            case .socket:
                if let ip = config.params["ip"],
                   let portStr = config.params["port"],
                   let port = Int(portStr) {
                    let sockType = config.params["sockType"] == "UDP" ? SocketType.udp : .tcp
                    let p = SocketParticipant(sessionId: sessionId, ip: ip, port: port, sockType: sockType)
                    p.onMessage = { [self] msg in
                        sessionManager.addMessage(sessionId, message: msg)
                        messages = sessionManager.getMessages(sessionId)
                    }
                    p.connect()
                    activeParticipants[config.id] = p
                } else {
                    let msg = Message(
                        senderId: "system",
                        senderType: .socket,
                        senderName: "系统",
                        content: "❌ SOCKET 配置错误：需要 ip 和 port",
                        isInfo: true
                    )
                    sessionManager.addMessage(sessionId, message: msg)
                }
            case .ai:
                if let ip = config.params["ip"],
                   let port = config.params["port"] {
                    let apiKey = config.params["apiKey"] ?? ""
                    let model = config.params["model"] ?? ""
                    let p = AiParticipant(sessionId: sessionId, ip: ip, port: port, apiKey: apiKey, model: model)
                    p.onMessage = { [self] msg in
                        sessionManager.addMessage(sessionId, message: msg)
                        messages = sessionManager.getMessages(sessionId)
                    }
                    p.connect()
                    activeParticipants[config.id] = p
                }
            case .telnet:
                if let ip = config.params["ip"],
                   let portStr = config.params["port"],
                   let port = Int(portStr) {
                    let user = config.params["user"] ?? ""
                    let password = config.params["password"] ?? ""
                    let p = TelnetParticipant(sessionId: sessionId, ip: ip, port: port, username: user, password: password)
                    p.onMessage = { [self] msg in
                        sessionManager.addMessage(sessionId, message: msg)
                        messages = sessionManager.getMessages(sessionId)
                    }
                    p.connect()
                    activeParticipants[config.id] = p
                }
            case .bluetooth:
                let device = config.params["device"] ?? ""
                let proto = config.params["protocol"] ?? "SPP"
                let p = BluetoothParticipant(sessionId: sessionId, deviceName: device, protocol_: proto)
                p.onMessage = { [self] msg in
                    sessionManager.addMessage(sessionId, message: msg)
                    messages = sessionManager.getMessages(sessionId)
                }
                p.connect()
                activeParticipants[config.id] = p
            default:
                let msg = Message(
                    senderId: "system",
                    senderType: config.type,
                    senderName: "系统",
                    content: "\(config.type.displayName) \(config.type.icon) 暂未实现",
                    isInfo: true
                )
                sessionManager.addMessage(sessionId, message: msg)
            }
        }

        messages = sessionManager.getMessages(sessionId)
    }

    private func disconnectParticipants() {
        activeParticipants.values.forEach { $0.disconnect() }
        activeParticipants.removeAll()
    }

    private func broadcastToParticipants(_ text: String) {
        let configs = sessionManager.getParticipants(sessionId)
        for config in configs {
            activeParticipants[config.id]?.sendInput(text)
        }
    }
}

// MARK: - Sticky bottom 兼容性 modifier（iOS 17+ 用 API，iOS 15-16 退到 Spacer）

/// 在 iOS 17+ 上包装 `defaultScrollAnchor(.bottom)`；低版本（项目 deployment target = 15.6 时）
/// 仍会运行，但 `defaultScrollAnchor` API 不可用，所以 iOS 15-16 不加任何 modifier（接受少量
/// "少消息时靠顶" 的退化 —— 这个分支几乎不被命中，反应在所有现代 iPhone 上都是 iOS 17+）。
private struct StickyBottomIfAvailable: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 17.0, *) {
            content.defaultScrollAnchor(.bottom)
        } else {
            content
        }
    }
}
