import SwiftUI
import UIKit
import PhotosUI
import UniformTypeIdentifiers

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

    // === 文件选择器（FILE bar，走 UIDocumentPickerViewController；支持任意文件类型） ===
    @State private var showFilePicker = false

    // === 语音模式（VOICE bar）===
    @State private var voiceState: VoiceState = .idle
    @State private var voiceRecorder = VoiceRecorder()
    @State private var voicePermissionDenied: Bool = false

    private enum VoiceState { case idle, recording }

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
        let prevMode = currentInputMode
        currentInputMode = mode

        // 离开 VOICE：cancel 进行中的录音，释放 AudioSession
        if prevMode == .voice {
            releaseVoiceRecorder()
        }
        // 进入 VOICE：请求权限（缺权限会触发 System 弹窗）
        if mode == .voice {
            Task { await requestVoicePermissionIfNeeded() }
        }

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
                .foregroundColor(Color(hex: "#333333"))
                .accentColor(Color(hex: "#2196F3"))
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background {
                    RoundedRectangle(cornerRadius: 20)
                        .fill(Color(hex: "#F5F5F5"))
                }
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
            .background {
                RoundedRectangle(cornerRadius: 20)
                    .fill(Color(hex: "#2196F3"))
            }
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
        HStack(spacing: 12) {
            switch voiceState {
            case .idle:
                // 空闲态：单个开始按钮（居中）
                Spacer()
                Button(action: { startVoiceRecording() }) {
                    Text(voicePermissionDenied ? "未授权麦克风" : "未在录音，点我开始")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Color(hex: voicePermissionDenied ? "#999999" : "#2196F3"))
                        .cornerRadius(20)
                }
                .buttonStyle(.plain)
                .disabled(voicePermissionDenied)
                Spacer()
            case .recording:
                // 录音态：横向「取消 / 发送」两个按钮（均分居中）
                Spacer()
                Button(action: { cancelVoiceRecording() }) {
                    Text("取消")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(Color(hex: "#2196F3"))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(Color(hex: "#E3F2FD"))
                        .cornerRadius(20)
                }
                .buttonStyle(.plain)

                Button(action: { sendVoiceRecording() }) {
                    Text("发送")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(Color(hex: "#2196F3"))
                        .cornerRadius(20)
                }
                .buttonStyle(.plain)
                Spacer()
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
        .background(Color.white)
    }

    private var fileInputBar: some View {
        HStack(spacing: 12) {
            Spacer()
            Button(action: { showFilePicker = true }) {
                HStack(spacing: 6) {
                    Text("📁")
                    Text("选择文件发送")
                }
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Color(hex: "#2196F3"))
                .cornerRadius(20)
            }
            .buttonStyle(.plain)
            Spacer()
        }
        .padding()
        .background(Color.white)
        .sheet(isPresented: $showFilePicker) {
            FilePicker(
                isPresented: $showFilePicker,
                onPicked: { url in
                    handlePickedURL(url)
                }
            )
        }
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
            senderType: .socket,
            senderName: "我",
            content: text
        )
        let info = Message(
            senderId: "self",
            senderType: .socket,
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
            senderType: .socket,
            senderName: "我",
            content: label
        )
        let info = Message(
            senderId: "self",
            senderType: .socket,
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
                    let sockTypeStr = config.params["sockType"] ?? "TCP"
                    if sockTypeStr == "WS" {
                        // WS 走 WsParticipant（URLSessionWebSocketTask）
                        let path = config.params["path"] ?? "/"
                        let p = WsParticipant(sessionId: sessionId, ip: ip, port: port, path: path)
                        p.onMessage = { [self] msg in
                            sessionManager.addMessage(sessionId, message: msg)
                            messages = sessionManager.getMessages(sessionId)
                        }
                        p.connect()
                        activeParticipants[config.id] = p
                    } else {
                        let sockType = sockTypeStr == "UDP" ? SocketType.udp : .tcp
                        let p = SocketParticipant(sessionId: sessionId, ip: ip, port: port, sockType: sockType)
                        p.onMessage = { [self] msg in
                            sessionManager.addMessage(sessionId, message: msg)
                            messages = sessionManager.getMessages(sessionId)
                        }
                        p.connect()
                        activeParticipants[config.id] = p
                    }
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
                    let subType = config.params["subType"] ?? "text"
                    let voice = config.params["voice"] ?? "alloy"
                    let p = AiParticipant(sessionId: sessionId, ip: ip, port: port, apiKey: apiKey, model: model, subType: subType, voice: voice)
                    p.onMessage = { [self] msg in
                        sessionManager.addMessage(sessionId, message: msg)
                        messages = sessionManager.getMessages(sessionId)
                    }
                    p.connect()
                    activeParticipants[config.id] = p
                }
            case .agent:
                if let addr = config.params["addr"],
                   let port = config.params["port"] {
                    let username = config.params["username"] ?? ""
                    let password = config.params["password"] ?? ""
                    let subType = config.params["subType"] ?? "openclaw"
                    let p = AgentParticipant(
                        sessionId: sessionId,
                        name: config.name,
                        addr: addr,
                        port: port,
                        username: username,
                        password: password,
                        subType: subType
                    )
                    p.onMessage = { [self] msg in
                        sessionManager.addMessage(sessionId, message: msg)
                        messages = sessionManager.getMessages(sessionId)
                    }
                    p.connect()
                    activeParticipants[config.id] = p
                } else {
                    let msg = Message(
                        senderId: "system",
                        senderType: .agent,
                        senderName: "系统",
                        content: "❌ AGENT 配置错误：需要 addr 和 port",
                        isInfo: true
                    )
                    sessionManager.addMessage(sessionId, message: msg)
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
            case .echo:
                // 复读机：纯客户端，发什么回什么，无需任何配置
                let delayStr = config.params["delay"] ?? "0.5"
                let delay = Float(delayStr) ?? 0.5
                let p = EchoParticipant(sessionId: sessionId, delaySeconds: delay)
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
        // 离开页面时释放语音资源（防后台麦克风常亮）
        releaseVoiceRecorder()
    }

    // MARK: - 语音模式 helpers

    /// 进入 VOICE mode 时调用：异步检查权限；通过则启用按钮，失败则禁用按钮 + 改文案。
    private func requestVoicePermissionIfNeeded() async {
        let granted = await voiceRecorder.initSession()
        voicePermissionDenied = !granted
    }

    /// 释放 VoiceRecorder；UI 复位到空闲态
    private func releaseVoiceRecorder() {
        voiceRecorder.release()
        voiceState = .idle
    }

    /// 「未在录音，点我开始」按钮点击：开始录音
    private func startVoiceRecording() {
        if voicePermissionDenied {
            // 用户之前拒绝过，重新尝试一次（iOS 17+ 系统会再次弹窗；低版本会直接返回 false）
            Task { await requestVoicePermissionIfNeeded() }
            return
        }
        if voiceRecorder.start() {
            voiceState = .recording
        } else {
            voicePermissionDenied = true
        }
    }

    /// 「取消」按钮点击：丢弃本次录音，回到空闲态
    private func cancelVoiceRecording() {
        voiceRecorder.cancel()
        voiceState = .idle
    }

    /// 「发送」按钮点击：停录音 → 贴气泡 + info → 广播 binary
    private func sendVoiceRecording() {
        guard let result = voiceRecorder.stop() else {
            // 空录音
            let sysMsg = Message(
                senderId: "system",
                senderType: .socket,
                senderName: "系统",
                content: "🎤 录音为空，未发送",
                isInfo: true
            )
            sessionManager.addMessage(sessionId, message: sysMsg)
            messages = sessionManager.getMessages(sessionId)
            voiceState = .idle
            return
        }

        let wavBytes = result.wavData
        let durationMs = result.durationMs
        voiceState = .idle

        // self audio bubble（imageBytes 字段复用，adapter 用 BlobSniffer 分流到 audio 气泡）
        let bubble = Message(
            senderId: "self",
            senderType: .socket,
            senderName: "我",
            content: "",
            imageBytes: wavBytes
        )
        sessionManager.addMessage(sessionId, message: bubble)

        // info 小灰字：📤 发送 type=audio/wav len=N duration=X.XXXs（秒，3 位小数）
        let info = Message(
            senderId: "self",
            senderType: .socket,
            senderName: "我",
            content: String(format: "📤 发送 type=audio/wav len=%d duration=%.3fs", wavBytes.count, durationMs / 1000.0),
            isInfo: true
        )
        sessionManager.addMessage(sessionId, message: info)
        messages = sessionManager.getMessages(sessionId)

        broadcastBinaryToParticipants(wavBytes)
    }

    private func broadcastToParticipants(_ text: String) {
        let configs = sessionManager.getParticipants(sessionId)
        for config in configs {
            activeParticipants[config.id]?.sendInput(text)
        }
    }

    /// 广播二进制帧给所有相关参与者：
    /// - SOCKET/WS → 发 binary frame
    /// - AI(subType=="stt") → 当作语音发给 STT API（/v1/audio/transcriptions）
    /// - 其他（SOCKET/TCP/UDP、TEXT AI、PTY 等）→ no-op
    /// 与 Android `broadcastBinaryToParticipants` 对齐。
    private func broadcastBinaryToParticipants(_ data: Data) {
        let configs = sessionManager.getParticipants(sessionId)
        for config in configs {
            switch config.type {
            case .socket:
                activeParticipants[config.id]?.sendBinary(data)  // Participant.sendBinary 默认 no-op，WS override 真正发
            case .ai:
                let subType = config.params["subType"] ?? "text"
                if subType == "stt",
                   let ai = activeParticipants[config.id] as? AiParticipant {
                    ai.sendVoice(data)
                }
            case .agent:
                break  // openclaw 暂不处理 binary
            case .echo:
                // 复读机：原样回吐收到的 bytes，adapter 按 mime 决定渲染分支
                activeParticipants[config.id]?.sendBinary(data)
            default:
                break  // PTY/SERIAL/SSH/TELNET/BLUETOOTH 等：binary no-op
            }
        }
    }

    /// 用户从系统相册选完图片后的处理：
    /// 1) 读 bytes
    /// 2) 贴自己 imageBytes 气泡
    /// 3) 打 📤 发送 type=... size=... len=... info
    /// 4) 广播给所有 WS participant
    /**
     * 从 UIDocumentPickerViewController 选完文件后的处理：
     * 1) 用 security-scoped resource 读 bytes
     * 2) 调 handlePickedData 走现有的 imageBytes 气泡 + info + broadcast 流程
     */
    private func handlePickedURL(_ url: URL?) {
        guard let url = url else {
            handlePickedData(nil)
            return
        }
        let didStart = url.startAccessingSecurityScopedResource()
        defer { if didStart { url.stopAccessingSecurityScopedResource() } }
        let data = try? Data(contentsOf: url)
        handlePickedData(data)
    }

    private func handlePickedData(_ data: Data?) {
        guard let bytes = data else {
            let msg = Message(
                senderId: "system",
                senderType: .socket,
                senderName: "系统",
                content: "❌ 图片读取失败",
                isInfo: true
            )
            sessionManager.addMessage(sessionId, message: msg)
            messages = sessionManager.getMessages(sessionId)
            return
        }

        // 1) self image bubble
        let bubble = Message(
            senderId: "self",
            senderType: .socket,
            senderName: "我",
            content: "",
            imageBytes: bytes
        )
        sessionManager.addMessage(sessionId, message: bubble)

        // 2) info 行
        let detected = BlobSniffer.detectType(bytes)
        var sizeStr = ""
        if let size = BlobSniffer.decodeImageSize(bytes) {
            sizeStr = " size=\(size.width)x\(size.height)"
        }
        let info = Message(
            senderId: "self",
            senderType: .socket,
            senderName: "我",
            content: "📤 发送 type=\(detected)\(sizeStr) len=\(bytes.count)",
            isInfo: true
        )
        sessionManager.addMessage(sessionId, message: info)
        messages = sessionManager.getMessages(sessionId)

        // 3) 广播给所有 WS participant
        broadcastBinaryToParticipants(bytes)
    }
}

// MARK: - UIDocumentPickerViewController 包装（任意文件类型，iOS 14+）

/// 把 UIDocumentPickerViewController 包成 SwiftUI view。打开系统文件选择器，支持任意文件类型。
/// 用 .sheet(isPresented:) 弹出，依赖 `isPresented` binding 在选完 / 取消时自动收起。
///
/// iOS 没有 /sdcard/ 概念（沙盒 + iCloud Drive），起始位置由系统默认（通常是 iCloud Drive / 最近使用）。
/// 选中文件后回调 URL，ChatView.handlePickedURL 负责读 bytes。
private struct FilePicker: UIViewControllerRepresentable {
    @Binding var isPresented: Bool
    let onPicked: (URL?) -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item])
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {
        // no-op
    }

    func makeCoordinator() -> FilePickerCoordinator {
        FilePickerCoordinator(
            onPicked: { [self] url in
                onPicked(url)
                isPresented = false
            },
            onCancel: { [self] in
                isPresented = false
            }
        )
    }
}

private final class FilePickerCoordinator: NSObject, UIDocumentPickerDelegate {
    let onPicked: (URL?) -> Void
    let onCancel: () -> Void

    init(onPicked: @escaping (URL?) -> Void, onCancel: @escaping () -> Void) {
        self.onPicked = onPicked
        self.onCancel = onCancel
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        onPicked(urls.first)
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        onCancel()
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
