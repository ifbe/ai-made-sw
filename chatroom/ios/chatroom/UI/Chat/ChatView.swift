import SwiftUI

/// 聊天界面主视图（对应 Android ChatFragment）
struct ChatView: View {
    let sessionId: String

    @StateObject private var sessionManager = SessionManager.shared
    @State private var currentInputMode: ChatInputMode = .text
    @State private var inputText: String = ""
    @State private var activeParticipants: [String: Participant] = [:]
    @State private var messages: [Message] = []

    var body: some View {
        VStack(spacing: 0) {
            // 消息列表（少消息时靠下显示在输入区附近，多消息时旧消息滚到上方）
            GeometryReader { geo in
                ScrollViewReader { proxy in
                    ScrollView {
                        MessagesListView(messages: messages, minHeight: geo.size.height)
                            .id("messagesList")
                    }
                    .onAppear {
                        proxy.scrollTo("messagesList", anchor: .bottom)
                    }
                    .onChange(of: messages) { _ in
                        proxy.scrollTo("messagesList", anchor: .bottom)
                    }
                }
            }
            .background(Color(hex: "#F0F0F0"))

            Divider()

            // 输入栏（5种模式）
            inputBar
        }
        .onAppear {
            loadMessages()
            connectParticipants()
        }
        .onDisappear {
            disconnectParticipants()
        }
    }

    // MARK: - Input Bar (5 modes)

    @ViewBuilder
    private var inputBar: some View {
        HStack(alignment: .center, spacing: 0) {
            // 模式切换（固定在左侧）
            Menu {
                Button {
                    currentInputMode = .text
                } label: {
                    Text("📝 文字")
                }
                Button {
                    currentInputMode = .remote
                } label: {
                    Text("🎮 遥控")
                }
                Button {
                    currentInputMode = .dim3
                } label: {
                    Text("📐 三维")
                }
                Button {
                    currentInputMode = .voice
                } label: {
                    Text("🎤 语音")
                }
                Button {
                    currentInputMode = .file
                } label: {
                    Text("📁 文件")
                }
            } label: {
                HStack(spacing: 2) {
                    Text(currentInputMode.icon)
                        .font(.system(size: 11))
                    Text(currentInputMode.label)
                        .font(.system(size: 10))
                }
                .foregroundColor(Color(hex: "#2196F3"))
                .frame(width: 70, height: 28)
                .background(Color(hex: "#E3F2FD"))
                .cornerRadius(8)
            }

            // 模式内容（填满右侧）
            inputModeContent
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
        .background(Color.white)
        .shadow(color: .black.opacity(0.1), radius: 4, y: -2)
    }

    @ViewBuilder
    private var inputModeContent: some View {
        switch currentInputMode {
        case .text:
            textInputBar
        case .remote:
            remoteInputBar
        case .dim3:
            dim3InputBar
        case .voice:
            voiceInputBar
        case .file:
            fileInputBar
        }
    }

    // MARK: - Text Mode

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
    }

    // MARK: - Remote Mode (3x3 direction pad + 3x3 numpad)

    private var remoteInputBar: some View {
        HStack(spacing: 4) {
            // 方向键 3x3
            DirectionPadView { label in
                sendDirectionLabel(label)
            }

            // 竖线分隔
            Rectangle()
                .fill(Color(hex: "#CCCCCC"))
                .frame(width: 1)
                .padding(.horizontal, 4)

            // 数字键盘 3x3
            NumPadView { label in
                sendDirectionLabel(label)
            }
        }
        .frame(height: 150)
    }

    // MARK: - DIM3 Mode (3D controls)

    private var dim3InputBar: some View {
        HStack(spacing: 4) {
            // 左侧：油门 + / -  + 3x3 方向键
            VStack(spacing: 6) {
                // 油门+（独立样式，80pt×24pt，蓝底白字）
                Button {
                    sendDirectionLabel("+")
                } label: {
                    Text("+")
                        .font(.system(size: 22, weight: .bold))
                        .foregroundColor(.white)
                        .frame(width: 80, height: 24)
                        .background(Color(hex: "#2196F3"))
                        .cornerRadius(8)
                }

                // 3x3 方向键
                DirectionPadView { label in
                    sendDirectionLabel(label)
                }

                // 油门-（独立样式，80pt×24pt，蓝底白字）
                Button {
                    sendDirectionLabel("-")
                } label: {
                    Text("-")
                        .font(.system(size: 22, weight: .bold))
                        .foregroundColor(.white)
                        .frame(width: 80, height: 24)
                        .background(Color(hex: "#2196F3"))
                        .cornerRadius(8)
                }
            }

            // 竖线分隔
            Rectangle()
                .fill(Color(hex: "#CCCCCC"))
                .frame(width: 1)
                .padding(.horizontal, 4)

            // 右侧：坐标轴
            AxisView { cmd in
                sendDirectionLabel(cmd)
            }
        }
        .frame(height: 200)
    }

    // MARK: - Voice Mode

    private var voiceInputBar: some View {
        HStack {
            Text("语音模式（TODO）")
                .font(.system(size: 14))
                .foregroundColor(Color(hex: "#999999"))
            Spacer()
        }
        .frame(height: 60)
    }

    // MARK: - File Mode

    private var fileInputBar: some View {
        HStack {
            Text("文件模式（TODO）")
                .font(.system(size: 14))
                .foregroundColor(Color(hex: "#999999"))
            Spacer()
        }
        .frame(height: 60)
    }

    // MARK: - Actions

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

/// 消息列表：内容撑满 ScrollView 高度，新消息贴在底部
private struct MessagesListView: View {
    let messages: [Message]
    let minHeight: CGFloat

    var body: some View {
        LazyVStack(spacing: 0) {
            // 顶部弹性空间，把内容推到下方
            Spacer()
                .frame(minHeight: minHeight - 20, maxHeight: .infinity)

            ForEach(messages) { msg in
                MessageRowView(message: msg)
                    .id(msg.id)
            }
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 4)
    }
}
