import SwiftUI

/// 首页（对应 Android HomeFragment）
struct HomeView: View {
    @StateObject private var sessionManager = SessionManager.shared
    @State private var editingCards: [EditingCardData] = []
    @State private var showingEmpty = true

    var onSessionCreated: ((String) -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            // 顶部工具栏
            HStack {
                Text("Chatroom")
                    .font(.system(size: 20, weight: .medium))
                    .foregroundColor(.white)
                Spacer()
                Button("创建") {
                    createSession()
                }
                .foregroundColor(.white)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color(hex: "#2196F3"))

            // 参与者卡片列表
            ZStack {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(editingCards) { card in
                            EditingCardView(card: card, onDelete: {
                                editingCards.removeAll { $0.id == card.id }
                                if editingCards.isEmpty { showingEmpty = true }
                            })
                        }

                        // + 添加参与者 卡片（对应 Android item_add_participant.xml）
                        AddParticipantCard {
                            editingCards.append(EditingCardData())
                            showingEmpty = false
                        }
                    }
                    .padding(16)
                }

                if showingEmpty {
                    Text("点击下方 + 添加参与者")
                        .font(.system(size: 16))
                        .foregroundColor(Color(hex: "#999999"))
                }
            }
            .background(Color(hex: "#F5F5F5"))
        }
    }

    private func createSession() {
        let validCards = editingCards.filter { $0.type != nil }
        if validCards.isEmpty {
            return
        }

        let sessionId = sessionManager.createSession()
        for card in validCards {
            sessionManager.addParticipant(sessionId, config: card.toConfig())
        }

        editingCards.removeAll()
        showingEmpty = true
        onSessionCreated?(sessionId)
    }
}

// MARK: - Add Participant Card

/// 对应 Android item_add_participant.xml：蓝色描边卡片 + 号
struct AddParticipantCard: View {
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                Text("+")
                    .font(.system(size: 32, weight: .medium))
                    .foregroundColor(Color(hex: "#2196F3"))

                Text("添加参与者")
                    .font(.system(size: 16))
                    .foregroundColor(Color(hex: "#2196F3"))

                Spacer()
            }
            .padding(.vertical, 16)
            .padding(.horizontal, 16)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(hex: "#E3F2FD"))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(hex: "#2196F3"), lineWidth: 2)
                    )
            )
        }
    }
}

// MARK: - Editing Card View

struct EditingCardView: View {
    @ObservedObject var card: EditingCardData
    let onDelete: () -> Void

    // AI 模型查询状态
    @State private var isQueryingModels = false
    @State private var modelPickerOptions: [String] = []
    @State private var showModelPicker = false
    @State private var showQueryAlert = false
    @State private var queryAlertMessage = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // 类型选择 + 删除按钮
            HStack {
                Text("类型：")
                    .font(.system(size: 14))
                    .foregroundColor(Color(hex: "#666666"))

                Picker("", selection: Binding(
                    get: { card.type },
                    set: { card.type = $0 }
                )) {
                    ForEach(ParticipantType.selectableCases) { type in
                        Text("\(type.icon) \(type.rawValue)").tag(type)
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()

                Spacer()

                Button {
                    onDelete()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.gray)
                }
            }

            Divider()

            // 动态字段
            paramsFields
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(12)
        .shadow(color: .black.opacity(0.08), radius: 4, y: 2)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color(hex: "#2196F3"), lineWidth: 2)
        )
    }

    @ViewBuilder
    private var paramsFields: some View {
        switch card.type {
        case .socket:
            socketFields
        case .pty:
            ptyFields
        case .serial:
            serialFields
        case .telnet:
            telnetFields
        case .ai:
            aiFields
        case .agent:
            agentFields
        case .bluetooth:
            bluetoothFields
        case .echo:
            echoFields
        default:
            genericParamsField
        }
    }

    private var socketFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("IP：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("192.168.x.x", text: $card.socketIp)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("端口：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("9999", text: $card.socketPort)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
            }
            HStack {
                Text("协议：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                HStack(spacing: 6) {
                    Button(action: { card.sockType = "TCP" }) {
                        Text("TCP")
                            .font(.system(size: 13))
                            .foregroundColor(.white)
                            .frame(width: 52, height: 26)
                            .background(card.sockType == "TCP" ? Color(hex: "#4CAF50") : Color(hex: "#CCCCCC"))
                            .cornerRadius(6)
                    }
                    Button(action: { card.sockType = "UDP" }) {
                        Text("UDP")
                            .font(.system(size: 13))
                            .foregroundColor(.white)
                            .frame(width: 52, height: 26)
                            .background(card.sockType == "UDP" ? Color(hex: "#4CAF50") : Color(hex: "#CCCCCC"))
                            .cornerRadius(6)
                    }
                    Button(action: { card.sockType = "WS" }) {
                        Text("WS")
                            .font(.system(size: 13))
                            .foregroundColor(.white)
                            .frame(width: 52, height: 26)
                            .background(card.sockType == "WS" ? Color(hex: "#4CAF50") : Color(hex: "#CCCCCC"))
                            .cornerRadius(6)
                    }
                }
                Spacer()
            }
            // path 仅 WS 才显示：与 Android 端约定一致（TCP/UDP 不消费 path）
            if card.sockType == "WS" {
                HStack {
                    Text("path：")
                        .font(.system(size: 13))
                        .foregroundColor(Color(hex: "#666666"))
                        .frame(width: 56, alignment: .leading)
                    TextField("/", text: $card.socketPath)
                        .font(.system(size: 13))
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
            }
        }
    }

    private var ptyFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("ptmx：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("/dev/ptmx", text: $card.ptyDevice)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("shell：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("/system/bin/sh", text: $card.ptyShell)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
        }
    }

    private var serialFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("串口：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("/dev/ttyS0", text: $card.serialDevice)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("波特率：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("115200", text: $card.serialBaud)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
            }
        }
    }

    private var telnetFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("IP：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("IP", text: $card.telnetIp)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("端口：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("23", text: $card.telnetPort)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
            }
            HStack {
                Text("用户：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("username", text: $card.telnetUser)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("密码：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                SecureField("password", text: $card.telnetPassword)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
        }
    }

    private var aiFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("IP：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("192.168.5.180", text: $card.aiIp)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("端口：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("12345", text: $card.aiPort)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
            }
            HStack {
                Text("Key：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("sk-xxxx", text: $card.aiApiKey)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("模型：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("模型名称", text: $card.aiModel)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                Button(action: { queryModels() }) {
                    Text(isQueryingModels ? "…" : "查询")
                        .font(.system(size: 13))
                        .foregroundColor(.white)
                        .frame(width: 52, height: 26)
                        .background(isQueryingModels ? Color(hex: "#CCCCCC") : Color(hex: "#4CAF50"))
                        .cornerRadius(6)
                }
                .disabled(isQueryingModels)
            }
            HStack {
                Text("子类型：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                HStack(spacing: 6) {
                    Button(action: { card.aiSubType = "text" }) {
                        Text("文本")
                            .font(.system(size: 13))
                            .foregroundColor(.white)
                            .frame(width: 64, height: 26)
                            .background(card.aiSubType == "text" ? Color(hex: "#4CAF50") : Color(hex: "#CCCCCC"))
                            .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    Button(action: { card.aiSubType = "stt" }) {
                        Text("语音转文字")
                            .font(.system(size: 13))
                            .foregroundColor(.white)
                            .frame(width: 80, height: 26)
                            .background(card.aiSubType == "stt" ? Color(hex: "#4CAF50") : Color(hex: "#CCCCCC"))
                            .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    Button(action: { card.aiSubType = "tts" }) {
                        Text("文字转语音")
                            .font(.system(size: 13))
                            .foregroundColor(.white)
                            .frame(width: 80, height: 26)
                            .background(card.aiSubType == "tts" ? Color(hex: "#4CAF50") : Color(hex: "#CCCCCC"))
                            .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                }
                Spacer()
            }
            // voice 仅在 subType=tts 时显示
            if card.aiSubType == "tts" {
                HStack {
                    Text("voice：")
                        .font(.system(size: 13))
                        .foregroundColor(Color(hex: "#666666"))
                        .frame(width: 56, alignment: .leading)
                    TextField("alloy", text: $card.aiVoice)
                        .font(.system(size: 13))
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
            }
        }
        .confirmationDialog("选择模型", isPresented: $showModelPicker, titleVisibility: .visible) {
            ForEach(modelPickerOptions, id: \.self) { model in
                Button(model) {
                    card.aiModel = model
                }
            }
            Button("取消", role: .cancel) {}
        }
        .alert("查询模型", isPresented: $showQueryAlert) {
            Button("知道了", role: .cancel) {}
        } message: {
            Text(queryAlertMessage)
        }
    }

    /// 调用 ModelQueryService 拉取 ip:port 的 /v1/models
    /// 查不到→alert 提示；查到→confirmationDialog 点选回填到 card.aiModel
    private func queryModels() {
        let ip = card.aiIp
        let port = card.aiPort
        let apiKey = card.aiApiKey
        guard !ip.isEmpty, !port.isEmpty else {
            queryAlertMessage = "请先填 IP 和端口"
            showQueryAlert = true
            return
        }
        isQueryingModels = true
        Task {
            let result = await AiParticipant.queryModels(ip: ip, port: port, apiKey: apiKey)
            await MainActor.run {
                isQueryingModels = false
                switch result {
                case .success(let models):
                    if models.isEmpty {
                        // 查不到：仅 alert 提示，不弹选弹框
                        queryAlertMessage = "未查到模型"
                        showQueryAlert = true
                    } else {
                        modelPickerOptions = models
                        showModelPicker = true
                    }
                case .failure(let error):
                    queryAlertMessage = "查询失败：" + (error.errorDescription ?? "未知错误")
                    showQueryAlert = true
                }
            }
        }
    }

    private var agentFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("子类型：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                Picker("", selection: $card.agentSubType) {
                    Text("openclaw").tag("openclaw")
                    Text("codex").tag("codex")
                    Text("claude").tag("claude")
                    Text("gemini").tag("gemini")
                    Text("copilot").tag("copilot")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            HStack {
                Text("地址：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("host 或 IP", text: $card.agentAddr)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }
            HStack {
                Text("端口：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("22", text: $card.agentPort)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
            }
            HStack {
                Text("用户：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("username", text: $card.agentUsername)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }
            HStack {
                Text("密码：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                SecureField("password", text: $card.agentPassword)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
        }
    }

    private var bluetoothFields: some View {
        VStack(spacing: 8) {
            HStack {
                Text("设备：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                TextField("请先刷新设备", text: $card.bluetoothDevice)
                    .font(.system(size: 13))
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Text("协议：")
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#666666"))
                    .frame(width: 56, alignment: .leading)
                Picker("", selection: $card.bluetoothProtocol) {
                    Text("SPP").tag("SPP")
                    Text("RFCOMM").tag("RFCOMM")
                }
                .pickerStyle(.segmented)
            }
            Button("刷新设备") {
                // TODO: CoreBluetooth
            }
            .font(.system(size: 14))
            .foregroundColor(Color(hex: "#2196F3"))
        }
    }

    private var genericParamsField: some View {
        HStack {
            Text("参数：")
                .font(.system(size: 13))
                .foregroundColor(Color(hex: "#666666"))
                .frame(width: 56, alignment: .leading)
            TextField("key:value ...", text: $card.params)
                .font(.system(size: 13))
                .textFieldStyle(.roundedBorder)
        }
    }

    private var echoFields: some View {
        HStack {
            Text("延迟(s)：")
                .font(.system(size: 13))
                .foregroundColor(Color(hex: "#666666"))
                .frame(width: 56, alignment: .leading)
            // SwiftUI 的 TextField 需要 String 绑定；手动做 Float ↔ String 转换
            TextField("0.5", text: Binding(
                get: { echoDelayText },
                set: { newValue in
                    card.echoDelay = Float(newValue) ?? 0.5
                }
            ))
            .font(.system(size: 13))
            .textFieldStyle(.roundedBorder)
            .keyboardType(.decimalPad)
        }
    }

    private var echoDelayText: String {
        // 默认 0.5 输入框显示 "0.5"，其他值显示完整 float
        if card.echoDelay == 0.5 { return "0.5" }
        return String(card.echoDelay)
    }
}