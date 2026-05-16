import SwiftUI

struct MainPage: View {
    @ObservedObject var viewModel: LoginViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                // Block 1: Connection
                connectionBlock

                // Block 2: Login
                loginBlock

                // Block 3: Peer
                peerBlock

                // Block 4: Message History
                messageHistoryBlock
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 8)
        }
        .background(Color.black)
    }

    // MARK: - Connection Block

    private var connectionBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                HStack(spacing: 4) {
                    Text("ws")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                    Toggle("", isOn: Binding(
                        get: { viewModel.uiState.useWss },
                        set: { viewModel.onUseWssChange($0) }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: Color(hex: 0x6650a4)))
                    .disabled(viewModel.uiState.loading)
                    .scaleEffect(0.8)
                    Text("wss")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                TextField("服务器", text: Binding(
                    get: { viewModel.uiState.serverHost },
                    set: { viewModel.onServerHostChange($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 14))
                .disabled(viewModel.uiState.loading)

                TextField("端口", text: Binding(
                    get: { viewModel.uiState.serverPort },
                    set: { viewModel.onServerPortChange($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .keyboardType(.numberPad)
                .frame(width: 80)
                .font(.system(size: 14))
                .disabled(viewModel.uiState.loading)
            }

            Button(action: {
                if viewModel.uiState.isConnected {
                    viewModel.onDisconnect()
                } else {
                    viewModel.onConnect()
                }
            }) {
                Text(viewModel.uiState.isConnected ? "已连接，点我断开" : "未连接，点我连接")
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.uiState.loading)
        }
        .padding(12)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }

    // MARK: - Login Block

    private var loginBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                TextField("用户名", text: Binding(
                    get: { viewModel.uiState.username },
                    set: { viewModel.onUsernameChange($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 14))
                .disabled(viewModel.uiState.loading)

                SecureField("密码", text: Binding(
                    get: { viewModel.uiState.password },
                    set: { viewModel.onPasswordChange($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 14))
                .disabled(viewModel.uiState.loading)
            }

            if let error = viewModel.uiState.error {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            Button(action: {
                if viewModel.uiState.isLoggedIn {
                    viewModel.onLogout()
                } else {
                    viewModel.onLogin()
                }
            }) {
                Text(viewModel.uiState.isLoggedIn ? "已登录，点我退出" : "未登录，点我登录")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!loginButtonEnabled)
        }
        .padding(12)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }

    private var loginButtonEnabled: Bool {
        if viewModel.uiState.isLoggedIn { return true }
        return viewModel.uiState.isConnected && !viewModel.uiState.username.isEmpty && !viewModel.uiState.password.isEmpty
    }

    // MARK: - Peer Block

    private var peerBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("对方用户名", text: Binding(
                get: { viewModel.uiState.targetUsername },
                set: { viewModel.onTargetUsernameChange($0) }
            ))
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 14))

            HStack(spacing: 8) {
                Button("list") {
                    viewModel.onList()
                }
                .buttonStyle(.bordered)

                Button("wghelp") {
                    viewModel.onWghelp()
                }
                .buttonStyle(.bordered)

                Button("udp") {
                    viewModel.onUdp()
                }
                .buttonStyle(.bordered)

                Button("tcp") {
                    viewModel.onTcp()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(12)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }

    // MARK: - Message History Block

    private var messageHistoryBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("收发历史")
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .foregroundColor(.secondary)

                Spacer()

                if !viewModel.uiState.messages.isEmpty {
                    Button("清空") {
                        viewModel.clearMessages()
                    }
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                }

                Button(action: {
                    let text = viewModel.uiState.messages.map { "\($0.direction.rawValue): \($0.content)" }.joined(separator: "\n")
                    UIPasteboard.general.string = text
                    showingCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        showingCopied = false
                    }
                }) {
                    Text("📋复制")
                        .font(.system(size: 10))
                }
                .foregroundColor(.secondary)

                if showingCopied {
                    Text("已复制")
                        .font(.system(size: 10))
                        .foregroundColor(.blue)
                }
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(viewModel.uiState.messages) { item in
                            HStack(alignment: .top, spacing: 4) {
                                Text(item.direction == .client ? "client:" : item.direction == .server ? "server:" : item.direction == .system ? "ios:" : item.direction == .udpSend ? "→ " : "← ")
                                    .font(.system(size: 7, design: .monospaced))
                                    .foregroundColor(item.direction == .client ? Color(hex: 0x6650a4) : item.direction == .server ? Color(hex: 0x7D5260) : item.direction == .system ? Color(hex: 0xFFB3261E) : item.direction == .udpSend ? Color(hex: 0x6650a4) : Color(hex: 0x7D5260))
                                    .frame(width: 40, alignment: .leading)
                                Text(item.content)
                                    .font(.system(size: 7, design: .monospaced))
                                    .foregroundColor(.secondary)
                                Spacer()
                            }
                            .id(item.id)
                        }
                    }
                }
            }
        }
        .padding(12)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }

    @State private var showingCopied = false
}