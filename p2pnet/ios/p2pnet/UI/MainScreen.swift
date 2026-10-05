import SwiftUI

struct MainScreen: View {
    @ObservedObject var viewModel: LoginViewModel

    var body: some View {
        VStack(spacing: 0) {
            // 页面内容 + App 内日志浮层（浮层在内容层里，**不盖住底部 tab 栏**）
            // 对应 Android MainScreen：Box { when(page){...}; AppLogOverlay(...) }
            ZStack {
                pageContent

                // App 内日志浮层：**应用级**，悬浮在所有页面之上，切到任何 tab 都在
                AppLogOverlay(
                    messages: viewModel.uiState.messages,
                    onClear: { viewModel.clearMessages() }
                )
            }

            // Tab bar
            if viewModel.uiState.tabs.count > 1 {
                Divider()
                tabBar
            }
        }
    }

    @ViewBuilder
    private var pageContent: some View {
        switch viewModel.uiState.currentPage {
        case .main:
            MainPage(viewModel: viewModel)
        case .udpTest(let targetUsername, let myIp, let myPublicPort, let myLocalIp, let myLocalPort, let peerIp, let peerPort):
            UdpTestPage(
                page: Page.udpTest(targetUsername: targetUsername, myIp: myIp, myPublicPort: myPublicPort, myLocalIp: myLocalIp, myLocalPort: myLocalPort, peerIp: peerIp, peerPort: peerPort),
                viewModel: viewModel
            )
        case .videoCall(let targetUsername):
            VideoCallPage(targetUsername: targetUsername, viewModel: viewModel)
        case .chat(let targetUsername):
            ChatPage(targetUsername: targetUsername, viewModel: viewModel)
        case .wireGuard(let targetUsername, let myIp, let myPort, let peerIp, let peerPort):
            WireGuardPage(
                page: Page.wireGuard(targetUsername: targetUsername, myIp: myIp, myPort: myPort, peerIp: peerIp, peerPort: peerPort),
                viewModel: viewModel
            )
        case .vswitch:
            SwitchPage(viewModel: viewModel)
        case .proxy:
            ProxyPage(viewModel: viewModel)
        case .vpn:
            VpnPage(viewModel: viewModel)
        case .media:
            MediaPage(viewModel: viewModel)
        }
    }

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(Array(viewModel.uiState.tabs.enumerated()), id: \.offset) { index, tab in
                    let isSelected = index == viewModel.uiState.currentTabIndex

                    HStack(spacing: 0) {
                        // Tab title - tap to switch
                        Button(action: {
                            viewModel.switchToTab(index)
                        }) {
                            Text(tab.title)
                                .font(.footnote)
                                .fontWeight(isSelected ? .medium : .regular)
                                .foregroundColor(isSelected ? Color(hex: 0x21005D) : .secondary)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                        }
                        .buttonStyle(.plain)

                        // × 按钮：只有可关闭的 tab 才显示
                        // （主页 / WireGuard / Switch 是固定配置页，closable = false，不给 ×）
                        if tab.closable {
                            Button(action: {
                                viewModel.removeTab(index)
                            }) {
                                Text("×")
                                    .font(.footnote)
                                    .foregroundColor(.secondary.opacity(0.5))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 8)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .background(isSelected ? Color(hex: 0xEADDFF) : Color(.systemGray6))
                    .cornerRadius(8)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
        .background(Color(.systemGray6).opacity(0.5))
    }
}

// MARK: - VideoCallPage & ChatPage (stubs)

struct VideoCallPage: View {
    let targetUsername: String
    @ObservedObject var viewModel: LoginViewModel

    var body: some View {
        VStack {
            Text("视频通话页 - \(targetUsername)")
                .foregroundColor(.secondary)
            Spacer()
        }
        .padding()
    }
}

struct ChatPage: View {
    let targetUsername: String
    @ObservedObject var viewModel: LoginViewModel

    var body: some View {
        VStack {
            Text("聊天页 - \(targetUsername)")
                .foregroundColor(.secondary)
            Spacer()
        }
        .padding()
    }
}

