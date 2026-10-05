import SwiftUI

// MARK: - 「实现」配置卡

/// WireGuard 页顶部的「实现」配置（对齐 Android `MainPage.kt`/`WireGuardPage.kt` 的 `WgImplCard`）。
///
/// 三档只决定「谁来跑协议栈」：
///  自己实现 / 官方库 → 我们自建 VpnService（iOS 上是 NEPacketTunnelProvider，本轮只留 TODO）；
///  调系统程序        → 把参数交给外部那个真正的 VPN 服务 app（iOS 用自定义 URL scheme）。
/// 共同点：**UDP 出口必须是打洞时那个本地端口**，否则 NAT 映射就废了。
private struct WgImplCard: View {
    let page: Page
    @ObservedObject var viewModel: LoginViewModel

    private let labelWidth: CGFloat = 64
    private let fieldHeight: CGFloat = 28

    private var cfg: WgPageConfig { viewModel.uiState.wgConfig }

    private var pagePeer: String {
        if case .wireGuard(_, _, _, let peerIp, let peerPort) = page, !peerIp.isEmpty {
            return formatHostPort(peerIp, peerPort)
        }
        return "(还没通路)"
    }

    private var pageMyPort: Int {
        if case .wireGuard(_, _, let port, _, _) = page { return port }
        return 0
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("实现")
                .font(.footnote)

            HStack(spacing: 4) {
                ForEach(WgPageConfig.implIds, id: \.self) { id in
                    let selected = cfg.impl == id
                    Button(action: { viewModel.onWgImplChange(id) }) {
                        Text(WgPageConfig.label(id))
                            .font(.system(size: 10))
                            .foregroundColor(selected ? Color(hex: 0x6650A4) : .secondary)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .overlay(
                                RoundedRectangle(cornerRadius: 6).stroke(
                                    selected ? Color(hex: 0x6650A4) : Color.secondary.opacity(0.5),
                                    lineWidth: 1
                                )
                            )
                    }
                    .buttonStyle(.plain)
                }
            }

            Text(WgPageConfig.describe(cfg.impl))
                .font(.system(size: 10))
                .foregroundColor(.secondary)

            if cfg.impl == WgPageConfig.implSystem {
                Divider().padding(.vertical, 2)
                Text("外部 VPN 应用")
                    .font(.footnote)

                // iOS 侧 extPackage 当 URL scheme 用（Android 那边是包名，JSON 键保持一致便于对照）
                HStack(spacing: 6) {
                    Text("scheme")
                        .font(.system(size: 11))
                        .frame(width: labelWidth, alignment: .leading)
                    TextField("留空 = p2pnetvpn", text: Binding(
                        get: { cfg.extPackage },
                        set: { viewModel.onWgExtPackageChange($0) }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11))
                    .frame(height: fieldHeight)
                }

                // extAction 在 iOS 上只保留作对照，拼 URL 时 host 固定用 "start"
                HStack(spacing: 6) {
                    Text("action")
                        .font(.system(size: 11))
                        .frame(width: labelWidth, alignment: .leading)
                    TextField("仅在 Android 用", text: Binding(
                        get: { cfg.extAction },
                        set: { viewModel.onWgExtActionChange($0) }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11))
                    .frame(height: fieldHeight)
                }

                Text("将传给对方：listen_port=\(pageMyPort > 0 ? String(pageMyPort) : "(还没通路)")  peer=\(pagePeer)")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)

                Text("listen_port 必须是打洞时那个本地端口，否则已建立的 NAT 映射会废")
                    .font(.system(size: 9))
                    .foregroundColor(.secondary)
            } else {
                Text("UDP 出口固定用已打洞的那个本地端口" + (pageMyPort > 0 ? "（本页当前 \(pageMyPort)）" : ""))
                    .font(.system(size: 9))
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }
}

struct WireGuardPage: View {
    let page: Page
    @ObservedObject var viewModel: LoginViewModel

    private var isAutoMode: Bool {
        if case .wireGuard(_, _, _, let peerIp, _) = page {
            return !peerIp.isEmpty
        }
        return false
    }

    private var pageMyPort: Int {
        if case .wireGuard(_, _, let port, _, _) = page { return port }
        return 51820
    }

    @State private var tunnelStatus: TunnelStatus = .disconnected
    @State private var wgInterface: WgInterface = WgInterface()
    @State private var showPrivateKey = false

    private let labelWidth: CGFloat = 72
    private let fieldHeight: CGFloat = 32
    private let rowSpacer: CGFloat = 4

    var body: some View {
        ScrollView {
            VStack(spacing: 6) {
                // 「实现」三档（决定 socket 卡片上点 wg 之后走哪条路）
                WgImplCard(page: page, viewModel: viewModel)

                // Connection button
                connectionButton

                // My Interface card
                myInterfaceCard

                // Peer list
                ForEach(Array(wgInterface.peers.enumerated()), id: \.element.id) { index, peer in
                    PeerCard(
                        peer: peer,
                        peerIndex: index,
                        isAutoMode: isAutoMode,
                        onUpdate: { updated in
                            var peers = wgInterface.peers
                            peers[index] = updated
                            wgInterface.peers = peers
                        },
                        onDelete: {
                            var peers = wgInterface.peers
                            peers.remove(at: index)
                            wgInterface.peers = peers
                        }
                    )
                }

                // Add Peer button
                if !isAutoMode {
                    Button(action: {
                        wgInterface.peers.append(WgPeer())
                    }) {
                        Text("+ 添加 Peer")
                            .font(.system(size: 11))
                            .frame(maxWidth: .infinity)
                            .frame(height: 32)
                    }
                    .buttonStyle(.bordered)
                }

                // 消息历史卡已删除：wg 的日志现在统一进「App 内日志」
                // （右下角「日志」按钮，应用级浮层，见 UI/Components/AppLogOverlay.swift）
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 6)
        }
        .onAppear {
            initInterface()
        }
    }

    private func initInterface() {
        wgInterface = WgInterface(
            myPort: pageMyPort,
            privateKey: "GHH4S==XXo89xk2k3n5jV8Q==",
            peers: [
                WgPeer(endpoint: "10.0.0.1:51820", publicKey: "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc=", allowedIPs: "0.0.0.0/0")
            ]
        )
    }

    // MARK: - Connection Button

    private var connectionButton: some View {
        Button(action: {
            if tunnelStatus == .disconnected {
                viewModel.appendWgLog("正在启动 WireGuard...")
                tunnelStatus = .connecting
                if isAutoMode {
                    viewModel.startWgTunnelAuto(page: page) { success, msg in
                        tunnelStatus = success ? .connected : .disconnected
                        viewModel.appendWgLog(success ? "WireGuard 已连接" : "启动失败: \(msg)")
                    }
                } else {
                    viewModel.startWgTunnelManual(wgInterface) { success, msg in
                        tunnelStatus = success ? .connected : .disconnected
                        viewModel.appendWgLog(success ? "WireGuard 已连接" : "启动失败: \(msg)")
                    }
                }
            } else {
                viewModel.stopWgTunnel()
                tunnelStatus = .disconnected
                viewModel.appendWgLog("WireGuard 已断开")
            }
        }) {
            Text(connectionButtonText)
                .font(.system(size: 12))
        }
        .buttonStyle(.borderedProminent)
        .tint(tunnelStatus == .connected ? Color(hex: 0xFFB3261E) : Color(hex: 0x6650a4))
        .frame(maxWidth: .infinity)
    }

    private var connectionButtonText: String {
        switch tunnelStatus {
        case .connected: return "已连接 — 点击断开"
        case .connecting: return "连接中..."
        case .failed: return "连接失败 — 重试"
        case .disconnected: return "启动 WireGuard"
        }
    }

    // MARK: - My Interface Card

    private var myInterfaceCard: some View {
        VStack(alignment: .leading, spacing: rowSpacer) {
            Text("My Interface")
                .font(.footnote)
                .padding(.bottom, rowSpacer)

            // IP/掩码 + 端口
            HStack(spacing: 6) {
                Text("IP/掩码")
                    .font(.system(size: 11))
                    .frame(width: labelWidth, alignment: .leading)
                TextField("IP/掩码", text: $wgInterface.myIp)
                    .font(.system(size: 11))
                    .frame(height: fieldHeight)
                Text("端口")
                    .font(.system(size: 11))
                    .frame(width: 32, alignment: .leading)
                TextField("端口", text: Binding(
                    get: { String(wgInterface.myPort) },
                    set: { wgInterface.myPort = Int($0) ?? 51820 }
                ))
                .font(.system(size: 11))
                .frame(width: 64)
                .frame(height: fieldHeight)
                .keyboardType(.numberPad)
            }

            Divider()
                .padding(.vertical, rowSpacer)

            // 私钥 + 切换/生成按钮
            HStack(spacing: 6) {
                Text("私钥")
                    .font(.system(size: 11))
                    .frame(width: labelWidth, alignment: .leading)
                SecureField("私钥", text: $wgInterface.privateKey)
                    .font(.system(size: 11))
                    .frame(height: fieldHeight)
                Button(action: { showPrivateKey.toggle() }) {
                    Text(showPrivateKey ? "🙈" : "👁")
                        .font(.system(size: 12))
                        .frame(width: fieldHeight, height: fieldHeight)
                }
                Button(action: {
                    viewModel.generateWgKeypair { _, privkey in
                        wgInterface.privateKey = privkey
                        viewModel.appendWgLog("密钥对已生成")
                    }
                }) {
                    Text("生成")
                        .font(.system(size: 11))
                        .frame(height: fieldHeight)
                        .padding(.horizontal, 8)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

}

// MARK: - PeerCard

struct PeerCard: View {
    let peer: WgPeer
    let peerIndex: Int
    let isAutoMode: Bool
    let onUpdate: (WgPeer) -> Void
    let onDelete: () -> Void

    private let labelWidth: CGFloat = 72
    private let fieldHeight: CGFloat = 32
    private let rowSpacer: CGFloat = 4

    var body: some View {
        VStack(alignment: .leading, spacing: rowSpacer) {
            // Title row
            HStack {
                Text("Peer \(peerIndex + 1)")
                    .font(.footnote)
                    .fontWeight(.medium)
                Spacer()
                if !isAutoMode {
                    Button(action: onDelete) {
                        Text("×")
                            .font(.system(size: 16))
                            .foregroundColor(Color(hex: 0xFFB3261E))
                            .frame(width: 20, height: 20)
                    }
                }
            }

            // Endpoint
            fieldRow("Endpoint", value: peer.endpoint, enabled: !isAutoMode) {
                onUpdate(peer.copy(endpoint: $0))
            }

            // Peer 公钥
            fieldRow("Peer公钥", value: peer.publicKey, enabled: !isAutoMode) {
                onUpdate(peer.copy(publicKey: $0))
            }

            // Preshared Key
            fieldRow("Preshared", value: peer.presharedKey, enabled: !isAutoMode) {
                onUpdate(peer.copy(presharedKey: $0))
            }

            // Allowed IPs
            fieldRow("AllowedIPs", value: peer.allowedIPs, enabled: !isAutoMode) {
                onUpdate(peer.copy(allowedIPs: $0))
            }
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    private func fieldRow(_ label: String, value: String, enabled: Bool, onChange: @escaping (String) -> Void) -> some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: labelWidth, alignment: .leading)
            TextField(label, text: .constant(value))
                .font(.system(size: 11))
                .frame(height: fieldHeight)
                .disabled(enabled)
                .onChange(of: value) { newVal in
                    onChange(newVal)
                }
        }
    }
}

// MARK: - WgPeer extension

extension WgPeer {
    func copy(
        endpoint: String? = nil,
        publicKey: String? = nil,
        presharedKey: String? = nil,
        allowedIPs: String? = nil
    ) -> WgPeer {
        WgPeer(
            id: id,
            endpoint: endpoint ?? self.endpoint,
            publicKey: publicKey ?? self.publicKey,
            presharedKey: presharedKey ?? self.presharedKey,
            allowedIPs: allowedIPs ?? self.allowedIPs,
            status: status
        )
    }
}