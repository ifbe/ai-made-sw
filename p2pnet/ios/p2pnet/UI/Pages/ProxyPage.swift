import SwiftUI

private let pxLabelWidth: CGFloat = 72
private let pxFieldHeight: CGFloat = 30

/// Proxy 页：端口转发（对齐 Android `ui/ProxyPage.kt`）。**一条洞 ↔ 一个固定端口**，分正/反向。
///
/// 版面：
///   **配置卡（在上面）**：模式 / 协议 / 保活间隔 / 洞地址 / 洞端口（单独一行）/ 启停按钮 / 通道
///   **代理卡（在下面）**：按模式只显示该模式的地址与端口（-L 是监听侧，-R 是目标侧）
struct ProxyPage: View {
    @ObservedObject var viewModel: LoginViewModel

    private var cfg: ProxyPageConfig { viewModel.uiState.proxyConfig }
    private var isL: Bool { cfg.mode == ProxyPageConfig.modeL }
    private var channels: [UdpSessionInfo] {
        viewModel.uiState.udpSockets.filter { $0.handedTo == "proxy" }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                configCard
                agentCard
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 6)
        }
    }

    // MARK: - 配置卡（在上面）

    private var configCard: some View {
        VStack(alignment: .leading, spacing: 5) {
            // 首行版式与同端 vpn / switch **完全一致**：
            // `配置`（左）+ 通道数状态（未接线 / 已接 N 条）+ Spacer + 启停按钮（最右，同一行）。
            // 原来的 `运行中 / 已停止` 去掉了 —— 运行状态已由按钮文案（启动/停止）表达
            HStack(spacing: 6) {
                Text("配置")
                    .font(.footnote)
                Text(channels.isEmpty ? "未接线" : "已接 \(channels.count) 条")
                    .font(.system(size: 10))
                    .foregroundColor(viewModel.uiState.proxyRunning ? Color(hex: 0x6650A4) : .secondary)

                Spacer(minLength: 6)

                Button(action: {
                    if viewModel.uiState.proxyRunning {
                        viewModel.onProxyStop()
                    } else {
                        viewModel.onProxyStart()
                    }
                }) {
                    Text(viewModel.uiState.proxyRunning ? "停止" : "启动")
                        .font(.system(size: 10))
                        .frame(height: 26)
                        .padding(.horizontal, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(viewModel.uiState.proxyRunning ? Color(hex: 0xFFB3261E) : Color(hex: 0x6650A4))
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            PxChoiceRow(
                label: "模式",
                ids: ProxyPageConfig.modeIds,
                selected: cfg.mode,
                labelOf: { ProxyPageConfig.modeLabel($0) },
                onSelect: { viewModel.onProxyModeChange($0) }
            )
            Text(isL
                 ? "   正向 -L：本机监听一个口，accept 后与洞互转（对端要跑 -R 来接）"
                 : "   反向 -R：本机 connect 一个本机服务，与洞互转（等同 python proxy.py）")
                .font(.system(size: 9))
                .foregroundColor(.secondary)

            PxChoiceRow(
                label: "协议",
                ids: ProxyPageConfig.protoIds,
                selected: cfg.proto,
                onSelect: { viewModel.onProxyProtoChange($0) }
            )
            PxNumberRow(
                label: "保活间隔",
                value: cfg.keepaliveSec,
                suffix: "s",
                onChange: { viewModel.onProxyKeepaliveChange($0) }
            )

            // 洞地址 / 洞端口：两行
            PxFieldRow(
                label: "洞地址",
                value: cfg.bindAddr,
                placeholder: "0.0.0.0",
                onChange: { viewModel.onProxyBindAddrChange($0) }
            )
            PxNumberRow(
                label: "洞端口",
                value: cfg.localPort,
                suffix: cfg.localPort.isEmpty ? "(用 session 的)" : "",
                onChange: { viewModel.onProxyLocalPortChange($0) }
            )
            Text("   洞端口留空 = 直接用这条 session 打洞出来的本机端口（推荐）")
                .font(.system(size: 9))
                .foregroundColor(.secondary)

            // 空态不渲染这一行（没有通道时不再挂一句"还没有"）
            if !channels.isEmpty {
                Text(channelText)
                    .font(.system(size: 9))
                    .foregroundColor(.secondary)
                    .lineLimit(2)
                    .truncationMode(.tail)
            }
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    /// 只在**有通道**时用（空态整行不渲染，见调用处）
    private var channelText: String {
        let list = channels.map { "\($0.target)(洞\($0.localPort))" }.joined(separator: "、")
        return "通道 \(channels.count) 条：\(list)"
    }

    // MARK: - 代理卡（在下面）

    private var agentCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(isL ? "正向代理 -L（本机监听）" : "反向代理 -R（本机 connect）")
                .font(.footnote)

            if isL {
                PxFieldRow(
                    label: "监听地址",
                    value: cfg.lListenIp,
                    placeholder: "127.0.0.1",
                    onChange: { viewModel.onProxyLListenIpChange($0) }
                )
                PxNumberRow(
                    label: "监听端口",
                    value: cfg.lListenPort,
                    suffix: cfg.lListenPort == "0" ? "(自动)" : "",
                    onChange: { viewModel.onProxyLListenPortChange($0) }
                )
                // （原来这里还有一行"本机应用连 … → 对端 -R 去 connect 它的目标"的说明，按用户要求整行删掉；
                //   端口是否自动/具体值已经在上面的输入框里显示）
            } else {
                PxFieldRow(
                    label: "目标地址",
                    value: cfg.rTargetHost,
                    placeholder: "127.0.0.1",
                    onChange: { viewModel.onProxyRTargetHostChange($0) }
                )
                PxNumberRow(
                    label: "目标端口",
                    value: cfg.rTargetPort,
                    placeholder: "3389",
                    onChange: { viewModel.onProxyRTargetPortChange($0) }
                )
                // （原来这里还有一行"洞里的流量 → …"和一行"目标通常是本机服务…"的说明，按用户要求整行删掉）
            }
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }
}

// MARK: - 零件（和 Android ProxyPage.kt 里那三个 private 辅助一一对应）

/// 一行「标签 + 若干二选一按钮」
private struct PxChoiceRow: View {
    let label: String
    let ids: [String]
    let selected: String
    var labelOf: (String) -> String = { $0 }
    let onSelect: (String) -> Void

    var body: some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: pxLabelWidth, alignment: .leading)
            ForEach(ids, id: \.self) { id in
                let on = id == selected
                Button(action: { onSelect(id) }) {
                    Text(labelOf(id))
                        .font(.system(size: 10))
                        .foregroundColor(on ? Color(hex: 0x6650A4) : .secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6).stroke(
                                on ? Color(hex: 0x6650A4) : Color.secondary.opacity(0.5),
                                lineWidth: 1
                            )
                        )
                }
                .buttonStyle(.plain)
            }
            Spacer(minLength: 0)
        }
    }
}

/// 一行「标签 + 文本框」
private struct PxFieldRow: View {
    let label: String
    let value: String
    var enabled: Bool = true
    var placeholder: String = ""
    var labelWidth: CGFloat = pxLabelWidth
    let onChange: (String) -> Void

    var body: some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: labelWidth, alignment: .leading)
            TextField(placeholder, text: Binding(get: { value }, set: { onChange($0) }))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11))
                .frame(height: pxFieldHeight)
                .disabled(!enabled)
        }
    }
}

/// 一行「标签 + 数字框（+ 可选后缀）」
private struct PxNumberRow: View {
    let label: String
    let value: String
    var suffix: String = ""
    var enabled: Bool = true
    var placeholder: String = ""
    var labelWidth: CGFloat = pxLabelWidth
    let onChange: (String) -> Void

    var body: some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: labelWidth, alignment: .leading)
            TextField(placeholder, text: Binding(
                get: { value },
                set: { newValue in onChange(newValue.filter { $0.isNumber }) }
            ))
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 11))
            .keyboardType(.numberPad)
            .frame(width: 80, height: pxFieldHeight)
            .disabled(!enabled)
            if !suffix.isEmpty {
                Text(suffix)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
            Spacer(minLength: 0)
        }
    }
}
