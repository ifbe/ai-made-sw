import SwiftUI

private let vpnLabelWidth: CGFloat = 84
private let vpnFieldHeight: CGFloat = 30

/// VPN 页：**一对一**（对齐 Android `ui/VpnPage.kt`，对应 python 端 client/app/vpn.py：
/// 一个洞 ↔ 一块 tun/tap）。
///
/// 和 `SwitchPage` 的唯一区别：**没有网口那张卡**（一对一只有一条隧道）。
/// 原来放在网口卡里的状态和启停按钮，并进配置卡顶部那一行。
/// 谁和谁是一对：在主页 socket 卡片第 5 行点 `tun`，页面里的「通道」会显示是哪一条。
struct VpnPage: View {
    @ObservedObject var viewModel: LoginViewModel

    private var cfg: VpnPageConfig { viewModel.uiState.vpnConfig }
    private var channels: [UdpSessionInfo] {
        viewModel.uiState.udpSockets.filter { $0.handedTo == "tun" }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                configCard
                // 内嵌 DHCP 关着 → 整张 DHCP 卡不渲染（开关在配置卡最后一行）
                if cfg.dhcpEnabled {
                    dhcpCard
                }
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 6)
        }
    }

    // MARK: - 配置卡（状态和启停并到顶部那一行）

    private var configCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text("配置")
                    .font(.footnote)
                Text(channels.isEmpty ? "未接线" : "已接 \(channels.count) 条")
                    .font(.system(size: 10))
                    .foregroundColor(viewModel.uiState.vpnRunning ? Color(hex: 0x6650A4) : .secondary)

                Spacer(minLength: 6)

                // 一对一：一个按钮管启停（运行时变红、字变「停止」）
                Button(action: {
                    if viewModel.uiState.vpnRunning {
                        viewModel.onVpnStop()
                    } else {
                        viewModel.onVpnStart()
                    }
                }) {
                    Text(viewModel.uiState.vpnRunning ? "停止" : "启动")
                        .font(.system(size: 10))
                        .frame(height: 26)
                        .padding(.horizontal, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(viewModel.uiState.vpnRunning ? Color(hex: 0xFFB3261E) : Color(hex: 0x6650A4))
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // card 设备：选 tun/tap 时 tun 地址框在按钮**右边同一行**；选 none 时不出
            HStack(spacing: 4) {
                Text("card 设备")
                    .font(.system(size: 11))
                    .frame(width: vpnLabelWidth, alignment: .leading)
                ForEach(VpnPageConfig.cardIds, id: \.self) { id in
                    VpnChoiceButton(id: id, selected: cfg.cardMode == id) {
                        viewModel.onVpnCardModeChange(id)
                    }
                }
                if cfg.cardMode != VpnPageConfig.cardNone {
                    TextField("tun 地址", text: Binding(
                        get: { cfg.tunIp },
                        set: { viewModel.onVpnTunIpChange($0) }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11))
                    .frame(height: vpnFieldHeight)
                }
                Spacer(minLength: 0)
            }

            HStack(spacing: 4) {
                Text("交换模式")
                    .font(.system(size: 11))
                    .frame(width: vpnLabelWidth, alignment: .leading)
                ForEach(VpnPageConfig.modeIds, id: \.self) { id in
                    VpnChoiceButton(id: id, selected: cfg.mode == id) {
                        viewModel.onVpnModeChange(id)
                    }
                }
                Spacer(minLength: 0)
            }

            // MTU 与 路由老化 各占一行
            VpnNumberRow(label: "MTU", value: cfg.mtu, suffix: "") { viewModel.onVpnMtuChange($0) }
            VpnNumberRow(label: "路由老化", value: cfg.routeTtl, suffix: "s") { viewModel.onVpnRouteTtlChange($0) }

            // 空态不渲染这一行：没有通道时的信息已经由配置卡首行的 `未接线` 表达
            if !channels.isEmpty {
                Text(channelText)
                    .font(.system(size: 9))
                    .foregroundColor(channels.count > 1 ? .red : .secondary)
                    .lineLimit(2)
                    .truncationMode(.tail)
            }

            // 最后一行：内嵌 DHCP 开关（默认关）。开了才渲染 DHCP 卡（见 body）
            // 版式与同卡片其它字段行**同构**：标签列（同一个 vpnLabelWidth）→ 控件列紧跟其后 → 行尾留空。
            // 不再用 Spacer 把开关顶到最右边（开关的左边 = vpnLabelWidth + 间距 4，与 MTU / 路由老化 那两行的
            // 输入框处在同一列），间距也和其他字段行一致（4）；行高不加高
            HStack(spacing: 4) {
                Text("内嵌 DHCP")
                    .font(.system(size: 11))
                    .frame(width: vpnLabelWidth, alignment: .leading)
                Toggle("", isOn: Binding(
                    get: { cfg.dhcpEnabled },
                    set: { viewModel.onVpnDhcpEnabledChange($0) }
                ))
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: Color(hex: 0x6650A4)))
                .scaleEffect(0.8)
                .frame(width: 44, height: 24)
                Spacer(minLength: 0)
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
        return "通道：\(list)" + (channels.count > 1 ? "  ⚠️ 一对一只要一条" : "")
    }

    // MARK: - DHCP 卡（和 switch 页一致；没有标题没有描述）

    private var dhcpCard: some View {
        // ⚠️ 容器/内边距/首行版式与 configCard **逐项对应**（同为 VStack(spacing: 4) + .padding(8)
        // + 撑满宽度 + Spacer(minLength: 6)），首行宽度结构上不可能不等
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text("嵌入 DHCP 服务器")
                    .font(.system(size: 11))
                Spacer(minLength: 6)
                Text("尚未实现")
                    .font(.system(size: 9))
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            VpnFieldRow(label: "地址池", value: cfg.dhcpPool, enabled: false) { viewModel.onVpnDhcpPoolChange($0) }
            VpnFieldRow(label: "网关", value: cfg.dhcpGateway, enabled: false) { viewModel.onVpnDhcpGatewayChange($0) }
            VpnFieldRow(label: "DNS", value: cfg.dhcpDns, enabled: false) { viewModel.onVpnDhcpDnsChange($0) }
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }
}

// MARK: - 零件（对应 Android VpnPage.kt 里那三个 private 辅助）

private struct VpnChoiceButton: View {
    let id: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(id)
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

private struct VpnFieldRow: View {
    let label: String
    let value: String
    var enabled: Bool = true
    let onChange: (String) -> Void

    var body: some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: vpnLabelWidth, alignment: .leading)
            TextField(label, text: Binding(get: { value }, set: { onChange($0) }))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11))
                .frame(height: vpnFieldHeight)
                .disabled(!enabled)
        }
    }
}

private struct VpnNumberRow: View {
    let label: String
    let value: String
    var suffix: String = ""
    let onChange: (String) -> Void

    var body: some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: vpnLabelWidth, alignment: .leading)
            TextField(label, text: Binding(
                get: { value },
                set: { newValue in onChange(newValue.filter { $0.isNumber }) }
            ))
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 11))
            .keyboardType(.numberPad)
            .frame(width: 64, height: vpnFieldHeight)
            if !suffix.isEmpty {
                Text(suffix).font(.system(size: 10))
            }
            Spacer(minLength: 0)
        }
    }
}
