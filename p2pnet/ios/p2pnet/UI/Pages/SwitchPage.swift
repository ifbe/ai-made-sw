import SwiftUI

/// Switch 页：虚拟交换机（对应 python 端 `client/app/switch.py` 的单例 hub，参数一一对应；
/// 配置是全局一份，因为那边是单例）。对齐 Android `ui/SwitchPage.kt`。
///
/// 版面（自上而下）：
///   1. 配置卡：第一行 = `配置` + 运行状态 + `Spacer()` + **一个启停按钮**（照抄 vpn 页那行），
///      下面依次是 card 设备（选 tun/tap 时地址框在按钮右边同一行）/ 交换模式 / MTU / 路由老化；
///   2. DHCP 卡（不要标题不要描述，以后别的内嵌服务各自单独一张卡）；
///   3. 拓扑卡（**最后**）：`拓扑` + `已插 N 个` + 「点网口 = 拔线」，第二行是网口可视化
///      （动态增长，0 个时一个虚线空位）—— 用途是可视化虚拟连接拓扑，标题行不放启停按钮。
///
/// 网口不另存状态：直接由 `handedTo == "switch"` 的 session 派生，顺序就是 port1..portN。
struct SwitchPage: View {
    @ObservedObject var viewModel: LoginViewModel

    private let labelWidth: CGFloat = 72
    private let fieldHeight: CGFloat = 28

    private var cfg: SwitchPageConfig { viewModel.uiState.switchConfig }
    private var ports: [UdpSessionInfo] {
        viewModel.uiState.udpSockets.filter { $0.handedTo == "switch" }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                configCard
                // 内嵌 DHCP 关着 → 整张 DHCP 卡不渲染（开关在配置卡最后一行）
                if cfg.dhcpEnabled {
                    dhcpCard
                }
                topologyCard
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 6)
        }
    }

    // MARK: - 拓扑（最后一张卡，只是可视化，标题行不放启停按钮）

    private var topologyCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text("拓扑")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                Text("已插 \(ports.count) 个")
                    .font(.system(size: 11))
                    .foregroundColor(viewModel.uiState.switchRunning ? Color(hex: 0x6650A4) : .secondary)
                if !ports.isEmpty {
                    // 必要的最短操作提示（插上线之后才有意义）
                    Text("点网口 = 拔线")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                Spacer(minLength: 6)
            }

            // 第二行：网口动态增长；0 个时一个虚线空位
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    if ports.isEmpty {
                        PortCell(title: "空", line1: "未插线", line2: "", filled: false, dashed: true, width: 84)
                    } else {
                        ForEach(Array(ports.enumerated()), id: \.element.id) { index, card in
                            PortCell(
                                title: "port\(index + 1)",
                                line1: card.target,
                                line2: formatHostPort(card.peerPublicIp, card.peerPublicPort),
                                filled: true,
                                dashed: false,
                                width: 108,
                                onTap: { viewModel.unplugSwitchPort(card.id) }
                            )
                        }
                    }
                }
                .padding(.vertical, 1)
            }
        }
        .padding(10)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    // MARK: - 配置

    private var configCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            // 第一行：`配置` + 运行状态 + Spacer + 一个启停按钮（照抄 vpn 页那行的写法）
            HStack(spacing: 6) {
                Text("配置")
                    .font(.footnote)
                // 状态用**网口数**（和同一页拓扑卡的 `已插 N 个` / `未插线` 同一套用词）；
                // 运行状态由右边的启停按钮文案（启动/停止）表达，和 vpn/proxy 的处理一致
                Text(ports.isEmpty ? "未插线" : "已插 \(ports.count) 个")
                    .font(.system(size: 10))
                    .foregroundColor(viewModel.uiState.switchRunning ? Color(hex: 0x6650A4) : .secondary)

                Spacer(minLength: 6)

                Button(action: {
                    if viewModel.uiState.switchRunning {
                        viewModel.onSwitchStop()
                    } else {
                        viewModel.onSwitchStart()
                    }
                }) {
                    Text(viewModel.uiState.switchRunning ? "停止" : "启动")
                        .font(.system(size: 10))
                        .frame(height: 26)
                        .padding(.horizontal, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(viewModel.uiState.switchRunning ? Color(hex: 0xFFB3261E) : Color(hex: 0x6650A4))
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // card 设备：选 tun/tap 时 tun 地址框出现在按钮**右边同一行**；选 none 时该框不出现
            HStack(spacing: 4) {
                Text("card 设备")
                    .font(.system(size: 11))
                    .frame(width: labelWidth, alignment: .leading)
                ForEach(SwitchPageConfig.cardIds, id: \.self) { id in
                    choiceButton(id, selected: cfg.cardMode == id) {
                        viewModel.onSwitchCardModeChange(id)
                    }
                }
                if cfg.cardMode != SwitchPageConfig.cardNone {
                    TextField("tun 地址", text: Binding(
                        get: { cfg.tunIp },
                        set: { viewModel.onSwitchTunIpChange($0) }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11))
                    .frame(height: fieldHeight)
                }
                Spacer(minLength: 0)
            }

            HStack(spacing: 4) {
                Text("交换模式")
                    .font(.system(size: 11))
                    .frame(width: labelWidth, alignment: .leading)
                ForEach(SwitchPageConfig.modeIds, id: \.self) { id in
                    choiceButton(id, selected: cfg.mode == id) {
                        viewModel.onSwitchModeChange(id)
                    }
                }
                Spacer(minLength: 0)
            }

            // MTU 与 路由老化 各占一行
            numberRow("MTU", value: cfg.mtu, suffix: "") { viewModel.onSwitchMtuChange($0) }
            numberRow("路由老化", value: cfg.routeTtl, suffix: "s") { viewModel.onSwitchRouteTtlChange($0) }

            // 最后一行：内嵌 DHCP 开关（默认关）。视觉上「这一行开启下面那张卡」——
            // 开了才渲染 DHCP 卡（见 body），关着整张卡不存在
            // 版式与同卡片其它字段行**同构**：标签列（同一个 labelWidth）→ 控件列紧跟其后 → 行尾留空。
            // 不再用 Spacer 把开关顶到最右边（开关的左边 = labelWidth + 间距 4，与 MTU / 路由老化 那两行的
            // 输入框处在同一列），间距也和其他字段行一致（4）；行高不加高
            HStack(spacing: 4) {
                Text("内嵌 DHCP")
                    .font(.system(size: 11))
                    .frame(width: labelWidth, alignment: .leading)
                Toggle("", isOn: Binding(
                    get: { cfg.dhcpEnabled },
                    set: { viewModel.onSwitchDhcpEnabledChange($0) }
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

    // MARK: - DHCP（单独一张卡，不要标题）

    private var dhcpCard: some View {
        // ⚠️ 容器/内边距/首行版式与 configCard **逐项对应**（同为 VStack(spacing: 6) + .padding(8)
        // + 撑满宽度 + Spacer(minLength: 6)），所以两张卡的首行在结构上不可能不等宽
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text("嵌入 DHCP 服务器")
                    .font(.system(size: 11))
                Spacer(minLength: 6)
                Text("尚未实现")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            disabledField("地址池", value: cfg.dhcpPool) { viewModel.onSwitchDhcpPoolChange($0) }
            disabledField("网关", value: cfg.dhcpGateway) { viewModel.onSwitchDhcpGatewayChange($0) }
            disabledField("DNS", value: cfg.dhcpDns) { viewModel.onSwitchDhcpDnsChange($0) }
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    // MARK: - 零件

    private func choiceButton(_ id: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(id)
                .font(.system(size: 10))
                .foregroundColor(selected ? Color(hex: 0x6650A4) : .secondary)
                .padding(.horizontal, 6)
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

    private func numberRow(_ label: String, value: String, suffix: String, onChange: @escaping (String) -> Void) -> some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: labelWidth, alignment: .leading)
            TextField(label, text: Binding(
                get: { value },
                set: { newValue in onChange(newValue.filter { $0.isNumber }) }
            ))
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 11))
            .keyboardType(.numberPad)
            .frame(width: 64, height: fieldHeight)
            if !suffix.isEmpty {
                Text(suffix).font(.system(size: 10))
            }
            Spacer(minLength: 0)
        }
    }

    private func disabledField(_ label: String, value: String, onChange: @escaping (String) -> Void) -> some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: labelWidth, alignment: .leading)
            TextField(label, text: Binding(get: { value }, set: { onChange($0) }))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11))
                .frame(height: fieldHeight)
                .disabled(true)
        }
    }
}

/// 一个网口的格子：标题（portN）+ 两行内容；filled = 已插线，dashed = 空位
private struct PortCell: View {
    let title: String
    let line1: String
    let line2: String
    let filled: Bool
    let dashed: Bool
    let width: CGFloat
    var onTap: (() -> Void)? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .font(.system(size: 10))
                .foregroundColor(filled ? Color(hex: 0x6650A4) : .secondary)
                .lineLimit(1)
            if !line1.isEmpty {
                Text(line1)
                    .font(.system(size: 10))
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            if !line2.isEmpty {
                Text(line2)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 4)
        .frame(width: width, height: 46, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(filled ? Color(hex: 0xEADDFF).opacity(0.4) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(
                    filled ? Color(hex: 0x6650A4) : Color.secondary.opacity(0.5),
                    style: StrokeStyle(lineWidth: 1, dash: dashed ? [6, 4] : [])
                )
        )
        .contentShape(Rectangle())
        .onTapGesture { onTap?() }
    }
}
