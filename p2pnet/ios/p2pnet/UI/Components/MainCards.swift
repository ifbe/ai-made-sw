import SwiftUI

/// 「名字(ip:port)」—— 没 ip 也没 port 时只显示名字。
/// 和 Android `MainPage.kt` 的 `nodeLabel` 逐字一致（那边也用 `$ip:$port` 直接拼，
/// 没走 `formatHostPort`，这里刻意不「改进」，免得两端显示不一样）。
func nodeLabel(_ name: String, _ ip: String, _ port: Int) -> String {
    if !ip.isEmpty || port != 0 {
        return "\(name)(\(ip):\(port))"
    }
    return name
}

/// 紧凑输入框（对齐 Android `MainPage.kt` 的 `CompactField`）：
/// 高度减半（28）、文字上下边距为 0；标签可以在框内（当占位符），也可以在框外左侧。
struct CompactField: View {
    let label: String
    let value: String
    var isPassword: Bool = false
    var labelOutside: Bool = false
    var enabled: Bool = true
    var keyboard: UIKeyboardType = .default
    var minWidth: CGFloat = 0
    let onChange: (String) -> Void

    private let fieldHeight: CGFloat = 28

    var body: some View {
        HStack(spacing: 4) {
            if labelOutside {
                Text(label)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .frame(width: 44, alignment: .leading)
            }
            Group {
                if isPassword {
                    SecureField(labelOutside ? "" : label, text: binding)
                } else {
                    TextField(labelOutside ? "" : label, text: binding)
                }
            }
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 12))
            .keyboardType(keyboard)
            .frame(height: fieldHeight)
            .frame(minWidth: minWidth)
            .disabled(!enabled)
        }
    }

    private var binding: Binding<String> {
        Binding(get: { value }, set: { onChange($0) })
    }
}

/// 服务器卡片（顶部固定，不参与拖动）：**三行**。
///
/// ```
/// 第一行   协议        服务器              端口        ← 小字标签，只起提示作用
/// 第二行   [ws]        [地址框]            [端口框]    ← 一个按钮，点一下在 ws↔wss 之间切
/// 第三行   [        未连接，点我连接 / 已连接，点我断开      ]
/// ```
///
/// 第一行和第二行**用完全相同的一组列宽**（`protoWidth` / 地址弹性≤`addrMaxWidth` / `portWidth`，
/// 同一组 `spacing`），所以标签左边缘必然正对下面的控件；iOS 15.6 没有 `Grid`，就用两排等宽的 `HStack`。
/// 中间那格两行都是「弹性、上限 300」，在同一宽度下会解出同一个值，因此不会错位。
struct ConnectionCard: View {
    @ObservedObject var viewModel: LoginViewModel

    /// 协议按钮宽（要放下 `wss`）
    private let protoWidth: CGFloat = 62
    /// 端口框宽（要完整显示 `10000`）
    private let portWidth: CGFloat = 118
    /// 地址框弹性上限（窄屏时先收窄它）
    private let addrMaxWidth: CGFloat = 300
    /// 两行共用：列间距
    private let colSpacing: CGFloat = 6
    /// 第一行小字标签字号（明显小于输入框正文 12）
    private let labelFontSize: CGFloat = 9
    private let fieldHeight: CGFloat = 28

    private var proto: String { viewModel.uiState.useWss ? "wss" : "ws" }

    var body: some View {
        VStack(spacing: 6) {
            // ── 第一行：小字标签（位置对齐下面三个控件）──
            HStack(spacing: colSpacing) {
                Text("协议")
                    .font(.system(size: labelFontSize))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .frame(width: protoWidth, alignment: .leading)

                Text("服务器")
                    .font(.system(size: labelFontSize))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .frame(maxWidth: addrMaxWidth, alignment: .leading)

                Text("端口")
                    .font(.system(size: labelFontSize))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .frame(width: portWidth, alignment: .leading)
            }

            // ── 第二行：协议切换按钮 + 地址 + 端口 ──
            HStack(spacing: colSpacing) {
                Button(action: { viewModel.onUseWssChange(!viewModel.uiState.useWss) }) {
                    Text(proto)
                        .font(.system(size: 12))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .frame(height: fieldHeight)
                }
                .buttonStyle(.bordered)
                .frame(width: protoWidth)
                .disabled(viewModel.uiState.loading)
                .help("点击切换 ws / wss")
                .accessibilityLabel("协议 \(proto)")
                .accessibilityHint("点击切换 ws / wss")

                TextField("", text: Binding(
                    get: { viewModel.uiState.serverHost },
                    set: { viewModel.onServerHostChange($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12))
                .keyboardType(.URL)
                .frame(height: fieldHeight)
                .frame(maxWidth: addrMaxWidth)
                .disabled(viewModel.uiState.loading)

                TextField("", text: Binding(
                    get: { viewModel.uiState.serverPort },
                    set: { viewModel.onServerPortChange($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12))
                .keyboardType(.numberPad)
                .frame(width: portWidth)
                .frame(height: fieldHeight)
                .disabled(viewModel.uiState.loading)
            }

            // ── 第三行：连接 / 断开（原样保留）──
            Button(action: {
                if viewModel.uiState.isConnected {
                    viewModel.onDisconnect()
                } else {
                    viewModel.onConnect()
                }
            }) {
                Text(viewModel.uiState.isConnected ? "已连接，点我断开" : "未连接，点我连接")
                    .font(.system(size: 12))
                    .lineLimit(1)
                    .frame(maxWidth: .infinity)
                    .frame(height: 32)
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.uiState.loading)
        }
        .padding(12)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }
}

/// 「我」卡片（自由层里，默认贴底居中，拖标题行可移动）。
/// 用户名在上、密码在下，标签在框外左侧；下面一行：登录/退出在左、list 在右（list 不登录也能点）。
struct MeCard: View {
    @ObservedObject var viewModel: LoginViewModel
    let onDrag: (DragGesture.Value) -> Void
    let onDragEnd: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // 标题：未 list 时只有「我」，list 之后变成「我(ip:port)」；这一行也是拖动把手
            Text(nodeLabel("我", viewModel.uiState.myIp, viewModel.uiState.myPort))
                .font(.system(size: 13, weight: .medium))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                // ⚠️ 必须用 `.global`：卡片位置是**由这个手势的位移驱动的**，
                // 默认的 `.local` 坐标空间会跟着卡片一起动 —— 手指没动，卡片一移
                // `translation` 就变了，于是每帧都写一次状态、卡片再移，形成停不下来的
                // 振荡回路（表现：点标题行正常，一拖整页卡死）。`.global` 是固定参照系，没这个问题。
                .gesture(
                    DragGesture(minimumDistance: 2, coordinateSpace: .global)
                        .onChanged(onDrag)
                        .onEnded { _ in onDragEnd() }
                )

            CompactField(
                label: "用户名",
                value: viewModel.uiState.username,
                labelOutside: true,
                enabled: !viewModel.uiState.loading,
                minWidth: 140,
                onChange: { viewModel.onUsernameChange($0) }
            )
            CompactField(
                label: "密码",
                value: viewModel.uiState.password,
                isPassword: true,
                labelOutside: true,
                enabled: !viewModel.uiState.loading,
                minWidth: 140,
                onChange: { viewModel.onPasswordChange($0) }
            )

            if let error = viewModel.uiState.error {
                Text(error)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
            }

            HStack(spacing: 8) {
                Button(action: {
                    if viewModel.uiState.isLoggedIn {
                        viewModel.onLogout()
                    } else {
                        viewModel.onLogin()
                    }
                }) {
                    Text(viewModel.uiState.isLoggedIn ? "退出" : "登录")
                        .font(.system(size: 11))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .frame(height: 30)
                }
                .buttonStyle(.borderedProminent)
                // 只要连着就能按（密码为空时由 onLogin 给提示），避免出现按钮灰着点不了的死状态
                .disabled(viewModel.uiState.loading || !(viewModel.uiState.isLoggedIn || viewModel.uiState.isConnected))

                // 应用层 ping：发 {"type":"ping","seq":N}，服务端原样回 {"type":"pong","seq":N}。
                // 和连接心跳不是一回事（心跳是 WS 协议级的 sendPing，见 WsClient.startHeartbeat）
                Button(action: { viewModel.onPing() }) {
                    Text("ping")
                        .font(.system(size: 11))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .frame(height: 30)
                }
                .buttonStyle(.bordered)

                Button(action: { viewModel.onList() }) {
                    Text("list")
                        .font(.system(size: 11))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .frame(height: 30)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(10)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }
}

/// 「其他人」卡片（自由层里，可拖标题行）。
/// 这里**只有打洞行为**：direct / upnp / udp / tcp（顺序固定）；
/// 任何「应用」行为（udptest / tun / switch / wg）都在打洞成功后到 socket 卡片第 5 行上选。
struct PeerNodeCard: View {
    let peer: PeerEntry
    let onPunch: (String) -> Void
    let onDrag: (DragGesture.Value) -> Void
    let onDragEnd: () -> Void

    private static let actions = ["direct", "upnp", "udp", "tcp"]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(nodeLabel(peer.username, peer.ip, peer.port))
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                // 同「我」卡片：拖动位移驱动卡片位置，所以必须用固定的 `.global` 坐标空间
                .gesture(
                    DragGesture(minimumDistance: 2, coordinateSpace: .global)
                        .onChanged(onDrag)
                        .onEnded { _ in onDragEnd() }
                )

            HStack(spacing: 4) {
                ForEach(Self.actions, id: \.self) { action in
                    Button(action: { onPunch(action) }) {
                        Text(action)
                            .font(.system(size: 10))
                            .lineLimit(1)
                            .frame(width: 44, height: 28)
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(8)
        .background(Color(hex: 0xFF2B2B2B))
        .cornerRadius(12)
    }
}
