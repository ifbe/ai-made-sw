import SwiftUI

private let mdLabelWidth: CGFloat = 72

/// media 页：多媒体聊天（对齐 Android `ui/MediaPage.kt`，对应 python 端 client/app/media.py）。
///
/// **我们的程序只负责打洞**：打好了把这条洞的参数交给聊天程序，由它去收发流。
///
/// ⚠️ 这一页**没有地址端口让人填**：双方用于多媒体聊天的地址端口都是打洞结果带出来的，
/// 放在**只读文本框**里只是给人看（能选中复制），没通道时显示「打洞后自动带出」：
///   - 收流卡：本机地址 / 本机端口 = 洞的本机侧
///   - 推流卡：对端地址 / 对端端口 = **对方路由器公网**地址端口（对方内网地址不用管）
struct MediaPage: View {
    @ObservedObject var viewModel: LoginViewModel

    /// 本机真实网卡地址（只取一次，别每帧都去 getifaddrs）
    @State private var nics: String = ""

    private var cfg: MediaPageConfig { viewModel.uiState.mediaConfig }
    private var channels: [UdpSessionInfo] {
        viewModel.uiState.udpSockets.filter { $0.handedTo == "media" }
    }
    private var ch: UdpSessionInfo? { channels.first }

    // 双方地址端口全部由打洞结果带出来（没有通道就是空）
    private var localAddr: String { ch?.localIp ?? "" }
    private var localPort: String { ch.map { String($0.localPort) } ?? "" }
    private var peerAddr: String { ch?.peerPublicIp ?? "" }
    private var peerPort: String { ch.map { String($0.peerPublicPort) } ?? "" }

    /// 洞是绑在「任意网卡」（`::` / `0.0.0.0`）上的，展示时要把本机真实网卡地址列出来，
    /// 免得用户看到 `[::]` 以为坏了
    private var addrIsAny: Bool {
        localAddr.isEmpty || localAddr == "::" || localAddr == "0.0.0.0"
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                recvCard
                sendCard
                launchCard
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 6)
        }
        .onAppear {
            let (v4, v6) = LocalAddrs.localAddresses()
            nics = (v4 + v6).joined(separator: ", ")
        }
    }

    // MARK: - 收流（对端 → 本机）

    private var recvCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("收流（对端 → 本机）")
                .font(.footnote)
            MdChoiceRow(
                label: "协议",
                ids: MediaPageConfig.protoIds,
                selected: cfg.recvProto,
                onSelect: { viewModel.onMediaRecvProtoChange($0) }
            )
            // 展示用（只读）：值是打洞结果，不是让人填的
            MdReadOnlyRow(label: "本机地址", value: localAddr, pending: "打洞后自动带出")
            MdReadOnlyRow(label: "本机端口", value: localPort, pending: "打洞后自动带出")

            Text(recvHint)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    private var recvHint: String {
        if ch == nil {
            return "   这两个值是打洞结果，不用填；打通后自动出现在这里"
        }
        if addrIsAny {
            return "   \(localAddr) 表示绑任意网卡（洞就是绑在任意网卡上的）"
                + (nics.isEmpty ? "" : "；本机网卡：\(nics)")
        }
        return "   洞的本机侧，媒体程序照这个绑定/接收"
    }

    // MARK: - 推流（本机 → 对端）

    private var sendCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("推流（本机 → 对端）")
                .font(.footnote)
            MdChoiceRow(
                label: "协议",
                ids: MediaPageConfig.protoIds,
                selected: cfg.sendProto,
                onSelect: { viewModel.onMediaSendProtoChange($0) }
            )
            // 对端只关心「路由器公网地址:端口」，对方内网地址不管
            MdReadOnlyRow(label: "对端地址", value: peerAddr, pending: "打洞后自动带出")
            MdReadOnlyRow(label: "对端端口", value: peerPort, pending: "打洞后自动带出")
            Text("   对方路由器公网地址:端口（对方内网地址不用管）")
                .font(.system(size: 9))
                .foregroundColor(.secondary)

            MdChoiceRow(
                label: "采集",
                ids: MediaPageConfig.captureIds,
                selected: cfg.capture,
                onSelect: { viewModel.onMediaCaptureChange($0) }
            )
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    // MARK: - 拉起应用

    private var launchCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("拉起应用")
                .font(.footnote)
            // iOS 侧 appPackage 当 URL scheme 用（Android 那边是包名，JSON 键保持一致便于对照）
            MdFieldRow(
                label: "scheme",
                value: cfg.appPackage,
                placeholder: "留空 = p2pnetmedia",
                onChange: { viewModel.onMediaAppPackageChange($0) }
            )
            MdFieldRow(
                label: "Action",
                value: cfg.appAction,
                placeholder: "仅在 Android 用",
                onChange: { viewModel.onMediaAppActionChange($0) }
            )

            Text("将传给聊天程序：")
                .font(.system(size: 9))
                .foregroundColor(.secondary)
            Text(previewText)
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.secondary)

            // 空态不渲染这一行（没有通道时不再挂一句说明；只读地址框会显示"打洞后自动带出"）
            if !channels.isEmpty {
                Text(channelText)
                    .font(.system(size: 9))
                    .foregroundColor(channels.count > 1 ? .red : .secondary)
                    .lineLimit(2)
                    .truncationMode(.tail)
            }

            Button(action: { viewModel.onMediaLaunchApp() }) {
                Text(ch != nil ? "拉起应用" : "打洞后才能拉起")
                    .font(.system(size: 11))
                    .frame(maxWidth: .infinity)
                    .frame(height: 32)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color(hex: 0x6650A4))
            .disabled(ch == nil)
        }
        .padding(8)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    /// 参数表以 Android `MainActivity.launchMediaApp` 的 extras 为准（一共 7 个 key）
    private var previewText: String {
        "   localaddr=\(localAddr.isEmpty ? "—" : localAddr)  localport=\(localPort.isEmpty ? "—" : localPort)\n"
            + "   peeraddr=\(peerAddr.isEmpty ? "—" : peerAddr)  peerport=\(peerPort.isEmpty ? "—" : peerPort)\n"
            + "   recv=\(cfg.recvProto)  send=\(cfg.sendProto)  capture=\(cfg.capture)"
    }

    /// 只在**有通道**时用（空态整行不渲染，见调用处）
    private var channelText: String {
        let list = channels.map { "\($0.target)(洞\($0.localPort))" }.joined(separator: "、")
        return "通道：\(list)" + (channels.count > 1 ? "  ⚠️ 多媒体聊天一般只要一条" : "")
    }
}

// MARK: - 零件（对应 Android MediaPage.kt 里的 private 辅助）

/// 只读的地址/端口框：**值是打洞结果**（洞本机侧 / 对端公网侧），
/// 放在文本框里只是给人看（能选中复制），不能改；没通道时显示占位提示。
///
/// SwiftUI 没有 `readOnly`，用 `.constant(value)` 绑定：输入不会改到任何状态，
/// 显示和选中复制的手感跟普通输入框一样。
private struct MdReadOnlyRow: View {
    let label: String
    let value: String
    let pending: String

    var body: some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: mdLabelWidth, alignment: .leading)
            TextField(pending, text: .constant(value))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11, design: .monospaced))
                .frame(height: 30)
        }
    }
}

private struct MdChoiceRow: View {
    let label: String
    let ids: [String]
    let selected: String
    let onSelect: (String) -> Void

    var body: some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: mdLabelWidth, alignment: .leading)
            ForEach(ids, id: \.self) { id in
                let on = id == selected
                Button(action: { onSelect(id) }) {
                    Text(id)
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

private struct MdFieldRow: View {
    let label: String
    let value: String
    var placeholder: String = ""
    let onChange: (String) -> Void

    var body: some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.system(size: 11))
                .frame(width: mdLabelWidth, alignment: .leading)
            TextField(placeholder, text: Binding(get: { value }, set: { onChange($0) }))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11))
                .frame(height: 30)
        }
    }
}
