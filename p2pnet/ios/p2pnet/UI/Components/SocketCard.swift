import SwiftUI

/// socket 卡片（对齐 Android `ui/login/MainPage.kt` 的 `UdpSocketCardView`）。
///
/// 三种形态：
///  - `isPreview`（tcp / upnp）：渲染 `plan` 的每步 + 「（仅流程预览，尚未实现真实握手）」，**没有**用法按钮；
///  - `kind == "direct"`：渲染 `plan`（实时打勾）+ `note` 结果行（可达地址一行一个，最多 10 条），
///    同样**没有**用法按钮；
///  - `kind == "udp"`：本机绑定 + 四步进度 + 公网/对方信息 + 第 5 行四个用法按钮。
///
/// 宽度按内容自适应（VStack 天然如此），外层套 `.fixedSize()` 就不会被容器拉满；
/// 整卡可拖动（手势由 FreeLayer 挂）。
struct SocketCard: View {
    let card: UdpSessionInfo
    let usageIds: [String]
    let onClose: () -> Void
    let onUse: (String) -> Void

    private let accent = Color(hex: 0x6650A4)

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            header

            if card.isPreview {
                planRows
            } else if card.kind == "direct" {
                planRows
                if !card.note.isEmpty { noteRow(card.note) }
            } else {
                udpRows
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color(.systemBackground))
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.15), radius: 3, y: 1)
    }

    // MARK: - 三种形态

    private var header: some View {
        HStack(spacing: 0) {
            Text(title)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
                .lineLimit(1)
            Spacer(minLength: 10)
            Button(action: onClose) {
                Text("✕")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
            }
            .buttonStyle(.plain)
        }
    }

    /// tcp / upnp 预览 与 direct 共用：按 plan 渲染步骤（direct 的 done 是实时进度）
    private var planRows: some View {
        ForEach(Array(card.plan.enumerated()), id: \.offset) { _, step in
            stepRow(step.text, step.done)
            if !step.detail.isEmpty { infoRow(step.detail) }
        }
    }

    /// UDP 形态：本机绑定 + 四步进度 + 公网/对方 + 第 5 行用法按钮
    private var udpRows: some View {
        Group {
            Text("本机绑定 \(formatHostPort(card.localIp, card.localPort))")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(accent)
                .lineLimit(1)

            stepRow("发给服务器", card.sentToServer)
            stepRow("收到服务器回复", card.serverReplied)
            if card.serverReplied {
                infoRow("公网 \(formatHostPort(card.myPublicIp, card.myPublicPort))")
                infoRow("对方 \(formatHostPort(card.peerPublicIp, card.peerPublicPort))")
            }
            stepRow("发给对端", card.sentToPeer)
            stepRow("收到对端回复", card.peerReplied)

            // 第 5 行：选用法。第 4 步（收到对端回复）打勾之后才可点
            HStack(spacing: 4) {
                ForEach(usageIds, id: \.self) { id in
                    usageButton(id)
                }
            }
            .padding(.top, 3)
        }
    }

    private var title: String {
        if card.isPreview { return "\(card.kind) 流程预览" }
        if card.kind == "udp" { return "UDP socket" }
        return "\(card.kind) 直连探测 · \(card.target)"
    }

    // MARK: - 零件

    /// 一步：完成打 ✓，未完成是 ○
    private func stepRow(_ label: String, _ done: Bool) -> some View {
        HStack(spacing: 4) {
            Text(done ? "✓" : "○")
                .font(.system(size: 11))
                .foregroundColor(done ? .green : .secondary)
            Text(label)
                .font(.system(size: 11))
                .foregroundColor(done ? .primary : .secondary)
                .lineLimit(1)
        }
    }

    /// 说明/地址信息（缩进一级）
    private func infoRow(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.secondary)
            .lineLimit(2)
            .padding(.leading, 14)
    }

    /// direct 的结果行：note 是**多行**的（可达地址一行一个）+ 可能一行「…还有 N 条」。
    /// 每行**不折行**（`lineLimit(1)` + 按内容占宽），所以不再限宽、也不再有 3 行上限；
    /// 地址行绿色，其它（备注行 / "0/N 个地址可达" / "本机不能发 ICMP…"）灰色。
    private func noteRow(_ note: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            ForEach(
                Array(note.split(separator: "\n", omittingEmptySubsequences: false).enumerated()),
                id: \.offset
            ) { _, raw in
                let line = String(raw)
                Text(line)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(Self.isAddressLine(line) ? .green : .secondary)
                    .lineLimit(1)
                    // 卡片宽度本来就是内容自适应；这里明确"按内容占宽"，长 IPv6 不会被压缩或折行
                    .fixedSize(horizontal: true, vertical: false)
            }
        }
        .padding(.leading, 14)
        .padding(.top, 2)
    }

    /// 这一行是不是「可达地址」：IPv6 一定含 `:`；IPv4 只由数字和点组成
    private static func isAddressLine(_ line: String) -> Bool {
        if line.contains(":") { return true }
        return line.contains(".") && line.allSatisfy { $0.isNumber || $0 == "." }
    }


    /// 第 5 行的用法按钮
    private func usageButton(_ id: String) -> some View {
        let enabled = card.peerReplied
        let selected = card.handedTo == id
        let color: Color = selected ? .green : (enabled ? accent : Color.secondary.opacity(0.4))
        return Button(action: { onUse(id) }) {
            Text(id)
                .font(.system(size: 10))
                .foregroundColor(color)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .overlay(
                    RoundedRectangle(cornerRadius: 6).stroke(color, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
    }
}
