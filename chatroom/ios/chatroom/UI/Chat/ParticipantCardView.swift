import SwiftUI

/// 重连面板里的参与者卡片（只读）。
///
/// 对应 Android `ChatFragment.refreshReconnectPanel()` 复用 `item_participant_card.xml` 的做法：
/// 面板和主页展示同一套卡片，只是把删除按钮藏掉。
/// 这里外壳对齐主页的 `EditingCardView`（白底 + 12 圆角 + 阴影 + 蓝色描边），
/// 内容是只读的「图标 + 名称 + 参数 · 状态」。
struct ParticipantCardView: View {

    let config: ParticipantConfig
    /// "已连接" / "未连接"
    let stateLabel: String

    var body: some View {
        HStack(spacing: 12) {
            Text(config.type.icon)
                .font(.system(size: 26))
                .frame(width: 48, height: 48)

            VStack(alignment: .leading, spacing: 2) {
                Text(config.name)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(Color(hex: "#333333"))

                Text(subtitle)
                    .font(.system(size: 13))
                    .foregroundColor(Color(hex: "#888888"))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white)
        .cornerRadius(12)
        .shadow(color: .black.opacity(0.08), radius: 4, y: 2)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color(hex: "#2196F3"), lineWidth: 2)
        )
    }

    private var subtitle: String {
        let params = Self.paramsText(config.params)
        return params.isEmpty ? stateLabel : "\(params) · \(stateLabel)"
    }

    /// 参数按「常用键优先、其余按键名排序」拼成 `key=value key=value`（Android 是 `joinToString(" ")`）
    private static func paramsText(_ params: [String: String]) -> String {
        guard !params.isEmpty else { return "" }
        let preferred = [
            "ip", "port", "sockType", "path",
            "device", "baud", "shell",
            "addr", "user", "username",
            "model", "subType", "voice", "protocol", "delay"
        ]
        var ordered: [String] = []
        for key in preferred where params[key] != nil {
            ordered.append("\(key)=\(params[key]!)")
        }
        for key in params.keys.sorted() where !preferred.contains(key) {
            ordered.append("\(key)=\(params[key]!)")
        }
        return ordered.joined(separator: " ")
    }
}
