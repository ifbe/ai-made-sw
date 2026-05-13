import SwiftUI

/// 消息行视图（对应 Android 的 item_message_left/right/info.xml）
struct MessageRowView: View {
    let message: Message

    var body: some View {
        switch category {
        case .info:
            InfoMessageRow(message: message)
        case .selfMessage:
            SelfMessageRow(message: message)
        case .other:
            OtherMessageRow(message: message)
        }
    }

    private var category: MessageCategory {
        if message.isInfo { return .info }
        if message.senderId == "self" { return .selfMessage }
        return .other
    }
}

// MARK: - Categories

private enum MessageCategory {
    case info, selfMessage, other
}

// MARK: - Info（灰色居中小字，Android: #AAAAAA, 12sp, center, gravity=center）

private struct InfoMessageRow: View {
    let message: Message

    var body: some View {
        HStack {
            Spacer()
            Text(message.content)
                .font(.system(size: 12))
                .foregroundColor(Color(hex: "#AAAAAA"))
                .multilineTextAlignment(.center)
                .padding(.vertical, 4)
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 2)
    }
}

// MARK: - 自己发的（右侧蓝色气泡）

private struct SelfMessageRow: View {
    let message: Message

    var body: some View {
        HStack {
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                BubbleView(
                    content: message.content,
                    style: .right,
                    fontSize: 15,
                    fgColor: .white,
                    bgColor: Color(hex: "#2196F3"),
                    horizontalPadding: 14,
                    verticalPadding: 10
                )
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
        }
    }
}

// MARK: - 其他参与者（左侧白色气泡 + 发送者名称）

private struct OtherMessageRow: View {
    let message: Message

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                // 发送者名称（Android: 12sp, #888888, marginStart=1dp, marginBottom=2dp）
                HStack(spacing: 4) {
                    Text(message.senderType.icon)
                    Text(message.senderName)
                }
                .font(.system(size: 12))
                .foregroundColor(Color(hex: "#888888"))
                .padding(.leading, 1)
                .padding(.bottom, 2)

                // 气泡（Android: marginStart=1dp, marginEnd=4dp, paddingHorizontal=4dp）
                HStack {
                    BubbleView(
                        content: message.content,
                        style: .left,
                        fontSize: bubbleFontSize,
                        fgColor: Color(hex: "#333333"),
                        bgColor: .white,
                        horizontalPadding: 4,
                        verticalPadding: 10
                    )
                    Spacer()
                }
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 2)
    }

    /// PTY/SSH 用 7pt 等宽字体（容纳 80 字符），其他 15pt
    private var bubbleFontSize: CGFloat {
        switch message.senderType {
        case .pty, .ssh:
            return 7
        default:
            return 15
        }
    }
}

// MARK: - Bubble

private struct BubbleView: View {
    let content: String
    let style: BubbleStyle
    let fontSize: CGFloat
    let fgColor: Color
    let bgColor: Color
    let horizontalPadding: CGFloat
    let verticalPadding: CGFloat

    var body: some View {
        Text(content)
            .font(.system(size: fontSize, design: .monospaced))
            .foregroundColor(fgColor)
            .padding(.horizontal, horizontalPadding)
            .padding(.vertical, verticalPadding)
            .background(
                BubbleShape(style: style)
                    .fill(bgColor)
            )
    }
}
