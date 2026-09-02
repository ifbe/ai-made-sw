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
    @State private var showFullscreen = false

    var body: some View {
        HStack {
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                if let data = message.imageBytes {
                    let mime = BlobSniffer.detectType(data)
                    if mime.hasPrefix("image/") {
                        // 原图片分支 + 点击全屏（再点返回）
                        Image(uiImage: UIImage(data: data) ?? UIImage())
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: 240)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .background(
                                BubbleShape(style: .right)
                                    .fill(Color(hex: "#2196F3"))
                            )
                            .onTapGesture {
                                showFullscreen = true
                            }
                            .fullScreenCover(isPresented: $showFullscreen) {
                                FullscreenImageView(imageData: data)
                            }
                    } else if mime.hasPrefix("audio/") {
                        // 新音频分支
                        AudioBubbleView(data: data, style: .right,
                                        fgColor: .white,
                                        bgColor: Color(hex: "#2196F3"),
                                        horizontalPadding: 14)
                    } else {
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
                } else {
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
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
        }
    }
}

// MARK: - 其他参与者（左侧白色气泡 + 发送者名称）

private struct OtherMessageRow: View {
    let message: Message
    @State private var showFullscreen = false

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
                    if let data = message.imageBytes {
                        let mime = BlobSniffer.detectType(data)
                        if mime.hasPrefix("image/") {
                            // 原图片分支 + 点击全屏（再点返回）
                            Image(uiImage: UIImage(data: data) ?? UIImage())
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: 240)
                                .padding(.horizontal, 4)
                                .padding(.vertical, 10)
                                .background(
                                    BubbleShape(style: .left)
                                        .fill(Color.white)
                                )
                                .onTapGesture {
                                    showFullscreen = true
                                }
                                .fullScreenCover(isPresented: $showFullscreen) {
                                    FullscreenImageView(imageData: data)
                                }
                        } else if mime.hasPrefix("audio/") {
                            AudioBubbleView(data: data, style: .left,
                                            fgColor: Color(hex: "#333333"),
                                            bgColor: .white,
                                            horizontalPadding: 4)
                        } else {
                            BubbleView(
                                content: message.content,
                                style: .left,
                                fontSize: bubbleFontSize,
                                fgColor: Color(hex: "#333333"),
                                bgColor: .white,
                                horizontalPadding: 4,
                                verticalPadding: 10
                            )
                        }
                    } else {
                        BubbleView(
                            content: message.content,
                            style: .left,
                            fontSize: bubbleFontSize,
                            fgColor: Color(hex: "#333333"),
                            bgColor: .white,
                            horizontalPadding: 4,
                            verticalPadding: 10
                        )
                    }
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

// MARK: - 音频气泡（imageBytes 嗅探为 audio/* 时渲染，点击调 AudioMessagePlayer 播放）

/// 音频气泡：`▶ 播放` + 时长文字（`%.3fs` 秒），与 Android VoiceRecorder 时长计算对齐。
/// 时长从 WAV 字节数推算：pcmBytes = bytes.count - 44，durationSec = pcmBytes / 32000。
private struct AudioBubbleView: View {
    let data: Data
    let style: BubbleStyle
    let fgColor: Color
    let bgColor: Color
    let horizontalPadding: CGFloat

    private var durationSec: Double {
        let pcmSize = max(data.count - VoiceRecorder.WAV_HEADER_SIZE, 0)
        return Double(pcmSize) / VoiceRecorder.BYTES_PER_SECOND
    }

    private var durationText: String {
        String(format: "%.3fs", durationSec)
    }

    var body: some View {
        Button {
            let cacheDir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            AudioMessagePlayer.shared.play(data, cacheDir: cacheDir)
        } label: {
            HStack(spacing: 8) {
                Text("▶ 播放")
                    .font(.system(size: 13, weight: .medium))
                Text(durationText)
                    .font(.system(size: 13))
            }
            .foregroundColor(fgColor)
            .padding(.horizontal, horizontalPadding)
            .padding(.vertical, 10)
            .background(
                BubbleShape(style: style)
                    .fill(bgColor)
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Fullscreen Image Viewer

/// 全屏图片查看器：黑底、图片 scaledToFit 适配、点任意位置退出。
/// SwiftUI 原生 .fullScreenCover 实现，不需 Info.plist 额外配置。
private struct FullscreenImageView: View {
    let imageData: Data
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            Image(uiImage: UIImage(data: imageData) ?? UIImage())
                .resizable()
                .scaledToFit()
                .ignoresSafeArea()
        }
        .contentShape(Rectangle())
        .onTapGesture {
            dismiss()
        }
        .statusBarHidden(true)
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
