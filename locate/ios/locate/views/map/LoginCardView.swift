import SwiftUI

/// 地图页顶部的登录矩形：四行 —— 服务器地址 / 用户名 / 密码 / 登录按钮。
///
/// 悬浮在地图上方（不把地图顶下去）。未登录、自动登录中时显示；
/// 登录成功后由 MapContainerView 收起来。
struct LoginCard: View {
    @ObservedObject var viewModel: MapViewModel

    /// 自动登录也要转圈，和手动登录共用一套状态
    private var busy: Bool {
        viewModel.uiState.loading || viewModel.uiState.autoLoggingIn
    }

    var body: some View {
        VStack(spacing: 5) {
            CompactField(
                label: "服务器地址",
                text: $viewModel.uiState.serverUrl,
                keyboard: .URL,
                secure: false
            )
            CompactField(
                label: "用户名",
                text: $viewModel.uiState.username,
                keyboard: .default,
                secure: false
            )
            CompactField(
                label: "密码",
                text: $viewModel.uiState.password,
                keyboard: .default,
                secure: true
            )

            if let error = viewModel.uiState.error {
                Text(error)
                    .font(.system(size: 10))
                    .foregroundColor(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Button(action: { viewModel.onLogin() }) {
                HStack(spacing: 6) {
                    if busy {
                        ProgressView()
                            .scaleEffect(0.6)
                            .frame(width: 14, height: 14)
                    }
                    Text("登录")
                        .font(.system(size: 12))
                }
                .frame(maxWidth: .infinity)
                .frame(height: 38)
            }
            .buttonStyle(.borderedProminent)
            .disabled(
                busy
                    || viewModel.uiState.username.isEmpty
                    || viewModel.uiState.password.isEmpty
            )
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: 300)
        .background(Color.white.opacity(0.96))
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.black.opacity(0.12), lineWidth: 1)
        )
        .disabled(busy)
    }
}

/// 紧凑输入框：标签和输入框在同一行，一行一个字段（对应 Android 的 CompactField）
private struct CompactField: View {
    let label: String
    @Binding var text: String
    let keyboard: UIKeyboardType
    let secure: Bool

    var body: some View {
        HStack(spacing: 0) {
            Text(label)
                .font(.system(size: 10))
                .foregroundColor(Color(red: 0.53, green: 0.53, blue: 0.53))
                .frame(width: 56, alignment: .leading)

            Group {
                if secure {
                    SecureField("", text: $text)
                } else {
                    TextField("", text: $text)
                }
            }
            .font(.system(size: 12))
            // 卡片一直是白底，深色模式下 .primary 会变成白色，所以颜色写死
            .foregroundColor(Color(red: 0.1, green: 0.1, blue: 0.1))
            .tint(Color(red: 0.1, green: 0.1, blue: 0.1))
            .keyboardType(keyboard)
            .textInputAutocapitalization(.never)
            .disableAutocorrection(true)
            .padding(.horizontal, 8)
            .frame(height: 30)
            .background(Color.black.opacity(0.06))
            .cornerRadius(6)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.black.opacity(0.13), lineWidth: 1)
            )
        }
    }
}
