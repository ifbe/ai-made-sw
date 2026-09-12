import SwiftUI

/// 准备页（对应 Android 的 LoginActivity 启动页）。
///
/// 只做启动准备：预热 Keychain、保证最短显示时间，准备好就直接进地图页；
/// 登录表单搬到了地图页顶部的登录矩形里。
struct SplashView: View {
    let keychain: KeychainStorage
    var onReady: () -> Void

    private let minDisplaySeconds: TimeInterval = 0.6

    @State private var prepDone = false
    @State private var minTimeElapsed = false
    @State private var finished = false

    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()

            VStack(spacing: 20) {
                Text("旅迹定位")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                ProgressView()
            }
        }
        .onAppear {
            AppLog.i("正在准备…")

            // 预热：先把 Keychain 读一遍（服务器地址/凭证），别等进了地图才第一次读盘
            DispatchQueue.global(qos: .userInitiated).async {
                _ = keychain.serverUrl
                _ = keychain.username
                _ = keychain.password
                _ = keychain.hasCredentials()
                DispatchQueue.main.async {
                    prepDone = true
                    goIfReady()
                }
            }

            DispatchQueue.main.asyncAfter(deadline: .now() + minDisplaySeconds) {
                minTimeElapsed = true
                goIfReady()
            }
        }
    }

    private func goIfReady() {
        guard prepDone, minTimeElapsed, !finished else { return }
        finished = true
        AppLog.i("准备完成，进入地图")
        onReady()
    }
}
