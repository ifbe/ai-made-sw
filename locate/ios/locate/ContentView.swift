import SwiftUI

/// 启动流程：准备页 → 地图页。
/// 登录不再是单独一页，表单长在地图页顶部的登录矩形里。
struct ContentView: View {
    @State private var keychain = KeychainStorage()
    @State private var ready = false
    @State private var mapViewModel: MapViewModel?

    var body: some View {
        Group {
            if ready, let viewModel = mapViewModel {
                MapContainerView(viewModel: viewModel)
            } else {
                SplashView(keychain: keychain) {
                    mapViewModel = MapViewModel(
                        keychain: keychain,
                        serverUrl: keychain.serverUrl
                    )
                    ready = true
                }
            }
        }
    }
}

#Preview {
    ContentView()
}
