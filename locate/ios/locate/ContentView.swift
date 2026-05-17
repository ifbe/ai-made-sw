import SwiftUI

struct ContentView: View {
    @State private var keychain = KeychainStorage()
    @State private var isLoggedIn = false

    var body: some View {
        Group {
            if isLoggedIn {
                MapContainerView(viewModel: MapViewModel(
                    keychain: keychain,
                    serverUrl: keychain.serverUrl
                ), onLogout: {
                    isLoggedIn = false
                })
            } else {
                LoginView(viewModel: LoginViewModel(keychain: keychain)) {
                    isLoggedIn = true
                }
            }
        }
    }
}

#Preview {
    ContentView()
}