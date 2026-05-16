import SwiftUI

struct ContentView: View {
    @Environment(\.colorScheme) var colorScheme
    var body: some View {
        ContentView_P2P()
            .preferredColorScheme(colorScheme)
            .background(colorScheme == .dark ? Color.black : Color(hex: 0xFFFFFBFE))
    }
}

struct ContentView_P2P: View {
    @StateObject private var viewModel: LoginViewModel

    init() {
        let localPrefs = LocalPrefs()
        let repository = P2pRepository(localPrefs: localPrefs)
        _viewModel = StateObject(wrappedValue: LoginViewModel(repository: repository))
    }

    var body: some View {
        MainScreen(viewModel: viewModel)
    }
}

#Preview {
    ContentView()
}