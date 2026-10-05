import SwiftUI

struct ContentView: View {
    @Environment(\.colorScheme) var colorScheme
    var body: some View {
        ContentView_P2P()
            .preferredColorScheme(colorScheme)
            // 悬浮（edge-to-edge）：**根背景铺满整个窗口**，只让背景越界、内容仍留在安全区内。
            // 于是安全区外那两条（顶部状态栏/灵动岛、底部 home indicator）就是纯黑"避让区"：
            // 它们只是背景，不参与命中测试；`MainScreen` 的 VStack / tabBar / AppLogOverlay
            // 都还在安全区里，一行都不用改。
            // 边范围选 [.top, .bottom]：竖屏下等价于全铺（左右本来就没有安全区）；
            // 横屏刘海屏的左右安全区不属于"上下避让区"，铺黑会在两侧出现黑块，所以不动它。
            .background(Color.black.ignoresSafeArea(edges: [.top, .bottom]))
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