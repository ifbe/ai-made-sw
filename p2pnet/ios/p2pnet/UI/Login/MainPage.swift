import SwiftUI

/// 主页（对齐 Android `ui/login/MainPage.kt`）：
/// **一个填满内容区的自由层**，服务器卡片是它内部顶部对齐的元素（不再单独占一行）。
///
/// 这样"自由层正中"就是整个内容区的正中 —— 「我」卡片默认落在那里。
/// 服务器卡片的宽度按内容区宽高比实时算（竖屏满宽 / 横屏**水平居中半宽**，见 `ContentLayout`）。
struct MainPage: View {
    @ObservedObject var viewModel: LoginViewModel

    var body: some View {
        FreeLayer(viewModel: viewModel)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.black)
    }
}
