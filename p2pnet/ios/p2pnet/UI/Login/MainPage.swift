import SwiftUI

/// 主页（对齐 Android `ui/login/MainPage.kt`）：**服务器卡片固定在最上面 + 下面一整块自由层**。
///
/// App 内日志浮层已经搬去 `MainScreen`（应用级，悬浮在所有页面之上），
/// 这里只剩页面内容。
struct MainPage: View {
    @ObservedObject var viewModel: LoginViewModel

    var body: some View {
        VStack(spacing: 0) {
            // 只留水平外边距（侧面留白、配合卡片圆角）；
            // 顶部不再留额外的 8pt：避让状态栏/灵动岛由 safe area 负责，卡片紧贴安全区上沿，
            // 这样顶部那条纯黑避让区的高度就**恰好等于状态栏/灵动岛 inset**（对齐安卓同轮改动）
            ConnectionCard(viewModel: viewModel)
                .padding(.horizontal, 4)

            FreeLayer(viewModel: viewModel)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Color.black)
    }
}
