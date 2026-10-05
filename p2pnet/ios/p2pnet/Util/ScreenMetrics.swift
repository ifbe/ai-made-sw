import UIKit

/// 屏幕/窗口尺寸小工具。
///
/// 用它是为了画「屏幕几何中心的横线」：Android 那边用
/// `WindowManager.currentWindowMetrics.bounds` 拿到整个窗口（含状态栏、含底部 tab 栏），
/// iOS 的对应物是 key window 的 bounds。
/// 不用 `UIScreen.main`（iOS 16 起已废弃，会带 deprecation 警告）。
///
/// 注意：`UIApplication.shared` / `UIWindowScene.windows` 都是 **MainActor 隔离**的，
/// 所以这里不能标 `nonisolated`；调用方（View 的 onAppear）本来就在主线程，
/// 而且要把结果缓存进 @State，别在 Canvas 每帧绘制里读。
enum ScreenMetrics {

    /// 窗口高度（整个屏幕，不是安全区内的可用高度）；拿不到返回 0（调用方据此跳过画线）
    static var windowHeight: CGFloat {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        for scene in scenes {
            if let window = scene.windows.first(where: { $0.isKeyWindow }) {
                return window.bounds.height
            }
        }
        for scene in scenes {
            if let window = scene.windows.first {
                return window.bounds.height
            }
        }
        return 0
    }
}
