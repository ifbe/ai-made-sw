//
//  ChessApp.swift
//  chess
//
//  Created by 史蒙健 on 2026/9/15.
//

import SwiftUI

@main
struct ChessApp: App {

    init() {
        // 我们代码里**最早**的一行日志。计时起点是进程创建时刻（见 StartupClock），
        // 所以这一行的毫秒数 = 「dyld + 系统加载 + App.init」一共花掉的时间：
        //   - 这里就很大（比如 >1000ms）→ 慢在 App 之前的加载，跟界面代码无关；
        //   - 这里很小、后面 RootView 的计时才变大 → 慢在我们的视图 / 首帧。
        StartupClock.log("App.init（我们代码的第一行）")
    }

    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}
