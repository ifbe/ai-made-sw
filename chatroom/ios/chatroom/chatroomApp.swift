//
//  chatroomApp.swift
//  chatroom
//
//  Created by 史蒙健 on 2026/5/10.
//

import SwiftUI
import UIKit

/// iOS 应用入口（对应 Android `Application` + `TcpForegroundService` 的组合）。
///
/// iOS 没有 Android `ForegroundService` 的完全等价物——任意 app 都不能在后台无限运行。
/// 我们能做的：
/// 1. **TCP keep-alive**（SocketParticipant.swift）—— OS 层 socket option，让系统代发 TCP probe，
///    app 不发任何字节，不污染数据流。
/// 2. **`beginBackgroundTask`**（本文件）—— 按 Home 后申请 ~30s 后台时间，期间 NWConnection 仍活跃。
/// 3. **长期后台保活**——需要 Background Modes capability（voip/audio/processing）+ 推送唤醒，
///    改动较大，本次未做。用户如需长期后台请提。
@main
struct chatroomApp: App {
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onChange(of: scenePhase) { newPhase in
            BackgroundTaskManager.shared.handleScenePhase(newPhase)
        }
    }
}

/// 后台任务管理器：单例。
///
/// iOS 上点 Home 后大约有 30s 的后台运行时间（`beginBackgroundTask` 申请），期间 socket 仍活跃；
/// 之后系统会挂起 app 并关闭 NWConnection。要在 app 内主动调 `endBackgroundTask` 释放，否则系统会
/// 在过期时强制结束并触发 expirationHandler。
///
/// **跟 Android 的对照**：
/// - Android `TcpForegroundService`：常驻通知 + wake lock + keep-alive = 切到后台 TCP 一直不断
/// - iOS：beginBackgroundTask 只能撑 ~30s；过了这个时间即使 keep-alive 也会被挂起
final class BackgroundTaskManager {
    static let shared = BackgroundTaskManager()

    private var bgTaskId: UIBackgroundTaskIdentifier = .invalid

    private init() {}

    func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .background:
            // 进入后台：申请一个 background task。OS 给约 30s 后台运行时间。
            // 在这段时间内 NWConnection 仍活跃，TCP keep-alive 由 OS 在 socket 层自动处理。
            guard bgTaskId == .invalid else { return }
            bgTaskId = UIApplication.shared.beginBackgroundTask(withName: "chatroom-tcp-keepalive") { [weak self] in
                // 过期回调：OS 即将挂起 app，主动结束任务，避免被系统警告。
                guard let self = self else { return }
                if self.bgTaskId != .invalid {
                    UIApplication.shared.endBackgroundTask(self.bgTaskId)
                    self.bgTaskId = .invalid
                }
            }

        case .active:
            // 回到前台：结束 background task。
            if bgTaskId != .invalid {
                UIApplication.shared.endBackgroundTask(bgTaskId)
                bgTaskId = .invalid
            }

        case .inactive:
            // 短暂中间状态（控制中心、通知中心拉下时的过渡态），不动。
            break

        @unknown default:
            break
        }
    }
}