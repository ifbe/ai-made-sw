//
//  AppLog.swift
//  chess
//
//  对照 Android: log/AppLog.kt
//

import Foundation
import os

/// App 内的「特殊日志」：连接、断开、出错这类值得看一眼的事，不记高频动作。
///
/// 留一份环形缓冲（默认 200 行），并推给监听者（右下角那个日志框）。
/// **监听回调在调用线程上**（很可能是网络线程），界面那边自己切主线程。
///
/// iOS 上同时输出到 `os.Logger`（category = `ChessApp`），
/// 方便 `xcrun simctl spawn booted log stream --predicate 'category == "ChessApp"'` 抓。
enum AppLog {

    private static let maxLines = 200

    private static let lock = NSLock()
    private static var lines: [String] = []
    private static var listeners: [UUID: ([String]) -> Void] = [:]
    private static var sinks: [UUID: (String) -> Void] = [:]

    private static let logger = Logger(subsystem: "com.ifbe.aimadesw.chess", category: "ChessApp")

    private static let timeFormat: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    /// 一行日志。格式：`HH:mm:ss  <内容>`（本地时间）。
    static func log(_ message: String) {
        let stamped = "\(timeFormat.string(from: Date()))  \(message)"

        let snapshot: [String]
        let currentSinks: [(String) -> Void]
        lock.lock()
        lines.append(stamped)
        if lines.count > maxLines {
            lines.removeFirst(lines.count - maxLines)
        }
        snapshot = lines
        currentSinks = Array(sinks.values)
        lock.unlock()

        // os.Logger：等价于 Android 侧的 logcat（tag = ChessApp）
        logger.info("\(message, privacy: .public)")

        for sink in currentSinks {
            sink(message)
        }
        notifyListeners(snapshot)
    }

    static func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return lines
    }

    @discardableResult
    static func addListener(_ listener: @escaping ([String]) -> Void) -> UUID {
        let id = UUID()
        let snapshot: [String]
        lock.lock()
        listeners[id] = listener
        snapshot = lines
        lock.unlock()
        if !snapshot.isEmpty {
            listener(snapshot)
        }
        return id
    }

    static func removeListener(_ id: UUID) {
        lock.lock()
        listeners.removeValue(forKey: id)
        lock.unlock()
    }

    @discardableResult
    static func addSink(_ sink: @escaping (String) -> Void) -> UUID {
        let id = UUID()
        lock.lock()
        sinks[id] = sink
        lock.unlock()
        return id
    }

    static func removeSink(_ id: UUID) {
        lock.lock()
        sinks.removeValue(forKey: id)
        lock.unlock()
    }

    static func clear() {
        lock.lock()
        lines.removeAll()
        lock.unlock()
        notifyListeners([])
    }

    private static func notifyListeners(_ snapshot: [String]) {
        lock.lock()
        let current = Array(listeners.values)
        lock.unlock()
        for listener in current {
            listener(snapshot)
        }
    }
}

/// 启动计时（纯诊断，不参与任何业务逻辑）。
///
/// 关键是起点取**进程真正的创建时刻**（`sysctl(KERN_PROC_PID)` 里的 `p_starttime`），
/// 而不是我们代码第一次执行的时间 —— 这样才分得清：
///
///  - 「App.init」那一行数字很大 → 时间花在 **dyld / 系统加载**（Debug 包的 debug dylib、
///    老设备符号绑定），跟 App 逻辑无关；
///  - 「App.init」很快、但「onAppear」那行数字很大 → 时间花在**我们的视图 / 首帧**里。
enum StartupClock {

    /// 进程创建时刻，换算成 `CFAbsoluteTime`（2001-01-01 起算的秒）。
    private static let processStart: CFAbsoluteTime = {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else {
            return CFAbsoluteTimeGetCurrent()
        }
        let tv = info.kp_proc.p_starttime
        // Unix 纪元 → CFAbsoluteTime 纪元（2001-01-01 00:00:00 UTC）
        return CFAbsoluteTime(tv.tv_sec) + CFAbsoluteTime(tv.tv_usec) / 1_000_000 - 978_307_200
    }()

    /// 距进程创建过去了多少毫秒。
    static func elapsedMs() -> Int {
        Int((CFAbsoluteTimeGetCurrent() - processStart) * 1000)
    }

    static func log(_ stage: String) {
        AppLog.log("启动计时 \(elapsedMs())ms  \(stage)")
    }

    private static var loggedStages: Set<String> = []

    /// 同一个阶段只记一次（`body` 会被反复求值，不去重会刷屏）。
    @discardableResult
    static func logOnce(_ stage: String) -> Bool {
        if loggedStages.contains(stage) { return false }
        loggedStages.insert(stage)
        log(stage)
        return true
    }
}
