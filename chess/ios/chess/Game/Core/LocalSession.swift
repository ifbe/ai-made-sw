//
//  LocalSession.swift
//  chess
//
//  对照 Android: game/share/core/LocalSession.kt
//

import Foundation

/// 不联网时的本地回环出口：接住本地事件并留一份流水。
/// （也方便以后做存档、回放、悔棋。）
final class LocalSession {

    private var log: [MoveEvent] = []

    /// 到目前为止本机产生过的全部事件。
    var events: [MoveEvent] { log }

    func onLocalEvents(_ events: [MoveEvent]) {
        log.append(contentsOf: events)
    }

    func clear() {
        log.removeAll()
    }
}
