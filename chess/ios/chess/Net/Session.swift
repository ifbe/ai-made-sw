//
//  Session.swift
//  chess
//
//  对照 Android: net/Session.kt
//

import Foundation

/// 连接状态：左下角那个按钮上显示的就是它。
enum LinkState {
    /// 还没开始。
    case idle
    /// 正在启动服务 / 正在连接。
    case starting
    /// 服务已启动 / 已经连上。
    case online
    /// 出错或断开了。
    case failed
}

/// 一条「房间」连接：本地事件从这里出去，对端事件从 `listen` 进来。
/// 服务端和客户端是同一个接口，游戏代码只认它。
protocol Session: AnyObject {
    /// 把本地产生的事件发出去（这些事件本机已经应用过了）。
    func send(_ events: [MoveEvent])

    /// 注册对端事件回调（**在网络线程上**回调，UI 那边要自己切线程）。
    func listen(_ listener: @escaping (MoveEvent) -> Void)

    /// 关掉服务 / 断开连接。
    func close()
}
