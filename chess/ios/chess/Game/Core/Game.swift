//
//  Game.swift
//  chess
//
//  对照 Android: game/share/core/Game.kt
//

import Combine
import Foundation

extension Float {
    /// 与 Kotlin `Float.roundToInt()` 等价：`floor(v + 0.5)`。
    /// （不能用 Swift 默认的 `.toNearestOrAwayFromZero`，负数半格会差 1。）
    var roundToIntK: Int { Int((self + 0.5).rounded(.down)) }
}

extension Int {
    func coerceIn(_ lower: Int, _ upper: Int) -> Int { Swift.min(Swift.max(self, lower), upper) }
}

/// 本地手势。View 负责把像素换算成**棋盘语义坐标**（x 沿 file、y 沿 rank，单位 = 格），
/// 再交给 `Game`；所以 Game 既不认识 UIKit，也不认识像素，纯 Swift 就能测。
enum Gesture {
    /// 拿起盘上某个落点/格子上的子。
    case pickUp(index: Int)

    /// 从托盘里拿一颗新子（只有围棋/五子棋用）。
    /// `side` 0 = 先手，1 = 后手；`cellX`/`cellY` 是托盘那一点在棋盘语义坐标里的位置
    /// （在棋盘外，对端照样能看见这颗子被拿着走）。
    case pickUpNew(side: Int, cellX: Float, cellY: Float)

    /// 拖动中。
    case dragTo(cellX: Float, cellY: Float)

    /// 松手：`targetIndex` 是吸附后的落点/格子下标，-1 表示落在棋盘外。
    case drop(cellX: Float, cellY: Float, targetIndex: Int)

    /// 手势被系统取消（比如被父容器拦截）。
    case cancel
}

/// 正在被拖的那颗子（本地或远端），渲染用。
struct DragOverlay {
    let piece: PieceRef
    /// 它原来在哪个落点/格子上 —— 渲染时要跳过这一格，免得画两遍。
    let from: Int
    var cellX: Float
    var cellY: Float
    /// true = 本机玩家在拖；false = 对端在拖（这就是「看见对方乱动」）。
    let byMe: Bool

    func moved(cellX: Float, cellY: Float) -> DragOverlay {
        DragOverlay(piece: piece, from: from, cellX: cellX, cellY: cellY, byMe: byMe)
    }
}

/// 全量棋盘快照。
struct BoardSnapshot {
    let game: GameKind
    let board: String
    /// 0 = 先手，1 = 后手。
    let turn: Int
    let counts: [Int]
}

/// 每种棋的共同门面：**数据 + 逻辑都在实现类里，View 只渲染和报手势**。
///
/// 约定：`onGesture` 会先更新本地状态，再把「需要广播出去的事件」返回给调用方；
/// `apply` 只处理**对端**来的事件，不会把自己的事件回灌。
///
/// 继承 `ObservableObject` 只是为了让 SwiftUI 能订阅刷新（§13.3），逻辑本身不碰 UI。
protocol Game: AnyObject, ObservableObject {
    var kind: GameKind { get }

    /// 接下来该谁走：0 = 先手，1 = 后手。
    var turn: Int { get }

    /// 全量状态（落子后广播这一包）。
    func snapshot() -> BoardSnapshot

    /// 某个落点/格子上有没有子（View 用它决定按下去要不要接这个手势）。
    func hasPieceAt(_ index: Int) -> Bool

    /// 当前拖拽浮层，没有则 nil。
    var drag: DragOverlay? { get }

    /// 本地手势 → 要广播出去的事件（本地状态已经更新）。
    func onGesture(_ gesture: Gesture) -> [MoveEvent]

    /// 收到对端事件 → 更新本地状态。
    func apply(_ event: MoveEvent)

    /// 重开一局，返回要广播的事件。
    func reset() -> [MoveEvent]
}

/// 本地事件的出口：WebSocket Session 接在这里。
typealias MoveEventSink = ([MoveEvent]) -> Void
