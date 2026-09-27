//
//  MoveEvent.swift
//  chess
//
//  对照 Android: game/share/protocol/MoveEvent.kt
//

import Foundation

/// 要广播出去的一件事，分成两类：
///
///  - **拖拽流** `.dragStarted` / `.dragMoved` / `.dragEnded`：高频、可丢、纯装饰。
///    它只是「让对方看见我在把子拿着走」，丢了、晚了、乱了都不影响棋局；
///  - **状态流** `.boardChanged` / `.gameReset`：低频、必须可靠，是唯一权威。
///    接收方直接照抄盘面，不自己算走法，所以永远不会累积误差。
enum MoveEvent: Equatable {
    case dragStarted(game: GameKind, seq: Int64, piece: PieceRef, from: Int, pos: BoardPos)
    case dragMoved(game: GameKind, seq: Int64, piece: PieceRef, pos: BoardPos)
    case dragEnded(game: GameKind, seq: Int64, piece: PieceRef, pos: BoardPos, committed: Bool)
    /// 全量棋盘：落子 / 吃子 / 拖出棋盘 / 重开之后都发这一包。
    case boardChanged(game: GameKind, seq: Int64, board: String, turn: Int, counts: [Int])
    /// 重开一局（双方各自 reset 出同一个开局，所以不需要传盘面）。
    case gameReset(game: GameKind, seq: Int64)

    var game: GameKind {
        switch self {
        case let .dragStarted(game, _, _, _, _): return game
        case let .dragMoved(game, _, _, _): return game
        case let .dragEnded(game, _, _, _, _): return game
        case let .boardChanged(game, _, _, _, _): return game
        case let .gameReset(game, _): return game
        }
    }

    /// 发送方自己递增的序号：去重、丢弃过期包用；服务器可以重新盖章。
    var seq: Int64 {
        switch self {
        case let .dragStarted(_, seq, _, _, _): return seq
        case let .dragMoved(_, seq, _, _): return seq
        case let .dragEnded(_, seq, _, _, _): return seq
        case let .boardChanged(_, seq, _, _, _): return seq
        case let .gameReset(_, seq): return seq
        }
    }

    /// 换一个序号（服务端转发时重新盖章用）。
    func withSeq(_ newSeq: Int64) -> MoveEvent {
        switch self {
        case let .dragStarted(game, _, piece, from, pos):
            return .dragStarted(game: game, seq: newSeq, piece: piece, from: from, pos: pos)
        case let .dragMoved(game, _, piece, pos):
            return .dragMoved(game: game, seq: newSeq, piece: piece, pos: pos)
        case let .dragEnded(game, _, piece, pos, committed):
            return .dragEnded(game: game, seq: newSeq, piece: piece, pos: pos, committed: committed)
        case let .boardChanged(game, _, board, turn, counts):
            return .boardChanged(game: game, seq: newSeq, board: board, turn: turn, counts: counts)
        case let .gameReset(game, _):
            return .gameReset(game: game, seq: newSeq)
        }
    }

    /// 是不是高频的位置流（决定要不要走 30Hz 合并）。
    var isDragMove: Bool {
        if case .dragMoved = self { return true }
        return false
    }
}
