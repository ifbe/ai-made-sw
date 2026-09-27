//
//  StoneGame.swift
//  chess
//
//  对照 Android: game/share/stone/StoneGame.kt
//

import Combine
import Foundation

/// 围棋 / 五子棋共用的盘面数据 + 逻辑（两者只有路数不同，围棋 19、五子棋 15）。
///
/// 规则：
///  - 不做任何吃子 / 提子 / 连五判断，只判断轮次；
///  - 盘上的子谁都能拿起来拖（对端也能看见），不该自己走 ⇒ 松手弹回原位；
///  - 把盘上的子拖出棋盘 ⇒ 这颗子被吃掉，直接消失（不回托盘、不换手）；
///  - 托盘只有该走的那一方能拿，落到盘上空位就落子并把数量 -1。
final class StoneGame: Game {

    /// 每色棋子初始数量。
    static let initialStones = 180

    static let empty = 0
    static let black = 1
    static let white = 2

    /// 黑先。
    static let firstSide = 0

    static func sideOf(_ color: Int) -> Int { color == StoneGame.black ? 0 : 1 }

    static func colorOf(_ side: Int) -> Int { side == StoneGame.firstSide ? StoneGame.black : StoneGame.white }

    let lines: Int
    let kind: GameKind

    /// 每个落点上的棋子：empty / black / white。
    private(set) var grid: [Int]

    /// 每颗子的自增编号（0 表示这一格没有子）—— 石头没有名字，就用它当身份。
    private(set) var ids: [Int]

    private(set) var blackToMove = true
    private(set) var blackRemaining = StoneGame.initialStones
    private(set) var whiteRemaining = StoneGame.initialStones

    var turn: Int { blackToMove ? StoneGame.firstSide : 1 }

    @Published private(set) var drag: DragOverlay?

    private var dragFrom = -1
    private var dragColor = StoneGame.empty
    private var dragPiece: PieceRef?

    /// 手上这颗是不是刚从托盘拿出来的新子。
    private var dragFromTray = false
    private var nextStoneId = 1
    private var seq: Int64 = 0

    /// SwiftUI 刷新用：任何会改变渲染结果的操作都调一次。
    @Published private var revision = 0

    init(lines: Int, kind: GameKind) {
        self.lines = lines
        self.kind = kind
        self.grid = [Int](repeating: StoneGame.empty, count: lines * lines)
        self.ids = [Int](repeating: 0, count: lines * lines)
    }

    private func didChange() { revision &+= 1 }

    private func nextSeq() -> Int64 {
        seq += 1
        return seq
    }

    func remaining(side: Int) -> Int {
        side == StoneGame.firstSide ? blackRemaining : whiteRemaining
    }

    func remainingOf(color: Int) -> Int {
        color == StoneGame.black ? blackRemaining : whiteRemaining
    }

    /// 重开：清空棋盘、数量回到初始值、重新黑先。
    private func setup() {
        for i in grid.indices {
            grid[i] = StoneGame.empty
            ids[i] = 0
        }
        blackToMove = true
        blackRemaining = StoneGame.initialStones
        whiteRemaining = StoneGame.initialStones
        clearDrag()
    }

    private func clearDrag() {
        drag = nil
        dragFrom = -1
        dragColor = StoneGame.empty
        dragPiece = nil
        dragFromTray = false
    }

    // MARK: - Game

    func snapshot() -> BoardSnapshot {
        BoardSnapshot(
            game: kind,
            board: StoneProtocol.encode(grid),
            turn: turn,
            counts: [blackRemaining, whiteRemaining]
        )
    }

    func hasPieceAt(_ index: Int) -> Bool {
        index >= 0 && index < grid.count && grid[index] != StoneGame.empty
    }

    func onGesture(_ gesture: Gesture) -> [MoveEvent] {
        let events: [MoveEvent]
        switch gesture {
        case let .pickUp(index):
            events = pickUpBoardStone(index)
        case let .pickUpNew(side, cellX, cellY):
            events = pickUpNewStone(side: side, cellX: cellX, cellY: cellY)
        case let .dragTo(cellX, cellY):
            events = dragTo(cellX: cellX, cellY: cellY)
        case let .drop(cellX, cellY, targetIndex):
            events = drop(cellX: cellX, cellY: cellY, targetIndex: targetIndex)
        case .cancel:
            events = cancel()
        }
        didChange()
        return events
    }

    private func pickUpBoardStone(_ index: Int) -> [MoveEvent] {
        guard hasPieceAt(index) else { return [] }
        let color = grid[index]
        dragFrom = index
        dragColor = color
        dragFromTray = false
        let ref = PieceRef(side: StoneGame.sideOf(color), name: "", id: ids[index])
        dragPiece = ref
        let pos = StoneProtocol.posOf(index, lines: lines)
        drag = DragOverlay(piece: ref, from: index, cellX: pos.cellX, cellY: pos.cellY, byMe: true)
        return [.dragStarted(game: kind, seq: nextSeq(), piece: ref, from: index, pos: pos)]
    }

    private func pickUpNewStone(side: Int, cellX: Float, cellY: Float) -> [MoveEvent] {
        // 托盘只有该走的那一方能拿
        guard side == turn else { return [] }
        guard remaining(side: side) > 0 else { return [] }

        let color = StoneGame.colorOf(side)
        let ref = PieceRef(side: side, name: "", id: nextStoneId)
        nextStoneId += 1
        dragFrom = -1
        dragColor = color
        dragFromTray = true
        dragPiece = ref
        let pos = BoardPos.ofCells(cellX: cellX, cellY: cellY)
        drag = DragOverlay(piece: ref, from: -1, cellX: pos.cellX, cellY: pos.cellY, byMe: true)
        return [.dragStarted(game: kind, seq: nextSeq(), piece: ref, from: -1, pos: pos)]
    }

    private func dragTo(cellX: Float, cellY: Float) -> [MoveEvent] {
        guard let current = drag else { return [] }
        drag = current.moved(cellX: cellX, cellY: cellY)
        return [.dragMoved(
            game: kind, seq: nextSeq(), piece: current.piece,
            pos: BoardPos.ofCells(cellX: cellX, cellY: cellY)
        )]
    }

    private func drop(cellX: Float, cellY: Float, targetIndex: Int) -> [MoveEvent] {
        guard let current = drag else { return [] }
        let from = dragFrom
        let color = dragColor
        let ref = current.piece
        let fromTray = dragFromTray
        clearDrag()

        let pos = BoardPos.ofCells(cellX: cellX, cellY: cellY)
        var events: [MoveEvent] = []
        events.reserveCapacity(2)

        // 从盘上拿起来的子
        if !fromTray {
            // 拖出棋盘 = 被吃，直接消失（不回托盘、不换手）
            if targetIndex < 0 {
                if from >= 0 && from < grid.count {
                    grid[from] = StoneGame.empty
                    ids[from] = 0
                }
                events.append(.dragEnded(game: kind, seq: nextSeq(), piece: ref, pos: pos, committed: false))
                events.append(boardChanged())
                return events
            }
            let blocked = targetIndex == from ||
                StoneGame.sideOf(color) != turn ||
                grid[targetIndex] != StoneGame.empty
            if blocked {
                events.append(.dragEnded(game: kind, seq: nextSeq(), piece: ref, pos: pos, committed: false))
                return events
            }
            grid[targetIndex] = color
            ids[targetIndex] = ids[from]
            grid[from] = StoneGame.empty
            ids[from] = 0
            blackToMove.toggle()
            events.append(.dragEnded(game: kind, seq: nextSeq(), piece: ref, pos: pos, committed: true))
            events.append(boardChanged())
            return events
        }

        // 从托盘拖出来的新子：落不到盘上就相当于放回托盘
        if targetIndex < 0 || grid[targetIndex] != StoneGame.empty {
            events.append(.dragEnded(game: kind, seq: nextSeq(), piece: ref, pos: pos, committed: false))
            return events
        }
        grid[targetIndex] = color
        ids[targetIndex] = ref.id
        if color == StoneGame.black {
            blackRemaining -= 1
        } else {
            whiteRemaining -= 1
        }
        blackToMove.toggle()
        events.append(.dragEnded(game: kind, seq: nextSeq(), piece: ref, pos: pos, committed: true))
        events.append(boardChanged())
        return events
    }

    private func cancel() -> [MoveEvent] {
        guard let current = drag else { return [] }
        let pos = current.from >= 0
            ? StoneProtocol.posOf(current.from, lines: lines)
            : BoardPos.ofCells(cellX: current.cellX, cellY: current.cellY)
        let ref = current.piece
        clearDrag()
        return [.dragEnded(game: kind, seq: nextSeq(), piece: ref, pos: pos, committed: false)]
    }

    private func boardChanged() -> MoveEvent {
        .boardChanged(
            game: kind,
            seq: nextSeq(),
            board: StoneProtocol.encode(grid),
            turn: turn,
            counts: [blackRemaining, whiteRemaining]
        )
    }

    func reset() -> [MoveEvent] {
        setup()
        let events: [MoveEvent] = [.gameReset(game: kind, seq: nextSeq()), boardChanged()]
        didChange()
        return events
    }

    func apply(_ event: MoveEvent) {
        guard event.game == kind else { return }
        seq = max(seq, event.seq)

        switch event {
        case let .dragStarted(_, _, piece, from, pos):
            // 从托盘拿的新子（from < 0）没法校验，直接显示；盘上的子要确认还在原地
            if from >= 0 {
                guard hasPieceAt(from) else { return }
                guard StoneGame.sideOf(grid[from]) == piece.side else { return }
            }
            drag = DragOverlay(piece: piece, from: from, cellX: pos.cellX, cellY: pos.cellY, byMe: false)

        case let .dragMoved(_, _, piece, pos):
            guard let current = drag else { return }
            guard current.piece == piece else { return }
            drag = current.moved(cellX: pos.cellX, cellY: pos.cellY)

        case let .dragEnded(_, _, piece, _, _):
            guard let current = drag else { return }
            if current.piece == piece { drag = nil }

        case let .boardChanged(_, _, board, turn, counts):
            var next = grid
            if StoneProtocol.decode(board, into: &next) {
                grid = next
                blackToMove = turn == StoneGame.firstSide
                if counts.count >= 2 {
                    blackRemaining = counts[0]
                    whiteRemaining = counts[1]
                }
            }
            clearDrag()

        case .gameReset:
            setup()
        }

        didChange()
    }
}
