//
//  XiangqiGame.swift
//  chess
//
//  对照 Android: game/xiangqi/XiangqiGame.kt
//

import Combine
import Foundation

/// 象棋的七种棋子，红黑两方的显示名不一样（相/象、仕/士、帅/将）。
enum XiangqiPiece: CaseIterable {
    case rook
    case horse
    case elephant
    case advisor
    case king
    case cannon
    case pawn

    /// 盘面编码用的大写字母（红大写、黑小写）。
    var code: Character {
        switch self {
        case .rook: return "R"
        case .horse: return "N"
        case .elephant: return "B"
        case .advisor: return "A"
        case .king: return "K"
        case .cannon: return "C"
        case .pawn: return "P"
        }
    }

    /// 红方的显示名。
    var redName: Character {
        switch self {
        case .rook: return "车"
        case .horse: return "马"
        case .elephant: return "相"
        case .advisor: return "仕"
        case .king: return "帅"
        case .cannon: return "炮"
        case .pawn: return "兵"
        }
    }

    /// 黑方的显示名。
    var blackName: Character {
        switch self {
        case .rook: return "车"
        case .horse: return "马"
        case .elephant: return "象"
        case .advisor: return "士"
        case .king: return "将"
        case .cannon: return "炮"
        case .pawn: return "卒"
        }
    }

    func nameOf(color: Int) -> Character {
        color == XiangqiGame.red ? redName : blackName
    }
}

/// 象棋的盘面数据 + 全部逻辑。
///
/// 规则：
///  - 只判断轮次，不做任何走法校验；
///  - 盘上的子谁都能拿起来拖（对端也能看见我乱动）；
///  - 不该自己走时松手 ⇒ 弹回原位；点一下没动 / 走到自己子上 ⇒ 弹回原位；
///  - 该自己走时走到对方子上 ⇒ 直接吃掉；
///  - 拖出棋盘 ⇒ 这个子被吃掉，直接消失（不换手）。
final class XiangqiGame: Game {

    /// 横排 9 路，纵排 10 路。
    static let files = 9
    static let ranks = 10
    static let size = files * ranks

    static let empty = 0
    static let red = 1
    static let black = 2

    /// 红先。
    static let firstSide = 0

    private static let backRow: [XiangqiPiece] = [
        .rook, .horse, .elephant, .advisor, .king, .advisor, .elephant, .horse, .rook,
    ]

    /// 1（红）/ 2（黑）→ 0（先手）/ 1（后手）。
    static func sideOf(_ color: Int) -> Int { color == XiangqiGame.red ? firstSide : 1 }

    /// 0（先手）/ 1（后手）→ 1（红）/ 2（黑）。
    static func colorOf(_ side: Int) -> Int { side == XiangqiGame.firstSide ? red : black }

    let kind = GameKind.xiangqi

    /// 每个落点上的棋子，下标 = rank * files + file。
    private(set) var colors: [Int]
    private(set) var pieces: [XiangqiPiece?]

    private(set) var redToMove = true

    var turn: Int { redToMove ? 0 : 1 }

    @Published private(set) var drag: DragOverlay?

    private var dragFrom = -1
    private var dragColor = XiangqiGame.empty
    private var dragPiece: XiangqiPiece?
    private var seq: Int64 = 0

    /// SwiftUI 刷新用：任何会改变渲染结果的操作都调一次。
    @Published private var revision = 0

    init() {
        colors = [Int](repeating: XiangqiGame.empty, count: XiangqiGame.size)
        pieces = [XiangqiPiece?](repeating: nil, count: XiangqiGame.size)
        setup()
    }

    private func didChange() { revision &+= 1 }

    private func nextSeq() -> Int64 {
        seq += 1
        return seq
    }

    /// 摆回开局：红方在下、黑方在上，中间楚河汉界。
    private func setup() {
        for i in 0..<XiangqiGame.size {
            colors[i] = XiangqiGame.empty
            pieces[i] = nil
        }
        for file in 0..<XiangqiGame.files {
            put(file: file, rank: 0, color: XiangqiGame.black, piece: XiangqiGame.backRow[file])
            put(file: file, rank: 9, color: XiangqiGame.red, piece: XiangqiGame.backRow[file])
        }
        put(file: 1, rank: 2, color: XiangqiGame.black, piece: .cannon)
        put(file: 7, rank: 2, color: XiangqiGame.black, piece: .cannon)
        put(file: 1, rank: 7, color: XiangqiGame.red, piece: .cannon)
        put(file: 7, rank: 7, color: XiangqiGame.red, piece: .cannon)
        for file in stride(from: 0, to: XiangqiGame.files, by: 2) {
            put(file: file, rank: 3, color: XiangqiGame.black, piece: .pawn)
            put(file: file, rank: 6, color: XiangqiGame.red, piece: .pawn)
        }
        redToMove = true
        clearDrag()
    }

    private func put(file: Int, rank: Int, color: Int, piece: XiangqiPiece) {
        let index = rank * XiangqiGame.files + file
        colors[index] = color
        pieces[index] = piece
    }

    private func clearDrag() {
        drag = nil
        dragFrom = -1
        dragColor = XiangqiGame.empty
        dragPiece = nil
    }

    // MARK: - Game

    func snapshot() -> BoardSnapshot {
        BoardSnapshot(
            game: kind,
            board: XiangqiProtocol.encode(colors: colors, pieces: pieces),
            turn: turn,
            counts: []
        )
    }

    func hasPieceAt(_ index: Int) -> Bool {
        index >= 0 && index < XiangqiGame.size && colors[index] != XiangqiGame.empty
    }

    func onGesture(_ gesture: Gesture) -> [MoveEvent] {
        let events: [MoveEvent]
        switch gesture {
        case let .pickUp(index):
            events = pickUp(index)
        case let .dragTo(cellX, cellY):
            events = dragTo(cellX: cellX, cellY: cellY)
        case let .drop(cellX, cellY, targetIndex):
            events = drop(cellX: cellX, cellY: cellY, targetIndex: targetIndex)
        case .cancel:
            events = cancel()
        case .pickUpNew:
            events = [] // 象棋没有托盘
        }
        didChange()
        return events
    }

    private func pickUp(_ index: Int) -> [MoveEvent] {
        guard hasPieceAt(index) else { return [] }
        let color = colors[index]
        guard let piece = pieces[index] else { return [] }

        dragFrom = index
        dragColor = color
        dragPiece = piece

        let ref = PieceRef(side: XiangqiGame.sideOf(color), name: String(piece.nameOf(color: color)), id: index)
        let pos = XiangqiProtocol.posOf(index)
        drag = DragOverlay(piece: ref, from: index, cellX: pos.cellX, cellY: pos.cellY, byMe: true)
        return [.dragStarted(game: kind, seq: nextSeq(), piece: ref, from: index, pos: pos)]
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
        let piece = dragPiece
        clearDrag()

        let pos = BoardPos.ofCells(cellX: cellX, cellY: cellY)
        var events: [MoveEvent] = []
        events.reserveCapacity(2)

        // 拖出棋盘 = 被吃，直接消失（不换手）
        if targetIndex < 0 {
            if from >= 0 && from < XiangqiGame.size {
                colors[from] = XiangqiGame.empty
                pieces[from] = nil
            }
            events.append(.dragEnded(game: kind, seq: nextSeq(), piece: current.piece, pos: pos, committed: false))
            events.append(boardChanged())
            return events
        }

        // 点一下没动 / 不该自己走 / 走到自己子上 ⇒ 弹回原位
        let blocked = piece == nil ||
            targetIndex == from ||
            XiangqiGame.sideOf(color) != turn ||
            colors[targetIndex] == color
        if blocked {
            events.append(.dragEnded(game: kind, seq: nextSeq(), piece: current.piece, pos: pos, committed: false))
            return events
        }

        // 落到空格就是走子，落到对方子上就是把对方吃掉（直接覆盖）
        colors[targetIndex] = color
        pieces[targetIndex] = piece
        colors[from] = XiangqiGame.empty
        pieces[from] = nil
        redToMove.toggle()

        events.append(.dragEnded(game: kind, seq: nextSeq(), piece: current.piece, pos: pos, committed: true))
        events.append(boardChanged())
        return events
    }

    private func cancel() -> [MoveEvent] {
        guard let current = drag else { return [] }
        clearDrag()
        return [.dragEnded(
            game: kind, seq: nextSeq(), piece: current.piece,
            pos: XiangqiProtocol.posOf(current.from), committed: false
        )]
    }

    private func boardChanged() -> MoveEvent {
        .boardChanged(
            game: kind,
            seq: nextSeq(),
            board: XiangqiProtocol.encode(colors: colors, pieces: pieces),
            turn: turn,
            counts: []
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
            // 对端拿起一颗子：只有它确实还在那个位置、名字也对得上才开浮层。
            guard from >= 0 && from < XiangqiGame.size else { return }
            let color = colors[from]
            guard color != XiangqiGame.empty else { return }
            guard let localPiece = pieces[from] else { return }
            guard String(localPiece.nameOf(color: color)) == piece.name else { return }
            drag = DragOverlay(piece: piece, from: from, cellX: pos.cellX, cellY: pos.cellY, byMe: false)

        case let .dragMoved(_, _, piece, pos):
            guard let current = drag else { return }
            guard current.piece == piece else { return }
            drag = current.moved(cellX: pos.cellX, cellY: pos.cellY)

        case let .dragEnded(_, _, piece, _, _):
            guard let current = drag else { return }
            if current.piece == piece { drag = nil }

        case let .boardChanged(_, _, board, turn, _):
            var nextColors = colors
            var nextPieces = pieces
            if XiangqiProtocol.decode(board, colors: &nextColors, pieces: &nextPieces) {
                colors = nextColors
                pieces = nextPieces
                redToMove = turn == XiangqiGame.firstSide
            }
            clearDrag()

        case .gameReset:
            setup()
        }

        didChange()
    }
}
