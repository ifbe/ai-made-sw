//
//  IntlChessGame.swift
//  chess
//
//  对照 Android: game/guojixiangqi/IntlChessGame.kt
//

import Combine
import Foundation

/// 国际象棋的六种棋子（显示用的字形见 `glyph`）。
enum IntlChessPiece: CaseIterable {
    case king
    case queen
    case rook
    case bishop
    case knight
    case pawn

    /// 盘面编码 / 棋子身份用的字母。
    var code: Character {
        switch self {
        case .king: return "K"
        case .queen: return "Q"
        case .rook: return "R"
        case .bishop: return "B"
        case .knight: return "N"
        case .pawn: return "P"
        }
    }

    /// 画在棋盘上的 Unicode 实心字形（黑白靠颜色区分）。
    ///
    /// ⚠️ 每个字形后面都缀了 **U+FE0E（VARIATION SELECTOR-15，强制「文字呈现」）**，
    /// 这是踩过坑的：
    ///
    ///  - 系统字体（`Font.system` → SF Pro）**并不含**这六个码位，一定要走字体回退；
    ///  - 而 **♟ U+265F 在 Emoji 11.0（2018）被 emoji 化了**，iOS 的规则是
    ///    「只要该 pictograph 有 emoji 版本就画成彩色 emoji」——**彩色 emoji 完全忽略
    ///    `foregroundColor`**，于是白兵被画成黑兵（其余五个码位没被 emoji 化，所以正常）；
    ///  - 补上 VS15 后，回退会选中文字字体 `AppleSymbols`（已验证六个字形齐全，
    ///    且填充色生效），黑白才分得开。
    ///
    /// 参考：<https://blog.emojipedia.org/a-chess-piece-is-emojified/>
    var glyph: String {
        switch self {
        case .king: return "\u{265A}\u{FE0E}"
        case .queen: return "\u{265B}\u{FE0E}"
        case .rook: return "\u{265C}\u{FE0E}"
        case .bishop: return "\u{265D}\u{FE0E}"
        case .knight: return "\u{265E}\u{FE0E}"
        case .pawn: return "\u{265F}\u{FE0E}"
        }
    }

    static func of(_ code: Character) -> IntlChessPiece? {
        allCases.first { $0.code == code }
    }
}

/// 国际象棋的盘面数据 + 全部逻辑。
///
/// 规则（和另外几种棋一致）：
///  - 不做任何走法判断，只判断轮次（白先）；
///  - 盘上的子谁都能拿起来拖（对端也能看见）；
///  - 不该自己走 / 点一下没动 / 走到自己子上 ⇒ 弹回原位；
///  - 该自己走时走到对方子上 ⇒ 直接把对方子吃掉；
///  - 拖出棋盘 ⇒ 这个子被吃掉，直接消失（不换手）。
final class IntlChessGame: Game {

    static let files = 8
    static let ranks = 8
    static let size = files * ranks

    static let empty = 0
    static let white = 1
    static let black = 2

    /// 白先。
    static let firstSide = 0

    /// 底线从左到右：车 马 象 后 王 象 马 车。
    private static let backRank: [IntlChessPiece] = [
        .rook, .knight, .bishop, .queen, .king, .bishop, .knight, .rook,
    ]

    /// 1（白）/ 2（黑）→ 0（先手）/ 1（后手）。
    static func sideOf(_ color: Int) -> Int { color == IntlChessGame.white ? firstSide : 1 }

    static func colorOf(_ side: Int) -> Int { side == IntlChessGame.firstSide ? white : black }

    let kind = GameKind.intlChess

    /// 下标 = rank * files + file。
    private(set) var colors: [Int]
    private(set) var types: [IntlChessPiece?]

    private(set) var whiteToMove = true

    var turn: Int { whiteToMove ? IntlChessGame.firstSide : 1 }

    @Published private(set) var drag: DragOverlay?

    private var dragFrom = -1
    private var dragColor = IntlChessGame.empty
    private var dragPiece: IntlChessPiece?
    private var seq: Int64 = 0

    /// SwiftUI 刷新用：任何会改变渲染结果的操作都调一次。
    @Published private var revision = 0

    init() {
        colors = [Int](repeating: IntlChessGame.empty, count: IntlChessGame.size)
        types = [IntlChessPiece?](repeating: nil, count: IntlChessGame.size)
        setup()
    }

    private func didChange() { revision &+= 1 }

    private func nextSeq() -> Int64 {
        seq += 1
        return seq
    }

    /// 白方在下、黑方在上，标准开局。
    private func setup() {
        for i in 0..<IntlChessGame.size {
            colors[i] = IntlChessGame.empty
            types[i] = nil
        }
        for file in 0..<IntlChessGame.files {
            put(file: file, rank: 0, color: IntlChessGame.black, piece: IntlChessGame.backRank[file])
            put(file: file, rank: 1, color: IntlChessGame.black, piece: .pawn)
            put(file: file, rank: 6, color: IntlChessGame.white, piece: .pawn)
            put(file: file, rank: 7, color: IntlChessGame.white, piece: IntlChessGame.backRank[file])
        }
        whiteToMove = true
        clearDrag()
    }

    private func put(file: Int, rank: Int, color: Int, piece: IntlChessPiece) {
        let index = rank * IntlChessGame.files + file
        colors[index] = color
        types[index] = piece
    }

    private func clearDrag() {
        drag = nil
        dragFrom = -1
        dragColor = IntlChessGame.empty
        dragPiece = nil
    }

    // MARK: - Game

    func snapshot() -> BoardSnapshot {
        BoardSnapshot(
            game: kind,
            board: IntlChessProtocol.encode(colors: colors, types: types),
            turn: turn,
            counts: []
        )
    }

    func hasPieceAt(_ index: Int) -> Bool {
        index >= 0 && index < IntlChessGame.size && colors[index] != IntlChessGame.empty
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
            events = [] // 国际象棋没有托盘
        }
        didChange()
        return events
    }

    private func pickUp(_ index: Int) -> [MoveEvent] {
        guard hasPieceAt(index) else { return [] }
        let color = colors[index]
        guard let piece = types[index] else { return [] }

        dragFrom = index
        dragColor = color
        dragPiece = piece

        let ref = PieceRef(side: IntlChessGame.sideOf(color), name: String(piece.code), id: index)
        let pos = IntlChessProtocol.posOf(index)
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
            if from >= 0 && from < IntlChessGame.size {
                colors[from] = IntlChessGame.empty
                types[from] = nil
            }
            events.append(.dragEnded(game: kind, seq: nextSeq(), piece: current.piece, pos: pos, committed: false))
            events.append(boardChanged())
            return events
        }

        // 点一下没动 / 不该自己走 / 走到自己子上 ⇒ 弹回原位
        let blocked = piece == nil ||
            targetIndex == from ||
            IntlChessGame.sideOf(color) != turn ||
            colors[targetIndex] == color
        if blocked {
            events.append(.dragEnded(game: kind, seq: nextSeq(), piece: current.piece, pos: pos, committed: false))
            return events
        }

        // 落到空格就是走子，落到对方子上就是把对方吃掉（直接覆盖）
        colors[targetIndex] = color
        types[targetIndex] = piece
        colors[from] = IntlChessGame.empty
        types[from] = nil
        whiteToMove.toggle()

        events.append(.dragEnded(game: kind, seq: nextSeq(), piece: current.piece, pos: pos, committed: true))
        events.append(boardChanged())
        return events
    }

    private func cancel() -> [MoveEvent] {
        guard let current = drag else { return [] }
        clearDrag()
        return [.dragEnded(
            game: kind, seq: nextSeq(), piece: current.piece,
            pos: IntlChessProtocol.posOf(current.from), committed: false
        )]
    }

    private func boardChanged() -> MoveEvent {
        .boardChanged(
            game: kind,
            seq: nextSeq(),
            board: IntlChessProtocol.encode(colors: colors, types: types),
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
            guard from >= 0 && from < IntlChessGame.size else { return }
            let color = colors[from]
            guard color != IntlChessGame.empty else { return }
            guard let localPiece = types[from] else { return }
            guard String(localPiece.code) == piece.name else { return }
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
            var nextTypes = types
            if IntlChessProtocol.decode(board, colors: &nextColors, types: &nextTypes) {
                colors = nextColors
                types = nextTypes
                whiteToMove = turn == IntlChessGame.firstSide
            }
            clearDrag()

        case .gameReset:
            setup()
        }

        didChange()
    }
}
