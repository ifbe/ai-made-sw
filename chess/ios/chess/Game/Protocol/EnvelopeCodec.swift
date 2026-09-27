//
//  EnvelopeCodec.swift
//  chess
//
//  对照 Android: game/share/protocol/EnvelopeCodec.kt
//

import Foundation

/// 报文的「信封」编解码。格式是 `key=value` 拼起来的单行文本：
///
/// ```
/// v1|game=xiangqi|seq=12|t=drag_move|side=0|name=车|id=54|x=1280|y=-1152
/// v1|game=weiqi|seq=13|t=board|board=..b.w..|turn=1|counts=179,180
/// ```
///
/// 第一段是版本号，以后加字段不会打乱老客户端；值里不能出现 '|'（棋子名、盘面串都不含）。
/// **这段编解码必须与 Android 逐字节一致，否则跨平台连不上。**
enum EnvelopeCodec {

    static let version = "v1"
    private static let sep: Character = "|"

    private static let tStart = "drag_start"
    private static let tMove = "drag_move"
    private static let tEnd = "drag_end"
    private static let tBoard = "board"
    private static let tReset = "reset"

    static func encode(_ event: MoveEvent) -> String {
        var parts: [String] = []
        parts.reserveCapacity(12)
        parts.append(version)
        parts.append("game=\(event.game.id)")
        parts.append("seq=\(event.seq)")

        switch event {
        case let .dragStarted(_, _, piece, from, pos):
            parts.append("t=\(tStart)")
            parts.append("side=\(piece.side)")
            parts.append("name=\(piece.name)")
            parts.append("id=\(piece.id)")
            parts.append("from=\(from)")
            parts.append("x=\(pos.x)")
            parts.append("y=\(pos.y)")

        case let .dragMoved(_, _, piece, pos):
            parts.append("t=\(tMove)")
            parts.append("side=\(piece.side)")
            parts.append("name=\(piece.name)")
            parts.append("id=\(piece.id)")
            parts.append("x=\(pos.x)")
            parts.append("y=\(pos.y)")

        case let .dragEnded(_, _, piece, pos, committed):
            parts.append("t=\(tEnd)")
            parts.append("side=\(piece.side)")
            parts.append("name=\(piece.name)")
            parts.append("id=\(piece.id)")
            parts.append("x=\(pos.x)")
            parts.append("y=\(pos.y)")
            parts.append("committed=\(committed ? 1 : 0)")

        case let .boardChanged(_, _, board, turn, counts):
            parts.append("t=\(tBoard)")
            parts.append("board=\(board)")
            parts.append("turn=\(turn)")
            parts.append("counts=\(counts.map(String.init).joined(separator: ","))")

        case .gameReset:
            parts.append("t=\(tReset)")
        }

        return parts.joined(separator: String(sep))
    }

    /// 解析一行报文；版本不对、字段缺失或脏数据都返回 nil，不抛异常。
    static func decode(_ line: String) -> MoveEvent? {
        let parts = line.split(separator: sep, omittingEmptySubsequences: false).map(String.init)
        guard let first = parts.first, first == version else { return nil }

        var fields: [String: String] = [:]
        fields.reserveCapacity(parts.count * 2)
        for i in 1..<parts.count {
            let part = parts[i]
            guard let eq = part.firstIndex(of: "=") else { continue }
            // 等价于 Kotlin 的 `if (eq <= 0) continue`：key 不能为空。
            guard eq != part.startIndex else { continue }
            let key = String(part[part.startIndex..<eq])
            let value = String(part[part.index(after: eq)...])
            fields[key] = value
        }

        guard let gameId = fields["game"], let game = GameKind.fromId(gameId) else { return nil }
        guard let seq = Int64(fields["seq"] ?? "") else { return nil }

        let piece = PieceRef(
            side: Int(fields["side"] ?? "") ?? 0,
            name: fields["name"] ?? "",
            id: Int(fields["id"] ?? "") ?? -1
        )
        let pos = BoardPos(
            x: Int(fields["x"] ?? "") ?? 0,
            y: Int(fields["y"] ?? "") ?? 0
        )

        switch fields["t"] {
        case tStart:
            return .dragStarted(
                game: game, seq: seq, piece: piece,
                from: Int(fields["from"] ?? "") ?? -1, pos: pos
            )

        case tMove:
            return .dragMoved(game: game, seq: seq, piece: piece, pos: pos)

        case tEnd:
            return .dragEnded(
                game: game, seq: seq, piece: piece, pos: pos,
                committed: fields["committed"] == "1"
            )

        case tBoard:
            let counts = (fields["counts"] ?? "")
                .split(separator: ",", omittingEmptySubsequences: true)
                .compactMap { Int($0) }
            return .boardChanged(
                game: game, seq: seq,
                board: fields["board"] ?? "",
                turn: Int(fields["turn"] ?? "") ?? 0,
                counts: counts
            )

        case tReset:
            return .gameReset(game: game, seq: seq)

        default:
            return nil
        }
    }
}
