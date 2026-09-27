//
//  XiangqiProtocol.swift
//  chess
//
//  对照 Android: game/xiangqi/XiangqiProtocol.kt
//

import Foundation

/// 象棋的**负载编解码**：
///
///  - 盘面 → 90 个字符：'.' 表示空，红方用大写 `R N B A K C P`，黑方用小写；
///    行序 = rank 0..9（黑方底线在上），列序 = file 0..8；
///  - 落点下标 ↔ 相对棋盘中心的格坐标：x ∈ [-4, +4]（整数），y ∈ [-4.5, +4.5]（半整数）。
enum XiangqiProtocol {

    static let cells = XiangqiGame.size

    /// 棋盘左边界 / 上边界对应的偏移（9 路 → 4，10 路 → 4.5）。
    private static let halfFiles: Float = Float((XiangqiGame.files - 1)) / 2
    private static let halfRanks: Float = Float((XiangqiGame.ranks - 1)) / 2

    static func encode(colors: [Int], pieces: [XiangqiPiece?]) -> String {
        var out = ""
        out.reserveCapacity(cells)
        for index in 0..<cells {
            let color = colors[index]
            guard color != XiangqiGame.empty, let piece = pieces[index] else {
                out.append(".")
                continue
            }
            let code = piece.code
            out.append(color == XiangqiGame.red ? code : Character(code.lowercased()))
        }
        return out
    }

    /// 把 `board` 写回两个数组；长度或字符不对返回 false（此时不改动调用方的数组）。
    static func decode(_ board: String, colors: inout [Int], pieces: inout [XiangqiPiece?]) -> Bool {
        let chars = Array(board)
        guard chars.count == cells, colors.count == cells, pieces.count == cells else { return false }

        var nextColors = colors
        var nextPieces = pieces
        for index in 0..<cells {
            let c = chars[index]
            if c == "." {
                nextColors[index] = XiangqiGame.empty
                nextPieces[index] = nil
                continue
            }
            guard let piece = pieceOf(Character(c.uppercased())) else { return false }
            nextColors[index] = c.isUppercase ? XiangqiGame.red : XiangqiGame.black
            nextPieces[index] = piece
        }
        colors = nextColors
        pieces = nextPieces
        return true
    }

    /// 落点下标 → 相对棋盘中心的格坐标。
    static func cellXOf(_ index: Int) -> Float {
        Float(index % XiangqiGame.files) - halfFiles
    }

    static func cellYOf(_ index: Int) -> Float {
        Float(index / XiangqiGame.files) - halfRanks
    }

    static func posOf(_ index: Int) -> BoardPos {
        BoardPos.ofCells(cellX: cellXOf(index), cellY: cellYOf(index))
    }

    /// 格坐标 → 最近的落点下标（会夹在棋盘范围内；是不是盘外由棋盘几何判断）。
    static func indexOf(cellX: Float, cellY: Float) -> Int {
        let file = (cellX + halfFiles).roundToIntK.coerceIn(0, XiangqiGame.files - 1)
        let rank = (cellY + halfRanks).roundToIntK.coerceIn(0, XiangqiGame.ranks - 1)
        return rank * XiangqiGame.files + file
    }

    private static func pieceOf(_ code: Character) -> XiangqiPiece? {
        switch code {
        case "R": return .rook
        case "N": return .horse
        case "B": return .elephant
        case "A": return .advisor
        case "K": return .king
        case "C": return .cannon
        case "P": return .pawn
        default: return nil
        }
    }
}
