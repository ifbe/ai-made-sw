//
//  IntlChessProtocol.swift
//  chess
//
//  对照 Android: game/guojixiangqi/IntlChessProtocol.kt
//

import Foundation

/// 国际象棋的**负载编解码**：
///
///  - 盘面 → 64 个字符：'.' 表示空，白方大写 `K Q R B N P`，黑方小写；
///    行序 = rank 0..7（黑方底线在上），列序 = file 0..7；
///  - 方格下标 ↔ 相对棋盘中心的格坐标：x, y ∈ [-3.5, +3.5]（半整数）。
enum IntlChessProtocol {

    static let cells = IntlChessGame.size

    /// 8 格 → ±3.5。
    private static let halfFiles: Float = Float(IntlChessGame.files - 1) / 2
    private static let halfRanks: Float = Float(IntlChessGame.ranks - 1) / 2

    static func encode(colors: [Int], types: [IntlChessPiece?]) -> String {
        var out = ""
        out.reserveCapacity(cells)
        for index in 0..<cells {
            let color = colors[index]
            guard color != IntlChessGame.empty, let piece = types[index] else {
                out.append(".")
                continue
            }
            let code = piece.code
            out.append(color == IntlChessGame.white ? code : Character(code.lowercased()))
        }
        return out
    }

    /// 把 `board` 写回两个数组；长度或字符不对返回 false（此时不改动调用方的数组）。
    static func decode(_ board: String, colors: inout [Int], types: inout [IntlChessPiece?]) -> Bool {
        let chars = Array(board)
        guard chars.count == cells, colors.count == cells, types.count == cells else { return false }

        var nextColors = colors
        var nextTypes = types
        for index in 0..<cells {
            let c = chars[index]
            if c == "." {
                nextColors[index] = IntlChessGame.empty
                nextTypes[index] = nil
                continue
            }
            guard let piece = IntlChessPiece.of(Character(c.uppercased())) else { return false }
            nextColors[index] = c.isUppercase ? IntlChessGame.white : IntlChessGame.black
            nextTypes[index] = piece
        }
        colors = nextColors
        types = nextTypes
        return true
    }

    /// 方格下标 → 相对棋盘中心的格坐标。
    static func cellXOf(_ index: Int) -> Float {
        Float(index % IntlChessGame.files) - halfFiles
    }

    static func cellYOf(_ index: Int) -> Float {
        Float(index / IntlChessGame.files) - halfRanks
    }

    static func posOf(_ index: Int) -> BoardPos {
        BoardPos.ofCells(cellX: cellXOf(index), cellY: cellYOf(index))
    }

    /// 格坐标 → 最近的方格下标（会夹在棋盘范围内；是不是盘外由棋盘几何判断）。
    static func indexOf(cellX: Float, cellY: Float) -> Int {
        let file = (cellX + halfFiles).roundToIntK.coerceIn(0, IntlChessGame.files - 1)
        let rank = (cellY + halfRanks).roundToIntK.coerceIn(0, IntlChessGame.ranks - 1)
        return rank * IntlChessGame.files + file
    }
}
