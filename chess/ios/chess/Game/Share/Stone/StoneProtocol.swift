//
//  StoneProtocol.swift
//  chess
//
//  对照 Android: game/share/stone/StoneProtocol.kt
//

import Foundation

/// 围棋 / 五子棋的**负载编解码**。
///
///  - 盘面 → `lines × lines` 个字符：'.' 空，'b' 黑子，'w' 白子；行序 = 行 0..lines-1；
///  - 落点下标 ↔ 相对棋盘中心的格坐标：19 路是 x,y ∈ [-9, +9]，15 路是 [-7, +7]。
enum StoneProtocol {

    static func encode(_ grid: [Int]) -> String {
        var out = ""
        out.reserveCapacity(grid.count)
        for cell in grid {
            switch cell {
            case StoneGame.black: out.append("b")
            case StoneGame.white: out.append("w")
            default: out.append(".")
            }
        }
        return out
    }

    /// 解析盘面到 `grid`；长度不对或有非法字符返回 false（此时 grid 可能已被部分改写，调用方应丢弃）。
    static func decode(_ board: String, into grid: inout [Int]) -> Bool {
        let chars = Array(board)
        guard chars.count == grid.count else { return false }
        for index in grid.indices {
            switch chars[index] {
            case "b": grid[index] = StoneGame.black
            case "w": grid[index] = StoneGame.white
            case ".": grid[index] = StoneGame.empty
            default: return false
            }
        }
        return true
    }

    /// 落点下标 → 相对棋盘中心的格坐标。
    static func cellXOf(_ index: Int, lines: Int) -> Float {
        Float(index % lines) - Float(lines - 1) / 2
    }

    static func cellYOf(_ index: Int, lines: Int) -> Float {
        Float(index / lines) - Float(lines - 1) / 2
    }

    static func posOf(_ index: Int, lines: Int) -> BoardPos {
        BoardPos.ofCells(cellX: cellXOf(index, lines: lines), cellY: cellYOf(index, lines: lines))
    }

    /// 格坐标 → 最近的落点下标（会夹在棋盘范围内；是不是盘外由棋盘几何判断）。
    static func indexOf(cellX: Float, cellY: Float, lines: Int) -> Int {
        let col = (cellX + Float(lines - 1) / 2).roundToIntK.coerceIn(0, lines - 1)
        let row = (cellY + Float(lines - 1) / 2).roundToIntK.coerceIn(0, lines - 1)
        return row * lines + col
    }
}
