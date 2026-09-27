//
//  BoardPos.swift
//  chess
//
//  对照 Android: game/share/protocol/BoardPos.kt
//

import Foundation

/// 相对棋盘中心的坐标，单位 = 1/256 格，用整数避免浮点误差。
///
/// x 沿 file / 列方向（向右为正），y 沿 rank / 行方向（向下为正）——
/// 这是「棋盘语义坐标」而不是屏幕坐标，所以棋盘在横屏被转 90° 也照样对得上。
///
/// 各种棋的落点范围（拖动中可能超出，超出棋盘 = 被吃）：
///  - 象棋：x ∈ [-4, +4]（整数），y ∈ [-4.5, +4.5]（半整数）
///  - 国际象棋：x, y ∈ [-3.5, +3.5]
///  - 围棋 19 路：x, y ∈ [-9, +9]；五子棋 15 路：x, y ∈ [-7, +7]
struct BoardPos: Equatable {
    var x: Int
    var y: Int

    /// 一格的精度单位。
    static let unitsPerCell = 256

    var cellX: Float { Float(x) / Float(BoardPos.unitsPerCell) }
    var cellY: Float { Float(y) / Float(BoardPos.unitsPerCell) }

    static let origin = BoardPos(x: 0, y: 0)

    static func ofCells(cellX: Float, cellY: Float) -> BoardPos {
        BoardPos(
            x: (cellX * Float(unitsPerCell)).roundToIntK,
            y: (cellY * Float(unitsPerCell)).roundToIntK
        )
    }
}
