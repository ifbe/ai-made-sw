//
//  BoardGeometry.swift
//  chess
//
//  对照 Android: game/share/stone/BoardGeometry.kt
//

import Foundation

/// 棋盘几何计算。纯 Swift，不依赖 UI，方便单测验证。
///
/// 规则：
///  - 棋盘正方形边长 = min(width, height)，中心 = 视图中心；
///  - 正方形被等分成 `subdivisions` × `subdivisions` 个格子，格子边长 = 边长 / subdivisions；
///  - 第 i 个落点落在第 i 个格子的正中心，即 (i + 1) * cell，所以最外圈落点离正方形边界正好一格；
///  - 正方形外的两侧余量用来放托盘，哪两侧余量大就放哪两侧。
final class BoardGeometry {

    let width: Float
    let height: Float
    let lines: Int
    let subdivisions: Int

    /// 棋盘正方形边长 = min(width, height)。
    let boardSize: Float

    init(width: Float, height: Float, lines: Int = 19, subdivisions: Int? = nil) {
        self.width = width
        self.height = height
        self.lines = lines
        self.subdivisions = subdivisions ?? (lines + 1)
        self.boardSize = min(width, height)
    }

    /// 各尺寸棋盘的传统星位。
    /// 19 路围棋是 9 个星；15 路五子棋（连珠）和 13 / 9 路是 5 个星（四角 + 天元）。
    static func starPoints(lines: Int) -> [(col: Int, row: Int)] {
        switch lines {
        case 19:
            var points: [(Int, Int)] = []
            for row in [3, 9, 15] {
                for col in [3, 9, 15] {
                    points.append((col, row))
                }
            }
            return points
        case 15:
            return [(3, 3), (11, 3), (3, 11), (11, 11), (7, 7)]
        case 13:
            return [(3, 3), (9, 3), (3, 9), (9, 9), (6, 6)]
        case 9:
            return [(2, 2), (6, 2), (2, 6), (6, 6), (4, 4)]
        default:
            return []
        }
    }

    /// 棋盘正方形左边 / 上边坐标（正方形中心 = 视图中心）。
    var boardLeft: Float { (width - boardSize) / 2 }
    var boardTop: Float { (height - boardSize) / 2 }

    /// 格子边长。
    var cell: Float { boardSize / Float(subdivisions) }

    /// 棋盘上棋子的半径。
    var stoneRadius: Float { cell * 0.46 }

    /// 托盘里的棋子和拖动中的那颗棋子共用同一个半径（比盘上的子略大一点），
    /// 所以「棋盘外的棋子」和「拖动时的棋子」永远一样大。
    var pieceRadius: Float { stoneRadius * 1.08 }

    /// 棋盘正方形左右的余量（每侧）与上下的余量（每侧）。
    var sideSpace: Float { boardLeft }
    var verticalSpace: Float { boardTop }

    /// true：托盘放左右两侧（横屏 / 平板）；false：托盘放上下两侧（竖屏手机）。
    var trayOnSides: Bool { boardLeft > boardTop }

    /// 放托盘那条空带的宽度。
    var trayStrip: Float { trayOnSides ? boardLeft : boardTop }

    /// 落点 (col, row) 的中心坐标。
    func gridX(_ col: Int) -> Float { boardLeft + Float(col + 1) * cell }
    func gridY(_ row: Int) -> Float { boardTop + Float(row + 1) * cell }

    /// 棋盘语义坐标（x 沿列、y 沿行，单位 = 格，原点 = 棋盘中心）↔ 屏幕像素。
    /// 石头棋盘永远是正的（不旋转），所以是简单线性映射。
    func cellXAt(px: Float) -> Float { (px - boardLeft - boardSize / 2) / cell }
    func cellYAt(py: Float) -> Float { (py - boardTop - boardSize / 2) / cell }
    func pxOfCell(_ cellX: Float) -> Float { boardLeft + boardSize / 2 + cellX * cell }
    func pyOfCell(_ cellY: Float) -> Float { boardTop + boardSize / 2 + cellY * cell }

    func isInsideBoard(x: Float, y: Float) -> Bool {
        x >= boardLeft && x <= boardLeft + boardSize &&
            y >= boardTop && y <= boardTop + boardSize
    }

    /// 手指位置吸附到最近的落点，返回下标（row * lines + col）。
    /// 不在棋盘正方形里时返回 -1。
    func indexAt(x: Float, y: Float) -> Int {
        guard isInsideBoard(x: x, y: y) else { return -1 }
        let col = (((x - boardLeft) / cell) - 1).roundToIntK.coerceIn(0, lines - 1)
        let row = (((y - boardTop) / cell) - 1).roundToIntK.coerceIn(0, lines - 1)
        return row * lines + col
    }

    /// 托盘圆心的 x / y。`black` 为 true 表示黑棋托盘。
    func trayCenterX(black: Bool) -> Float {
        guard trayOnSides else { return width / 2 }
        return black ? boardLeft / 2 : width - boardLeft / 2
    }

    func trayCenterY(black: Bool) -> Float {
        guard !trayOnSides else { return height / 2 }
        return black ? boardTop / 2 : height - boardTop / 2
    }
}
