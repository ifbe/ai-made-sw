//
//  IntlChessGeometry.swift
//  chess
//
//  对照 Android: game/guojixiangqi/IntlChessGeometry.kt
//

import Foundation

/// 国际象棋棋盘几何。纯 Swift，不依赖 UI。
///
///  - 棋盘区就是 min(w,h) 的正方形，居中，分成 8 × 8 个方格（棋子站在方格正中心）；
///  - 竖屏时白方在下、黑方在上；横屏（宽 > 高）时把棋盘转 90°，黑方在左、白方在右，
///    这样两端的小牌子正好落在棋盘外的空带上，和象棋页一个做法。
///
/// 棋盘坐标：file 0..7 = a..h（未旋转时从左到右），rank 0..7 = 第 8 横排..第 1 横排
/// （rank 0 是黑方底线，rank 7 是白方底线）。
final class IntlChessGeometry {

    /// 每边 8 个方格。
    static let files = 8
    static let ranks = 8

    let width: Float
    let height: Float

    /// 棋盘区边长 = min(width, height)。
    let boardSize: Float
    let boardLeft: Float
    let boardTop: Float

    /// 每个方格的边长。
    let cell: Float

    /// 横屏时把棋盘转 90°。
    let rotated: Bool

    /// 棋盘外左右 / 上下剩下的空间（每侧）。
    let sideSpace: Float
    let verticalSpace: Float

    init(width: Float, height: Float) {
        self.width = width
        self.height = height
        self.boardSize = min(width, height)
        self.boardLeft = (width - boardSize) / 2
        self.boardTop = (height - boardSize) / 2
        self.cell = boardSize / Float(IntlChessGeometry.files)
        self.rotated = width > height
        self.sideSpace = boardLeft
        self.verticalSpace = boardTop
    }

    /// 某个格子是不是深色格（a1 是深色，标准棋盘）。
    func isDarkSquare(file: Int, rank: Int) -> Bool { (file + rank) % 2 == 1 }

    /// 棋盘坐标 → 屏幕上的列 / 行。
    func screenCol(file: Int, rank: Int) -> Int { rotated ? rank : file }
    func screenRow(file: Int, rank: Int) -> Int { rotated ? file : rank }

    /// 方格中心坐标。
    func squareX(file: Int, rank: Int) -> Float {
        boardLeft + (Float(screenCol(file: file, rank: rank)) + 0.5) * cell
    }

    func squareY(file: Int, rank: Int) -> Float {
        boardTop + (Float(screenRow(file: file, rank: rank)) + 0.5) * cell
    }

    /// 方格左上角坐标。
    func squareLeft(file: Int, rank: Int) -> Float {
        boardLeft + Float(screenCol(file: file, rank: rank)) * cell
    }

    func squareTop(file: Int, rank: Int) -> Float {
        boardTop + Float(screenRow(file: file, rank: rank)) * cell
    }

    /// 棋盘语义坐标（x 沿 file、y 沿 rank，单位 = 格，原点 = 棋盘中心）↔ 屏幕像素。
    /// 横屏时棋盘转了 90°，这里一并处理掉，协议层拿到的永远是棋盘语义坐标。
    func cellXAt(px: Float, py: Float) -> Float {
        rotated ? (py - boardTop - boardSize / 2) / cell : (px - boardLeft - boardSize / 2) / cell
    }

    func cellYAt(px: Float, py: Float) -> Float {
        rotated ? (px - boardLeft - boardSize / 2) / cell : (py - boardTop - boardSize / 2) / cell
    }

    func pxOfCell(cellX: Float, cellY: Float) -> Float {
        rotated ? boardLeft + boardSize / 2 + cellY * cell : boardLeft + boardSize / 2 + cellX * cell
    }

    func pyOfCell(cellX: Float, cellY: Float) -> Float {
        rotated ? boardTop + boardSize / 2 + cellX * cell : boardTop + boardSize / 2 + cellY * cell
    }

    func isInsideBoard(x: Float, y: Float) -> Bool {
        x >= boardLeft && x <= boardLeft + boardSize &&
            y >= boardTop && y <= boardTop + boardSize
    }

    /// 手指落在哪个格子上，返回棋盘坐标下标（rank * files + file），不在棋盘内返回 -1。
    /// 注意：这里是**向下取整**（Kotlin `.toInt()`），不是四舍五入。
    func indexAt(x: Float, y: Float) -> Int {
        guard isInsideBoard(x: x, y: y) else { return -1 }
        let col = Int((x - boardLeft) / cell).coerceIn(0, IntlChessGeometry.files - 1)
        let row = Int((y - boardTop) / cell).coerceIn(0, IntlChessGeometry.ranks - 1)
        let file = rotated ? row : col
        let rank = rotated ? col : row
        return rank * IntlChessGeometry.files + file
    }

    /// 挂双方小牌子的那条空带有多宽。
    var badgeStrip: Float { rotated ? boardLeft : boardTop }

    /// 某一方的牌子挂在棋盘外哪一端（black = 黑方，rank 0 那一端）。
    func sideAnchorX(black: Bool) -> Float {
        if !rotated { return width / 2 }
        return black ? boardLeft / 2 : width - boardLeft / 2
    }

    func sideAnchorY(black: Bool) -> Float {
        if rotated { return height / 2 }
        return black ? boardTop / 2 : height - boardTop / 2
    }

    /// 牌子上的字要转多少度才正对着那一端的玩家（和象棋页同一套规则）。
    func sideTextRotation(black: Bool) -> Float {
        if !rotated { return black ? 180 : 0 }
        return black ? 90 : -90
    }

    /// 棋子上的字要转多少度：朝着当前该走的那一方（白先）。
    func pieceTextRotation(whiteToMove: Bool) -> Float {
        sideTextRotation(black: !whiteToMove)
    }
}
