//
//  XiangqiGeometry.swift
//  chess
//
//  对照 Android: game/xiangqi/XiangqiGeometry.kt
//

import Foundation

/// 象棋棋盘几何。纯 Swift，不依赖 UI。
///
/// 棋盘是 9 路 × 10 路，方向固定：**短边放 9 路、长边放 10 路**。格子边长取两条限制里更小的那个：
///
///   格子 = min(短边 / 9,  长边 / 10 × 0.8)
///
///  - 短边 / 9：棋盘最多占满短边；
///  - 长边 / 10 × 0.8：棋盘在长边方向最多只占 80%，也就是**长边两端永远各留 10%**，
///    够放左上角的按钮和两端「该谁走」的指示框。
///
/// 落点都在各自格子的正中心，所以最外圈离棋盘边还有半格，边上的棋子不会被切掉。
final class XiangqiGeometry {

    /// 横排落点数。
    static let files = 9
    /// 竖排落点数。
    static let ranks = 10
    /// 长边方向棋盘最多占的比例（两端各留 10%）。
    static let compactFill: Float = 0.8

    let width: Float
    let height: Float

    private let shortSide: Float
    private let longSide: Float

    /// 两条限制：占满短边 vs 长边只占 80%。
    private let fillShortSideLimit: Float
    private let leaveRoomLimit: Float

    /// true：格子由「占满短边」决定（细长屏）；false：由「长边两端各留 10%」决定。
    let fillsShortSide: Bool

    /// 格子边长 = min(短边 / 9, 长边 / 10 × 0.8)。
    let cell: Float

    /// 屏幕横向 / 纵向各有多少个落点：竖屏 9 列 × 10 行，横屏转 90°（10 列 × 9 行）。
    let cols: Int
    let rows: Int

    /// 棋盘（cols × rows 个格子）的像素尺寸和左上角。
    let boardWidth: Float
    let boardHeight: Float
    let boardLeft: Float
    let boardTop: Float

    /// 棋盘外左右 / 上下剩下的空间（每侧），用来放「轮到谁走」的提示。
    let sideSpace: Float
    let verticalSpace: Float

    /// true：棋盘转了 90°（10 路沿着屏幕横向走）。
    let rotated: Bool

    init(width: Float, height: Float) {
        self.width = width
        self.height = height
        self.shortSide = min(width, height)
        self.longSide = max(width, height)
        self.fillShortSideLimit = shortSide / Float(XiangqiGeometry.files)
        self.leaveRoomLimit = longSide / Float(XiangqiGeometry.ranks) * XiangqiGeometry.compactFill
        self.fillsShortSide = fillShortSideLimit <= leaveRoomLimit
        self.cell = min(fillShortSideLimit, leaveRoomLimit)
        self.cols = width <= height ? XiangqiGeometry.files : XiangqiGeometry.ranks
        self.rows = width <= height ? XiangqiGeometry.ranks : XiangqiGeometry.files
        self.boardWidth = Float(cols) * cell
        self.boardHeight = Float(rows) * cell
        self.boardLeft = (width - boardWidth) / 2
        self.boardTop = (height - boardHeight) / 2
        self.sideSpace = boardLeft
        self.verticalSpace = boardTop
        self.rotated = cols == XiangqiGeometry.ranks
    }

    /// 屏幕列 / 行对应的像素中心。
    func gridX(_ col: Int) -> Float { boardLeft + (Float(col) + 0.5) * cell }
    func gridY(_ row: Int) -> Float { boardTop + (Float(row) + 0.5) * cell }

    /// 棋盘坐标（file 0..8，rank 0..9）→ 屏幕上的列 / 行。
    func screenCol(file: Int, rank: Int) -> Int { rotated ? rank : file }
    func screenRow(file: Int, rank: Int) -> Int { rotated ? file : rank }

    /// 棋盘坐标上的像素位置。
    func pieceX(file: Int, rank: Int) -> Float { gridX(screenCol(file: file, rank: rank)) }
    func pieceY(file: Int, rank: Int) -> Float { gridY(screenRow(file: file, rank: rank)) }

    /// 棋盘语义坐标（x 沿 file、y 沿 rank，单位 = 格，原点 = 棋盘中心）↔ 屏幕像素。
    /// 横屏时棋盘转了 90°（屏幕 x 对应 rank、屏幕 y 对应 file），这里一并处理掉，
    /// 所以协议层拿到的坐标永远是棋盘语义坐标，跟屏幕方向无关。
    func cellXAt(px: Float, py: Float) -> Float {
        rotated ? (py - boardTop - boardHeight / 2) / cell : (px - boardLeft - boardWidth / 2) / cell
    }

    func cellYAt(px: Float, py: Float) -> Float {
        rotated ? (px - boardLeft - boardWidth / 2) / cell : (py - boardTop - boardHeight / 2) / cell
    }

    func pxOfCell(cellX: Float, cellY: Float) -> Float {
        rotated ? boardLeft + boardWidth / 2 + cellY * cell : boardLeft + boardWidth / 2 + cellX * cell
    }

    func pyOfCell(cellX: Float, cellY: Float) -> Float {
        rotated ? boardTop + boardHeight / 2 + cellX * cell : boardTop + boardHeight / 2 + cellY * cell
    }

    /// 楚河汉界这条带子的起止（屏幕坐标）。
    var riverStart: Float { rotated ? gridX(4) : gridY(4) }
    var riverEnd: Float { rotated ? gridX(5) : gridY(5) }

    func isInsideBoard(x: Float, y: Float) -> Bool {
        x >= boardLeft && x <= boardLeft + boardWidth &&
            y >= boardTop && y <= boardTop + boardHeight
    }

    /// 手指位置吸附到最近的落点，返回棋盘坐标下标（rank * files + file）。
    /// 不在棋盘内时返回 -1。
    func indexAt(x: Float, y: Float) -> Int {
        guard isInsideBoard(x: x, y: y) else { return -1 }
        let col = (((x - boardLeft) / cell) - 0.5).roundToIntK.coerceIn(0, cols - 1)
        let row = (((y - boardTop) / cell) - 0.5).roundToIntK.coerceIn(0, rows - 1)
        let file = rotated ? row : col
        let rank = rotated ? col : row
        return rank * XiangqiGeometry.files + file
    }

    /// 某个落点是不是在九宫里（file 3..5，rank 0..2 或 7..9）。
    func isInPalace(file: Int, rank: Int) -> Bool {
        (3...5).contains(file) && ((0...2).contains(rank) || (7...9).contains(rank))
    }

    /// 挂双方小牌子的那条空带有多宽。
    var badgeStrip: Float { rotated ? boardLeft : boardTop }

    /// 某一方的牌子挂在棋盘外哪一端（black = 棋盘 rank 0 那一端）。
    func sideAnchorX(black: Bool) -> Float {
        if !rotated { return width / 2 }
        return black ? boardLeft / 2 : width - boardLeft / 2
    }

    func sideAnchorY(black: Bool) -> Float {
        if rotated { return height / 2 }
        return black ? boardTop / 2 : height - boardTop / 2
    }

    /// 牌子上的字要转多少度，才是正对着坐在那一端的玩家（面对面下棋）：
    /// 正常方向时上方那家转 180°；棋盘转了 90° 时，左边那家转 +90°、右边那家转 -90°。
    func sideTextRotation(black: Bool) -> Float {
        if !rotated { return black ? 180 : 0 }
        return black ? 90 : -90
    }

    /// 棋盘上棋子里的字要转多少度：朝着当前该走的那一方。
    /// 竖屏手机就是「红方走 0°，轮到黑方走 180°」。
    func pieceTextRotation(redToMove: Bool) -> Float {
        sideTextRotation(black: !redToMove)
    }
}
