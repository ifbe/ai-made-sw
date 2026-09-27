//
//  StoneBoardView.swift
//  chess
//
//  对照 Android: game/share/stone/StoneBoardView.kt
//
//  围棋 / 五子棋共用的「石头棋盘」页。**只负责画和报手势**，
//  盘面数据、轮次、吃子、落子全在 StoneGame 里。
//
//  布局（design.md §6.1）：页面底色纯黑；棋盘是边长 = min(视图宽, 视图高)、
//  中心 = 屏幕中心的正方形；正方形等分成 (lines + 1) × (lines + 1) 个格子，
//  格子正中心就是横竖线交叉点（落点）；正方形外剩下的两侧余量放黑 / 白棋子托盘。
//
//  绘制层序见 §7.1（棋盘 → 线 → 星位 → 盘上的子 → 悬停圈 → 黑托盘 → 白托盘 → 拖动浮层），
//  线宽 / 字号公式见 §7.2，黄框见 §7.5 / §7.6，拖动浮层见 §7.7，悬停见 §7.8，
//  手势状态机见 §8.1。
//

import SwiftUI
import UIKit

struct StoneBoardView: View {

    @ObservedObject var game: StoneGame

    /// 本地事件的出口：联网时把 WebSocket 的 Session 接到这里。
    let sink: MoveEventSink?

    // MARK: - 视图层手势状态（对照 Kotlin 的 dragging / hoverIndex）

    /// 本机正在拖（只用于决定要不要接后续的 MOVE / UP，跟棋局状态无关）。
    @State private var dragging = false

    /// 手指当前悬停的落点下标，-1 表示不在棋盘内。
    @State private var hoverIndex = -1

    /// 这一串触摸事件本视图是不是已经「接管」了。
    /// Android 里 ACTION_DOWN 返回 false 之后就再也收不到 MOVE / UP；而 SwiftUI 的
    /// DragGesture 一旦开始就会一直回调，所以这里显式记一笔，等价于 Android 的
    /// 「不接管 ⇒ 后续事件全部忽略」。
    @State private var engaged = false

    var body: some View {
        GeometryReader { proxy in
            // 绘制和手势共用同一个几何实例，命中和画面才不会错位。
            let geo = BoardGeometry(
                width: Float(proxy.size.width),
                height: Float(proxy.size.height),
                lines: game.lines
            )
            Canvas { ctx, _ in
                draw(&ctx, geo: geo)
            }
            .background(Theme.pageBackground) // Android: setBackgroundColor(0xFF000000)
            .contentShape(Rectangle())
            // Android 在拿起子 / 托盘时 requestDisallowInterceptTouchEvent(true)，
            // iOS 对应「比父容器优先级更高的手势」。
            .highPriorityGesture(dragGesture(geo: geo))
        }
        .onDisappear {
            // Android 没有对应回调（View 被移除时触摸序列自然断掉）；
            // 这里补一条 cancel，免得拖动浮层留在对端画面上。
            engaged = false
            hoverIndex = -1
            guard dragging else { return }
            dragging = false
            emit(game.onGesture(.cancel))
        }
    }

    // MARK: - 尺寸公式（§7.2；Android 的 dp(v) = v * density，iOS 的逻辑点直接取 v）

    /// 棋盘边框：max(1dp, cell * 0.05)
    private func boardBorderWidth(_ geo: BoardGeometry) -> CGFloat { CGFloat(max(1, geo.cell * 0.05)) }

    /// 横竖线：max(1dp, cell * 0.035)
    private func lineWidth(_ geo: BoardGeometry) -> CGFloat { CGFloat(max(1, geo.cell * 0.035)) }

    /// 棋子环描边：max(1dp, cell * 0.05)
    private func stoneRimWidth(_ geo: BoardGeometry) -> CGFloat { CGFloat(max(1, geo.cell * 0.05)) }

    /// 星位半径：max(2.5dp, cell * 0.11)
    private func starRadius(_ geo: BoardGeometry) -> CGFloat { CGFloat(max(2.5, geo.cell * 0.11)) }

    /// 悬停圈线宽：max(2dp, cell * 0.06)
    private func hoverRingWidth(_ geo: BoardGeometry) -> CGFloat { CGFloat(max(2, geo.cell * 0.06)) }

    /// 托盘数量文字字号：max(15sp, cell * 0.5)（数字要看得清，不跟着棋子一起缩小）。
    private func trayTextSize(_ geo: BoardGeometry) -> CGFloat { CGFloat(max(15, geo.cell * 0.5)) }

    // MARK: - 绘制

    /// 层序（§7.1，从下往上）。和 Kotlin 的 onDraw 一一对应。
    private func draw(_ ctx: inout GraphicsContext, geo: BoardGeometry) {
        drawBoardSurface(&ctx, geo: geo)
        drawGrid(&ctx, geo: geo)
        drawPlacedStones(&ctx, geo: geo)
        drawHover(&ctx, geo: geo)
        drawTray(&ctx, geo: geo, color: StoneGame.black)
        drawTray(&ctx, geo: geo, color: StoneGame.white)
        drawDraggedStone(&ctx, geo: geo)
    }

    /// 鹅黄棋盘方块 + 稍深一点的边框（描边往里收半个线宽，才不会超出正方形）。
    private func drawBoardSurface(_ ctx: inout GraphicsContext, geo: BoardGeometry) {
        let border = boardBorderWidth(geo)
        let rect = CGRect(
            x: CGFloat(geo.boardLeft),
            y: CGFloat(geo.boardTop),
            width: CGFloat(geo.boardSize),
            height: CGFloat(geo.boardSize)
        )
        ctx.fill(Path(rect), with: .color(Theme.stoneBoardFill))
        let inset = border / 2
        ctx.stroke(
            Path(rect.insetBy(dx: inset, dy: inset)),
            with: .color(Theme.stoneBoardStroke),
            lineWidth: border
        )
    }

    /// 横竖各 lines 条线（圆头笔帽，跟 Android 的 Paint.Cap.ROUND 一致），再画盘内的星位。
    private func drawGrid(_ ctx: inout GraphicsContext, geo: BoardGeometry) {
        let last = game.lines - 1
        var path = Path()
        for i in 0..<game.lines {
            let x = CGFloat(geo.gridX(i))
            path.move(to: CGPoint(x: x, y: CGFloat(geo.gridY(0))))
            path.addLine(to: CGPoint(x: x, y: CGFloat(geo.gridY(last))))

            let y = CGFloat(geo.gridY(i))
            path.move(to: CGPoint(x: CGFloat(geo.gridX(0)), y: y))
            path.addLine(to: CGPoint(x: CGFloat(geo.gridX(last)), y: y))
        }
        ctx.stroke(
            path,
            with: .color(Theme.stoneLine),
            style: StrokeStyle(lineWidth: lineWidth(geo), lineCap: .round)
        )

        let radius = starRadius(geo)
        for point in BoardGeometry.starPoints(lines: game.lines) {
            let cx = CGFloat(geo.gridX(point.col))
            let cy = CGFloat(geo.gridY(point.row))
            ctx.fill(
                Path(ellipseIn: CGRect(x: cx - radius, y: cy - radius, width: radius * 2, height: radius * 2)),
                with: .color(Theme.stoneLine) // 星位跟线同色
            )
        }
    }

    /// 已经落在盘上的棋子。正在被拖（本地或对端）的那颗原位不画，画在浮层上。
    private func drawPlacedStones(_ ctx: inout GraphicsContext, geo: BoardGeometry) {
        let draggingFrom = game.drag?.from ?? -1
        let rim = stoneRimWidth(geo)
        for index in game.grid.indices {
            if index == draggingFrom { continue }
            let color = game.grid[index]
            if color == StoneGame.empty { continue }
            drawStone(
                &ctx,
                cx: geo.gridX(index % game.lines),
                cy: geo.gridY(index / game.lines),
                radius: geo.stoneRadius,
                color: color,
                alpha: 1,
                rimWidth: rim
            )
        }
    }

    /// 一颗棋子：实心圆 + 描边圆。描边圆按 Android 的做法取「半径 - 线宽/2」的椭圆。
    private func drawStone(
        _ ctx: inout GraphicsContext,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Int,
        alpha: Double,
        rimWidth: CGFloat
    ) {
        let fill = color == StoneGame.black ? Theme.stoneBlackFill : Theme.stoneWhiteFill
        let rim = color == StoneGame.black ? Theme.stoneBlackStroke : Theme.stoneWhiteStroke
        let r = CGFloat(radius)
        let center = CGPoint(x: CGFloat(cx), y: CGFloat(cy))

        ctx.fill(
            Path(ellipseIn: CGRect(x: center.x - r, y: center.y - r, width: r * 2, height: r * 2)),
            with: .color(fill.opacity(alpha))
        )
        let rimRadius = r - rimWidth / 2
        ctx.stroke(
            Path(ellipseIn: CGRect(
                x: center.x - rimRadius,
                y: center.y - rimRadius,
                width: rimRadius * 2,
                height: rimRadius * 2
            )),
            with: .color(rim.opacity(alpha)),
            lineWidth: rimWidth
        )
    }

    /// 手指悬停在棋盘落点上时的提示圈：
    /// 该自己走、且落点是空的 ⇒ 能落下（墨色）；其余情况松手会弹回（红色）。
    private func drawHover(_ ctx: inout GraphicsContext, geo: BoardGeometry) {
        guard dragging, hoverIndex >= 0, hoverIndex < game.grid.count else { return }
        let canDrop = game.drag.map { overlay in
            overlay.piece.side == game.turn && game.grid[hoverIndex] == StoneGame.empty
        } ?? false

        let radius = CGFloat(geo.stoneRadius * 1.15)
        let cx = CGFloat(geo.gridX(hoverIndex % game.lines))
        let cy = CGFloat(geo.gridY(hoverIndex / game.lines))
        ctx.stroke(
            Path(ellipseIn: CGRect(x: cx - radius, y: cy - radius, width: radius * 2, height: radius * 2)),
            with: .color(canDrop ? Theme.stoneHoverOk : Theme.stoneHoverBad),
            lineWidth: hoverRingWidth(geo)
        )
    }

    /// 一方托盘：棋子圆 + `x{剩余}` 文字 + 当前方的黄框。
    private func drawTray(_ ctx: inout GraphicsContext, geo: BoardGeometry, color: Int) {
        let isActive = StoneGame.sideOf(color) == game.turn
        let text = trayText(geo: geo, color: color)
        let textWidth = ctx.resolve(text)
            .measure(in: CGSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            ))
            .width
        let layout = trayLayout(geo: geo, color: color, textWidth: textWidth)

        // 该走的那一方：用黄色方框把棋子和数量一起圈起来（另一方只是没有黄框，颜色不变暗）。
        if isActive {
            ctx.stroke(Path(layout.bounds), with: .color(Theme.accent), lineWidth: Theme.yellowFrameLineWidth)
        }

        // 托盘里的棋子和棋盘上的棋子同一个半径、同一个颜色，白子也不会发灰。
        drawStone(
            &ctx,
            cx: layout.stoneCx,
            cy: layout.stoneCy,
            radius: geo.pieceRadius,
            color: color,
            alpha: 1,
            rimWidth: stoneRimWidth(geo)
        )
        drawTrayText(&ctx, text: text, layout: layout, geo: geo)
    }

    /// 托盘数量文字。Canvas 的 anchor 是「文字包围盒的哪个点落在 point 上」，
    /// 所以 Android 里按基线画的算式要换成对应的锚点。
    private func drawTrayText(_ ctx: inout GraphicsContext, text: Text, layout: TrayLayout, geo: BoardGeometry) {
        if geo.trayOnSides {
            // 左右余量很窄：圆在空带正中，数量写在圆的正下方并水平居中。
            // 基线 y = 圆心y + radius + gap - ascent ⇒ 换成「上边中点」锚点。
            ctx.draw(
                text,
                at: CGPoint(x: CGFloat(layout.stoneCx), y: CGFloat(layout.textBaseline + layout.ascent)),
                anchor: .top
            )
        } else {
            // 上下余量很宽：数量写在圆的右侧、垂直居中于圆心 ⇒ 「左中」锚点。
            ctx.draw(
                text,
                at: CGPoint(x: CGFloat(layout.textLeft), y: CGFloat(layout.stoneCy)),
                anchor: .leading
            )
        }
    }

    /// 拖动中的那颗子：位置来自 `DragOverlay`，本地和远端的画法完全一样。
    private func drawDraggedStone(_ ctx: inout GraphicsContext, geo: BoardGeometry) {
        guard let overlay = game.drag else { return }
        drawStone(
            &ctx,
            cx: geo.pxOfCell(overlay.cellX),
            cy: geo.pyOfCell(overlay.cellY),
            radius: geo.pieceRadius,
            color: StoneGame.colorOf(overlay.piece.side),
            alpha: 1,
            rimWidth: stoneRimWidth(geo)
        )
    }

    // MARK: - 托盘排版

    /// 一方托盘的排版结果（对照 Kotlin 的 trayBounds + tray* 字段）。
    private struct TrayLayout {
        /// 棋子圆心。
        var stoneCx: Float
        var stoneCy: Float
        /// 数量文字的左端。
        var textLeft: Float
        /// Android 的基线位置，只用来算包围盒；真正绘制换成锚点（见 drawTrayText）。
        var textBaseline: Float
        /// 字体度量：ascent 为负、descent 为正（与 Android 的 Paint.FontMetrics 同号）。
        var ascent: Float
        var descent: Float
        /// 「棋子 + 数量」的包围盒，已经向外扩 radius * 0.4（黄框和托盘命中区都用它）。
        var bounds: CGRect
    }

    /// 算出一方托盘的排版：棋子圆心、数量文字位置，以及把两者都包住的矩形（已留内边距）。
    private func trayLayout(geo: BoardGeometry, color: Int, textWidth: CGFloat) -> TrayLayout {
        let black = color == StoneGame.black
        let radius = geo.pieceRadius
        let gap = radius * 0.45
        let metrics = fontMetrics(trayTextSize(geo))
        let ascent = Float(metrics.ascent)
        let descent = Float(metrics.descent)
        let width = Float(textWidth)

        let stoneCx: Float
        let stoneCy: Float
        let textLeft: Float
        let textBaseline: Float
        if geo.trayOnSides {
            // 左右余量很窄：圆放在空带正中间，数量写在圆的正下方并水平居中。
            stoneCx = geo.trayCenterX(black: black)
            stoneCy = geo.trayCenterY(black: black)
            textLeft = stoneCx - width / 2
            textBaseline = stoneCy + radius + gap - ascent
        } else {
            // 上下余量很宽：数量写在圆的右侧，整组（圆 + 数字）水平居中。
            stoneCy = geo.trayCenterY(black: black)
            let groupWidth = radius * 2 + gap + width
            stoneCx = geo.width / 2 - groupWidth / 2 + radius
            textLeft = stoneCx + radius + gap
            textBaseline = stoneCy - (ascent + descent) / 2
        }

        let left = min(stoneCx - radius, textLeft)
        let top = min(stoneCy - radius, textBaseline + ascent)
        let right = max(stoneCx + radius, textLeft + width)
        let bottom = max(stoneCy + radius, textBaseline + descent)
        // 方框比内容再大一圈。
        let pad = radius * 0.4

        return TrayLayout(
            stoneCx: stoneCx,
            stoneCy: stoneCy,
            textLeft: textLeft,
            textBaseline: textBaseline,
            ascent: ascent,
            descent: descent,
            bounds: CGRect(
                x: CGFloat(left - pad),
                y: CGFloat(top - pad),
                width: CGFloat(right - left + pad * 2),
                height: CGFloat(bottom - top + pad * 2)
            )
        )
    }

    /// 托盘里的数量文字（`x{剩余}`，纯白字写在棋盘外的黑底上）。
    private func trayText(geo: BoardGeometry, color: Int) -> Text {
        Text(Theme.Text.trayCount(game.remainingOf(color: color)))
            .font(.system(size: trayTextSize(geo)))
            .foregroundColor(Theme.stoneCountText)
    }

    /// 字体度量：按 Android `Paint.FontMetrics` 的符号约定返回（ascent 为负、descent 为正）。
    /// iOS 的 UIFont 两个符号正好相反，这里翻一下，后面的算式就能照抄 Kotlin。
    private func fontMetrics(_ size: CGFloat) -> (ascent: CGFloat, descent: CGFloat) {
        let font = UIFont.systemFont(ofSize: size)
        return (ascent: -font.ascender, descent: -font.descender)
    }

    /// 手势里拿不到 Canvas 的 ctx，用同一套系统字体量文字宽度
    /// （和 Canvas 里 `ctx.resolve(...).measure(...)` 的结果一致到亚点）。
    private func measureTextWidth(_ text: String, size: CGFloat) -> CGFloat {
        (text as NSString).size(withAttributes: [.font: UIFont.systemFont(ofSize: size)]).width
    }

    /// 托盘的可点区域：就是那个「棋子 + 数字」的方框再往外放 12pt，
    /// 所以手指按在黄框里任意位置都能开始拖。
    private func hitTray(geo: BoardGeometry, color: Int, x: Float, y: Float) -> Bool {
        let label = Theme.Text.trayCount(game.remainingOf(color: color))
        let layout = trayLayout(
            geo: geo,
            color: color,
            textWidth: measureTextWidth(label, size: trayTextSize(geo))
        )
        let slop: Float = 12 // Android: dp(12f)
        return x >= Float(layout.bounds.minX) - slop && x <= Float(layout.bounds.maxX) + slop
            && y >= Float(layout.bounds.minY) - slop && y <= Float(layout.bounds.maxY) + slop
    }

    // MARK: - 手势（§8.1，和 Kotlin 的 onTouchEvent 一一对应）

    // 注意：`Gesture` 这个名字被 Game/Core/Game.swift 里的本地手势枚举占了，这里要写全 `SwiftUI.Gesture`。
    private func dragGesture(geo: BoardGeometry) -> some SwiftUI.Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { value in
                let x = Float(value.location.x)
                let y = Float(value.location.y)

                // 第一次 onChanged 当作 ACTION_DOWN。
                if !engaged {
                    engaged = true
                    touchDown(geo: geo, x: x, y: y)
                    return
                }

                // 没接管的这一串手势：后续事件全部忽略（等价 Android 收不到 MOVE / UP）。
                guard dragging else { return }
                hoverIndex = geo.indexAt(x: x, y: y) // 只影响提示圈
                emit(game.onGesture(.dragTo(cellX: geo.cellXAt(px: x), cellY: geo.cellYAt(py: y))))
            }
            .onEnded { value in
                engaged = false
                guard dragging else { return }
                let x = Float(value.location.x)
                let y = Float(value.location.y)
                emit(game.onGesture(.drop(
                    cellX: geo.cellXAt(px: x),
                    cellY: geo.cellYAt(py: y),
                    targetIndex: geo.indexAt(x: x, y: y) // 盘外自然是 -1
                )))
                dragging = false
                hoverIndex = -1
            }
    }

    /// ACTION_DOWN：先看按没按在盘上的棋子上，再看按没按在该走那一方的托盘上，都不是就不接管。
    private func touchDown(geo: BoardGeometry, x: Float, y: Float) {
        // 盘上的子谁都能拿起来（不看轮次）。
        let index = geo.indexAt(x: x, y: y)
        if index >= 0 && game.hasPieceAt(index) {
            dragging = true
            hoverIndex = index
            emit(game.onGesture(.pickUp(index: index)))
            return
        }

        // 否则看是不是按在该走的那一方的托盘上。
        let side = game.turn
        guard game.remaining(side: side) > 0 else { return }
        let color = StoneGame.colorOf(side)
        guard hitTray(geo: geo, color: color, x: x, y: y) else { return }

        dragging = true
        hoverIndex = -1
        // 托盘中心换算成棋盘语义坐标（在棋盘外，对端照样看得见）。
        let layout = trayLayout(
            geo: geo,
            color: color,
            textWidth: measureTextWidth(
                Theme.Text.trayCount(game.remainingOf(color: color)),
                size: trayTextSize(geo)
            )
        )
        emit(game.onGesture(.pickUpNew(
            side: side,
            cellX: geo.cellXAt(px: layout.stoneCx),
            cellY: geo.cellYAt(py: layout.stoneCy)
        )))
    }

    /// 本地事件的出口：本地状态已经更新，这里只负责广播。
    private func emit(_ events: [MoveEvent]) {
        guard !events.isEmpty else { return }
        sink?(events)
    }
}
