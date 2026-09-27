//
//  XiangqiBoardView.swift
//  chess
//
//  对照 Android: game/xiangqi/XiangqiBoardView.kt
//
//  象棋页。**只负责画和报手势**，盘面数据、轮次、吃子、落子全在 `XiangqiGame` 里。
//
//  布局规则见 `XiangqiGeometry`：9 路 × 10 路，短边 9 路 / 长边 10 路，棋盘居中，
//  落点在各自格子的正中心；中间留出楚河汉界，两端画出九宫斜线。
//
//  Android 是 `View.onDraw` + `Paint`，这里是 `Canvas` + `GraphicsContext`：
//  坐标公式、层序（§7.1）、线宽 / 半径 / 字号公式（§7.2、§7.3）与 Kotlin **逐行对应**，
//  `dp` / `pt` 数值相同（§7.2 的换算说明）。
//

import SwiftUI

struct XiangqiBoardView: View {

    // ------------------------------------------------------------------ 输入

    /// 盘面数据 + 逻辑。
    @ObservedObject var game: XiangqiGame

    /// 本地事件的出口：联网时把 WebSocket 的 Session 接到这里。
    let sink: MoveEventSink?

    // ------------------------------------------------------------------ 常量

    private static let files = XiangqiGame.files
    private static let ranks = XiangqiGame.ranks

    private static let empty = XiangqiGame.empty
    private static let red = XiangqiGame.red
    private static let black = XiangqiGame.black

    /// 楚河汉界：两半带子里的字和它们的位置（0..1）。
    private static let riverTexts: [String] = [Theme.Text.riverRed, Theme.Text.riverBlack]
    private static let riverPositions: [Float] = [0.25, 0.75]

    /// 牌子 / 提示画在棋盘外的黑底上，用浅色字。
    /// 来源：Kotlin `indicatorTextPaint.color = 0xFFFFFFFF`（Theme 里没有对应常量，故局部定义）。
    private static let indicatorText = Color(argb: 0xFFFFFFFF)

    // ------------------------------------------------------------------ 手势状态

    /// 本机正在拖（只用于决定要不要接后续的 onChanged / onEnded）。
    @State private var dragging = false

    /// 手指悬停的落点下标，-1 表示不在棋盘内。
    @State private var hoverIndex = -1

    /// 本次手势有没有处理过「按下」。
    /// `DragGesture` 没有独立的 touchDown / cancel，所以第一次 `onChanged` 当按下：
    /// 没点到子就整段手势都不接管（象棋没有托盘）。
    @State private var touchDown = false

    // ------------------------------------------------------------------ 视图

    var body: some View {
        GeometryReader { proxy in
            // 几何只建一次，Canvas 和手势用同一个实例（对应 Android 的 `geo` 成员）。
            let geo = XiangqiGeometry(width: Float(proxy.size.width), height: Float(proxy.size.height))
            Canvas { ctx, _ in
                draw(ctx, geo: geo)
            }
            .contentShape(Rectangle())
            .gesture(dragGesture(geo: geo))
            .onDisappear {
                // 视图消失 = Android 的 ACTION_CANCEL：还在拖就补一条取消，浮层不会留在盘上。
                guard dragging else { return }
                dragging = false
                hoverIndex = -1
                touchDown = false
                emit(game.onGesture(.cancel))
            }
        }
    }

    /// 本地事件出口：和 Android 的 `emit` 一样，空列表不打扰 sink。
    private func emit(_ events: [MoveEvent]) {
        guard !events.isEmpty else { return }
        sink?(events)
    }

    // ------------------------------------------------------------------ 尺寸

    // Android 在 `onSizeChanged` 里把这些值一次算好写进 Paint；这里按同一批公式现算。
    // `dp(v)` = v pt、`sp(v)` = v pt（本 App 的棋盘不跟随系统字号）。

    /// 棋盘线 / 九宫：`max(dp(1f), cell * 0.03)`。
    private func lineWidth(geo: XiangqiGeometry) -> CGFloat { CGFloat(max(1, geo.cell * 0.03)) }

    /// 棋子环：`max(dp(2f), cell * 0.045)`。
    private func ringWidth(geo: XiangqiGeometry) -> CGFloat { CGFloat(max(2, geo.cell * 0.045)) }

    /// 悬停圈：`max(dp(2f), cell * 0.06)`。
    private func hoverWidth(geo: XiangqiGeometry) -> CGFloat { CGFloat(max(2, geo.cell * 0.06)) }

    /// 河界文字：`cell * 0.42`。
    private func riverFontSize(geo: XiangqiGeometry) -> CGFloat { CGFloat(geo.cell * 0.42) }

    /// 牌子文字：`max(sp(16f), cell * 0.42)`。
    private func indicatorFontSize(geo: XiangqiGeometry) -> CGFloat { CGFloat(max(16, geo.cell * 0.42)) }

    /// 棋子半径：`cell * 0.42`。
    private func pieceRadius(geo: XiangqiGeometry) -> CGFloat { CGFloat(geo.cell * 0.42) }

    /// 黄框线宽：`dp(2f)`。
    private func activeBoxWidth() -> CGFloat { Theme.yellowFrameLineWidth }

    // ------------------------------------------------------------------ 绘制

    /// 层序与 Android `onDraw` 完全一致（§7.1）：底 → 线 → 九宫 → 河界 → 棋子 → 悬停 → 牌子 → 拖动的子。
    private func draw(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        fillBoard(ctx, geo: geo)
        drawGrid(ctx, geo: geo)
        drawPalaces(ctx, geo: geo)
        drawRiverText(ctx, geo: geo)
        drawPieces(ctx, geo: geo)
        drawHover(ctx, geo: geo)
        drawSideBadge(ctx, geo: geo, black: true)
        drawSideBadge(ctx, geo: geo, black: false)
        drawDraggedPiece(ctx, geo: geo)
    }

    /// 鹅黄棋盘方块。
    ///
    /// Kotlin 里的 `boardBorderPaint`（`#E0C67E`）声明了但**从来没画过**（后面用外框矩形代替了），
    /// 以 Kotlin 为准，这里同样不描边；`Theme.xiangqiBoardStroke` 留作其他棋种 / 以后用。
    private func fillBoard(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        let rect = CGRect(
            x: CGFloat(geo.boardLeft),
            y: CGFloat(geo.boardTop),
            width: CGFloat(geo.boardWidth),
            height: CGFloat(geo.boardHeight)
        )
        ctx.fill(Path(rect), with: .color(Theme.xiangqiBoardFill))
    }

    /// 外框一整圈 + 里面的横竖线；楚河汉界处竖线断开（`rotated` 时换成横线断开）。
    private func drawGrid(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        let left = CGFloat(geo.gridX(0))
        let right = CGFloat(geo.gridX(geo.cols - 1))
        let top = CGFloat(geo.gridY(0))
        let bottom = CGFloat(geo.gridY(geo.rows - 1))
        let style = StrokeStyle(lineWidth: lineWidth(geo: geo))
        let shading = GraphicsContext.Shading.color(Theme.xiangqiLine)

        // 外框是完整的一圈，楚河汉界只打断里面的线。
        ctx.stroke(
            Path(CGRect(x: left, y: top, width: right - left, height: bottom - top)),
            with: shading,
            style: style
        )

        for col in 1..<(geo.cols - 1) {
            let x = CGFloat(geo.gridX(col))
            var path = Path()
            if geo.rotated {
                path.move(to: CGPoint(x: x, y: top))
                path.addLine(to: CGPoint(x: x, y: bottom))
            } else {
                // 竖向的线在楚河汉界处断开
                path.move(to: CGPoint(x: x, y: top))
                path.addLine(to: CGPoint(x: x, y: CGFloat(geo.riverStart)))
                path.move(to: CGPoint(x: x, y: CGFloat(geo.riverEnd)))
                path.addLine(to: CGPoint(x: x, y: bottom))
            }
            ctx.stroke(path, with: shading, style: style)
        }

        for row in 1..<(geo.rows - 1) {
            let y = CGFloat(geo.gridY(row))
            var path = Path()
            if geo.rotated {
                // 棋盘转了 90° 时，断开的换成横向的线
                path.move(to: CGPoint(x: left, y: y))
                path.addLine(to: CGPoint(x: CGFloat(geo.riverStart), y: y))
                path.move(to: CGPoint(x: CGFloat(geo.riverEnd), y: y))
                path.addLine(to: CGPoint(x: right, y: y))
            } else {
                path.move(to: CGPoint(x: left, y: y))
                path.addLine(to: CGPoint(x: right, y: y))
            }
            ctx.stroke(path, with: shading, style: style)
        }
    }

    /// 两端的九宫斜线（file 3..5，rank 0..2 和 7..9）。
    private func drawPalaces(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        let style = StrokeStyle(lineWidth: lineWidth(geo: geo))
        let shading = GraphicsContext.Shading.color(Theme.xiangqiLine)

        for baseRank in [0, 7] {
            var path = Path()
            path.move(to: CGPoint(
                x: CGFloat(geo.pieceX(file: 3, rank: baseRank)),
                y: CGFloat(geo.pieceY(file: 3, rank: baseRank))
            ))
            path.addLine(to: CGPoint(
                x: CGFloat(geo.pieceX(file: 5, rank: baseRank + 2)),
                y: CGFloat(geo.pieceY(file: 5, rank: baseRank + 2))
            ))
            path.move(to: CGPoint(
                x: CGFloat(geo.pieceX(file: 5, rank: baseRank)),
                y: CGFloat(geo.pieceY(file: 5, rank: baseRank))
            ))
            path.addLine(to: CGPoint(
                x: CGFloat(geo.pieceX(file: 3, rank: baseRank + 2)),
                y: CGFloat(geo.pieceY(file: 3, rank: baseRank + 2))
            ))
            ctx.stroke(path, with: shading, style: style)
        }
    }

    /// 楚河汉界四个字，跟着棋盘方向走。
    ///
    /// Android 是按 baseline 画（`y = 带子中点 + offset`），这里换成 Canvas 的 `.center`：
    /// 文字包围盒正中落在带子中点上 —— 与 `offset = -(ascent + descent)/2` 的算式等价。
    private func drawRiverText(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        let start = geo.riverStart
        let end = geo.riverEnd
        let size = riverFontSize(geo: geo)

        for i in Self.riverTexts.indices {
            if geo.rotated {
                // 河界是竖着的一条带子，字也跟着转 90°。
                //
                // 有意偏离：Kotlin 这一支把给 baseline 用的 `offset` 又加到了 x 上（`x = 中点 + offset`），
                // 转完等于再沿带子法向偏了约 `2 * offset`（≈ 0.3 格）；这里按「字心落在带子中线上」画，
                // 与不旋转的那一支、以及 §7.5 的意图一致。
                let centerX = CGFloat((start + end) / 2)
                let centerY = CGFloat(geo.boardTop + geo.boardHeight * Self.riverPositions[i])
                drawText(
                    ctx, Self.riverTexts[i],
                    at: CGPoint(x: centerX, y: centerY),
                    anchor: .center, size: size, color: Theme.xiangqiRiverText, degrees: 90
                )
            } else {
                let centerX = CGFloat(geo.boardLeft + geo.boardWidth * Self.riverPositions[i])
                let centerY = CGFloat((start + end) / 2)
                drawText(
                    ctx, Self.riverTexts[i],
                    at: CGPoint(x: centerX, y: centerY),
                    anchor: .center, size: size, color: Theme.xiangqiRiverText
                )
            }
        }
    }

    /// 整盘棋子（**跳过正在被拖的那一颗的原位**，§7.7）。
    private func drawPieces(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        let radius = pieceRadius(geo: geo)
        // 轮到谁走，整盘棋子的字就朝着谁（竖屏时就是 0° / 180°）。
        let textRotation = geo.pieceTextRotation(redToMove: game.redToMove)
        let draggingFrom = game.drag?.from ?? -1

        for rank in 0..<Self.ranks {
            for file in 0..<Self.files {
                let index = rank * Self.files + file
                if index == draggingFrom { continue }
                let color = game.colors[index]
                if color == Self.empty { continue }
                guard let piece = game.pieces[index] else { continue }
                drawPiece(
                    ctx,
                    cx: CGFloat(geo.pieceX(file: file, rank: rank)),
                    cy: CGFloat(geo.pieceY(file: file, rank: rank)),
                    radius: radius,
                    ring: ringWidth(geo: geo),
                    color: color,
                    label: piece.nameOf(color: color),
                    alpha: 1,
                    textRotation: textRotation
                )
            }
        }
    }

    /// 一枚棋子：面 + 环 + 字。
    ///
    /// Kotlin 的 `drawPiece` 从预先设好的 Paint 上取线宽，这里多带一个 `ring` 参数
    /// （牌子里的棋子半径会被 `strip * 0.38` 压小，但环的线宽仍然按 `cell` 算，所以不能从半径反推）。
    private func drawPiece(
        _ ctx: GraphicsContext,
        cx: CGFloat,
        cy: CGFloat,
        radius: CGFloat,
        ring: CGFloat,
        color: Int,
        label: Character,
        alpha: Double,
        textRotation: Float = 0
    ) {
        let ringColor = color == Self.red ? Theme.xiangqiRed : Theme.xiangqiBlack
        let face = Theme.xiangqiPieceFill.opacity(alpha)
        let stroke = ringColor.opacity(alpha)

        // 面：整圆填充。
        ctx.fill(Path(ellipseIn: circleRect(cx: cx, cy: cy, radius: radius)), with: .color(face))

        // 环：Android 是 `drawCircle(radius - strokeWidth / 2)` + STROKE（描边压着半径两侧），
        // 所以这里同样把半径收进半个线宽再居中描边（不用 strokeBorder）。
        ctx.stroke(
            Path(ellipseIn: circleRect(cx: cx, cy: cy, radius: radius - ring / 2)),
            with: .color(stroke),
            lineWidth: ring
        )

        // 字：字号 = radius * 1.1，绕棋子中心转，所以转完还是正好居中在棋子上。
        drawText(
            ctx, String(label),
            at: CGPoint(x: cx, y: cy),
            anchor: .center, size: radius * 1.1, color: stroke, degrees: textRotation
        )
    }

    /// 悬停提示圈：拖动中才有；能落下是深墨色、放不下是红色（§7.8）。
    private func drawHover(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        if !dragging || hoverIndex < 0 { return }
        guard hoverIndex < game.colors.count else { return }

        // 该自己走、且落点不是自己的子（空格或对方子）⇒ 能落下；其余情况（包括没有浮层）松手会弹回。
        let canDrop: Bool
        if let overlay = game.drag {
            canDrop = overlay.piece.side == game.turn
                && game.colors[hoverIndex] != XiangqiGame.colorOf(overlay.piece.side)
        } else {
            canDrop = false
        }

        let file = hoverIndex % Self.files
        let rank = hoverIndex / Self.files
        let rect = circleRect(
            cx: CGFloat(geo.pieceX(file: file, rank: rank)),
            cy: CGFloat(geo.pieceY(file: file, rank: rank)),
            radius: pieceRadius(geo: geo) * 1.12
        )
        ctx.stroke(
            Path(ellipseIn: rect),
            with: .color(canDrop ? Theme.xiangqiHoverOk : Theme.xiangqiHoverBad),
            lineWidth: hoverWidth(geo: geo)
        )
    }

    /// 棋盘外空出来的那一端挂一方的小牌子：一枚棋子 + 这一方的名字。
    ///
    /// 轮到谁走，谁的牌子就被黄色方框圈住；牌子上的字朝着坐在那一端的玩家转 ——
    /// 整个牌子（黄框 + 棋子 + 文字）作为一个整体绕 anchor 旋转。
    private func drawSideBadge(_ ctx: GraphicsContext, geo: XiangqiGeometry, black: Bool) {
        let strip = geo.badgeStrip
        if strip <= 0 { return }

        let isActive = game.turn == (black ? 1 : 0)
        let radius = min(CGFloat(geo.cell * 0.42), CGFloat(strip * 0.38))
        let label = black ? Theme.Text.sideBlack : Theme.Text.sideRed
        let gap = radius * 0.5
        let size = indicatorFontSize(geo: geo)
        let textWidth = textWidth(ctx, label, size: size)
        let groupWidth = radius * 2 + gap + textWidth

        let anchorX = CGFloat(geo.sideAnchorX(black: black))
        let anchorY = CGFloat(geo.sideAnchorY(black: black))

        // 绕 anchor 转，层里之后所有坐标都是「相对 anchor」的。
        ctx.drawLayer { layer in
            layer.translateBy(x: anchorX, y: anchorY)
            layer.rotate(by: .degrees(Double(geo.sideTextRotation(black: black))))

            let left = -groupWidth / 2
            let pieceCx = left + radius

            // 黄框（只有当前该走的一方有）：包围盒向外扩 radius * 0.45，线宽 2dp，色 #E6B24C。
            if isActive {
                let box = CGRect(x: left, y: -radius, width: groupWidth, height: radius * 2)
                    .insetBy(dx: -radius * 0.45, dy: -radius * 0.45)
                layer.stroke(Path(box), with: .color(Theme.accent), lineWidth: activeBoxWidth())
            }

            drawPiece(
                layer,
                cx: pieceCx,
                cy: 0,
                radius: radius,
                ring: ringWidth(geo: geo),
                color: black ? Self.black : Self.red,
                label: black ? XiangqiPiece.king.blackName : XiangqiPiece.king.redName,
                alpha: 1
            )

            // 文字在圆的右侧、垂直居中于 anchor，左对齐（Kotlin 的 `Paint.Align.LEFT`）。
            drawText(
                layer, label,
                at: CGPoint(x: pieceCx + radius + gap, y: 0),
                anchor: .leading, size: size, color: Self.indicatorText
            )
        }
    }

    /// 拖动浮层：本地拖和对端拖画法完全一样（§7.7），位置来自语义坐标 `cellX / cellY`。
    private func drawDraggedPiece(_ ctx: GraphicsContext, geo: XiangqiGeometry) {
        guard let overlay = game.drag else { return }
        guard let label = overlay.piece.name.first else { return }
        drawPiece(
            ctx,
            cx: CGFloat(geo.pxOfCell(cellX: overlay.cellX, cellY: overlay.cellY)),
            cy: CGFloat(geo.pyOfCell(cellX: overlay.cellX, cellY: overlay.cellY)),
            radius: pieceRadius(geo: geo),
            ring: ringWidth(geo: geo),
            color: XiangqiGame.colorOf(overlay.piece.side),
            label: label,
            alpha: 1,
            textRotation: geo.pieceTextRotation(redToMove: game.redToMove)
        )
    }

    // ------------------------------------------------------------------ 文字助手

    /// 画一行字。
    ///
    /// Android 是「baseline + textAlign」，这里用 Canvas 的 anchor 等价替换：
    /// `.center` = 包围盒正中、`.leading` = 左中（对应 `Paint.Align.LEFT` + 垂直居中）。
    /// `degrees != 0` 时绕**文字中心**旋转（等价于 `canvas.rotate(deg, cx, cy)` 后再居中画）。
    ///
    /// 颜色走 `resolve` + `shading`：`Text.foregroundColor` 从 iOS 17 起被弃用（会有 warning），
    /// 而 `Text.foregroundStyle` 要 iOS 17+，本工程 target 是 16.6，所以用 iOS 15 就有的 shading。
    private func drawText(
        _ ctx: GraphicsContext,
        _ string: String,
        at point: CGPoint,
        anchor: UnitPoint,
        size: CGFloat,
        color: Color,
        degrees: Float = 0
    ) {
        var text = ctx.resolve(Text(verbatim: string).font(.system(size: size)))
        text.shading = .color(color)

        if degrees == 0 {
            ctx.draw(text, at: point, anchor: anchor)
            return
        }
        ctx.drawLayer { layer in
            layer.translateBy(x: point.x, y: point.y)
            layer.rotate(by: .degrees(Double(degrees)))
            layer.draw(text, at: .zero, anchor: anchor)
        }
    }

    /// 量一行字的宽度（等价于 Android 的 `Paint.measureText`）。
    private func textWidth(_ ctx: GraphicsContext, _ string: String, size: CGFloat) -> CGFloat {
        ctx.resolve(Text(verbatim: string).font(.system(size: size)))
            .measure(in: CGSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            ))
            .width
    }

    /// 以 (cx, cy) 为圆心、radius 为半径的圆的外接矩形。
    private func circleRect(cx: CGFloat, cy: CGFloat, radius: CGFloat) -> CGRect {
        CGRect(x: cx - radius, y: cy - radius, width: radius * 2, height: radius * 2)
    }

    // ------------------------------------------------------------------ 触摸

    /// 对应 Android 的 `onTouchEvent`：`DragGesture(minimumDistance: 0)` 的第一次 `onChanged` 当按下。
    ///
    /// 注意 `Gesture` 这个名字在本工程里已经被 `Game.swift` 的手势枚举占了，
    /// 所以返回类型要写全 `SwiftUI.Gesture`。
    private func dragGesture(geo: XiangqiGeometry) -> some SwiftUI.Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { value in
                handleChanged(at: value.location, geo: geo)
            }
            .onEnded { value in
                handleEnded(at: value.location, geo: geo)
            }
    }

    /// touchDown + touchMove。
    private func handleChanged(at point: CGPoint, geo: XiangqiGeometry) {
        let px = Float(point.x)
        let py = Float(point.y)

        if !touchDown {
            // 按下：点到子才接管这段手势，点到空处整段忽略（象棋没有托盘）。
            touchDown = true
            let index = geo.indexAt(x: px, y: py)
            guard index >= 0, game.hasPieceAt(index) else {
                dragging = false
                hoverIndex = -1
                return
            }
            dragging = true
            hoverIndex = index
            emit(game.onGesture(.pickUp(index: index)))
            return
        }

        guard dragging else { return }
        // 悬停下标只影响提示圈。
        hoverIndex = geo.indexAt(x: px, y: py)
        emit(game.onGesture(.dragTo(cellX: geo.cellXAt(px: px, py: py), cellY: geo.cellYAt(px: px, py: py))))
    }

    /// touchUp：落点由几何吸附，盘外自然是 -1。
    private func handleEnded(at point: CGPoint, geo: XiangqiGeometry) {
        let wasDragging = dragging
        dragging = false
        hoverIndex = -1
        touchDown = false
        guard wasDragging else { return }

        let px = Float(point.x)
        let py = Float(point.y)
        emit(game.onGesture(.drop(
            cellX: geo.cellXAt(px: px, py: py),
            cellY: geo.cellYAt(px: px, py: py),
            targetIndex: geo.indexAt(x: px, y: py)
        )))
    }
}
