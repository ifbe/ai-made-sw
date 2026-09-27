//
//  IntlChessBoardView.swift
//  chess
//
//  对照 Android: game/guojixiangqi/IntlChessBoardView.kt
//
//  国际象棋页。**只负责画和报手势**，盘面数据、轮次、吃子、落子全在 `IntlChessGame` 里。
//
//  棋盘：min(w,h) 的正方形居中，8 × 8 个方格，标准棋盘配色（浅格 #F0D9B5 / 深格 #B58863），
//  白方在下、黑方在上（横屏时整块转 90°，黑方在左、白方在右）。
//
//  Android 的 `onDraw` 各段一一对应到下面 `draw*` 的私有方法，层序见 design.md §7.1：
//  8×8 方格 → 棋盘外框 → 棋子（跳过被拖的那颗）→ 悬停高亮 → 两端牌子 → 拖动浮层。
//

import SwiftUI

struct IntlChessBoardView: View {

    /// 盘面数据 + 逻辑（对应 Android 的 `private val game = IntlChessGame()`；
    /// 这边由外部持有，网络收到的事件灌到同一个实例上）。
    @ObservedObject var game: IntlChessGame

    /// 本地事件的出口：联网时把 WebSocket 的 Session 接到这里（对应 Android 的 `eventSink`）。
    let sink: MoveEventSink?

    // MARK: - 手势状态（对应 Android 的 dragging / hoverIndex）

    /// 本机正在拖（只用于决定要不要接后续的 MOVE/UP）。
    @State private var dragging = false

    /// 手指悬停的格子下标，-1 表示不在棋盘内。
    @State private var hoverIndex = -1

    // MARK: - 尺寸

    /// 字号按系统「文字大小」缩放，对应 Android 的 `sp`（`TypedValue.COMPLEX_UNIT_SP`）。
    /// Android 的 `dp` 就是逻辑点，iOS 的 pt 直接对应，所以 `dp(2f)` = 2pt。
    @ScaledMetric(relativeTo: .body) private var spUnit: CGFloat = 1

    /// `sp(value)`：把数值按系统字号缩放换成 pt，再加到 `max(...)` 的下限上。
    private func sp(_ value: CGFloat) -> CGFloat { value * spUnit }

    // MARK: - body

    var body: some View {
        GeometryReader { proxy in
            // 几何用同一个实例算，手势里也用这一个（对应 Android 的 onSizeChanged 里建 geo）。
            let geo = IntlChessGeometry(width: Float(proxy.size.width), height: Float(proxy.size.height))
            let painter = Painter(
                geo: geo,
                labelFontSize: max(sp(16), CGFloat(geo.cell) * 0.42)
            )

            Canvas { ctx, _ in
                draw(ctx, painter: painter)
            }
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0.0)
                    .onChanged { value in handleDragChanged(value, painter: painter) }
                    .onEnded { value in handleDragEnded(value, painter: painter) }
            )
        }
        .onDisappear {
            // 视图消失时如果还在拖，补一条 cancel（Android 的 ACTION_CANCEL）。
            guard dragging else { return }
            dragging = false
            hoverIndex = -1
            emit(game.onGesture(.cancel))
        }
    }

    // MARK: - 绘制（对应 Android 的 onDraw）

    private func draw(_ ctx: GraphicsContext, painter: Painter) {
        drawSquares(ctx, painter: painter)
        drawPieces(ctx, painter: painter)
        drawHover(ctx, painter: painter)
        drawSideBadge(ctx, painter: painter, black: true)
        drawSideBadge(ctx, painter: painter, black: false)
        drawDraggedPiece(ctx, painter: painter)
    }

    /// 8 × 8 方格 + 棋盘外框描边（对应 drawSquares）。
    private func drawSquares(_ ctx: GraphicsContext, painter: Painter) {
        let g = painter.geo
        for rank in 0..<IntlChessGeometry.ranks {
            for file in 0..<IntlChessGeometry.files {
                let rect = painter.squareRect(file: file, rank: rank)
                let fill = g.isDarkSquare(file: file, rank: rank) ? Theme.intlDarkSquare : Theme.intlLightSquare
                ctx.fill(Path(rect), with: .color(fill))
            }
        }

        // 边框往内缩半个线宽画（对应 Android 的 `inset = strokeWidth / 2f`）。
        let inset = painter.boardBorderWidth / 2
        ctx.stroke(
            Path(painter.boardRect.insetBy(dx: inset, dy: inset)),
            with: .color(Theme.intlBoardBorder),
            lineWidth: painter.boardBorderWidth
        )
    }

    /// 盘上的棋子：**跳过正在被拖的那一颗的原位**（对应 drawPieces）。
    private func drawPieces(_ ctx: GraphicsContext, painter: Painter) {
        let g = painter.geo
        let rotation = g.pieceTextRotation(whiteToMove: game.whiteToMove)
        let size = painter.glyphSize
        let draggingFrom = game.drag?.from ?? -1

        for index in game.colors.indices {
            if index == draggingFrom { continue }
            let color = game.colors[index]
            if color == IntlChessGame.empty { continue }
            guard let piece = game.types[index] else { continue }
            let file = index % IntlChessGeometry.files
            let rank = index / IntlChessGeometry.files
            drawGlyph(
                ctx, painter: painter,
                cx: CGFloat(g.squareX(file: file, rank: rank)),
                cy: CGFloat(g.squareY(file: file, rank: rank)),
                size: size,
                color: color,
                code: piece.code,
                rotation: rotation
            )
        }
    }

    /// 画一枚棋子：先描边再填色，两种底色上都清楚（对应 drawGlyph）。
    ///
    /// iOS 16 的 `Text` 没有描边 API（`Text.strokeWidth` 要 iOS 17），所以描边用
    /// 「描边色画 8 个平移副本、填充色再压正中」等价替换。
    private func drawGlyph(
        _ ctx: GraphicsContext,
        painter: Painter,
        cx: CGFloat,
        cy: CGFloat,
        size: CGFloat,
        color: Int,
        code: Character,
        rotation: Float
    ) {
        guard let piece = IntlChessPiece.of(code) else { return }

        let isWhite = color == IntlChessGame.white
        let fillColor = isWhite ? Theme.intlWhiteGlyph : Theme.intlBlackGlyph
        let strokeColor = isWhite ? Theme.intlWhiteGlyphStroke : Theme.intlBlackGlyphStroke
        let strokeWidth = isWhite ? painter.whiteStrokeWidth : painter.blackStrokeWidth
        let glyph = painter.text(piece.glyph, size: size)

        if rotation != 0 {
            // Android 是 canvas.rotate(rotation, cx, cy) 后再 drawText；
            // 这里绕 (cx, cy) 转一层，整块（描边 + 填充）一起转，等价。
            ctx.drawLayer { layer in
                layer.translateBy(x: cx, y: cy)
                layer.rotate(by: .degrees(Double(rotation)))
                paintGlyph(layer, glyph: glyph, fill: fillColor, stroke: strokeColor,
                           strokeWidth: strokeWidth)
            }
        } else {
            paintGlyph(ctx, glyph: glyph, fill: fillColor, stroke: strokeColor,
                       strokeWidth: strokeWidth, offsetX: cx, offsetY: cy)
        }
    }

    /// 把「描边 + 填充」两遍画在中心点上（旋转时中心点是层的原点）。
    private func paintGlyph(
        _ ctx: GraphicsContext,
        glyph: Text,
        fill: Color,
        stroke: Color,
        strokeWidth: CGFloat,
        offsetX: CGFloat = 0,
        offsetY: CGFloat = 0
    ) {
        // 先描边：8 个方向各画一遍描边色的字，偏移量 = 线宽的一半，
        // 合起来正好把字形轮廓向外撑一个线宽。
        let r = strokeWidth / 2
        for dx in [-r, 0, r] {
            for dy in [-r, 0, r] where !(dx == 0 && dy == 0) {
                ctx.draw(
                    glyph.foregroundColor(stroke),
                    at: CGPoint(x: offsetX + dx, y: offsetY + dy),
                    anchor: .center
                )
            }
        }
        // 再填充，压住描边的内侧（Android 也是最后画 FILL 那遍）。
        ctx.draw(glyph.foregroundColor(fill), at: CGPoint(x: offsetX, y: offsetY), anchor: .center)
    }

    /// 悬停高亮整格（对应 drawHover）。
    private func drawHover(_ ctx: GraphicsContext, painter: Painter) {
        guard dragging, hoverIndex >= 0 else { return }
        let file = hoverIndex % IntlChessGeometry.files
        let rank = hoverIndex / IntlChessGeometry.files
        let rect = painter.squareRect(file: file, rank: rank)

        // 该自己走、且落点不是自己的子（空格或对方子）⇒ 能落下；其余情况松手会弹回。
        let overlay = game.drag
        let canDrop = overlay != nil &&
            overlay?.piece.side == game.turn &&
            game.colors[hoverIndex] != IntlChessGame.colorOf(game.turn)
        ctx.fill(Path(rect), with: .color(canDrop ? Theme.intlHoverOk : Theme.intlHoverBad))
    }

    /// 棋盘外空出来的那一端挂一方的小牌子：一枚王 + 这一方的名字
    /// （对应 drawSideBadge）。轮到谁走，谁的牌子就被黄色方框圈住；
    /// 牌子上的字朝着坐在那一端的玩家转。
    private func drawSideBadge(_ ctx: GraphicsContext, painter: Painter, black: Bool) {
        let g = painter.geo
        let strip = CGFloat(g.badgeStrip) // CGFloat(Float) 不会失败，故无 `?: return` 分支
        if strip <= 0 { return }

        let isActive = (IntlChessGame.colorOf(game.turn) == IntlChessGame.black) == black
        let radius = min(CGFloat(g.cell) * 0.42, strip * 0.38)
        let label = black ? Theme.Text.sideBlack : Theme.Text.sideWhite
        let gap = radius * 0.5
        let groupWidth = radius * 2 + gap + textWidth(ctx, painter.label(label, size: painter.labelFontSize))

        let anchorX = CGFloat(g.sideAnchorX(black: black))
        let anchorY = CGFloat(g.sideAnchorY(black: black))
        let rotation = g.sideTextRotation(black: black)

        // 整个牌子作为一个整体绕 anchor 旋转（和 Android 一样）。
        var badge = ctx
        badge.translateBy(x: anchorX, y: anchorY)
        badge.rotate(by: .degrees(Double(rotation)))
        // 之后都在「以 anchor 为原点」的局部坐标里画：左端 = -groupWidth / 2。
        let left = -groupWidth / 2
        let pieceCx = left + radius

        if isActive {
            // 黄框 = (圆 + 文字) 的包围盒向外扩 radius * 0.45，线宽 2dp。
            let box = CGRect(x: left, y: -radius, width: groupWidth, height: radius * 2)
                .insetBy(dx: -radius * 0.45, dy: -radius * 0.45)
            badge.stroke(Path(box), with: .color(Theme.accent), lineWidth: Theme.yellowFrameLineWidth)
        }

        // 牌子里的棋子：王，字号 = radius * 2，不旋转（跟着牌子一起转过了）。
        drawGlyph(
            badge, painter: painter,
            cx: pieceCx, cy: 0,
            size: radius * 2,
            color: black ? IntlChessGame.black : IntlChessGame.white,
            code: "K",
            rotation: 0
        )

        // 名字：中点在 anchor 那条线上、左边缘紧跟在王的右边。
        badge.draw(
            painter.label(label, size: painter.labelFontSize).foregroundColor(.white),
            at: CGPoint(x: pieceCx + radius + gap, y: 0),
            anchor: .leading
        )
    }

    /// 拖动浮层（对应 drawDraggedPiece）：位置来自语义坐标，字号 × 1.1。
    private func drawDraggedPiece(_ ctx: GraphicsContext, painter: Painter) {
        let g = painter.geo
        guard let overlay = game.drag else { return }
        guard let code = overlay.piece.name.first else { return }
        drawGlyph(
            ctx, painter: painter,
            cx: CGFloat(g.pxOfCell(cellX: overlay.cellX, cellY: overlay.cellY)),
            cy: CGFloat(g.pyOfCell(cellX: overlay.cellX, cellY: overlay.cellY)),
            size: painter.glyphSize * 1.1,
            color: IntlChessGame.colorOf(overlay.piece.side),
            code: code,
            rotation: g.pieceTextRotation(whiteToMove: game.whiteToMove)
        )
    }

    // MARK: - 触摸（对应 onTouchEvent）

    /// `DragGesture(minimumDistance: 0)` 没有独立的 down/cancel：
    /// 第一次 `onChanged` 当 touchDown，`onEnded` 当 touchUp，视图消失时补 cancel。
    ///
    /// 注：手势体写在 `body` 里（而不是抽成 `-> some Gesture` 的方法）——
    /// 本工程的 `Game` 是 `ObservableObject` 协议、又用 `@ObservedObject` 装它，
    /// 这种组合下 Swift 5 会拒绝解析 `some Gesture`，写在内联位置就没有这个问题。
    private func handleDragChanged(_ value: DragGesture.Value, painter: Painter) {
        let g = painter.geo
        let x = Float(value.location.x)
        let y = Float(value.location.y)

        if !dragging {
            // touchDown：盘上有子才接管，否则后续事件全部忽略（国际象棋没有托盘）。
            let index = g.indexAt(x: x, y: y)
            guard index >= 0, game.hasPieceAt(index) else { return }
            dragging = true
            hoverIndex = index
            emit(game.onGesture(.pickUp(index: index)))
            return
        }

        // touchMove：只有接管了才处理；hover 只影响提示，不改盘面。
        let index = g.indexAt(x: x, y: y)
        if index != hoverIndex { hoverIndex = index }
        emit(game.onGesture(.dragTo(cellX: g.cellXAt(px: x, py: y), cellY: g.cellYAt(px: x, py: y))))
    }

    private func handleDragEnded(_ value: DragGesture.Value, painter: Painter) {
        guard dragging else { return }
        let g = painter.geo
        let x = Float(value.location.x)
        let y = Float(value.location.y)
        // 盘外自然是 -1（indexAt 在正方形外返回 -1）。
        emit(game.onGesture(.drop(
            cellX: g.cellXAt(px: x, py: y),
            cellY: g.cellYAt(px: x, py: y),
            targetIndex: g.indexAt(x: x, y: y)
        )))
        dragging = false
        hoverIndex = -1
    }

    /// 本地事件的出口：空事件不发（对应 Android 的 `emit`）。
    /// **只报手势，不自己改盘面** —— 盘面由 `IntlChessGame` 更新。
    private func emit(_ events: [MoveEvent]) {
        if events.isEmpty { return }
        sink?(events)
    }

    // MARK: - 绘制上下文（对应 Android 的 Paint 集合 + 尺寸公式，见 §7.2）

    /// 一次绘制需要的一切：几何 + 已经算好的线宽 / 字号。
    /// （Android 是在 `onSizeChanged` 里把线宽写进 Paint，这里是每次绘制现算，数值一样。）
    private struct Painter {
        let geo: IntlChessGeometry
        /// 牌子文字字号：`max(sp(16f), cell * 0.42f)`。
        let labelFontSize: CGFloat

        /// 棋盘外框矩形（Android 的 boardRect）。
        var boardRect: CGRect {
            CGRect(
                x: CGFloat(geo.boardLeft),
                y: CGFloat(geo.boardTop),
                width: CGFloat(geo.boardSize),
                height: CGFloat(geo.boardSize)
            )
        }

        /// 某一格的方框。
        func squareRect(file: Int, rank: Int) -> CGRect {
            CGRect(
                x: CGFloat(geo.squareLeft(file: file, rank: rank)),
                y: CGFloat(geo.squareTop(file: file, rank: rank)),
                width: CGFloat(geo.cell),
                height: CGFloat(geo.cell)
            )
        }

        /// 棋盘边框线宽：`max(dp(2f), cell * 0.05f)`。
        var boardBorderWidth: CGFloat { max(2, CGFloat(geo.cell) * 0.05) }

        /// 白子描边线宽：`max(dp(2f), cell * 0.035f)`。
        var whiteStrokeWidth: CGFloat { max(2, CGFloat(geo.cell) * 0.035) }

        /// 黑子描边线宽：`max(dp(1.5f), cell * 0.022f)`。
        var blackStrokeWidth: CGFloat { max(1.5, CGFloat(geo.cell) * 0.022) }

        /// 棋子字形大小：`cell * 0.8f`（拖动时再 × 1.1）。
        var glyphSize: CGFloat { CGFloat(geo.cell) * 0.8 }

        /// 棋子字形：用系统字体（Android 用的是默认 sans-serif）。
        func text(_ glyph: String, size: CGFloat) -> Text {
            Text(glyph).font(.system(size: size))
        }

        /// 牌子文字。
        func label(_ text: String, size: CGFloat) -> Text {
            Text(text).font(.system(size: size))
        }
    }

    /// 量一段文字有多宽（对应 Android 的 `Paint.measureText`）。
    /// Canvas 里量宽要先 `resolve`，再给一个「无限大」的容器测。
    private func textWidth(_ ctx: GraphicsContext, _ text: Text) -> CGFloat {
        ctx.resolve(text)
            .measure(in: CGSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude))
            .width
    }
}
