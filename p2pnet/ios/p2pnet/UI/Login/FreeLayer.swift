import SwiftUI

/// 自由层（对齐 Android `MainPage.kt` 的 `FreeLayer`）：
/// 连接线 + 「我」卡片 + 随机分布的其他人卡片 + socket 卡片，都可拖动。
///
/// 位置规则（和 Android 一致）：
///  - 「我」：默认贴底居中，横向限制在屏幕 25%~75% 之间（可拖）
///  - 其他人：位置由名字哈希算出来（只在上半区），进程内稳定，不会每帧乱跳（可拖标题行）
///  - socket 卡片：初始位置**挂在对应其他人卡片正下方**（下半屏），第一次量到尺寸时冻结，之后不跟随对方移动
///  - 连线：服务器卡片下沿 → 各卡片；屏幕几何中心一条贯通横线（用窗口高度算，不是自由层中心）
struct FreeLayer: View {
    @ObservedObject var viewModel: LoginViewModel

    /// socket 卡片的基准中心（冻结一次的初始位置）
    @State private var socketBases: [Int64: CGPoint] = [:]
    /// 各卡片累计拖动位移
    @State private var socketDrags: [Int64: CGSize] = [:]
    @State private var socketDragStart: [Int64: CGSize] = [:]
    @State private var socketSizes: [Int64: CGSize] = [:]

    @State private var peerDrags: [String: CGSize] = [:]
    @State private var peerDragStart: [String: CGSize] = [:]
    @State private var peerSizes: [String: CGSize] = [:]

    @State private var meDrag: CGSize = .zero
    /// nil = 当前没在拖；**不能用 `.zero` 当哨兵**（初始位置就是 .zero，会导致每帧重置起点、位移越滚越大）
    @State private var meDragStart: CGSize?
    @State private var meSize: CGSize = .zero

    /// 自由层顶边在窗口里的 y（把「屏幕中心」换算到自由层本地坐标用）
    @State private var freeTopInWindow: CGFloat = 0
    /// 窗口高度（缓存一次；ScreenMetrics 是 MainActor 的，不能每帧在 Canvas 里读）
    @State private var windowHeight: CGFloat = 0

    private let linkGreen = Color(hex: 0x4CAF50)
    private let linkWidth: CGFloat = 2
    private let socketGap: CGFloat = 24
    /// 其他人卡片标题行的中心距卡片顶部的距离（连线连到这里，对齐 Android PeerTitleCenterY）
    private let peerTitleCenterY: CGFloat = 12

    private var uiState: LoginUiState { viewModel.uiState }

    var body: some View {
        GeometryReader { geo in
            let area = geo.size
            ZStack(alignment: .topLeading) {
                // ── 连线（画在最底下）──
                connections(area: area)
                    .onAppear { refreshGlobalMetrics(geo) }
                    // 只观察自身尺寸变化（键盘弹出/旋转/tab 切换时重算），
                    // 不去 onChange 观察 `.global` frame —— 那会让 body 依赖全局布局，容易触发更新循环
                    .onChange(of: geo.size) { _ in refreshGlobalMetrics(geo) }

                // ── 「我」卡片：默认贴底居中 ──
                MeCard(
                    viewModel: viewModel,
                    onDrag: { value in
                        let start = meDragStart ?? meDrag
                        if meDragStart == nil { meDragStart = start }
                        meDrag = clampMeDrag(
                            CGSize(
                                width: start.width + value.translation.width,
                                height: start.height + value.translation.height
                            ),
                            area
                        )
                    },
                    onDragEnd: { meDragStart = nil }
                )
                .fixedSize()
                .background(sizeReader { size in
                    if size != .zero && meSize != size { meSize = size }
                })
                .position(meCenter(area))
                // ⚠️ 这里**不能**再挂一层整卡 `.gesture`：
                // 卡片里的标题行已经有拖动手势（对齐 Android 的 `dragHandle`：只有标题行能拖），
                // 两层手势抢同一个拖拽，加上「我」卡里还有 TextField，会让 UIKit 的触摸管线卡死
                // —— 表现就是「卡片动一下之后整页点什么都没反应」

                // ── 其他人卡片 ──
                ForEach(uiState.peers) { peer in
                    PeerNodeCard(
                        peer: peer,
                        onPunch: { action in viewModel.onPeerPunch(peer.username, action) },
                        onDrag: { value in
                            if peerDragStart[peer.username] == nil {
                                peerDragStart[peer.username] = peerDrags[peer.username] ?? .zero
                            }
                            let start = peerDragStart[peer.username] ?? .zero
                            peerDrags[peer.username] = CGSize(
                                width: start.width + value.translation.width,
                                height: start.height + value.translation.height
                            )
                        },
                        onDragEnd: { peerDragStart[peer.username] = nil }
                    )
                    .fixedSize()
                    .background(sizeReader { size in
                        if size != .zero && peerSizes[peer.username] != size {
                            peerSizes[peer.username] = size
                        }
                    })
                    .position(peerCenter(peer.username, area))
                    // 同上：拖动只走标题行自己的手势（Android 也是 `dragHandle` 挂在名字那一行）
                }

                // ── socket 卡片（最后画，压在其他卡片之上，✕ 始终可点）──
                ForEach(uiState.udpSockets) { card in
                    SocketCard(
                        card: card,
                        usageIds: viewModel.sessionManager.usageIds,
                        onClose: { viewModel.closeUdpSocket(card.id) },
                        onUse: { viewModel.useUdpSocket(card.id, $0) }
                    )
                    .fixedSize()
                    .background(sizeReader { size in registerSocket(card, size: size, area: area) })
                    .position(socketCenter(card.id, area))
                    .gesture(socketDragGesture(card.id, area))
                }
            }
        }
    }

    /// 免费层在窗口里的位置与窗口高度：只在 onAppear / 自身尺寸变化时取一次（都是主线程）
    private func refreshGlobalMetrics(_ geo: GeometryProxy) {
        freeTopInWindow = geo.frame(in: .global).minY
        windowHeight = ScreenMetrics.windowHeight
    }

    // MARK: - 量尺寸

    /// 量一张卡片的尺寸（首帧可能拿到 .zero，所以忽略 0）
    private func sizeReader(_ onSize: @escaping (CGSize) -> Void) -> some View {
        GeometryReader { g in
            Color.clear
                .onAppear { onSize(g.size) }
                .onChange(of: g.size) { newSize in onSize(newSize) }
        }
    }

    /// socket 卡片第一次量到尺寸时，把初始位置冻结下来：挂在对应其他人卡片正下方（下半屏）
    private func registerSocket(_ card: UdpSessionInfo, size: CGSize, area: CGSize) {
        guard size.width > 0, size.height > 0 else { return }
        if socketSizes[card.id] != size { socketSizes[card.id] = size }
        guard socketBases[card.id] == nil else { return }

        let peerTop = peerTopLeft(card.target, area: area)
        let peerW = peerSizes[card.target]?.width ?? 160
        let peerH = peerSizes[card.target]?.height ?? 58
        let baseX: CGFloat
        let baseY: CGFloat
        if let peerTop = peerTop {
            baseX = peerTop.x + (peerW - size.width) / 2
            baseY = max(area.height / 2, peerTop.y + peerH + socketGap)
        } else {
            // 找不到对应的人（例如被动收到的 direct 卡片）：下半屏居中
            baseX = (area.width - size.width) / 2
            baseY = area.height / 2
        }
        let maxX = max(0, area.width - size.width)
        let maxY = max(0, area.height - size.height)
        let topLeft = CGPoint(x: min(max(baseX, 0), maxX), y: min(max(baseY, 0), maxY))
        socketBases[card.id] = CGPoint(x: topLeft.x + size.width / 2, y: topLeft.y + size.height / 2)
    }

    // MARK: - 位置

    /// 「我」卡片中心：默认贴底居中 + 拖动位移（横向限制在屏幕 25%~75%，即 ±(宽度-卡片宽)/2）
    private func meCenter(_ area: CGSize) -> CGPoint {
        let maxDx = max(0, (area.width - meSize.width) / 2)
        let hiY: CGFloat = 0
        let loY = min(hiY, -(area.height - meSize.height))
        let dx = min(max(meDrag.width, -maxDx), maxDx)
        let dy = min(max(meDrag.height, loY), hiY)
        return CGPoint(x: area.width / 2 + dx, y: area.height - meSize.height / 2 + dy)
    }

    /// 其他人的默认左上角（相对位置 × 可用空间，用名字哈希当种子）+ 拖动位移
    private func peerTopLeft(_ name: String, area: CGSize) -> CGPoint? {
        guard uiState.peers.contains(where: { $0.username == name }) else { return nil }
        let size = peerSizes[name] ?? CGSize(width: 160, height: 58)
        let (rx, ry) = Self.pseudoRandom(name)
        let maxX = max(0, area.width - size.width)
        let maxY = max(0, area.height - size.height)
        let base = CGPoint(x: maxX * rx, y: maxY * ry)
        let d = peerDrags[name] ?? .zero
        return CGPoint(x: base.x + d.width, y: base.y + d.height)
    }

    private func peerCenter(_ name: String, _ area: CGSize) -> CGPoint {
        let size = peerSizes[name] ?? CGSize(width: 160, height: 58)
        guard let topLeft = peerTopLeft(name, area: area) else {
            return CGPoint(x: area.width / 2, y: area.height / 2)
        }
        return CGPoint(x: topLeft.x + size.width / 2, y: topLeft.y + size.height / 2)
    }

    /// socket 卡片当前中心 = 冻结的基准位置 + 自己的拖动位移
    private func socketCenter(_ id: Int64, _ area: CGSize) -> CGPoint {
        guard let base = socketBases[id] else {
            return CGPoint(x: area.width / 2, y: area.height / 2)
        }
        let size = socketSizes[id] ?? CGSize(width: 190, height: 150)
        let d = socketDrags[id] ?? .zero
        let halfW = size.width / 2
        let halfH = size.height / 2
        let x = min(max(base.x + d.width, halfW), max(halfW, area.width - halfW))
        let y = min(max(base.y + d.height, halfH), max(halfH, area.height - halfH))
        return CGPoint(x: x, y: y)
    }

    /// 稳定的伪随机（同一个名字每次一样）：x ∈ [0,1]，y ∈ [0,0.5]（只在上半区）
    private static func pseudoRandom(_ name: String) -> (CGFloat, CGFloat) {
        var seed = UInt64(bitPattern: Int64(name.hashValue))
        func next() -> CGFloat {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            return CGFloat((seed >> 33) % 1000) / 1000.0
        }
        return (next(), next() * 0.5)
    }

    // MARK: - 拖动

    /// 「我」卡片的位移夹取：横向限制在屏幕 25%~75%，纵向只能往上（不能拖到服务器卡上）
    private func clampMeDrag(_ next: CGSize, _ area: CGSize) -> CGSize {
        let maxDx = max(0, (area.width - meSize.width) / 2)
        let loY = min(0, -(area.height - meSize.height))
        return CGSize(
            width: min(max(next.width, -maxDx), maxDx),
            height: min(max(next.height, loY), 0)
        )
    }

    /// socket 卡片的拖动：Android 那边这张卡就是**整卡可拖**（`UdpSocketCardView` 把
    /// `dragHandle` 挂在 Card 上，注释写「整卡可拖动，右上角 ✕ 关闭」），所以这里保留整卡手势；
    /// 参数 `area` 用来把卡片夹在可视范围内（用 `.position` 时卡片中心不能超出边界）
    private func socketDragGesture(_ id: Int64, _ area: CGSize) -> some Gesture {
        // 同「我」/其他人卡片：卡片位置由这个手势驱动，必须用固定的 `.global` 坐标空间
        DragGesture(minimumDistance: 2, coordinateSpace: .global)
            .onChanged { value in
                if socketDragStart[id] == nil { socketDragStart[id] = socketDrags[id] ?? .zero }
                let start = socketDragStart[id] ?? .zero
                var next = CGSize(
                    width: start.width + value.translation.width,
                    height: start.height + value.translation.height
                )
                if let base = socketBases[id] {
                    let size = socketSizes[id] ?? CGSize(width: 190, height: 150)
                    let halfW = size.width / 2
                    let halfH = size.height / 2
                    let minDx = halfW - base.x
                    let maxDx = max(minDx, area.width - halfW - base.x)
                    let minDy = halfH - base.y
                    let maxDy = max(minDy, area.height - halfH - base.y)
                    next.width = min(max(next.width, minDx), maxDx)
                    next.height = min(max(next.height, minDy), maxDy)
                }
                socketDrags[id] = next
            }
            .onEnded { _ in socketDragStart[id] = nil }
    }

    // MARK: - 连线

    @ViewBuilder
    private func connections(area: CGSize) -> some View {
        Canvas { ctx, size in
            // 屏幕几何中心一条贯通的横线（y 用窗口高度算，不是自由层中心）。
            // ⚠️ 这里用 onAppear 缓存好的 @State，**别每帧去读 ScreenMetrics**
            //（它内部是 UIApplication.shared / UIWindowScene，主线程 API，放在 Canvas 渲染闭包里很危险）
            if windowHeight > 0 {
                let y = windowHeight / 2 - freeTopInWindow
                if y >= 0 && y <= size.height {
                    var path = Path()
                    path.move(to: CGPoint(x: 0, y: y))
                    path.addLine(to: CGPoint(x: size.width, y: y))
                    ctx.stroke(path, with: .color(Color.secondary.opacity(0.35)), lineWidth: 1)
                }
            }

            // 服务器卡片下沿 → 「我」卡片中心：已连接未登录=白色虚线，登录后=绿色实线
            if uiState.isConnected && meSize.height > 0 {
                let center = meCenter(area)
                var path = Path()
                path.move(to: CGPoint(x: center.x, y: 0))
                path.addLine(to: center)
                ctx.stroke(
                    path,
                    with: .color(uiState.isLoggedIn ? linkGreen : .white),
                    style: StrokeStyle(
                        lineWidth: linkWidth,
                        lineCap: .round,
                        dash: uiState.isLoggedIn ? [] : [8, 6]
                    )
                )
            }

            // 服务器卡片下沿 → 其他人卡片标题中心：绿色实线
            for peer in uiState.peers {
                guard let topLeft = peerTopLeft(peer.username, area: area) else { continue }
                let w = peerSizes[peer.username]?.width ?? 160
                let centerX = topLeft.x + w / 2
                var path = Path()
                path.move(to: CGPoint(x: centerX, y: 0))
                path.addLine(to: CGPoint(x: centerX, y: topLeft.y + peerTitleCenterY))
                ctx.stroke(
                    path,
                    with: .color(linkGreen),
                    style: StrokeStyle(lineWidth: linkWidth, lineCap: .round)
                )
            }

            // 其他人卡片底边 → 它对应的 socket 卡片顶边：白色虚线
            for card in uiState.udpSockets {
                guard let peerTop = peerTopLeft(card.target, area: area),
                      let socketBase = socketBases[card.id] else { continue }
                let peerW = peerSizes[card.target]?.width ?? 160
                let peerH = peerSizes[card.target]?.height ?? 58
                let socketSize = socketSizes[card.id] ?? CGSize(width: 190, height: 150)
                let d = socketDrags[card.id] ?? .zero
                let socketCenterX = socketBase.x + d.width
                let socketTopY = socketBase.y + d.height - socketSize.height / 2
                var path = Path()
                path.move(to: CGPoint(x: peerTop.x + peerW / 2, y: peerTop.y + peerH))
                path.addLine(to: CGPoint(x: socketCenterX, y: socketTopY))
                ctx.stroke(
                    path,
                    with: .color(.white),
                    style: StrokeStyle(lineWidth: linkWidth, lineCap: .round, dash: [8, 6])
                )
            }
        }
    }
}
