//
//  RootView.swift
//  chess
//
//  根视图：纯黑全屏 + 四个棋盘 + 四角控件（标签栏 / 重置 / 联机条 / 日志框）。
//  对照 Android: MainActivity.kt（壳 + 联机条 + 日志框接线）。
//

import SwiftUI
import UIKit

struct RootView: View {

    // 每页各自的棋局（切走再切回来棋还在，§8.5）
    @StateObject private var xiangqiGame = XiangqiGame()
    @StateObject private var intlChessGame = IntlChessGame()
    @StateObject private var weiqiGame = StoneGame(lines: 19, kind: .weiqi)
    @StateObject private var wuziqiGame = StoneGame(lines: 15, kind: .wuziqi)

    @State private var page: GameKind = .xiangqi

    // MARK: 联机状态

    @State private var netMode: NetMode = .server
    @State private var session: WsSession?
    @State private var linkState: LinkState = .idle
    @State private var statusDetail = ""

    /// 本次 App 启动里，**各自模式**下用户输入过的地址（空串 = 这个模式还没输入过）。
    @State private var serverAddress = ""
    @State private var clientAddress = ""

    /// 当前这次连接的令牌：网络回调回来时用它判断「还是不是当前这个会话」。
    @State private var sessionToken = UUID()

    /// 本地事件流水（不联网时也留一份，方便回放 / 排查）。
    @State private var localSession = LocalSession()

    var body: some View {
        // 启动计时（纯诊断）：区分「我们的视图代码慢」还是「App 加载慢」。
        let _ = StartupClock.logOnce("RootView.body 第一次求值")

        // 结构刻意保持成最简单的 ZStack（和之前能正常显示的版本一致）：
        //   黑底（忽略安全区）/ 棋盘（忽略安全区）/ 四角控件（在安全区里）
        // 四角控件内部用「铺满屏的透明锚点 + frame 对齐」定位（见 Layout.swift）。
        ZStack {
            // 页面底色：全屏纯黑
            Theme.pageBackground
                .ignoresSafeArea()

            // 四个棋盘页叠在一起，同一时刻只有一个在渲染树里（§4.1）
            boardPages
                .ignoresSafeArea()

            // 四角控件：自己在安全区里，四角各再让开 12pt（§4.2）
            // 键盘避让交给系统：键盘弹出 → 底部安全区抬高 → 这一层自动缩小、下面那行上移
            CornerControls(
                topLeading: {
                    TabBarView(selected: page) { kind in
                        page = kind
                    }
                },
                topTrailing: {
                    resetButton
                },
                bottomLeading: {
                    netBar
                },
                bottomTrailing: {
                    LogPanelView()
                }
            )
        }
        .preferredColorScheme(.dark)
        .onAppear {
            // 启动计时（纯诊断）：到这里说明首帧已经出来了。
            StartupClock.log("RootView.onAppear（首帧附近）")
            // 再等一轮 runloop：这时首帧已经提交上屏了。
            DispatchQueue.main.async {
                StartupClock.log("首帧已提交上屏")
            }
            AppLog.log("应用启动，本机地址 \(NetAddress.localIpv4() ?? "（没有局域网 IP）")")
            applyNetMode()
        }
        .onDisappear {
            keepScreenOn(false)
            session?.close()
            session = nil
        }
    }


    // MARK: - 棋盘页

    @ViewBuilder
    private var boardPages: some View {
        switch page {
        case .xiangqi:
            XiangqiBoardView(game: xiangqiGame, sink: sink)
        case .intlChess:
            IntlChessBoardView(game: intlChessGame, sink: sink)
        case .weiqi:
            StoneBoardView(game: weiqiGame, sink: sink)
        case .wuziqi:
            StoneBoardView(game: wuziqiGame, sink: sink)
        }
    }

    /// 四个页面本地事件的统一出口：转发给当前连接（没连就等于只记流水）。
    private var sink: MoveEventSink {
        { events in
            localSession.onLocalEvents(events)
            session?.send(events)
        }
    }

    // MARK: - 右上角重置

    private var resetButton: some View {
        Button {
            resetCurrentPage()
        } label: {
            Text(Theme.Text.reset)
                .font(.system(size: Theme.resetFontSize))
                .foregroundColor(Theme.resetText)
                .padding(.horizontal, Theme.resetPaddingH)
                .padding(.vertical, Theme.resetPaddingV)
                .background(
                    RoundedRectangle(cornerRadius: Theme.resetCornerRadius)
                        .fill(Theme.tabBackground)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.resetCornerRadius)
                        .strokeBorder(Theme.tabBorder, lineWidth: 1)
                        .allowsHitTesting(false)
                )
        }
        .buttonStyle(.plain)
    }

    /// 只重置当前正在看的那一页，并广播 reset + 一条全量 board（§8.4）。
    private func resetCurrentPage() {
        let events: [MoveEvent]
        switch page {
        case .xiangqi: events = xiangqiGame.reset()
        case .intlChess: events = intlChessGame.reset()
        case .weiqi: events = weiqiGame.reset()
        case .wuziqi: events = wuziqiGame.reset()
        }
        sink(events)
    }

    // MARK: - 左下角联机条

    private var netBar: some View {
        NetBarView(
            mode: netMode,
            address: addressBinding,
            hint: netMode == .server ? Theme.Text.netHintServer : Theme.Text.netHintClient,
            actionTitle: actionTitle,
            onToggleMode: toggleNetMode,
            onAction: toggleSession
        )
    }

    /// 服 / 客各记各的地址；程序回填不算「用户输入」。
    private var addressBinding: Binding<String> {
        Binding(
            get: { netMode == .server ? serverAddress : clientAddress },
            set: { newValue in
                if netMode == .server {
                    serverAddress = newValue
                } else {
                    clientAddress = newValue
                }
            }
        )
    }

    /// 按钮文字 = 当前状态（§11.4）。
    private var actionTitle: String {
        guard session != nil else {
            return netMode == .server ? Theme.Text.netStartServer : Theme.Text.netStartClient
        }
        if !statusDetail.isEmpty { return statusDetail }
        switch linkState {
        case .starting: return Theme.Text.netStarting
        case .online: return Theme.Text.netOnline
        case .failed, .idle: return Theme.Text.netFailed
        }
    }

    private func toggleNetMode() {
        if session != nil { return } // 连着呢，先关了再切
        netMode = netMode == .server ? .client : .server
        AppLog.log(netMode == .server ? "切换为服务端模式" : "切换为客户端模式")
        applyNetMode()
    }

    /// 两种模式共用同一个地址框：没输入过 → 填默认值「本机局域网 IP : 端口」。
    private func applyNetMode() {
        let current = netMode == .server ? serverAddress : clientAddress
        let text = current.isEmpty ? defaultAddress() : current
        if netMode == .server {
            if serverAddress.isEmpty { serverAddress = text }
        } else {
            if clientAddress.isEmpty { clientAddress = text }
        }
    }

    /// 默认地址：本机 192 网段 IP + 默认端口。
    private func defaultAddress() -> String {
        let ip = NetAddress.localIpv4()
        AppLog.log("本机局域网地址：\(ip ?? "（没有，可能在用流量 / 没连 Wi-Fi）")")
        return "\(ip ?? "0.0.0.0"):\(NetAddress.defaultPort)"
    }

    private func toggleSession() {
        if let current = session {
            current.close()
            session = nil
            linkState = .idle
            statusDetail = ""
            keepScreenOn(false)
            return
        }

        // iOS 的「本地网络」权限弹窗由系统在第一次真正发起局域网连接时弹出（§14.2），
        // 所以这里不需要像 Android 16 那样预先申请。
        startSessionNow()
    }

    /// 真正开始服务 / 开始连接。
    private func startSessionNow() {
        if session != nil { return }

        let token = UUID()
        sessionToken = token

        let created = WsSession { state, detail in
            // 网络线程回调 → 切主线程改按钮文字
            DispatchQueue.main.async {
                guard sessionToken == token else { return }
                linkState = state
                statusDetail = detail
            }
        }
        created.listen { event in
            DispatchQueue.main.async {
                routeRemote(event)
            }
        }
        session = created
        // 开着服务 / 连着对局的时候别黑屏，否则 App 被挂起、socket 就没人处理了（§4.7）
        keepScreenOn(true)

        if netMode == .server {
            // 端口以文本框里的为准（IP 部分只是给对端看的，服务端绑的是 0.0.0.0）
            let port = NetAddress.portOf(serverAddress)
            AppLog.log("开始服务：端口 \(port)，对端请连 \(serverAddress)")
            linkState = .starting
            statusDetail = Theme.Text.netStarting
            created.startServer(port: port)
        } else {
            guard let endpoint = NetAddress.toWsEndpoint(clientAddress) else {
                AppLog.log("地址不合法：\(clientAddress)")
                session = nil
                linkState = .failed
                statusDetail = Theme.Text.netBadAddress
                return
            }
            linkState = .starting
            statusDetail = Theme.Text.netConnecting
            created.startClient(endpoint)
        }
    }

    /// 对端事件按棋种分发给对应页面。
    private func routeRemote(_ event: MoveEvent) {
        switch event.game {
        case .xiangqi: xiangqiGame.apply(event)
        case .intlChess: intlChessGame.apply(event)
        case .weiqi: weiqiGame.apply(event)
        case .wuziqi: wuziqiGame.apply(event)
        }
    }

    /// 联机期间保持屏幕常亮。
    private func keepScreenOn(_ on: Bool) {
        UIApplication.shared.isIdleTimerDisabled = on
    }
}
