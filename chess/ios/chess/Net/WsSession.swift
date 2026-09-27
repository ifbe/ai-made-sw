//
//  WsSession.swift
//  chess
//
//  对照 Android: net/ws/WsSession.kt
//
//  Android 侧用的是 Java-WebSocket；iOS 侧统一用 Network.framework
//  （服务端 `NWListener` + `NWProtocolWebSocket`，客户端 `NWConnection` + `NWProtocolWebSocket`）。
//  好处：两端协议处理逻辑一模一样，而且完全不受 ATS 明文限制（§14.1）。
//

import Foundation
import Network

/// 一个 WebSocket 房间，既能当服务端也能当客户端（同一个类的两种用法，协议完全一样）。
///
///  - **服务端**：收到的事件转发给**其它**客户端（不回给发送者），
///    并缓存每个棋种最后一包全量棋盘 —— 新加入 / 重连的人一连上就先把这些发给他；
///  - **客户端**：本地事件发给服务端；
///  - **高频位置流**（`.dragMoved`）只留最新一条、按 30Hz 发送；发关键事件前先把攒着的
///    位置发掉，保证「先动、后落」。
///
/// `onState` 会在网络线程（内部串行队列）上回调，UI 记得自己切主线程。
final class WsSession: Session {

    /// 位置流的发送间隔：30Hz 足够跟手，再快只是浪费带宽。
    private static let dragIntervalMs = 33

    /// 显式绑 IPv4 通配地址（我们发给对端的也是 192.168.x.x）。
    private static let bindHost = "0.0.0.0"

    /// 所有网络回调都在这个串行队列上。
    private let queue = DispatchQueue(label: "chess.ws-session")

    /// 保护 `pendingDrag` / `lastBoard` / `closing` / `mode`（跨线程访问）。
    private let lock = NSLock()

    private let onState: (LinkState, String) -> Void
    private var listener: ((MoveEvent) -> Void)?

    /// 用户主动关闭时，不再把断开 / 出错报成故障。
    private var closing = false
    private var mode: Mode = .none

    /// 每个棋种最后一包全量棋盘：给新加入的人做同步。
    private var lastBoard: [GameKind: String] = [:]

    private var pendingDrag: MoveEvent?

    // 以下只在 queue 上访问
    private var nwListener: NWListener?
    private var serverConns: [UUID: ServerConn] = [:]
    private var clientConn: NWConnection?
    private var timer: DispatchSourceTimer?

    /// 客户端最近一次上报过的失败（`.waiting` 会反复回调，去重免得刷屏）。
    private var lastClientError: String?

    /// 服务端实际绑定的端口。
    private(set) var boundPort = -1

    private enum Mode { case none, server, client }

    /// 一个接入的服务端连接。
    private final class ServerConn {
        let id = UUID()
        let connection: NWConnection
        let endpoint: String
        var isOpen = false
        var closeCode: NWProtocolWebSocket.CloseCode?

        init(connection: NWConnection, endpoint: String) {
            self.connection = connection
            self.endpoint = endpoint
        }
    }

    init(onState: @escaping (LinkState, String) -> Void) {
        self.onState = onState
    }

    private var isClosing: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closing
    }

    func listen(_ listener: @escaping (MoveEvent) -> Void) {
        self.listener = listener
    }

    // MARK: - 启动

    func startServer(port: Int) {
        lock.lock()
        closing = false
        mode = .server
        lock.unlock()

        AppLog.log("启动服务：监听 \(Self.bindHost):\(port)（仅 IPv4）")
        onState(.starting, "启动中…")

        queue.async { [weak self] in
            guard let self else { return }

            let params = NWParameters.tcp
            // 之前那些连接会在端口上留下 TIME_WAIT，不开 reuseAddr 就会
            // 「Address already in use」——哪怕没有别的程序监听这个端口。
            params.allowLocalEndpointReuse = true

            let ws = NWProtocolWebSocket.Options()
            ws.autoReplyPing = true
            // Network.framework 只把「子协议 + 附加头」交给这个回调，拿不到资源路径 / UA
            // （对应 Android 的 onWebsocketHandshakeReceivedAsServer，能记的先记下来）。
            ws.setClientRequestHandler(self.queue) { subprotocols, headers in
                let headerText = headers.map { "\($0.name)=\($0.value)" }.joined(separator: "&")
                AppLog.log("收到握手请求：subprotocols=[\(subprotocols.joined(separator: ","))]，headers=[\(headerText)]")
                return NWProtocolWebSocket.Response(status: .accept, subprotocol: nil)
            }
            params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)

            if let portValue = NWEndpoint.Port(rawValue: UInt16(clamping: port)) {
                params.requiredLocalEndpoint = .hostPort(host: .ipv4(.any), port: portValue)
            }

            do {
                // 优先按 Android 的做法显式绑 IPv4 通配地址；万一系统不接受这种绑法，
                // 再退回「只给端口」（双栈监听，IPv4 客户端照样连得上）。
                let listener: NWListener
                do {
                    listener = try NWListener(using: params)
                } catch {
                    AppLog.log("绑定 0.0.0.0:\(port) 失败（\(error)），改用双栈监听")
                    params.requiredLocalEndpoint = nil
                    listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
                }
                self.nwListener = listener
                listener.stateUpdateHandler = { [weak self] state in
                    self?.handleListenerState(state)
                }
                listener.newConnectionHandler = { [weak self] connection in
                    self?.accept(connection)
                }
                listener.start(queue: self.queue)
            } catch {
                AppLog.log("服务启动失败：\(type(of: error)) \(error)")
                self.onState(.failed, "服务出错")
            }
        }
    }

    private func handleListenerState(_ state: NWListener.State) {
        switch state {
        case .ready:
            let port = Int(nwListener?.port?.rawValue ?? 0)
            boundPort = port
            AppLog.log("服务已启动，实际监听 \(Self.bindHost):\(port)")
            onState(.online, "服务中·\(openConnectionCount())")

        case let .failed(error):
            guard !isClosing else { return }
            AppLog.log("服务出错：\(Self.describe(error))")
            onState(.failed, "服务出错")

        default:
            break
        }
    }

    // MARK: - 服务端

    private func accept(_ connection: NWConnection) {
        guard !isClosing else {
            connection.cancel()
            return
        }

        let conn = ServerConn(connection: connection, endpoint: Self.describe(connection.endpoint))
        serverConns[conn.id] = conn

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                conn.isOpen = true
                // 新人加入：先把每个棋种最后一包全量棋盘发给他
                self.pushBoards(to: conn)
                AppLog.log(
                    "客户端接入 \(conn.endpoint)，当前 \(self.openConnectionCount()) 个；" +
                        "已推送 \(self.cachedBoardCount()) 个棋种的盘面"
                )
                self.onState(.online, "服务中·\(self.openConnectionCount())")

            case let .failed(error):
                self.dropConnection(conn, code: conn.closeCode, reason: Self.describe(error))

            case .cancelled:
                self.dropConnection(conn, code: conn.closeCode, reason: "已取消")

            default:
                break
            }
        }
        connection.start(queue: queue)
        receiveLoop(conn)
    }

    private func receiveLoop(_ conn: ServerConn) {
        conn.connection.receiveMessage { [weak self] data, context, _, error in
            guard let self else { return }

            if let error {
                self.dropConnection(conn, code: conn.closeCode, reason: Self.describe(error))
                return
            }

            let metadata = context?
                .protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
            if let metadata, metadata.opcode == .close {
                conn.closeCode = metadata.closeCode
                self.dropConnection(conn, code: metadata.closeCode, reason: "")
                return
            }

            if let data, !data.isEmpty, let text = String(data: data, encoding: .utf8) {
                if !self.isClosing {
                    self.handleMessage(text)
                    // 转发给其它客户端（不回给发送者，避免他自己收到回放）
                    self.forward(text, from: conn)
                }
            }
            self.receiveLoop(conn)
        }
    }

    private func dropConnection(_ conn: ServerConn, code: NWProtocolWebSocket.CloseCode?, reason: String) {
        guard serverConns.removeValue(forKey: conn.id) != nil else { return }
        conn.isOpen = false
        conn.connection.cancel()
        guard !isClosing else { return }
        let codeText = code.map { "\($0)" } ?? "-"
        AppLog.log("客户端断开 \(conn.endpoint)（code=\(codeText) \(reason)），当前 \(openConnectionCount()) 个")
        onState(.online, "服务中·\(openConnectionCount())")
    }

    private func pushBoards(to conn: ServerConn) {
        let boards = cachedBoards()
        for line in boards.values {
            sendText(line, to: conn.connection)
        }
    }

    private func cachedBoards() -> [GameKind: String] {
        lock.lock()
        defer { lock.unlock() }
        return lastBoard
    }

    private func cachedBoardCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return lastBoard.count
    }

    private func openConnectionCount() -> Int {
        serverConns.values.filter { $0.isOpen }.count
    }

    private func forward(_ text: String, from sender: ServerConn) {
        for (id, other) in serverConns where id != sender.id && other.isOpen {
            sendText(text, to: other.connection)
        }
    }

    // MARK: - 客户端

    func startClient(_ endpoint: WsEndpoint) {
        lock.lock()
        closing = false
        mode = .client
        lock.unlock()

        AppLog.log("开始连接：\(endpoint.uri)")
        onState(.starting, "连接中…")

        queue.async { [weak self] in
            guard let self else { return }

            // ★ 客户端必须用 **URL endpoint**：WebSocket 协议内部是拿 endpoint 里的 URL
            //   去拼握手请求行（`GET / HTTP/1.1` + `Host:`）的，函数就是 `nw_endpoint_get_url`。
            //   之前用 `.hostPort` 会拿到 null endpoint，Network.framework 直接
            //   `nw_endpoint_get_url called with null endpoint` + backtrace 挂掉。
            guard let url = Self.webSocketURL(endpoint) else {
                AppLog.log("地址不合法：\(endpoint.uri)")
                self.onState(.failed, "地址不对")
                return
            }

            // ws:// 是明文，走 TCP；wss:// 才需要 TLS（§14.1：明文用 Network.framework 不受 ATS 约束）
            let params: NWParameters = endpoint.scheme == "wss" ? NWParameters.tls : NWParameters.tcp
            let ws = NWProtocolWebSocket.Options()
            ws.autoReplyPing = true
            params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)

            let connection = NWConnection(to: .url(url), using: params)
            self.clientConn = connection
            self.lastClientError = nil

            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.lastClientError = nil
                    AppLog.log("已连接：\(endpoint.host):\(endpoint.port)")
                    self.onState(.online, "已连接")
                    self.receiveLoopClient(connection)

                case let .waiting(error):
                    self.reportClientFailure(error, connection: connection)

                case let .failed(error):
                    self.reportClientFailure(error, connection: connection)

                default:
                    break
                }
            }
            connection.start(queue: self.queue)
        }
    }

    /// 连不上：区分「本地网络权限被拒」和一般失败（§14.2）。
    private func reportClientFailure(_ error: NWError, connection: NWConnection) {
        guard !isClosing else { return }

        // 同一条错误（`.waiting` 会反复回调）只报一次
        let text = Self.describe(error)
        if lastClientError == text { return }
        lastClientError = text

        if Self.isLocalNetworkDenied(error) {
            // 首次连局域网时系统会弹「本地网络」授权框，弹框期间 / 被拒时拿到的就是 ENETDOWN。
            // 这里**不取消连接**：用户允许（或去设置里打开）之后路径一变，它会自己接着连；
            // 真要放弃就再点一下按钮（会 close）。
            AppLog.log(
                "连接失败：\(text)（需要「本地网络」权限；"
                    + "被拒的话去「设置 → 隐私与安全性 → 本地网络」打开本 App，再点一次连接）"
            )
            onState(.failed, "缺少本地网络权限")
            return
        }

        AppLog.log("连接失败：\(text)")
        onState(.failed, "连接失败")
        connection.cancel()
    }

    private static func isLocalNetworkDenied(_ error: NWError) -> Bool {
        guard case let .posix(code) = error else { return false }
        return code == .ENETDOWN || code == .EACCES || code == .EPERM
    }

    /// 日志里把 `NWError` 写得好认一点：默认的 `POSIXErrorCode(rawValue: 50)` 太丑。
    private static func describe(_ error: NWError) -> String {
        if case let .posix(code) = error {
            return "POSIX \(code.rawValue)（\(code)）"
        }
        return "\(error)"
    }

    /// 客户端连接的 URL endpoint。显式给一个 `/` 路径：WebSocket 握手请求行需要路径，
    /// 空路径（`ws://host:port`）会让对端不好解析。
    private static func webSocketURL(_ endpoint: WsEndpoint) -> URL? {
        var components = URLComponents()
        components.scheme = endpoint.scheme
        components.host = endpoint.host
        components.port = endpoint.port
        components.path = "/"
        return components.url
    }

    private func receiveLoopClient(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] data, context, _, error in
            guard let self else { return }

            if let error {
                guard !self.isClosing else { return }
                AppLog.log("连接断开（code=-，reason=\(Self.describe(error))）")
                self.onState(.failed, "连接已断开")
                return
            }

            let metadata = context?
                .protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
            if let metadata, metadata.opcode == .close {
                guard !self.isClosing else { return }
                AppLog.log("连接断开（code=\(metadata.closeCode)，reason=）")
                self.onState(.failed, "连接已断开")
                return
            }

            if let data, !data.isEmpty, let text = String(data: data, encoding: .utf8), !self.isClosing {
                self.handleMessage(text)
            }
            self.receiveLoopClient(connection)
        }
    }

    // MARK: - 发送

    func send(_ events: [MoveEvent]) {
        for event in events {
            if event.isDragMove {
                // 位置流：只留最新一条，交给定时器按 30Hz 发
                lock.lock()
                pendingDrag = event
                lock.unlock()
                ensureScheduler()
                continue
            }

            // 关键事件之前先把攒着的位置发掉，保证「先动、后落」
            flushPendingDrag()

            let line = EnvelopeCodec.encode(event)
            if case let .boardChanged(game, _, _, _, _) = event {
                // 自己这一手也要记下来，新加入的人才能同步到最新盘面
                lock.lock()
                lastBoard[game] = line
                lock.unlock()
            }
            sendNow(line)
        }
    }

    private func ensureScheduler() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.timer != nil { return }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(
                deadline: .now() + .milliseconds(Self.dragIntervalMs),
                repeating: .milliseconds(Self.dragIntervalMs)
            )
            timer.setEventHandler { [weak self] in self?.flushPendingDrag() }
            self.timer = timer
            timer.resume()
        }
    }

    private func flushPendingDrag() {
        lock.lock()
        let event = pendingDrag
        pendingDrag = nil
        lock.unlock()
        guard let event else { return }
        deliver(EnvelopeCodec.encode(event))
    }

    /// 任意线程调用 → 丢到 queue 上按顺序发。
    private func sendNow(_ line: String) {
        queue.async { [weak self] in self?.deliver(line) }
    }

    /// 只在 queue 上调用。
    private func deliver(_ line: String) {
        if nwListener != nil {
            for conn in serverConns.values where conn.isOpen {
                sendText(line, to: conn.connection)
            }
            return
        }
        if let client = clientConn {
            sendText(line, to: client)
        }
    }

    private func sendText(_ text: String, to connection: NWConnection) {
        let metadata = NWProtocolWebSocket.Metadata(opcode: .text)
        let context = NWConnection.ContentContext(identifier: "text", metadata: [metadata])
        connection.send(
            content: Data(text.utf8),
            contentContext: context,
            isComplete: true,
            completion: .contentProcessed { error in
                if error != nil {
                    AppLog.log("发送失败（队列满或连接已关闭）")
                }
            }
        )
    }

    // MARK: - 收报

    private func handleMessage(_ text: String) {
        guard let event = EnvelopeCodec.decode(text) else { return }
        if case let .boardChanged(game, _, _, _, _) = event {
            lock.lock()
            lastBoard[game] = text
            lock.unlock()
        }
        listener?(event)
    }

    // MARK: - 关闭

    func close() {
        lock.lock()
        let wasServer = mode == .server
        closing = true
        mode = .none
        pendingDrag = nil
        lock.unlock()

        queue.async { [weak self] in
            guard let self else { return }
            self.timer?.cancel()
            self.timer = nil
            self.nwListener?.cancel()
            self.nwListener = nil
            for conn in self.serverConns.values {
                conn.connection.cancel()
            }
            self.serverConns.removeAll()
            self.clientConn?.cancel()
            self.clientConn = nil
        }

        AppLog.log(wasServer ? "已关闭服务" : "已断开连接")
        onState(.idle, "已关闭")
    }

    private static func describe(_ endpoint: NWEndpoint) -> String {
        switch endpoint {
        case let .hostPort(host, port):
            return "\(host):\(port)"
        default:
            return "\(endpoint)"
        }
    }
}

extension WsSession: @unchecked Sendable {}
