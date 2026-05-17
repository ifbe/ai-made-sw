import Foundation

protocol WebSocketServiceDelegate: AnyObject {
    func onLoginSuccess(token: String, nickname: String)
    func onLoginFailed(error: String)
    func onUserList(users: [User])
    func onUserJoined(user: User)
    func onUserLeft(username: String)
    func onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?)
    func onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float)
    func onError(message: String)
    func onConnected()
    func onDisconnected()
}

/// WebSocket 服务，替代 Android 的 ApiClient
/// URLSessionWebSocketTask 实现，协议完全一致
final class WebSocketService: NSObject {
    weak var delegate: WebSocketServiceDelegate?

    private var webSocketTask: URLSessionWebSocketTask?
    private var token: String?
    private var username: String?
    private var serverUrl: String

    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        return URLSession(configuration: config, delegate: self, delegateQueue: .main)
    }()

    init(serverUrl: String) {
        self.serverUrl = serverUrl
        super.init()
    }

    private var wsUrl: String {
        serverUrl.replacingOccurrences(of: "http://", with: "ws://")
            .replacingOccurrences(of: "https://", with: "wss://") + "/"
    }

    func connectAndLogin(username: String, response: String, lat: Double, lng: Double, heading: Float) {
        self.username = username

        guard let url = URL(string: wsUrl) else { return }
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()

        // 发送登录消息
        let loginMsg: [String: Any] = [
            "type": "login",
            "username": username,
            "response": response,
            "lat": lat,
            "lng": lng,
            "heading": heading
        ]

        send(loginMsg)
        receiveMessage()
    }

    func sendPosition(lat: Double, lng: Double, heading: Float) {
        guard let token = token, let username = username else { return }
        let msg: [String: Any] = [
            "type": "update_position",
            "token": token,
            "username": username,
            "lat": lat,
            "lng": lng,
            "heading": heading
        ]
        send(msg)
    }

    func sendTarget(targetLat: Double?, targetLng: Double?) {
        guard let token = token, let username = username else { return }
        var msg: [String: Any] = [
            "type": "update_target",
            "token": token,
            "username": username
        ]
        if let lat = targetLat, let lng = targetLng {
            msg["target_lat"] = lat
            msg["target_lng"] = lng
        } else {
            msg["target_lat"] = NSNull()
            msg["target_lng"] = NSNull()
        }
        send(msg)
    }

    func disconnect() {
        webSocketTask?.cancel(with: .normalClosure, reason: nil)
        webSocketTask = nil
        token = nil
    }

    private func send(_ dict: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let jsonString = String(data: data, encoding: .utf8) else { return }
        webSocketTask?.send(.string(jsonString)) { error in
            if let error = error {
                print("WebSocket send error: \(error)")
            }
        }
    }

    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self?.handleMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self?.handleMessage(text)
                    }
                @unknown default:
                    break
                }
                // 继续接收下一条
                self?.receiveMessage()
            case .failure(let error):
                print("WebSocket receive error: \(error)")
                self?.delegate?.onDisconnected()
            }
        }
    }

    private func handleMessage(_ text: String) {
        guard let msg = ServerMessage.parse(text) else { return }

        switch msg {
        case .loginSuccess(let token, let nickname):
            self.token = token
            delegate?.onLoginSuccess(token: token, nickname: nickname)
        case .userList(let users):
            delegate?.onUserList(users: users)
        case .userJoined(let username, let lat, let lng, let heading, let nickname, let targetLat, let targetLng):
            delegate?.onUserJoined(user: User(
                username: username,
                lat: lat,
                lng: lng,
                heading: heading,
                nickname: nickname,
                targetLat: targetLat,
                targetLng: targetLng
            ))
        case .userLeft(let username):
            delegate?.onUserLeft(username: username)
        case .targetUpdate(let username, let targetLat, let targetLng):
            delegate?.onTargetUpdate(username: username, targetLat: targetLat, targetLng: targetLng)
        case .positionUpdate(let username, let lat, let lng, let heading):
            delegate?.onPositionUpdate(username: username, lat: lat, lng: lng, heading: heading)
        case .error(let message):
            delegate?.onError(message: message)
        }
    }
}

extension WebSocketService: URLSessionWebSocketDelegate {
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        delegate?.onConnected()
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        delegate?.onDisconnected()
    }
}