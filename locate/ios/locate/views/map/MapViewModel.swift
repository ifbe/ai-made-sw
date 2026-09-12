import Foundation
import Combine
import CoreLocation

final class MapViewModel: ObservableObject {
    @Published var uiState = MapUiState()
    @Published var otherUsers: [User] = []
    @Published var connectionStatus: Int = 0  // 0=连接中, 1=已连接, 2=断开
    @Published var onlineCount: Int = 0

    private(set) var loginUsername: String?
    private(set) var webSocket: WebSocketService?
    private(set) var locationManager: LocationManager?

    private var authService: AuthService
    private let keychain: KeychainStorage
    private var currentServerUrl: String
    /// 连接状态只在变化时写一行日志，否则每次位置更新都会刷屏
    private var lastConnectionLog: String?
    /// 第一次收到服务器回显自己的位置，记一行，用来判断位置到底有没有送上去
    private var loggedSelfEcho = false
    private var loggedEchoMismatch = false

    /// 最后一次上报的位置，心跳用它重发
    private var lastReported: (lat: Double, lng: Double, heading: Float)?
    private var positionHeartbeat: Timer?

    // 回调：地图 ready 后需要调用
    var onMapReady: (() -> Void)?
    var onSelfLocationUpdate: ((Double, Double) -> Void)?
    // 服务器广播回来的自己的位置（调试用，绿色标记）
    var onServerPositionUpdate: ((Double, Double, Float) -> Void)?

    init(keychain: KeychainStorage, serverUrl: String) {
        self.keychain = keychain
        self.currentServerUrl = serverUrl
        self.authService = AuthService(serverUrl: serverUrl, keychain: keychain)

        uiState.serverUrl = serverUrl
        uiState.username = keychain.username ?? ""

        rebuildWebSocket()

        locationManager = LocationManager()
        locationManager?.delegate = self

        attemptAutoLogin()
    }

    // MARK: - 连接

    private func rebuildWebSocket() {
        webSocket?.delegate = nil
        webSocket?.disconnect()
        let service = WebSocketService(serverUrl: currentServerUrl)
        service.delegate = self
        webSocket = service
    }

    /// 服务器地址只在登录时生效（登录成功后登录矩形是收起的，改不到）
    private func applyServerUrl(_ serverUrl: String) {
        guard serverUrl != currentServerUrl else { return }
        currentServerUrl = serverUrl
        keychain.serverUrl = serverUrl
        authService = AuthService(serverUrl: serverUrl, keychain: keychain)
        rebuildWebSocket()
        AppLog.i("服务器地址已切换：\(serverUrl)")
    }

    // MARK: - 登录 / 退出

    /// 有保存的凭证就自动登录；登录矩形里会转圈，和 Android 的行为一致
    private func attemptAutoLogin() {
        guard let username = keychain.username,
              let password = keychain.password,
              !username.isEmpty,
              !password.isEmpty else {
            uiState.autoLoggingIn = false
            AppLog.i("未登录：请填写服务器地址、用户名和密码")
            return
        }

        uiState.autoLoggingIn = true
        uiState.username = username
        AppLog.i("使用已保存凭证自动登录：\(username)")
        startLogin(username: username, password: password)
    }

    func onLogin() {
        let serverUrl = uiState.serverUrl
        let username = uiState.username
        let password = uiState.password

        guard !username.isEmpty, !password.isEmpty else {
            uiState.error = "请输入用户名和密码"
            return
        }

        applyServerUrl(serverUrl)
        uiState.loading = true
        uiState.error = nil
        AppLog.i("正在登录：\(username) @ \(serverUrl)")
        startLogin(username: username, password: password)
    }

    private func startLogin(username: String, password: String) {
        Task {
            let challengeResult: AuthService.ChallengeResult?
            do {
                challengeResult = try await authService.getChallenge(username: username)
            } catch {
                await MainActor.run {
                    finishLoginWithError("获取挑战码失败: \(error)")
                }
                return
            }

            guard let result = challengeResult,
                  result.success,
                  let challenge = result.challenge,
                  let salt = result.salt else {
                await MainActor.run {
                    finishLoginWithError(challengeResult?.error ?? "获取挑战码失败")
                }
                return
            }

            let response = Crypto.computeAuthResponse(
                password: password,
                salt: salt,
                challenge: challenge
            )

            await MainActor.run {
                keychain.saveCredentials(username: username, password: password, token: "")
                loginUsername = username
                lastConnectionLog = nil
                webSocket?.connectAndLogin(
                    username: username,
                    response: response,
                    lat: 0, lng: 0, heading: 0
                )
            }
        }
    }

    private func finishLoginWithError(_ message: String) {
        uiState.loading = false
        uiState.autoLoggingIn = false
        uiState.error = message
        AppLog.e("登录失败：\(message)")
    }

    /// 退出登录：清凭证、断开连接，把界面恢复成"未登录"（登录矩形重新出现）
    func logout() {
        guard uiState.loggedIn else { return }
        AppLog.i("退出登录")
        resetSession()
    }

    /// 被服务器踢掉（同一账号在别处登录）：也回到未登录，但要说清楚原因，
    /// 否则会一直往一条已经不算数的连接上报位置
    func onForceLogout(message: String) {
        AppLog.w("账号在其他地方登录，本机已断开：\(message)")
        resetSession()
    }

    private func resetSession() {
        stopPositionHeartbeat()
        lastReported = nil
        webSocket?.delegate = nil
        webSocket?.disconnect()
        webSocket = nil
        locationManager?.stop()
        keychain.clearCredentials()

        loginUsername = nil
        lastConnectionLog = nil
        loggedSelfEcho = false
        otherUsers = []
        connectionStatus = 0
        onlineCount = 0

        uiState.loggedIn = false
        uiState.autoLoggingIn = false
        uiState.loading = false
        uiState.error = nil
        uiState.password = ""
        uiState.nickname = ""
        uiState.targetLat = nil
        uiState.targetLng = nil
        uiState.username = keychain.username ?? uiState.username

        rebuildWebSocket()
    }

    func clearError() {
        uiState.error = nil
    }
    // MARK: - 地图

    // 地图已准备好，获取当前位置
    func onFirstMapReady() {
        locationManager?.requestPermission()
        locationManager?.start()
        startPositionHeartbeat()
        onMapReady?()
    }

    /// 位置心跳。
    ///
    /// iOS 的 distanceFilter = 5 意味着"没走够 5 米就不再回调"，所以站着不动时
    /// 一条位置都不会发；而安卓那边是 LocationRequest 每 5 秒回调一次（没设
    /// 最小位移），所以服务器上安卓那份一直是新的、iOS 这份停在原地 —— 表现出来
    /// 就是蓝色箭头（服务器坐标）追不上金色三角，朝向也停在最后一次移动时的值。
    ///
    /// 这里补一个 5 秒心跳：重发最后的位置 + **当前**朝向（罗盘站着不动也会变），
    /// 顺便让 WebSocket 一直有流量（iOS 的 URLSessionWebSocketTask 空闲会被
    /// timeoutIntervalForRequest 掐掉，安卓那边 readTimeout 设的是 0，没这问题）。
    private func startPositionHeartbeat() {
        positionHeartbeat?.invalidate()
        positionHeartbeat = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.resendLastPosition()
        }
    }

    private func resendLastPosition() {
        guard uiState.loggedIn, let last = lastReported else { return }
        let heading = locationManager?.getCurrentHeading() ?? last.heading
        webSocket?.sendPosition(lat: last.lat, lng: last.lng, heading: heading)
    }

    private func stopPositionHeartbeat() {
        positionHeartbeat?.invalidate()
        positionHeartbeat = nil
    }

    func onMapClick(lat: Double, lng: Double) {
        setTarget(lat: lat, lng: lng)
    }

    func setTarget(lat: Double, lng: Double) {
        uiState.targetLat = lat
        uiState.targetLng = lng
        webSocket?.sendTarget(targetLat: lat, targetLng: lng)
    }

    func clearTarget() {
        uiState.targetLat = nil
        uiState.targetLng = nil
        webSocket?.sendTarget(targetLat: nil, targetLng: nil)
    }

    func onDestroy() {
        stopPositionHeartbeat()
        webSocket?.delegate = nil
        webSocket?.disconnect()
        locationManager?.stop()
    }

    /// 连接状态只在变化时写一行日志
    /// 日志里显示坐标用
    static func fmt(_ value: Double) -> String {
        String(format: "%.5f", value)
    }

    private func logConnection(_ status: Int, online: Int = 0) {
        let key = "\(status):\(online)"
        guard key != lastConnectionLog else { return }
        lastConnectionLog = key
        switch status {
        case 0: AppLog.i("服务器连接中…")
        case 1: AppLog.i("服务器已连接（在线 \(online) 人）")
        default: AppLog.w("服务器已断开")
        }
    }
}

// MARK: - WebSocketServiceDelegate

extension MapViewModel: WebSocketServiceDelegate {
    func onLoginSuccess(token: String, nickname: String) {
        keychain.token = token
        if loginUsername == nil { loginUsername = uiState.username }
        uiState.loggedIn = true
        uiState.loading = false
        uiState.autoLoggingIn = false
        uiState.error = nil
        uiState.nickname = nickname
        uiState.password = ""   // 密码不留在内存状态里
        loggedSelfEcho = false
        AppLog.i("登录成功：\(nickname.isEmpty ? uiState.username : nickname)")
    }

    func onLoginFailed(error: String) {
        finishLoginWithError("登录失败: \(error)")
    }

    func onUserList(users: [User]) {
        // user_list 是"全部在线的人"，里面已经有自己了，所以在线人数就是 users.count
        otherUsers = users
        updateConnectionStatus()
    }

    func onUserJoined(user: User) {
        // 同一账号重登时服务器会再广播一次 user_joined，而旧连接是被静默踢掉的（不发 user_left），
        // 所以这里按用户名覆盖，避免留下重复项、人数越登越多
        otherUsers.removeAll { $0.username == user.username }
        otherUsers.append(user)
        updateConnectionStatus()
    }

    func onUserLeft(username: String) {
        otherUsers.removeAll { $0.username == username }
        updateConnectionStatus()
    }

    func onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?) {
        if let index = otherUsers.firstIndex(where: { $0.username == username }) {
            otherUsers[index].targetLat = targetLat
            otherUsers[index].targetLng = targetLng
        }
    }

    func onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float) {
        // 服务器把我上报的位置回显回来了 —— 说明位置真的上去了
        if username == (loginUsername ?? uiState.username) {
            if !loggedSelfEcho {
                loggedSelfEcho = true
                AppLog.i("服务器确认了我的位置：\(MapViewModel.fmt(lat)), \(MapViewModel.fmt(lng))")
            }
            if !loggedEchoMismatch, let sent = lastReported,
               abs(sent.lat - lat) > 0.001 || abs(sent.lng - lng) > 0.001 {
                // 0.001° ≈ 100 米，比这个还大就不是"回显慢了一拍"能解释的了
                loggedEchoMismatch = true
                AppLog.w("服务器回显的位置和我刚发的不一致，上报可能没生效")
            }
        }
        if let index = otherUsers.firstIndex(where: { $0.username == username }) {
            otherUsers[index].lat = lat
            otherUsers[index].lng = lng
            otherUsers[index].heading = heading
        }
    }

    func onError(message: String) {
        AppLog.e(message)
        uiState.error = message
    }

    func onConnected() {
        connectionStatus = 1
        // 这时候还没登录、也没拿到 user_list，报人数一定是错的
        logConnection(0)
    }

    func onDisconnected() {
        connectionStatus = 2
        onlineCount = 0
        logConnection(2)
    }

    private func updateConnectionStatus() {
        onlineCount = otherUsers.count
        logConnection(1, online: onlineCount)
    }
}

// MARK: - LocationManagerDelegate

extension MapViewModel: LocationManagerDelegate {
    func didUpdateLocation(lat: Double, lng: Double, heading: Float) {
        lastReported = (lat, lng, heading)
        onSelfLocationUpdate?(lat, lng)
        // 是否真的发出去了由 WebSocketService 负责记日志（那边才知道 send 的结果）
        webSocket?.sendPosition(lat: lat, lng: lng, heading: heading)
    }
}
