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
    private var keychain: KeychainStorage

    // 回调：地图 ready 后需要调用
    var onMapReady: (() -> Void)?
    var onSelfLocationUpdate: ((Double, Double) -> Void)?
    // 服务器广播回来的自己的位置（调试用，绿色标记）
    var onServerPositionUpdate: ((Double, Double, Float) -> Void)?

    init(keychain: KeychainStorage, serverUrl: String) {
        self.keychain = keychain
        self.authService = AuthService(serverUrl: serverUrl, keychain: keychain)

        setupWebSocket()
        attemptAutoLogin()
    }

    private func setupWebSocket() {
        webSocket = WebSocketService(serverUrl: keychain.serverUrl)
        webSocket?.delegate = self

        locationManager = LocationManager()
        locationManager?.delegate = self
    }

    private func attemptAutoLogin() {
        guard let username = keychain.username,
              let password = keychain.password else { return }

        uiState.autoLoggingIn = true

        Task {
            // 获取 challenge
            guard let result = try? await authService.getChallenge(username: username),
                  result.success,
                  let challenge = result.challenge,
                  let salt = result.salt else {
                await MainActor.run {
                    uiState.autoLoggingIn = false
                }
                return
            }

            let response = Crypto.computeAuthResponse(
                password: password,
                salt: salt,
                challenge: challenge
            )

            await MainActor.run {
                uiState.autoLoggingIn = false
                loginUsername = username
                webSocket?.connectAndLogin(
                    username: username,
                    response: response,
                    lat: 0, lng: 0, heading: 0
                )
            }
        }
    }

    // 地图已准备好，获取当前位置
    func onFirstMapReady() {
        locationManager?.requestPermission()
        locationManager?.start()
        onMapReady?()
    }

    func onMapClick(lat: Double, lng: Double) {
        uiState.targetLat = lat
        uiState.targetLng = lng
        webSocket?.sendTarget(targetLat: lat, targetLng: lng)
    }

    func clearTarget() {
        uiState.targetLat = nil
        uiState.targetLng = nil
        webSocket?.sendTarget(targetLat: nil, targetLng: nil)
    }

    func setTarget(lat: Double, lng: Double) {
        uiState.targetLat = lat
        uiState.targetLng = lng
        webSocket?.sendTarget(targetLat: lat, targetLng: lng)
    }

    func logout() {
        keychain.clearCredentials()
        webSocket?.disconnect()
        locationManager?.stop()
    }

    func clearError() {
        uiState.error = nil
    }

    func onDestroy() {
        webSocket?.delegate = nil
        webSocket?.disconnect()
        locationManager?.stop()
    }
}

// MARK: - WebSocketServiceDelegate

extension MapViewModel: WebSocketServiceDelegate {
    func onLoginSuccess(token: String, nickname: String) {
        uiState.loggedIn = true
        uiState.nickname = nickname
        keychain.token = token
    }

    func onLoginFailed(error: String) {
        uiState.error = "登录失败: \(error)"
    }

    func onUserList(users: [User]) {
        otherUsers = users  // 不过滤，全部显示
        updateConnectionStatus()
    }

    func onUserJoined(user: User) {
        if !otherUsers.contains(where: { $0.username == user.username }) {
            otherUsers.append(user)
        }
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
        if username == loginUsername {
            // 服务器广播回来的自己的位置 → 更新自己的坐标到列表
            if let index = otherUsers.firstIndex(where: { $0.username == username }) {
                otherUsers[index].lat = lat
                otherUsers[index].lng = lng
                otherUsers[index].heading = heading
            }
        } else {
            if let index = otherUsers.firstIndex(where: { $0.username == username }) {
                otherUsers[index].lat = lat
                otherUsers[index].lng = lng
                otherUsers[index].heading = heading
            }
        }
    }

    func onError(message: String) {
        uiState.error = message
    }

    func onConnected() {
        connectionStatus = 1
        updateConnectionStatus()
    }

    func onDisconnected() {
        connectionStatus = 2
        onlineCount = 0
    }

    private func updateConnectionStatus() {
        onlineCount = otherUsers.count
    }
}

// MARK: - LocationManagerDelegate

extension MapViewModel: LocationManagerDelegate {
    func didUpdateLocation(lat: Double, lng: Double, heading: Float) {
        onSelfLocationUpdate?(lat, lng)
        webSocket?.sendPosition(lat: lat, lng: lng, heading: heading)
    }
}