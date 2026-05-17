import Foundation
import Combine

final class LoginViewModel: ObservableObject {
    @Published var uiState = LoginUiState()
    @Published var loginSuccess: Bool = false

    private var authService: AuthService
    private let keychain: KeychainStorage
    private var webSocket: WebSocketService?
    private var savedListener: WebSocketServiceDelegate?

    init(keychain: KeychainStorage) {
        self.keychain = keychain
        self.authService = AuthService(
            serverUrl: keychain.serverUrl,
            keychain: keychain
        )

        checkSavedCredentials()
    }

    private func checkSavedCredentials() {
        if authService.hasSavedCredentials {
            uiState.username = keychain.username ?? ""
            uiState.autoLogin = true
        }
    }

    func onServerUrlChange(_ serverUrl: String) {
        guard serverUrl != uiState.serverUrl else { return }
        uiState.serverUrl = serverUrl
        keychain.serverUrl = serverUrl
        authService = AuthService(serverUrl: serverUrl, keychain: keychain)
    }

    func onUsernameChange(_ username: String) {
        uiState.username = username
    }

    func onPasswordChange(_ password: String) {
        uiState.password = password
    }

    func onLogin(navigateToMap: @escaping () -> Void) {
        let state = uiState
        guard !state.username.isEmpty, !state.password.isEmpty else {
            uiState.error = "请输入用户名和密码"
            return
        }

        uiState.loading = true
        uiState.error = nil

        Task {
            // 获取 challenge
            let challengeResult: AuthService.ChallengeResult?
            do {
                challengeResult = try await authService.getChallenge(username: state.username)
            } catch {
                await MainActor.run {
                    uiState.loading = false
                    uiState.error = "获取挑战码失败: \(error)"
                }
                return
            }

            guard let res = challengeResult,
                  res.success,
                  let challenge = res.challenge,
                  let salt = res.salt else {
                await MainActor.run {
                    uiState.loading = false
                    uiState.error = challengeResult?.error ?? "获取挑战码失败"
                }
                return
            }

            // 2. 计算 response
            let response = Crypto.computeAuthResponse(
                password: state.password,
                salt: salt,
                challenge: challenge
            )

            await MainActor.run {
                uiState.loading = false

                // 3. 保存凭证
                keychain.saveCredentials(
                    username: state.username,
                    password: state.password,
                    token: ""
                )

                // 4. 连接 WebSocket
                webSocket = WebSocketService(serverUrl: keychain.serverUrl)
                webSocket?.delegate = self

                webSocket?.connectAndLogin(
                    username: state.username,
                    response: response,
                    lat: 0, lng: 0, heading: 0
                )
            }
        }
    }

    func onPermissionsGranted() {
        loginSuccess = true
    }

    func clearError() {
        uiState.error = nil
    }
}

extension LoginViewModel: WebSocketServiceDelegate {
    func onLoginSuccess(token: String, nickname: String) {
        keychain.token = token
        loginSuccess = true
    }

    func onLoginFailed(error: String) {
        uiState.error = "登录失败: \(error)"
    }

    func onUserList(users: [User]) { }
    func onUserJoined(user: User) { }
    func onUserLeft(username: String) { }
    func onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?) { }
    func onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float) { }
    func onError(message: String) { }
    func onConnected() { }
    func onDisconnected() { }
}