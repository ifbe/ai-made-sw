import Foundation

enum AuthError: Error {
    case networkError(String)
    case serverError(String)
}

final class AuthService {
    private let serverUrl: String
    private let keychain: KeychainStorage

    init(serverUrl: String, keychain: KeychainStorage) {
        self.serverUrl = serverUrl
        self.keychain = keychain
    }

    struct ChallengeResult {
        let success: Bool
        let challenge: String?
        let salt: String?
        let error: String?
    }

    /// 获取 challenge（对应 Android 的 AuthApi.getChallenge）
    /// POST /api/challenge { "username": "xxx" }
    func getChallenge(username: String) async throws -> ChallengeResult {
        guard let url = URL(string: serverUrl + Constants.apiChallenge) else {
            throw AuthError.networkError("无效的服务器地址")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10

        let body = ["username": username]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthError.networkError("服务器响应无效")
        }

        guard httpResponse.statusCode == 200 else {
            throw AuthError.serverError("HTTP \(httpResponse.statusCode)")
        }

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let success = json?["success"] as? Bool ?? false

        return ChallengeResult(
            success: success,
            challenge: json?["challenge"] as? String,
            salt: json?["salt"] as? String,
            error: json?["error"] as? String
        )
    }

    /// 登录（完整流程：获取 challenge → 计算 response → WebSocket 登录）
    /// 对应 Android 的 AuthRepository.login
    func login(
        username: String,
        password: String,
        webSocket: WebSocketService,
        onSuccess: @escaping (String, String) -> Void,
        onError: @escaping (String) -> Void
    ) {
        Task {
            // 1. 获取 challenge
            let result: ChallengeResult
            do {
                result = try await getChallenge(username: username)
            } catch {
                await MainActor.run { onError("获取挑战码失败: \(error)") }
                return
            }

            guard result.success,
                  let challenge = result.challenge,
                  let salt = result.salt else {
                await MainActor.run { onError(result.error ?? "获取挑战码失败") }
                return
            }

            // 2. 计算 response
            let response = Crypto.computeAuthResponse(
                password: password,
                salt: salt,
                challenge: challenge
            )

            // 3. 保存原始 listener，WebSocket 登录后由外部设置回调
            // 这里只负责把 credentials 存起来
            keychain.saveCredentials(username: username, password: password, token: "")

            // 连接并登录（回调由 MapViewModel 设置）
            webSocket.connectAndLogin(
                username: username,
                response: response,
                lat: 0,
                lng: 0,
                heading: 0
            )
        }
    }

    func logout() {
        keychain.clearCredentials()
    }

    var savedUsername: String? {
        keychain.username
    }

    var hasSavedCredentials: Bool {
        keychain.hasCredentials()
    }

    var currentServerUrl: String {
        get { keychain.serverUrl }
        set {
            keychain.serverUrl = newValue
        }
    }
}