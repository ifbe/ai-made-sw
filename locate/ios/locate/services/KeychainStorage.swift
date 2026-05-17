import Foundation
import Combine
import Security

/// 安全存储，替代 Android 的 EncryptedSharedPreferences
/// 使用 iOS Keychain 存储用户名、密码、token
/// ObservableObject 包装，使其可用于 SwiftUI @State/@StateObject
final class KeychainStorage: ObservableObject {
    private let service = "com.example.locate"

    private enum Keys {
        static let username = "username"
        static let password = "password"
        static let token = "token"
        static let serverUrl = "server_url"
    }

    // MARK: - Public Properties

    var username: String? {
        get { getString(Keys.username) }
        set {
            setString(newValue, forKey: Keys.username)
            objectWillChange.send()
        }
    }

    var password: String? {
        get { getString(Keys.password) }
        set {
            setString(newValue, forKey: Keys.password)
            objectWillChange.send()
        }
    }

    var token: String? {
        get { getString(Keys.token) }
        set {
            setString(newValue, forKey: Keys.token)
            objectWillChange.send()
        }
    }

    var serverUrl: String {
        get { getString(Keys.serverUrl) ?? Constants.defaultServerUrl }
        set {
            setString(newValue, forKey: Keys.serverUrl)
            objectWillChange.send()
        }
    }

    // MARK: - Credentials

    func saveCredentials(username: String, password: String, token: String) {
        setString(username, forKey: Keys.username)
        setString(password, forKey: Keys.password)
        setString(token, forKey: Keys.token)
    }

    func clearCredentials() {
        delete(Keys.username)
        delete(Keys.password)
        delete(Keys.token)
        objectWillChange.send()
    }

    func hasCredentials() -> Bool {
        return username != nil && password != nil
    }

    // MARK: - Private Helpers

    private func getString(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        return string
    }

    private func setString(_ value: String?, forKey key: String) {
        delete(key)
        guard let value = value else { return }

        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        SecItemAdd(query as CFDictionary, nil)
    }

    private func delete(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}