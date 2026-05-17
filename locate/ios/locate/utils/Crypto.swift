import Foundation
import CommonCrypto

/// 加密工具类
/// 对应 Android 的 Crypto.kt，算法完全一致：
/// 1. password_hash = SHA256(password + salt)
/// 2. response = HMAC-SHA256(password_hash, challenge)
enum Crypto {
    /// 计算 SHA256 哈希
    static func sha256(_ input: String) -> String {
        let data = Data(input.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    /// 计算 HMAC-SHA256
    /// key: password_hash, data: challenge
    static func hmacSha256(key: String, data: String) -> String {
        let keyData = Data(key.utf8)
        let messageData = Data(data.utf8)

        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        keyData.withUnsafeBytes { keyBuffer in
            messageData.withUnsafeBytes { msgBuffer in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    keyBuffer.baseAddress,
                    keyData.count,
                    msgBuffer.baseAddress,
                    messageData.count,
                    &hmac
                )
            }
        }
        return hmac.map { String(format: "%02x", $0) }.joined()
    }

    /// 根据服务器规则计算认证响应
    /// password_hash = SHA256(password + salt)
    /// response = HMAC-SHA256(password_hash, challenge)
    static func computeAuthResponse(password: String, salt: String, challenge: String) -> String {
        let passwordHash = sha256(password + salt)
        return hmacSha256(key: passwordHash, data: challenge)
    }
}