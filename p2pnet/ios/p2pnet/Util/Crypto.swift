import Foundation
import CommonCrypto

enum Crypto {
    static func sha256(_ input: String) -> String {
        let data = Data(input.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    static func sha256Bytes(_ input: String) -> Data {
        let data = Data(input.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    static func hmacSHA256(key: Data, data: Data) -> Data {
        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { keyPtr in
            data.withUnsafeBytes { dataPtr in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyPtr.baseAddress, key.count, dataPtr.baseAddress, data.count, &hmac)
            }
        }
        return Data(hmac)
    }

    static func hmacSHA256Hex(key: Data, data: Data) -> String {
        return hmacSHA256(key: key, data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func hexToBytes(_ hex: String) -> Data {
        var bytes = [UInt8]()
        for i in stride(from: 0, to: hex.count, by: 2) {
            let start = hex.index(hex.startIndex, offsetBy: i)
            let end = hex.index(start, offsetBy: 2)
            let byte = UInt8(hex[start..<end], radix: 16)!
            bytes.append(byte)
        }
        return Data(bytes)
    }

    static func computeAuthResponse(password: String, salt: String, challenge: String) -> String {
        let pwHash = sha256(password + salt)
        let pwHashBytes = hexToBytes(pwHash)
        let challengeBytes = hexToBytes(challenge)
        let hmac = hmacSHA256(key: pwHashBytes, data: challengeBytes)
        return hmac.map { String(format: "%02x", $0) }.joined()
    }

    static func generateRandomBase64(_ byteLen: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteLen)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteLen, &bytes)
        return Data(bytes).base64EncodedString()
    }
}