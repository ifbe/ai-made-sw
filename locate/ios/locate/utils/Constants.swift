import Foundation

enum Constants {
    // TODO: 部署前改成实际服务器地址
    static let defaultServerUrl = "https://deepstack.tech:9999"

    static let apiChallenge = "/api/challenge"
    static let wsPath = "/"

    static let challengeTimeoutMs: Int64 = 30_000
    static let locationUpdateIntervalMs: Int64 = 5_000
    static let locationFastestIntervalMs: Int64 = 3_000

    static let notificationChannelId = "location_tracker"
    static let notificationId = 1001

    static let prefsName = "secure_prefs"
    static let keyUsername = "username"
    static let keyPassword = "***"
    static let keyToken = "***"
    static let keyServerUrl = "server_url"

    /// 中国大陆地区代码，需要做 WGS84→GCJ02 转换
    static let cnRegions: Set<String> = ["CN", "TW", "HK", "MO"]
}