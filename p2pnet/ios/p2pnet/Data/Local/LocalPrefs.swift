import Foundation

struct Constants {
    static let defaultServerHost = "deepstack.tech"
    static let defaultServerPort = 10000
    static let prefsName = "p2pnet_prefs"
    static let keyServerHost = "server_host"
    static let keyServerPort = "server_port"
    static let keyUsername = "username"
    static let keyLoggedIn = "logged_in"
    /// 两个配置页的配置就存 JSON 原文（解析和默认值在 Models/PageConfig.swift 里）。
    /// 键名和 Android `util/Constants.kt` 保持一致。
    static let keyWgConfig = "wg_config"
    static let keySwitchConfig = "switch_config"
    static let keyProxyConfig = "proxy_config"
    static let keyVpnConfig = "vpn_config"
    static let keyMediaConfig = "media_config"
}

class LocalPrefs {
    private let defaults: UserDefaults

    init() {
        defaults = UserDefaults(suiteName: Constants.prefsName) ?? .standard
    }

    var serverHost: String {
        get { defaults.string(forKey: Constants.keyServerHost) ?? Constants.defaultServerHost }
        set { defaults.set(newValue, forKey: Constants.keyServerHost) }
    }

    var serverPort: Int {
        get { defaults.integer(forKey: Constants.keyServerPort) != 0 ? defaults.integer(forKey: Constants.keyServerPort) : Constants.defaultServerPort }
        set { defaults.set(newValue, forKey: Constants.keyServerPort) }
    }

    var username: String? {
        get { defaults.string(forKey: Constants.keyUsername) }
        set { defaults.set(newValue, forKey: Constants.keyUsername) }
    }

    var loggedIn: Bool {
        get { defaults.bool(forKey: Constants.keyLoggedIn) }
        set { defaults.set(newValue, forKey: Constants.keyLoggedIn) }
    }

    /// WireGuard 页配置（JSON 原文，解析见 Models/PageConfig.swift）
    var wgConfigJson: String? {
        get { defaults.string(forKey: Constants.keyWgConfig) }
        set { defaults.set(newValue, forKey: Constants.keyWgConfig) }
    }

    /// Switch 页配置（JSON 原文）
    var switchConfigJson: String? {
        get { defaults.string(forKey: Constants.keySwitchConfig) }
        set { defaults.set(newValue, forKey: Constants.keySwitchConfig) }
    }

    /// Proxy 页配置（JSON 原文）
    var proxyConfigJson: String? {
        get { defaults.string(forKey: Constants.keyProxyConfig) }
        set { defaults.set(newValue, forKey: Constants.keyProxyConfig) }
    }

    /// VPN 页配置（JSON 原文）
    var vpnConfigJson: String? {
        get { defaults.string(forKey: Constants.keyVpnConfig) }
        set { defaults.set(newValue, forKey: Constants.keyVpnConfig) }
    }

    /// media 页配置（JSON 原文）
    var mediaConfigJson: String? {
        get { defaults.string(forKey: Constants.keyMediaConfig) }
        set { defaults.set(newValue, forKey: Constants.keyMediaConfig) }
    }

    func clearSession() {
        defaults.removeObject(forKey: Constants.keyUsername)
        defaults.set(false, forKey: Constants.keyLoggedIn)
    }
}