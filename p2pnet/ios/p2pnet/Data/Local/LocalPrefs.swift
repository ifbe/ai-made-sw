import Foundation

struct Constants {
    static let defaultServerHost = "deepstack.tech"
    static let defaultServerPort = 10000
    static let prefsName = "p2pnet_prefs"
    static let keyServerHost = "server_host"
    static let keyServerPort = "server_port"
    static let keyUsername = "username"
    static let keyLoggedIn = "logged_in"
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

    func clearSession() {
        defaults.removeObject(forKey: Constants.keyUsername)
        defaults.set(false, forKey: Constants.keyLoggedIn)
    }
}