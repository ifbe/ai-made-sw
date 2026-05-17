import Foundation

struct MapUiState {
    var loggedIn: Bool = false
    var autoLoggingIn: Bool = false
    var nickname: String = ""
    var error: String?
    var targetLat: Double?
    var targetLng: Double?
}

struct LoginUiState {
    var serverUrl: String = Constants.defaultServerUrl
    var username: String = ""
    var password: String = ""
    var loading: Bool = false
    var error: String?
    var autoLogin: Bool = false
}