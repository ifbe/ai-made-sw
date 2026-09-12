import Foundation

/// 地图页的状态。登录矩形、两个角面板都读它。
/// `LoginUiState` 已经合并进来：登录表单现在长在地图页上，不再是单独一页。
struct MapUiState {
    var loggedIn: Bool = false
    var autoLoggingIn: Bool = false
    var loading: Bool = false
    var serverUrl: String = Constants.defaultServerUrl
    var username: String = ""
    var password: String = ""
    var nickname: String = ""
    var error: String?
    var targetLat: Double?
    var targetLng: Double?
}
