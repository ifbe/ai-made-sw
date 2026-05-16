import Foundation
import Combine

struct LoginUiState: Equatable {
    var useWss: Bool = false
    var serverHost: String = "deepstack.tech"
    var serverPort: String = "10000"
    var username: String = "test"
    var password: String = "test"
    var targetUsername: String = ""
    var loading: Bool = false
    var isConnected: Bool = false
    var isLoggedIn: Bool = false
    var loggedInUsername: String = ""
    var error: String? = nil
    var messages: [MessageItem] = []
    var tabs: [TabItem] = [TabItem.main(), TabItem.wireGuard()]
    var currentTabIndex: Int = 0
    var currentPage: Page = .main
}