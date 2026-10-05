import Foundation

/// list 回复（list_result）里的一个在线用户：名称 / ip / port。
/// 对应 Android `ui/login/LoginData.kt` 的 `PeerEntry`（字段严格对齐，不加多余字段）。
nonisolated struct PeerEntry: Equatable, Identifiable {
    var id: String { username }
    let username: String
    let ip: String
    let port: Int
}
