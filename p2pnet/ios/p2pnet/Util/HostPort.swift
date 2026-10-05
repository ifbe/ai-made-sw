import Foundation

/// v4/v6 通用的「地址:端口」显示（对齐 Android `net/NetFormat.kt` 的 `formatHostPort`）。
///
/// IPv6 里冒号本身就是地址的一部分，所以必须写成 `[地址]:端口`，
/// 直接拼 `\(ip):\(port)` 会变成 `2001:db8::1:4574` 这种没法读的字符串。
nonisolated func formatHostPort(_ ip: String, _ port: Int) -> String {
    let host = ip.trimmingCharacters(in: .whitespaces)
    if host.isEmpty { return ":\(port)" }
    if host.contains(":") && !host.hasPrefix("[") { return "[\(host)]:\(port)" }
    return "\(host):\(port)"
}
