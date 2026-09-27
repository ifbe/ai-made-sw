//
//  NetAddress.swift
//  chess
//
//  对照 Android: net/NetAddress.kt
//

import Foundation

/// 解析好的目标地址（等价于 Android 侧的 `java.net.URI`，但我们只关心 host / port / scheme）。
struct WsEndpoint: Equatable {
    var scheme: String
    var host: String
    var port: Int

    var uri: String { "\(scheme)://\(host):\(port)" }
}

/// 地址相关的小工具：找本机局域网 IP、把用户输入变成 ws:// 地址。
enum NetAddress {

    static let defaultPort = 8765

    /// 本机局域网 IPv4：优先 192.168.*，没有再退到其它私有网段。
    static func localIpv4() -> String? {
        var found: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ptr = cursor {
            defer { cursor = ptr.pointee.ifa_next }
            let flags = Int32(ptr.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard let sa = ptr.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                sa, socklen_t(sa.pointee.sa_len),
                &host, socklen_t(host.count),
                nil, 0,
                NI_NUMERICHOST
            )
            guard result == 0 else { continue }
            let ip = String(cString: host)
            // 等价于 Kotlin 的 isSiteLocalAddress：10/8、172.16/12、192.168/16
            if isSiteLocalIPv4(ip) { found.append(ip) }
        }

        return found.first { $0.hasPrefix("192.168.") } ?? found.first
    }

    private static func isSiteLocalIPv4(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        if parts[0] == 10 { return true }
        if parts[0] == 192 && parts[1] == 168 { return true }
        if parts[0] == 172 && (16...31).contains(parts[1]) { return true }
        return false
    }

    /// 服务端模式下文本框里显示的地址。
    static func serverAddress(port: Int = defaultPort) -> String {
        "\(localIpv4() ?? "本机没连局域网"):\(port)"
    }

    /// 从「ip:端口」里取端口；没写或不合法就用默认端口。
    static func portOf(_ text: String?, defaultPort: Int = NetAddress.defaultPort) -> Int {
        let raw = (text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard let colon = raw.lastIndex(of: ":") else { return defaultPort }
        let portText = String(raw[raw.index(after: colon)...])
        guard let port = Int(portText), (1...65535).contains(port) else { return defaultPort }
        return port
    }

    /// 用户输入 → ws 地址。允许省略 `ws://` 前缀，也允许不写端口（补默认端口）。
    /// 不合法返回 nil（界面据此报「地址不对」）。
    static func toWsEndpoint(_ text: String?, defaultPort: Int = NetAddress.defaultPort) -> WsEndpoint? {
        let raw = (text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return nil }
        // Android 的 URI 遇到空格 / 非法字符会直接抛异常；这里手动挡掉，行为一致。
        if raw.contains(where: { $0.isWhitespace }) { return nil }

        let scheme: String
        let rest: String
        if raw.hasPrefix("ws://") {
            scheme = "ws"
            rest = String(raw.dropFirst("ws://".count))
        } else if raw.hasPrefix("wss://") {
            scheme = "wss"
            rest = String(raw.dropFirst("wss://".count))
        } else {
            scheme = "ws"
            rest = raw
        }
        if rest.isEmpty { return nil }

        // 只取 host[:port]，后面的 path 忽略（和 Android 只取 host/port 一致）
        let authority = rest.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)[0]
        if authority.isEmpty { return nil }

        if let colon = authority.lastIndex(of: ":") {
            let host = String(authority[authority.startIndex..<colon])
            let portText = String(authority[authority.index(after: colon)...])
            guard !host.isEmpty else { return nil }
            if portText.isEmpty {
                return WsEndpoint(scheme: scheme, host: host, port: defaultPort)
            }
            guard let port = Int(portText), (1...65535).contains(port) else { return nil }
            return WsEndpoint(scheme: scheme, host: host, port: port)
        }

        return WsEndpoint(scheme: scheme, host: String(authority), port: defaultPort)
    }
}
