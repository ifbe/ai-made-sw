import Foundation

/// direct 用的地址工具：枚举本机地址（发给服务器 / 回给对方）、清洗对方给过来的地址。
///
/// 对齐 Android `net/LocalAddrs.kt`（以及 python 端 `client/hole/direct.py`）：
/// - 过滤 loopback / link-local / 组播 / 未指定，**不过滤私有地址**
///   （10/8、172.16/12、192.168/16 正是同局域网直连要用的）
/// - v6 去掉 `%en0` 这种 scope 后缀，否则服务端 `inet_pton` 会判非法直接扔
/// - 每族最多 32 条，和服务端 `MAX_DIRECT_ADDRS` 一致
nonisolated enum LocalAddrs {

    /// 每族最多报这么多条（和 server.py 的 MAX_DIRECT_ADDRS 一致）
    static let maxPerFamily = 32

    /// 枚举本机所有可用网卡的地址，返回 (v4, v6)
    static func localAddresses() -> (v4: [String], v6: [String]) {
        var v4: [String] = []
        var v6: [String] = []

        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return ([], []) }
        defer { freeifaddrs(ifaddrPtr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = ptr {
            let entry = cur.pointee
            ptr = entry.ifa_next

            guard let sa = entry.ifa_addr else { continue }
            let flags = Int32(entry.ifa_flags)
            // 接口 down / loopback 直接跳过
            if (flags & IFF_UP) == 0 || (flags & IFF_LOOPBACK) != 0 { continue }

            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                guard let addr = ipv4String(sa) else { continue }
                guard isUsableV4(addr), !v4.contains(addr), v4.count < maxPerFamily else { continue }
                v4.append(addr)
            case AF_INET6:
                guard var addr = ipv6String(sa) else { continue }
                addr = addr.trimmingCharacters(in: .whitespaces)
                guard isUsableV6(addr), !v6.contains(addr), v6.count < maxPerFamily else { continue }
                v6.append(addr)
            default:
                continue
            }
        }
        return (v4, v6)
    }

    /// 清洗对方给过来的地址（服务端已经过滤过一遍，这里只去空、去重、保序）
    static func dedupeAddrs(_ raw: [String]) -> [String] {
        var out: [String] = []
        for item in raw {
            let s = item.trimmingCharacters(in: .whitespaces)
            if !s.isEmpty && !out.contains(s) { out.append(s) }
        }
        return out
    }

    // MARK: - 内部

    private static func ipv4String(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        let addr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in.self).pointee
        var a = addr.sin_addr
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
        return String(cString: buf)
    }

    /// v6：去掉 `%en0` 这种 scope 后缀
    private static func ipv6String(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        let addr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in6.self).pointee
        var a = addr.sin6_addr
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
        return String(cString: buf).split(separator: "%").first.map(String.init)
    }

    /// v4 可用性：排除 loopback / link-local(169.254/16) / 组播(224/4) / 未指定 / 广播
    private static func isUsableV4(_ ip: String) -> Bool {
        var raw = in_addr()
        guard inet_pton(AF_INET, ip, &raw) == 1 else { return false }
        let bytes = withUnsafeBytes(of: raw) { Array($0) }
        guard bytes.count == 4 else { return false }
        if bytes[0] == 127 { return false }                                  // loopback
        if bytes[0] == 169 && bytes[1] == 254 { return false }                // link-local
        if bytes[0] >= 224 && bytes[0] <= 239 { return false }                // multicast
        if bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255 { return false }
        if bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 { return false }
        return true
    }

    /// v6 可用性：排除 loopback(::1) / link-local(fe80::/10) / 组播(ff00::/8) / 未指定(::)
    private static func isUsableV6(_ ip: String) -> Bool {
        var raw = in6_addr()
        guard inet_pton(AF_INET6, ip, &raw) == 1 else { return false }
        let bytes = withUnsafeBytes(of: raw) { Array($0) }
        guard bytes.count == 16 else { return false }
        if bytes.allSatisfy({ $0 == 0 }) { return false }                     // ::
        if bytes[0] == 0xff { return false }                                  // 组播
        if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 { return false }      // link-local
        let isLoopback = bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] == 1
        if isLoopback { return false }                                        // ::1
        return true
    }
}
