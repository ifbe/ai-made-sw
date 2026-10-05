import Foundation

/// UDP socket 上那点「必须按地址族区分对待」的样板。
///
/// 为什么需要它：为了 v4/v6 都能用，hello socket 会优先绑 `::`（双栈）。但 BSD 要求
/// **目的地地址族和 socket 地址族一致** —— 在 AF_INET6 的 socket 上往 v4 目的地发数据，
/// 必须把地址写成 v4-mapped（`::ffff:a.b.c.d` 的 `sockaddr_in6`），直接丢一个
/// `sockaddr_in` 过去会 `EAFNOSUPPORT`。
/// Java 的 `DatagramSocket.send()` 会自动做这个转换，所以 Android 那边不用管，
/// C 这边必须自己转（对应 Android `data/remote/WsClient.kt` 的 `createHelloSocket()`）。
///
/// 另外 `sin_port` / `sin6_port` 都是网络字节序，取值时一定要 `UInt16(bigEndian:)`
/// （原来 iOS 写成 `Int(sin_port).bigEndian` 是错的，见本轮 A2）。
nonisolated enum UdpSocket {

    /// 查 socket 的地址族（AF_INET / AF_INET6）；查不到返回 AF_UNSPEC
    static func family(of fd: Int32) -> sa_family_t {
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(fd, sa, &len)
            }
        }
        guard ok == 0 else { return sa_family_t(AF_UNSPEC) }
        return storage.ss_family
    }

    /// socket 的本地端口（主机字节序）。按 socket 实际地址族解析，双栈 socket 返回 sockaddr_in6 的端口。
    static func localPort(of fd: Int32) -> Int {
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(fd, sa, &len)
            }
        }
        guard ok == 0 else { return 0 }
        if storage.ss_family == sa_family_t(AF_INET6) {
            let addr = withUnsafePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            }
            return Int(UInt16(bigEndian: addr.sin6_port))
        }
        let addr = withUnsafePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        }
        return Int(UInt16(bigEndian: addr.sin_port))
    }

    /// socket 本机绑定的地址（未指定地址就返回 "::" / "0.0.0.0"，和 Android 的展示一致）
    static func localIp(of fd: Int32) -> String {
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(fd, sa, &len)
            }
        }
        guard ok == 0 else { return "" }
        if storage.ss_family == sa_family_t(AF_INET6) {
            let addr = withUnsafePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            }
            var a = addr.sin6_addr
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return "::" }
            return String(cString: buf)
        }
        let addr = withUnsafePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        }
        var a = addr.sin_addr
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return "0.0.0.0" }
        return String(cString: buf)
    }

    /// 建一个 UDP socket 并绑到 bindIp:0（临时端口）。
    /// - `bindIp = "::"`：双栈，显式把 `IPV6_V6ONLY` 关掉（既能收 v6，也能收 v4-mapped）；
    /// - `bindIp = "0.0.0.0"`：纯 v4。
    /// 成功返回 fd，失败返回 -1（失败时已经把 fd 关掉了）。
    static func openBound(_ bindIp: String) -> Int32 {
        let isV6 = bindIp.contains(":")
        let fd = isV6 ? Darwin.socket(AF_INET6, SOCK_DGRAM, 0) : Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        if fd < 0 { return -1 }

        if isV6 {
            var off: Int32 = 0
            if setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, socklen_t(MemoryLayout<Int32>.size)) < 0 {
                Darwin.close(fd)
                return -1
            }
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = 0
            if bindIp == "::" {
                addr.sin6_addr = in6addr_any
            } else if bindIp.withCString({ inet_pton(AF_INET6, $0, &addr.sin6_addr) }) != 1 {
                Darwin.close(fd)
                return -1
            }
            let ok = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
            if ok < 0 {
                Darwin.close(fd)
                return -1
            }
            return fd
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = 0
        addr.sin_port = 0
        let ok = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if ok < 0 {
            Darwin.close(fd)
            return -1
        }
        return fd
    }

    /// 把主机名解析成 IP 字面量（**IPv4 优先**，没有 v4 才用 v6）。
    ///
    /// 为什么必须有它：服务端 `send_udp_to_server` **只发 `udpport`，从不发 `server_ip`**
    /// （`server/server.py` 里 `server_ip` 0 处命中），而 `sendto` 只认 IP 字面量 ——
    /// 喂域名会直接失败（实测 `send(ip: "localhost")` → `-1 errno=22 EINVAL`）。
    /// 所以"给服务器 UDP 端口发 hello"之前必须自己解析，对齐安卓
    /// `WsClient.kt` 里的 `InetAddress.getByName(serverHost)` 兜底。
    ///
    /// 用 `getaddrinfo(AF_UNSPEC)`；结果经 `getnameinfo(NI_NUMERICHOST)` 转成纯数字形式，
    /// 并去掉 v6 可能带的 `%en0` scope 后缀（与 `LocalAddrs` 的处理保持一致）。
    static func resolveHost(_ host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(trimmed, nil, &hints, &info) == 0, let head = info else { return nil }
        defer { freeaddrinfo(head) }

        var v6: String?
        var cursor: UnsafeMutablePointer<addrinfo>? = head
        while let cur = cursor {
            let ai = cur.pointee
            if let sa = ai.ai_addr {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(sa, ai.ai_addrlen, &buf, socklen_t(NI_MAXHOST), nil, 0, NI_NUMERICHOST) == 0 {
                    let text = stripScope(String(cString: buf))
                    if ai.ai_family == AF_INET { return text }        // v4 优先
                    if ai.ai_family == AF_INET6, v6 == nil { v6 = text }
                }
            }
            cursor = ai.ai_next
        }
        return v6
    }

    /// 去掉 v6 的 `%en0` scope 后缀（`sendto` 只认纯地址；与 `LocalAddrs` 一致）
    static func stripScope(_ ip: String) -> String {
        return ip.split(separator: "%").first.map(String.init) ?? ip
    }

    /// 往 ip:port 发一个数据报；自动按 socket 地址族把 v4 目的地转成 v4-mapped。
    /// 返回 sendto 的返回值（<0 = 失败，errno 有效）。
    @discardableResult
    static func send(fd: Int32, data: Data, ip: String, port: Int) -> Int {
        let targetIsV6 = ip.contains(":")
        let sockIsV6 = family(of: fd) == sa_family_t(AF_INET6)

        if targetIsV6 || sockIsV6 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = UInt16(port).bigEndian
            // 双栈 socket 上的 v4 目的地必须写成 v4-mapped
            let text = targetIsV6 ? ip : "::ffff:\(ip)"
            guard text.withCString({ inet_pton(AF_INET6, $0, &addr.sin6_addr) }) == 1 else {
                errno = EINVAL
                return -1
            }
            return withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    data.withUnsafeBytes { bytes in
                        sendto(fd, bytes.baseAddress, data.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        guard ip.withCString({ inet_pton(AF_INET, $0, &addr.sin_addr) }) == 1 else {
            errno = EINVAL
            return -1
        }
        return withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                data.withUnsafeBytes { bytes in
                    sendto(fd, bytes.baseAddress, data.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }
}
