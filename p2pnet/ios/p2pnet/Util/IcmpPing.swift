import Foundation

/// direct 的可达性探测：非特权 ICMP（`SOCK_DGRAM` + `IPPROTO_ICMP` / `IPPROTO_ICMPV6`）。
///
/// 为什么不用更省事的办法：
///  - iOS 没有 `ping` 命令可调（Android 是子进程调 `/system/bin/ping`）；
///  - `SOCK_RAW` 需要 root；
///  - `Network.framework` 的 `NWConnection` 只能测 TCP/UDP 端口，测不了 ICMP。
/// 所以自己组 echo request：`SOCK_DGRAM` 的 ICMP socket 在 iOS/macOS 上普通 App 就能建，
/// **内核会把 ICMP id 改写成一个自己分配的 id**（不是我们填的那个）—— 所以校验时既不要死等自己填的 id，
/// 也别想用 `getsockname()` 反查它（Darwin 上发送前后都返回端口 0，实测）；回包归属靠"来源地址"校验。
///
/// ⚠️ Darwin（iOS/macOS）与 Linux 的两处不同，都踩过：
///  - **v4 的校验和必须自己算**（内核不会替 dgram ICMPv4 重算，留 0 就收不到回包）；
///  - **v4 的回包带 20 字节 IPv4 头**（v6 不带），读 type 前要按 IHL 跳过（见 `pingOnce` 收包处）。
///
/// 结果分三档，第三档**不能报成「对方不可达」**：
///  可达 / 不可达 / 本机无法执行 ICMP（建不了 socket 或没有权限）
nonisolated enum IcmpPing {

    /// 单次探测超时（毫秒）
    static let timeoutMs: Int32 = 1000
    /// 并发上限（对齐 Android `PING_WORKERS = 16`）
    static let workers = 16

    enum Status {
        case reachable
        case unreachable
        /// 本机跑不了 ICMP（没权限 / 建不了 socket）
        case unavailable
    }

    struct Result {
        let ip: String
        let status: Status
        let detail: String
    }

    /// 并发 ping 一串地址，返回结果（顺序和入参一致）；onResult 在每个结果出来时回调（可能乱序）
    ///
    /// 并发度 ≤ [workers]：**分块**跑（块内并发、块间等这一块结束）。
    /// 不用 `concurrentPerform` + 信号量那套 —— 那是在 GCD 线程池里阻塞，地址一多（服务端每族上限 32、
    /// 极端到 64 个）就有挂死的风险。
    /// - Parameter onIgnore: 收到"来源不符 / id 不符"的回包时回调一行说明（给 App 内日志用）；
    ///   nil = 不回调（回包照样丢弃）
    static func pingAll(
        _ addrs: [String],
        onResult: ((Result) -> Void)? = nil,
        onIgnore: ((String) -> Void)? = nil
    ) -> [Result] {
        guard !addrs.isEmpty else { return [] }
        var results = [Result?](repeating: nil, count: addrs.count)
        let lock = NSLock()
        let group = DispatchGroup()
        let concurrency = min(workers, addrs.count)

        var start = 0
        while start < addrs.count {
            let end = min(start + concurrency, addrs.count)
            for index in start..<end {
                group.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    let r = pingOnce(addrs[index], onIgnore: onIgnore)
                    lock.lock()
                    results[index] = r
                    lock.unlock()
                    onResult?(r)
                    group.leave()
                }
            }
            // 等在飞的这一块跑完再发下一块：在飞数量永远 ≤ concurrency
            group.wait()
            start = end
        }
        return results.compactMap { $0 }
    }

    /// ping 一次（v4/v6 自动判断）。
    /// - Parameter onIgnore: 收到"来源不符 / id 不符"的回包时回调一行说明；nil = 不回调
    static func pingOnce(_ ip: String, onIgnore: ((String) -> Void)? = nil) -> Result {
        let isV6 = ip.contains(":")
        let proto = isV6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP
        let family = isV6 ? AF_INET6 : AF_INET

        let fd = socket(family, SOCK_DGRAM, proto)
        guard fd >= 0 else {
            return Result(ip: ip, status: .unavailable, detail: "建不了 ICMP socket（errno=\(errno)）")
        }
        defer { close(fd) }

        // 目标地址的**二进制**形式：回包来源要和它按字节比
        //（v6 字符串有多种压缩/大小写写法，比字符串会误判）
        guard let targetBytes = addressBytes(ip, family: family) else {
            return Result(ip: ip, status: .unavailable, detail: "地址解析失败")
        }

        // 组一个 echo request
        let ident = UInt16(truncatingIfNeeded: getpid())
        let seq = UInt16(1)
        var packet = [UInt8](repeating: 0, count: 8 + 8)
        packet[0] = isV6 ? 128 : 8        // ICMPv6 echo request = 128，ICMPv4 = 8
        packet[1] = 0                     // code
        packet[4] = UInt8(ident >> 8)     // id（内核会改写，填一个值就行）
        packet[5] = UInt8(ident & 0xff)
        packet[6] = UInt8(seq >> 8)
        packet[7] = UInt8(seq & 0xff)
        // payload：放个固定串，方便在日志里认出来
        let payload = Array("p2pnet".utf8)
        for (i, b) in payload.enumerated() { packet[8 + i] = b }
        if !isV6 {
            // v4 的校验和**必须自己算**：Darwin 上内核不会替 `SOCK_DGRAM` 的 ICMPv4 重算
            //（实测：校验和留 0 时 sendto 成功、但一个回包都收不到）。别删这段。
            let sum = checksum(packet)
            packet[2] = UInt8(sum >> 8)
            packet[3] = UInt8(sum & 0xff)
        }
        // v6 的校验和带伪首部，交给内核算（SOCK_DGRAM 的 ICMPv6 由内核填）

        // 发出去
        let sent = sendPacket(fd: fd, family: family, ip: ip, packet: packet)
        guard sent else {
            return Result(ip: ip, status: .unreachable, detail: "sendto 失败（errno=\(errno)）")
        }

        // 等回包（用 poll 带超时，收到无关的包就继续等到超时）
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline {
            let remainMs = Int32(max(1, deadline.timeIntervalSinceNow * 1000))
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let n = poll(&pfd, 1, remainMs)
            guard n > 0, (pfd.revents & Int16(POLLIN)) != 0 else { return timeoutResult(ip) }

            var buf = [UInt8](repeating: 0, count: 1024)
            // 第 5/6 个参数：**必须取回包来源**，否则"只要有 ICMP echo reply 就判可达"，
            // 会把别人的回包算在自己头上（用户就遇到过"iOS 说能 ping 通、电脑 ping 不通"）
            var srcStorage = sockaddr_storage()
            var srcLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let got = withUnsafeMutablePointer(to: &srcStorage) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buf, buf.count, 0, sa, &srcLen)
                }
            }
            guard got > 0 else { continue }

            // ⚠️ Darwin 的两处差异（**实测过，别"优化"掉**）：
            //  1) **v4**（`SOCK_DGRAM` + `IPPROTO_ICMP`）的 recvfrom 回包**带 20 字节 IPv4 头**
            //     （不像 Linux 那样帮我们剥掉）—— 首字节是 IP 头的 0x45，不是 ICMP type 0，
            //     所以必须按 IHL 跳过 IP 头再读 type；否则永远匹配不上 echo reply，v4 会全判"不可达"
            //     （现象就是「安卓能 ping 通 iOS 的 v4，iOS 却只ping得通 v6」）。
            //     用 IHL 而不是硬编码 20，兼容带选项的 IP 头。
            //  2) **v6**（ICMPv6）的回包**不带** IPv6 头，`buf[0]` 直接就是 ICMPv6 type（129）。
            var icmpOffset = 0
            if !isV6 {
                guard got >= 20 else { continue }
                icmpOffset = Int(buf[0] & 0x0f) * 4          // IHL 的单位是 4 字节，正常 20
                guard icmpOffset >= 20, icmpOffset + 8 <= got else { continue }
            }
            let type = buf[icmpOffset]
            guard let source = sourceOf(srcStorage) else { continue }
            if type == (isV6 ? 129 : 0) {
                // **只认"来源就是我们要 ping 的那个地址"的回包**（按字节比）。
                //
                // 为什么不再校验 ICMP id：Darwin 上 dgram ICMP socket 的 id 由内核分配，
                // `getsockname()` 在 sendto 之前和之后都返回端口 0（本机实测，见 commit 说明），
                // 问不出那个 id 就没法比；而内核本来就是按这个 id 把回包分流给对应 socket 的，
                // 所以 16 路并发之间不会串包。宁可不校验，也不写一个看起来在验、实际永远跳过的检查。
                if source.bytes == targetBytes {
                    return Result(ip: ip, status: .reachable, detail: "echo reply from \(source.text)")
                }
                // 来源不符：**丢弃并继续等**（不判死），同时把真实来源报出去，方便一眼定性
                onIgnore?("\(ip) ← 忽略来自 \(source.text) 的回包（来源不符）")
                continue
            }
            // 其它 ICMP（比如 unreachable）继续等，别急着判死
        }
        return timeoutResult(ip)
    }

    /// 把地址字符串解析成二进制（v4 = 4 字节，v6 = 16 字节）
    private static func addressBytes(_ ip: String, family: Int32) -> [UInt8]? {
        if family == AF_INET6 {
            var raw = in6_addr()
            guard ip.withCString({ inet_pton(AF_INET6, $0, &raw) }) == 1 else { return nil }
            return withUnsafeBytes(of: raw) { Array($0) }
        }
        var raw = in_addr()
        guard ip.withCString({ inet_pton(AF_INET, $0, &raw) }) == 1 else { return nil }
        return withUnsafeBytes(of: raw) { Array($0) }
    }

    /// 从 `recvfrom` 填好的 `sockaddr_storage` 里取出源地址：二进制（用于比对）+ 可读文本（用于日志）
    private static func sourceOf(_ storage: sockaddr_storage) -> (bytes: [UInt8], text: String)? {
        var storage = storage
        switch Int32(storage.ss_family) {
        case AF_INET:
            var raw = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            }
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &raw, &text, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
            return (withUnsafeBytes(of: raw) { Array($0) }, String(cString: text))
        case AF_INET6:
            var raw = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            }
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &raw, &text, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
            return (withUnsafeBytes(of: raw) { Array($0) }, String(cString: text))
        default:
            return nil
        }
    }

    private static func timeoutResult(_ ip: String) -> Result {
        Result(ip: ip, status: .unreachable, detail: "\(timeoutMs)ms 没回包")
    }

    private static func sendPacket(fd: Int32, family: Int32, ip: String, packet: [UInt8]) -> Bool {
        if family == AF_INET6 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = 0
            guard ip.withCString({ inet_pton(AF_INET6, $0, &addr.sin6_addr) }) == 1 else { return false }
            let n = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    packet.withUnsafeBytes { bytes in
                        sendto(fd, bytes.baseAddress, packet.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
            return n > 0
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        guard ip.withCString({ inet_pton(AF_INET, $0, &addr.sin_addr) }) == 1 else { return false }
        let n = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                packet.withUnsafeBytes { bytes in
                    sendto(fd, bytes.baseAddress, packet.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return n > 0
    }

    /// 16 位反码校验和（ICMPv4）
    private static func checksum(_ data: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < data.count {
            sum += UInt32(data[i]) << 8 | UInt32(data[i + 1])
            i += 2
        }
        if i < data.count { sum += UInt32(data[i]) << 8 }
        while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return UInt16(~sum & 0xffff)
    }
}
