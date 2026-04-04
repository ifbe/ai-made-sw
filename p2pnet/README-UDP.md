# P2P UDP 打洞流程

## 消息类型

| 方向 | type | 说明 |
|------|------|------|
| C→S | `p2pudp` | 发起 P2P UDP 连接请求 |
| S→C | `send_udp_to_server` | 服务器通知客户端往服务器 UDP 端口发包 |
| S→C | `thisisyourpeer_udp` | 服务器告知对端公网(IP, 端口) |
| S→C | `incoming_p2pudp` | 通知有人想和你建立 P2P |

---

## 完整流程

```
alice 和 bob 都已登录，服务器已知双方 TCP 地址

alice:  > p2pudp bob
bob:    > p2pudp alice

alice:  服务器 → {"type": "send_udp_to_server", "udpport": 9999}
bob:    服务器 → {"type": "send_udp_to_server", "udpport": 9999}

alice:  往服务器 9999/UDP 发 UDP 包（p2pudp_hello）
bob:    往服务器 9999/UDP 发 UDP 包（p2pudp_hello）
        服务器从包头拿到双方公网地址：

        alice: (1.2.3.4, 40001)
        bob:   (5.6.7.8, 30001)

        服务器发现 alice 和 bob 都请求了对方（双向请求）

alice:  服务器 → {"type": "thisisyourpeer_udp", "name":"bob",   "ip":"5.6.7.8", "port":30001}
bob:    服务器 → {"type": "thisisyourpeer_udp", "name":"alice","ip":"1.2.3.4", "port":40001}

alice:  收到后启动 udp.py --peeraddr 5.6.7.8 --peerport 30001 --localport <hello_port>
bob:    收到后启动 udp.py --peeraddr 1.2.3.4 --peerport 40001 --localport <hello_port>

双方:   互发 UDP 包打洞
        ping/pong 确认双向可达
        收到 3 个连续 pong 后 tunnel 就绪
        失败则告知走中继
```

---

## 服务器状态字段

- `udp_addrs[username]` = `{"ip": "x.x.x.x", "port": yyyy, "timestamp": ...}`
- `p2p_requests[username]` = `{"target": "bob", "timestamp": ...}`

---

## udp.py 参数

```
python3 udp.py --peeraddr <ip> --peerport <port> --localport <port>
    [--localaddr <addr>]
    [--appmode fake|tun|tap|clientsocket|auto]   # 默认 fake
    [--socketpath PATH]
    [--cipher none|chacha20-poly1305]   # 加密方式，默认 none
    [--transport none|kcp]              # 可靠传输方式，默认 none
    [--obfs none|xor|tls]               # 混淆方式，默认 none
    [--key <base64>]                    # 对称密钥，client.py 登录后派生
    [--remotelog <path>]                # 日志文件路径（默认 stdout）
```

收到 `thisisyourpeer_udp` 后由 client.py 自动 spawn。

**IPv4 / IPv6 自动识别**：`--peeraddr` 支持任意格式 IP 地址，内部通过 `getaddrinfo(AF_UNSPEC)` 自动选择合适协议栈。

`--appmode` 说明：
- `fake`（默认）：假接口，用于测试；收到数据打印长度和前 32 字节，每 3 秒往 pipe 写一个 32bit 时间戳
- `auto`：按平台自动选择：Linux → `tun → tap → fake`，macOS → `tun → fake`
- `tun`：强制 TUN（IP 层），macOS 用 utun，Linux 用 /dev/net/tun；`--socketpath` 指定设备名（如 utun3），不指定则自动选
- `tap`：强制 TAP（Ethernet 层，Linux 专用）；`--socketpath` 指定设备名（如 tap0），不指定则自动选
- `clientsocket`：连接 client.py 提供的 Unix socket（client.py 自动传入 `--socketpath`）

## udp.py 架构

```
三个线程：
  main thread:        每秒向所有候选地址发 ping

  app_listener:      select([app]) → recv → handle_outgoing() → UDP 发出
                        handle_outgoing: TODO 加密 → 混淆 → UDP 发走

  udp_listener:      select([sock]) → recv → handle_incoming() → app.send() 直接写入
                        handle_incoming:
                          - ping  → 回 pong
                          - pong  → 更新候选，streak 够 3 个则 P2P 就绪
                          - 数据  → TODO 解密 → 解混淆 → app.send() 写入 app

心跳机制：
- ping 间隔：1 秒
- ready 条件：收到 3 个连续 pong（RTT 相近）
- 超时：confirmed 后 5s 无 pong 断开；未 confirmed 时 10s 放弃
```

## 数据流

```
发送：app 原始数据 → handle_outgoing() → 加密（--cipher）→ 混淆（--obfs）→ KCP（--transport kcp 时）→ UDP
接收：UDP → KCP（--transport kcp 时）→ 解混淆（--obfs）→ 解密（--cipher）→ handle_incoming() → app.send()

混淆在 KCP 之外做，KCP 把混淆后的数据当 opaque bytes 处理，不解析内容。
ping/pong 心跳包同样走混淆和 KCP（--transport kcp 时）。

--obfs 混淆方式：
  none：不做混淆
  xor：XOR 流混淆（可逆，接收方再次 XOR 还原）
  tls：TLS 指纹混淆，伪装成 HTTPS ClientHello（混淆后流量看起来像 TLS）
```

## Peer-Reflexive 支持

收到 `thisisyourpeer_udp` 后：
- 启动时已知候选 = server 告知的对端地址（srflx candidate）
- 同时向所有候选地址发 ping
- 收到来自新地址的包 → 动态发现 peer-reflexive candidate，切换 active_peer
- pong / 隧道数据 响应到实际收到包的来源地址

## fake 模式

```
启动: [HH:MM:SS][fake]  启动 (pipe r=3 w=4)
收到数据: [HH:MM:SS][fake]  recv 4B hex: 7f 00 00 01
每3秒: [HH:MM:SS][fake]  send 4B ts=1743742203 hex: 67 1e 5c 3b
销毁: [HH:MM:SS][fake]  销毁
```
