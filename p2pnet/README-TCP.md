# P2P TCP 打洞流程

## 消息类型

| 方向 | type | 说明 |
|------|------|------|
| C→S | `p2ptcp` | 发起 P2P TCP 连接请求 |
| S→C | `send_tcp_to_server` | 服务器通知客户端往服务器 TCP 端口发注册包 |
| S→C | `thisisyourpeer_tcp` | 服务器告知对端公网(IP, 端口)，以及本端被 NAT 看到的地址 |

---

## 完整流程

```
alice 和 bob 都已登录

alice:  > p2ptcp bob
bob:    > p2ptcp alice

alice:  服务器 → {"type": "send_tcp_to_server", "tcpport": <port>}
bob:    服务器 → {"type": "send_tcp_to_server", "tcpport": <port>}

alice:  temp_sock = socket()
        temp_sock.connect(SERVER:9999)          ← NAT 记住这个外出映射
        temp_sock.send({"username":"alice"}\n)
        temp_sock.close()                        ← 发完就关，但 NAT 映射留着

        （bob 同理，在 NAT 上建立另一条外向映射）

        服务器收到双方注册，拿到公网地址：
        alice: (1.2.3.4, 40001)
        bob:   (5.6.7.8, 30001)

alice:  服务器 → {"type": "thisisyourpeer_tcp", "name":"bob",   "ip":"5.6.7.8", "port":30001, "my_ip":"1.2.3.4", "my_port":40001}
bob:    服务器 → {"type": "thisisyourpeer_tcp", "name":"alice","ip":"1.2.3.4", "port":40001, "my_ip":"5.6.7.8", "my_port":30001}

alice:  收到后启动 tcp.py --peeraddr 5.6.7.8 --peerport 30001 --localport my_port

        tcp.py 执行：
        bind(my_port) + listen()              ← 同一端口，NAT 映射已由 temp_sock 建立
        connect(5.6.7.8, 30001)              ← SYN 发出

bob:    收到后启动 tcp.py --peeraddr 1.2.3.4 --peerport 40001 --localport my_port

        tcp.py 执行：
        bind(my_port) + listen()
        connect(1.2.3.4, 40001)              ← SYN 发出

        双方 SYN 在 NAT 边界相遇
        → simultaneous TCP connect
        → 某一方的 accept() 先返回
        → 另一方的 connect() 也返回

双方:   select 竞速 accept/connect
        拿到 tunnel socket
        tunnel 就绪（直接 P2P TCP）
        超时 8 秒无连接 → 失败（无 relay fallback）
```

---

## 服务器状态字段

- `p2p_tcp_requests[username]` = `{"target": "bob", "timestamp": ...}`
- `tcp_peer_info[username]` = `{"ip": "x.x.x.x", "port": yyyy, "target": "bob"}`

---

## tcp.py 参数

```
python3 tcp.py --peeraddr <ip> --peerport <port> --localport <port>
    [--localaddr <addr>]
    [--peername <name>]                   # 对方用户名（仅用于日志）
    [--appmode fake|tun|tap|clientsocket|auto]   # 默认 fake
    [--socketpath PATH]
    [--cipher none|chacha20-poly1305]   # 加密方式，默认 none
    [--transport none|framed]           # 分帧方式，默认 none
        none   = 心跳 JSON 文本行（\n 分隔）+ 原始数据 bytes
        framed = TLV 分帧：type=0 心跳明文 / type=1 数据密文（--cipher 时加密）
    [--obfs none|xor|tls]              # 混淆方式，默认 none
    [--key <base64>]                    # 对称密钥，client.py 登录后派生
    [--remotelog <path>]                # 日志文件路径（默认 stdout）
```

收到 `thisisyourpeer_tcp` 后由 client.py 自动 spawn。

**IPv4 / IPv6 自动识别**：`--peeraddr` 支持任意格式 IP 地址，内部通过 `getaddrinfo(AF_UNSPEC)` 自动选择合适协议栈。

`--appmode` 说明：
- `fake`（默认）：假接口，用于测试；收到数据打印长度和前 32 字节
- `auto`：按平台自动选择：Linux → `tun → tap → fake`，macOS → `tun → fake`
- `tun`：强制 TUN（IP 层），macOS 用 utun，Linux 用 /dev/net/tun；`--socketpath` 指定设备名（如 utun3），不指定则自动选
- `tap`：强制 TAP（Ethernet 层，Linux 专用）；`--socketpath` 指定设备名（如 tap0），不指定则自动选
- `clientsocket`：连接 client.py 提供的 Unix socket（client.py 自动传入 `--socketpath`）

## tcp.py 架构

```
打洞阶段（main thread）：
  bind(local_port) + listen()     ← 让 NAT 记住端口映射
  connect(peer_ip, peer_port)    ← 同时发出 SYN
  select 竞速：
    - accept 返回 → 用 accept socket 做 tunnel
    - connect 返回 → 用 connect socket 做 tunnel
  超时 8 秒无连接 → 退出（不 relay）

隧道建立后（三个线程）：
  main thread:       等待子线程结束

  app_listener:    select([app]) → recv → handle_outgoing() → tunnel 发出
                      handle_outgoing: TODO 加密 → 混淆 → 组帧 → tunnel

  tcp_listener:    select([tunnel]) → recv → handle_incoming() → app.send() 直接写入
                      handle_incoming: TODO 解帧 → 解密 → 解混淆 → app.send()

  app_writer:      不需要（handle_incoming 直接写 app）
```

TCP 是流式协议，操作系统保证可靠传输，无需 KCP。

## 数据流

```
发送：app 原始数据 → handle_outgoing() → 加密（--cipher）→ 混淆（--obfs）→ TLV 分帧 → tunnel
接收：tunnel → TLV 解析 → 解混淆（--obfs）→ 解密（--cipher）→ handle_incoming() → app.send()

混淆（--obfs）：
  xor：XOR 流混淆（可逆，接收方再次 XOR 还原）
  tls：TLS 指纹混淆，伪装成 HTTPS ClientHello

TLV 分帧（--transport framed）：
  type=0（心跳）：0x00 + len[4] + 明文 JSON（如 `{"seq":1,"ts":...}`）
  type=1（数据）：0x01 + len[4] + 原始 bytes（或加密 bytes，取决于 --cipher）

黏包处理：长度字段解决（type[1] + len[4] 保证完整消息边界）。
```

## 端口复用说明

服务器只用 **一个 TCP 端口（默认 `--port`，可配置）**：

| 连接类型 | 判断方式 | 处理 |
|---------|---------|------|
| WebSocket/HTTP | 第一个字节不是 `{` | 走 WS handshake → WS 主循环 |
| P2P TCP 注册 | 第一个字节是 `{` | JSON 解析 → `handle_tcp_p2p_registration()` → close |
