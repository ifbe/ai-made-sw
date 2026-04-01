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

alice:  收到后启动 tcp.py 5.6.7.8 30001 my_port

        tcp.py 执行：
        bind(my_port) + listen()              ← 同一端口，NAT 映射已由 temp_sock 建立
        connect(5.6.7.8, 30001)              ← SYN 发出

bob:    收到后启动 tcp.py 1.2.3.4 40001 my_port

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
python3 tcp.py <peer_ip> <peer_port> <local_port> <peer_name> [--nettype tun|tap|auto]
```

收到 `thisisyourpeer_tcp` 后由 client.py 自动 spawn。

`--nettype` 说明：
- `auto`（默认）：按平台自动选择：Linux → `tun → tap → fake`，macOS → `tun → fake`
- `tun`：强制 TUN（IP 层），macOS 用 utun，Linux 用 /dev/net/tun
- `tap`：强制 TAP（Ethernet 层，Linux 专用）
- `fake`：假接口，用于测试

## tcp.py 架构

```
直接 P2P TCP 打洞，无 relay：

  bind(local_port) + listen()     ← 让 NAT 记住端口映射
  connect(peer_ip, peer_port)    ← 同时发出 SYN
  select 竞速：
    - accept 返回 → 用 accept socket 做 tunnel
    - connect 返回 → 用 connect socket 做 tunnel
  超时 8 秒无连接 → 退出（不 relay）

  Tunnel：
    select([tunnel_socket, tun])
    tun -> tunnel_socket
    tunnel_socket -> tun
```

---

## 端口复用说明

服务器只用 **一个 TCP 端口（默认 `--port`，可配置）**：

| 连接类型 | 判断方式 | 处理 |
|---------|---------|------|
| WebSocket/HTTP | 第一个字节不是 `{` | 走 WS handshake → WS 主循环 |
| P2P TCP 注册 | 第一个字节是 `{` | JSON 解析 → `handle_tcp_p2p_registration()` → close |
