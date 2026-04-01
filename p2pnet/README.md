# p2pnet

P2P 隧道工具，支持链路层/网络层虚拟网卡，P2P 直连/打洞穿透。

**当前状态：v2 开发中（signaling server + P2P UDP tunnel + P2P TCP tunnel）**

---

## 目录结构

```
p2pnet/
├── server/
│   ├── server.py           # 信号服务器（WebSocket + UDP P2P + TCP P2P 复用 9999）
│   ├── secret.py           # 用户密码管理
│   └── static/
│       └── index.html     # Web 管理界面
└── client/
    ├── client.py           # CLI 客户端
    ├── remote/
    │   ├── udp.py        # P2P UDP 隧道
    │   └── tcp.py        # P2P TCP 隧道
    └── local/
        ├── fake.py        # 假 tun/tap（测试用）
        ├── tun.py         # TUN 设备（Linux / macOS utun）
        ├── tap.py         # TAP 设备（Linux 专用）
        ├── tun_windows.py # TUN 设备（Windows Wintun）
        └── tap_windows.py  # TAP 设备（Windows tap-windows）
```

详细文档：
- **[README-UDP.md](README-UDP.md)** — P2P UDP 打洞流程、udptunnel.py 架构
- **[README-TCP.md](README-TCP.md)** — P2P TCP 打洞流程、tcp.py 架构
- **[README-TODO.md](README-TODO.md)** — 大规模 Mesh 路由、 Warcraft 3 IPX 支持等待研究问题

---

## 快速开始

### 1. 创建用户

```bash
cd p2pnet/server
python3 secret.py add test    # 用户名/密码均输入 test
```

### 2. 启动服务器

```bash
python3 -u server.py --debug          # 默认 0.0.0.0:9999，--debug 打印所有 WS 消息
```

端口说明：
- **`<port>/TCP`**：login + WebSocket 命令 + P2P TCP 注册（通过 peek 识别 JSON vs HTTP）
- **`<port>/UDP`**：P2P UDP 打洞（默认 `--port`，可设 `--udpport` 单独指定）

### 3. CLI 客户端

```bash
cd p2pnet/client
python3 -u client.py --server 127.0.0.1 --port 9999
```

命令：
```
login <user>   - 登录（两步：输入用户名 → 输入密码 → challenge-response）
list           - 查看在线用户
p2pudp <user>  - 向用户发起 P2P UDP 连接
p2ptcp <user>  - 向用户发起 P2P TCP 连接
help           - 显示帮助
quit           - 退出
```

---

## P2P 连接概述

### P2P UDP
详见 [README-UDP.md](README-UDP.md)

```
p2pudp bob → 服务器记录 → 发 send_udp_to_server
→ 双方往服务器 UDP 发 hello → 服务器通知对方地址
→ 启动 udptunnel.py → ping/pong 确认 → tunnel 就绪
```

### P2P TCP
详见 [README-TCP.md](README-TCP.md)

```
p2ptcp bob → 服务器记录 → 发 send_tcp_to_server(tcpport=<port>)
→ 双方连服务器 TCP 发注册后 close → 服务器通知对方地址
→ 启动 tcp.py → bind+listen + connect 同时做 → select 竞速
→ 直接 P2P 成功 → tunnel 就绪；超时 8s → 失败
```

---

## WebSocket 协议

### 消息类型

| 方向 | type | 关键字段 |
|------|------|---------|
| C→S | `login` | `username`（第一步）或 `username`+`response`（第二步） |
| C→S | `list` | - |
| C→S | `p2pudp` | `target`（对方用户名） |
| C→S | `p2ptcp` | `target`（对方用户名） |
| S→C | `challenge` | `challenge`, `salt` |
| S→C | `login_ok` | - |
| S→C | `list_result` | `users[{username, ip}]` |
| S→C | `send_udp_to_server` | `udpport` |
| S→C | `send_tcp_to_server` | `tcpport` |
| S→C | `thisisyourpeer_udp` | `name`, `ip`, `port` |
| S→C | `thisisyourpeer_tcp` | `name`, `ip`, `port`, `my_ip`, `my_port` |
| S→C | `user_joined` | `username`, `ip` |
| S→C | `user_left` | `username` |
| S→C | `error` | `message` |

### 认证流程（Challenge-Response）

```
1. 客户端 → 服务器: {"type": "login", "username": "alice"}
2. 服务器 → 客户端: {"type": "challenge", "challenge": "xxx", "salt": "xxx"}
3. 客户端计算:
   password_hash = SHA256(password + salt)       # 十六进制字符串
   response = HMAC-SHA256(hex2bin(password_hash), hex2bin(challenge))
4. 客户端 → 服务器: {"type": "login", "username": "alice", "response": "xxx"}
5. 服务器 → 客户端: {"type": "login_ok"} 或 {"type": "error", "message": "..."}
```

---

## 技术细节

### 端口复用（TCP P2P）
- 服务器 9999/TCP 同时服务两种连接：
  - HTTP 请求 → WebSocket handshake → WS 主循环
  - 直接 JSON（以 `{` 开头）→ P2P 临时注册 → `handle_tcp_p2p_registration()` → close
- 客户端 P2P TCP 注册流程：connect → 发 `{"username":"xxx"}\n` → close
  - 连接发完就断，但 NAT 映射已建立，对端 SYN 能进来

### macOS loopback 注意
- `bind(('127.0.0.1', port))` 在 macOS 上对 loopback 有效
- `bind(('0.0.0.0', port))` 在 macOS 上对 loopback **无效**
- udptunnel 必须绑定 `127.0.0.1`

### macOS 虚拟网卡限制
- macOS 没有原生 TAP/TUN
- `local/fake.py` 是假 tun，用于测试
- 后续用 `utun`（TUN/IP 层）实现
