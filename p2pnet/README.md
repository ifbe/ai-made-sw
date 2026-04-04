# p2pnet

P2P 隧道工具，支持链路层/网络层虚拟网卡，P2P 直连/打洞穿透。

**IPv4 / IPv6 双栈自动识别**，地址支持 `192.168.x.x`、`1.2.3.4`、
`2001:db8::1` 等所有格式。

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
    ├── app/               # 业务层（--appmode）
    │   ├── fake.py        # 假 tun（测试用，每3秒发32bit时间戳）
    │   ├── tun.py         # TUN 设备（Linux / macOS utun）
    │   ├── tap.py         # TAP 设备（Linux 专用）
    │   ├── tun_windows.py # TUN 设备（Windows Wintun）
    │   ├── tap_windows.py # TAP 设备（Windows tap-windows）
    │   ├── clientsocket.py # Unix socket 客户端（switch port 连接模式）
    │   ├── switch.py     # L3 Switch（mesh VPN，tun + 路由表 + port socket）
    │   ├── audio.py       # 双向音频（ffmpeg RTMP/FLV）
    │   ├── video.py       # 音视频（RTMP 输入/输出）
    │   └── file.py        # 文件分片传输
    ├── remote/            # P2P 传输通道
    │   ├── udp.py        # P2P UDP 隧道
    │   └── tcp.py        # P2P TCP 隧道
    └── util/             # 工具层
        ├── crypto.py      # 密码学（HKDF / ECDH / ChaCha20-Poly1305）
        └── kcp.py        # KCP 可靠传输封装
```

详细文档：
- **[README-UDP.md](README-UDP.md)** — P2P UDP 打洞流程、udp.py 架构
- **[README-TCP.md](README-TCP.md)** — P2P TCP 打洞流程、tcp.py 架构

---

## 快速开始

### 1. 创建用户

```bash
cd p2pnet/server
python3 secret.py add test    # 用户名/密码均输入 test
```

### 2. 启动服务器

```bash
python3 -u server.py --debug   # 默认 0.0.0.0:10000，--debug 打印所有 WS 消息
```

端口说明：
- **`<port>/TCP`**：login + WebSocket 命令 + P2P TCP 注册（通过 peek 识别 JSON vs HTTP）
- **`<port>/UDP`**：P2P UDP 打洞（默认 `--port`，可设 `--udpport` 单独指定）

### 3. CLI 客户端

```bash
cd p2pnet/client
python3 -u client.py --server 127.0.0.1 --port 10000 --user alice --pass 123456
```

参数：
```
--server <host>     服务器地址
--port <port>       服务器端口（默认 10000）
--user <name>       用户名（连上后自动登录）
--pass <pwd>        密码（需配合 --user）
--remotelog         子进程日志写入 /tmp/p2pnet/{udp|tcp}-{user}_{peer}_{time}.log
--new-window        在新窗口启动子进程（默认当前窗口）
--close-window       子进程结束时自动关闭窗口
```

命令：
```
login <user>        登录（两步：输入用户名 → 输入密码 → challenge-response）
                     --user + --pass 时连上后自动登录（一次性的，失败后需重新手动 login）
list                查看在线用户
p2pudp <user>       向用户发起 P2P UDP 连接
p2ptcp <user>       向用户发起 P2P TCP 连接
appmode             显示当前模式（fake/switch/tun/tap/clientsocket/auto）
appmode fake        fake 模式（默认，子进程独立 tun，不汇入 client.py）
appmode switch      switch 模式（mesh VPN，L3 交换，client.py 通过 debug 口管理）
appmode tun [dev]   TUN 模式（Linux/macOS utun）
appmode tap [dev]   TAP 模式（Linux 专用）
appmode clientsocket clientsocket 模式（子进程连 Unix socket）
appmode auto        auto 模式（tun→tap→fake，自动选择）

route               查看 switch 路由表（需 appmode switch）
route_add <dest> <via>  添加静态路由（需 appmode switch）
help                显示帮助
quit                退出
children            列出所有子进程/子窗口
kill <pid>          杀掉指定 PID 的子进程/子窗口
```

---

## P2P 连接概述

### P2P UDP
详见 [README-UDP.md](README-UDP.md)

```
p2pudp bob → 服务器记录 → 发 send_udp_to_server
→ 双方往服务器 UDP 发 hello → 服务器通知对方地址
→ 启动 udp.py → ping/pong 确认 → tunnel 就绪
```

### P2P TCP
详见 [README-TCP.md](README-TCP.md)

```
p2ptcp bob → 服务器记录 → 发 send_tcp_to_server
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
| S→C | `login_fail` | - |
| S→C | `list_result` | `users[{username, ip}]` |
| S→C | `send_udp_to_server` | `udpport` |
| S→C | `send_tcp_to_server` | `tcpport` |
| S→C | `thisisyourpeer_udp` | `name`, `ip`, `port` |
| S→C | `thisisyourpeer_tcp` | `name`, `ip`, `port`, `my_ip`, `my_port` |
| S→C | `incoming_p2pudp` | `from_username` |
| S→C | `user_joined` | `username`, `ip` |
| S→C | `user_left` | `username` |
| S→C | `error` | `message` |

### 认证流程（Challenge-Response）

```
1. 客户端 → 服务器: {"type": "login", "username": "alice"}
2. 服务器 → 客户端: {"type": "challenge", "challenge": "xxx", "salt": "xxx"}
3. 客户端计算:
   password_hash = SHA256(password + salt)       # 十六进制字符串
   response = HMAC-SHA256(hex2binary(password_hash), hex2binary(challenge))   # 均先 hex→binary
4. 客户端 → 服务器: {"type": "login", "username": "alice", "response": "xxx"}
5. 服务器 → 客户端: {"type": "login_ok"} 或 {"type": "error", "message": "..."}
```

### 自动登录（--user / --pass）

`--user alice --pass 123456` 时：
- WS 连接成功后自动发 `{"type": "login", "username": "alice"}`
- 收到 `challenge` 后用 `--pass` 算出 response 发回
- **一次性**：登录成功后 `--pass` 即清空，下次 `login` 命令需重新输入密码
- 登录失败后 `--pass` 也清空，下次 `login` 需重新输入

---

## 技术细节

### 子进程启动行为

`launch_in_new_terminal()` 参数：
- `new_window=True`（`--new-window`）：新开终端窗口运行子进程
- `new_window=False`（默认）：当前窗口后台运行
- `_log_file` 有值时：子进程 stdout/stderr 重定向到文件；否则继承 parent stdout

子进程日志命名：`/tmp/p2pnet/{udp|tcp}-{user}_{peer}_{timestamp}.log`

### 启动打印格式（udp.py / tcp.py）

```
本端: 0.0.0.0:51234 (IPv4)
目标: x.x.x.x:7777
appmode=fake  socketpath=
cipher=none  obfs=none  transport=none
key=
remotelog=/tmp/p2pnet/udp-alice_bob_1234567890.log
```

### Web UI 认证依赖
- `static/index.html` 依赖 [crypto-js CDN](https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js)，用于 SHA256 / HMAC-SHA256 计算
- Challenge-Response 流程中，key 和 challenge 都以 hex→binary（`Hex.parse`）方式传入 HMAC，与服务器端 `binascii.unhexlify` 等价

### 端口复用（TCP P2P）
- 服务器 `<port>/TCP` 同时服务两种连接：
  - HTTP 请求 → WebSocket handshake → WS 主循环
  - 直接 JSON（以 `{` 开头）→ P2P 临时注册 → `handle_tcp_p2p_registration()` → close
- 客户端 P2P TCP 注册流程：connect → 发 `{"username":"xxx"}\n` → close
  - 连接发完就断，但 NAT 映射已建立，对端 SYN 能进来

### macOS 虚拟网卡限制
- macOS 没有原生 TAP/TUN
- `app/fake.py` 是假 tun，用于测试；收到数据打印长度和前 32 字节，每 3 秒往 pipe 写一个 32bit 时间戳
- 后续用 `utun`（TUN/IP 层）实现
