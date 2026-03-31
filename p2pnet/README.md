# p2pnet

P2P 隧道工具，支持链路层/网络层虚拟网卡，P2P 直连/打洞穿透。

**当前状态：v2 开发中（signaling server + P2P UDP tunnel）**

---

## 目录结构

```
p2pnet/
├── server/
│   ├── server.py           # 信号服务器（WebSocket + UDP P2P）
│   ├── secret.py           # 用户密码管理
│   └── static/
│       └── index.html     # Web 管理界面
└── client/
    ├── client.py           # CLI 客户端
    ├── remote/
    │   └── udptunnel.py   # P2P UDP 隧道（当前实现）
    └── local/
        └── fake.py        # 假 tun/tap（测试用）
```

---

## 快速开始

### 1. 创建用户

```bash
cd p2pnet/server
python3 secret.py add test    # 用户名/密码均输入 test
```

### 2. 启动服务器

```bash
python3 -u server.py --debug          # 默认 0.0.0.0:9999，-debug 打印所有 WS 消息
```

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
help           - 显示帮助
quit           - 退出
```

---

## P2P 连接流程

```
1. alice 和 bob 各自登录服务器

2. alice 输入 p2pudp bob
   → 服务器记录 p2p_requests['alice'] = bob
   → 服务器同时给 alice 和 bob 发 send_udp_to_server

3. alice 和 bob 都往服务器 UDP 端口发 UDP hello
   → 服务器收到后记录双方的公网地址

4. 服务器给 alice 发 thisisyourpeer_udp(bob 的地址)
   服务器给 bob   发 thisisyourpeer_udp(alice 的地址)

5. alice 启动 udptunnel.py -> bob 的地址
   bob   启动 udptunnel.py -> alice 的地址

6. 双方互发 ping，收到 3 个连续 pong 后 P2P 确认
   → Tunnel 就绪
```

---

## WebSocket 协议

### 消息类型

| 方向 | type | 关键字段 |
|------|------|---------|
| C→S | `login` | `username`（第一步）或 `username`+`response`（第二步） |
| C→S | `list` | - |
| C→S | `p2pudp` | `target`（对方用户名） |
| S→C | `challenge` | `challenge`, `salt` |
| S→C | `login_ok` | - |
| S→C | `list_result` | `users[{username, ip}]` |
| S→C | `send_udp_to_server` | `udpport` |
| S→C | `thisisyourpeer_udp` | `name`, `ip`, `port` |
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

## udptunnel.py 架构

```
用法: python3 udptunnel.py <peer_ip> <peer_port> <local_port>

三个线程：
  主线程（唯一）：select 监听 socket，收 UDP 包
    - 收到 ping  → 回复 pong
    - 收到 pong  → 统计，够 3 个连续后启动 tunnel 线程
    - 收到其他数据 → 进队列（tunnel 未就绪则丢弃）

  heartbeat_sender 线程：每秒发一个 ping

  tunnel_worker 线程：等 ready 后启动
    - 从 tun 读数据 → 发 UDP
    - 从队列取数据 → 写 tun
```

---

## 技术细节

### macOS loopback 注意
- `bind(('127.0.0.1', port))` 在 macOS 上对 loopback 有效
- `bind(('0.0.0.0', port))` 在 macOS 上对 loopback **无效**
- udptunnel 必须绑定 `127.0.0.1`

### 心跳机制
- ping 间隔：1 秒
- ready 条件：收到 3 个连续 pong（RTT 相近）
- 超时：confirmed 后 5s 无 pong 断开；未 confirmed 时 10s 放弃

### macOS 虚拟网卡限制
- macOS 没有原生 TAP/TUN
- `local/fake.py` 是假 tun，用于测试
- 后续用 `utun`（TUN/IP 层）实现
