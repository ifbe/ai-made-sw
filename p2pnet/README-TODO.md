# TODO / 待研究

---

## 大规模 Mesh（10+ peers）

**当前状态：** p2pnet 只做 pair-wise 直连，不含路由层。

**问题：**
- 全网状拓扑：N peers → 每人有 N-1 条 tunnel，总连接数 N×(N-1)/2，不可持续
- 不是每对 peers 都能打洞成功，需要 relay fallback
- 共用 TUN 接口时，多个 tunnel 进程写同一个 fd 有竞争风险

**方向：两层 Overlay**

```
第一层（现在做的）：打洞 + 裸 tunnel，P2P 直连或 relay
第二层（待加）：client.py 作为 central switch，多个子 tunnel 进程汇入
```

**已实现 / 进行中（clientsocket 架构）：**
- `local fake`（默认）→ 子进程用 `--nettype fake`
- `local tun <dev>` / `local tap <dev>` → 子进程用 `--nettype clientsocket --socketpath`
- `local auto` → 子进程用 `--nettype auto`
- client.py 监听 Unix socket `/tmp/p2p/{user}-{peer}.sock`
- 每个 udp.py / tcp.py 用 `--nettype clientsocket --socketpath PATH` 连入
- client.py select 监听 tun fd + 各 child socket
- tun 收包按路由表发往对应 child；child 数据汇总写 tun
- 子进程断连 → client.py 从表里删除 + log

**待实现：**
- client.py 侧 Unix socket server + select 多路复用
- 路由表：目的 IP → child socket（静态映射，peer IP 已知）

**路由协议可选：**
- Babel（轻量，支持有线/无线 mesh，易实现）
- OLSRv2（工业级，更复杂）
- 简化方案：中心 tracker 分发路由表（适合受控网络）

**IP 分配方案（/30 问题）：**
- 每对用一个 /30 → /30 数量 = N-1，不可持续
- 方案：所有人用同一 /24 网段，每人一个 IP，启动时协商分配

---

## Warcraft 3 IPX 支持

**问题：** 魔兽 3 局域网对战用 IPX/SPX 协议，不是 IP。TUN 只处理 IP 包，IPX 不通。

**协议栈对比：**
```
TUN (IP 层)     → 只认识 IP 协议族
TAP (Ethernet)  → 可以收发 Ethernet 帧，但帧内 Type 字段区分 IPv4/IPX 等
```

**方案 A：找 TCP/IP 版本**
- 魔兽 3 1.28+ 原生支持 TCP/IP，盗版/民间有 IPX-over-TCP 模拟器
- 最简单，改配置即可

**方案 B：TAP + 网桥封装**
- TAP 收到 Ethernet 帧，根据 Type 字段区分 IPv4 / IPX
- IPX 包通过额外封装的隧道到达对端 TAP
- 需要额外处理 IPX 广播（IPX 用广播做地址解析，NAT 穿透更复杂）

**结论：** 方案 A 最实际，除非有特殊需求必须用 IPX。

---

## 安全加密层

**当前问题：**
- 客户端 ↔ 服务器：WebSocket 明文，认证靠 challenge-response（防密码泄露，不防流量监听）
- 客户端 ↔ 客户端 P2P Tunnel：**完全无加密**，任何中间人都能看 tunnel 流量
- TCP P2P 注册：裸 `{"username":"xxx"}\n`，用户名直接暴露

**目标：三层安全**

| 层次 | 通道 | 加密方式 |
|------|------|---------|
| 主信令 | WebSocket → 升级 wss:// | TLS |
| P2P 打洞注册 | 新开 TCP/UDP（为 NAT 打洞） | session_key 加密 username + signature（TCP/UDP 共用） |
| long-term 公钥交换 | wss:// 主信令通道 | TLS 保证完整性 |
| P2P Tunnel | UDP 打洞后 | Noise IK + ChaCha20-Poly1305 |

---

### 登录 vs session_key 推导

| 步骤 | 算法 | 输入 |
|------|------|------|
| **Login（challenge-response）** | `HMAC-SHA256(pw_hash, challenge)` | `pw_hash = SHA256(password + salt)`，`challenge` 来自服务器 |
| **session_key 推导** | `HKDF(pw_hash, info=challenge)` | 同上，`pw_hash` 取自服务器存储，`challenge` 同上 |

- `session_key` 在登录成功后双方同时算出，**从不传输**
- 中间人看到 `challenge` + `response` + `signature`，但没有 `pw_hash` 就算不出 `session_key`

---

### P2P 打洞注册（临时消息加密）

TCP 打洞和 UDP 打洞**共用同一套** session_key 认证，不需要单独的 static 密钥对。

**流程：**
```
服务器 → Alice (WS):  send_tcp_to_server / send_udp_to_server
服务器 → Bob   (WS):  send_tcp_to_server / send_udp_to_server

Alice → 服务器 (新开 TCP/UDP):  session_key 加密({"username": "alice", "signature": "ping"})
Bob   → 服务器 (新开 TCP/UDP):  session_key 加密({"username": "bob",   "signature": "ping"})

服务器两边都验证成功 → 从 TCP/UDP 头拿到双方公网地址 → 通知双方打洞
```

**消息格式（JSON 明文传输，signature 字段加密）：**
```json
{
  "username": "alice",
  "signature": "session_key加密的('ping')"
}
```

- `username` 明文：服务器从 TCP/UDP 包头拿到公网地址，从 JSON 拿到用户名，对应起来
- `signature`：用 `session_key` 加密 `"ping"`；服务器用同样的 `session_key` 解开验证，通过则证明身份合法

**效果：** 复用打洞通道做认证，TCP 注册的裸 JSON 方案废除，代码大大幅简化。

---

### Noise IK 握手（P2P Tunnel 加密）

双方拿到对方的 static pubkey 后，P2P UDP 打洞成功，开始 Noise IK：

```
Alice（initiator）                          Bob（responder）
  │                                             │
  │  已知: Bob 的 static pubkey                  │
  │                                             │
  │  互发 UDP 包打洞                             │
  │                                             │
  │  -> e_a, {Alice 的 DH 公钥}                 │  用 Bob 的 static 公钥加密
  │              <- e_b, {Bob 的 DH 公钥}       │  用 Alice 的 static 公钥加密
  │                                             │
  │  ECDH(a, B) = ECDH(b, A) = 共享密钥 S       │
  │                                             │
  │  -> {cookie}  （PSK 加密，确认密钥）         │
  │                                             │
  │  = 相同对称隧道密钥 =                        │
  │                                             │
  │  后续所有 UDP 包: {8字节 nonce}{ChaCha20 密文}{tag} │
```

**区分心跳 vs 隧道数据**：无特殊标记，解密后以 `{` 开头的是 JSON 心跳控制消息，否则是 raw IP 包写入 tun。

**Nonce 防重放**：每个 UDP 包 nonce 递增，重复 nonce → ChaCha20 解密失败 → 丢弃。

**前向保密**：每次 P2P 会话生成新的临时 DH 密钥对 `e_a`/`e_b`，static 密钥不参与实际隧道加密。

---

### udp.py / tcp.py 新增参数

```
--peerpubkey   <base64>   对方的 static 公钥（用于 ECDH）
--selfprivkey  <base64>   自己的 static 私钥（用于 ECDH + 签名认证）
```

可选：`--psk <base64>` 做额外 PSK 认证（可由 password 再次 HKDF 得出）。

---

### 简化方案（不改动信令协议）

如暂时不想改 server.py 的信令逻辑，可以只做一件事：

**udp.py / tcp.py 加 Noise IK 加密层**，密钥手动共享（微信把 base64 发给对方）。

信令层和 P2P 注册保持现状，等后续再合入 wss:// + static pubkey 交换。

---

## ICE Peer-Reflexive 支持（无需 relay）

### 当前问题

`thisisyourpeer_udp` 消息里 server 告诉 A：「B 的地址是 X:Port」，这个 X:Port 是 server 从收到的 UDP 包中观察到的 A 的地址。但这个地址**不一定等于 B 实际收到时的来源地址**——对称型 NAT 会对不同目的地分配不同端口。

另外收到 `thisisyourpeer_udp` 后立即 `stop_udp_hello()`，导致：
1. NAT 映射表项失去 keepalive，可能超时失效
2. 没有持续的双向发包，B 无法发现 A 的 peer-reflexive 地址

### 目标

在至少有一方是非对称型 NAT 的情况下，实现 peer-reflexive 地址动态发现，提升打洞成功率。

### 三个关键改动

#### 1. udp.py 支持多地址候选 + 同时双向连接性检查

**现状**：udp.py 只往 `--peeraddr` 单播。

**改为**：
- 收到 `thisisyourpeer_udp` 时同时拿到自己的 observed 地址（server 告诉的 hello 端口对应的公网地址）
- udp.py 启动后，**同时**向 peer 告知的所有候选地址发连接性探测
- 收到对方发来的任何 UDP 包，从包头记录实际来源地址 → 这就是 peer-reflexive candidate
- 后续 tunnel 数据优先走 peer-reflexive 地址

具体在 udp.py 里：

```
已知候选：
  - srflx_A：server 告诉 A 的 B 地址（198.51.100.70:7000）
  - srflx_B：server 告诉 B 的 A 地址（203.0.113.50:6000）

Phase 1（连接性探测）：
  A 向 srflx_B 发探测包（STUN Binding Request 格式 or 自定义 ping）
  B 向 srflx_A 发探测包
  
Phase 2（动态发现）：
  B 收到 A 的探测包，从 IP 头记录 src = 203.0.113.50:6001（A 的 peer-reflexive）
  A 收到 B 的探测包，从 IP 头记录 src = 198.51.100.70:7001（B 的 peer-reflexive）
  
Phase 3（隧道切换）：
  发现 peer-reflexive 后，更新对端地址为新发现的地址
  停止探测，开始正常隧道传输
```

#### 2. udp.py 收到非预期来源的包时动态更新 peer 地址

**现状**：udp.py 只往 `--peeraddr` 发，收只从 `sock` 收，不检查来源。

**改为**：
- `select.select([sock], ...)` 后 `sock.recvfrom()` 拿到 `(data, addr)`
- 如果 `addr` ≠ 当前记录的 peer 地址，记录为 peer-reflexive candidate，切换隧道目标
- 探测阶段收到对方 ping，回 `pong` 到包的实际来源（不是 `--peeraddr`）

### 代码改动位置

**remote/udp.py**：
- 新增候选地址列表：`candidates = [(peer_ip, peer_port), (observed_srflx_A), ...]`
- 同时向所有候选发探测
- `recvfrom` 后比较来源地址，发现 peer-reflexive 时切换
- ping/pong 响应到 `addr`（收到的包的来源），而不是已知候选

### 注意事项

- peer-reflexive 发现后不立即废弃原 srflx，保留作为 fallback
- 对称型+对称型：本方案无法解决，需要 relay（用户已说不考虑）

---

## 目录结构重构

### 新目录三分类

```
client/
├── client.py    # 总管理器：连服务器 + 解析 appmode 命令 + 维护子进程
├── app/         # 业务层（--appmode）
│   ├── hub.py      # hub 模式：中心交换，所有子进程连到 hub
│   ├── tun.py      # IP 隧道
│   ├── tap.py      # Ethernet 隧道
│   ├── fake.py     # 测试
│   ├── audio.py    # 音频流（已实现，双向麦克风+扬声器，ffmpeg RTMP/FLV）
│   ├── video.py    # 音视频流（RTMP 输入/输出）
│   ├── media.py    # 注释：RTMP 输入 + RTMP 输出
│   ├── proxy.py    # 注释：netcat 转发（远程桌面、SSH 等）
│   └── file.py     # 注释：文件分片传输（断点续传）
├── remote/      # P2P 传输通道（无任何业务逻辑）
│   ├── udp.py   # UDP P2P（裸数据收发）
│   └── tcp.py   # TCP P2P
└── util/        # 工具层
    ├── crypto.py  # 密码学（hkdf、ecdh、hmac）
    └── kcp.py     # KCP 可靠传输封装
```

**原则：**
- `remote/` 只管裸数据收发，不写任何业务逻辑
- `app/` 只管业务呈现，不关心数据怎么到对端
- `client.py` 始终是总管理器，hub 只是其中一种 `--appmode`

### appmode 命令

```
appmode              # 显示当前模式
appmode fake         # 拉起 app/fake.py（测试用）
appmode tun [dev]    # 拉起 app/tun.py
appmode tap [dev]    # 拉起 app/tap.py
appmode voice        # 拉起 app/audio.py（纯音频，ffmpeg RTMP/FLV）
appmode video        # 拉起 app/video.py（音视频，RTMP 输入/输出）
appmode hub          # 拉起 app/hub.py（所有子进程连到 hub）
```

### udp.py 与 app 的交互

**不依赖 hub 时**（单个 app + 单个 udp.py）：
- `udp.py --mode tun --socketpath /tmp/p2p/alice/bob-tun.sock`
- `--socketpath` 指向对端 app 监听的 socket
- udp.py 收到数据写到 socket；app 从 socket 读数据

**走 hub 时**（多个 app + 多个 udp.py）：
- `udp.py --mode voice --socketpath /tmp/p2p/alice/hub.sock`
- 所有数据发给 hub，hub 内部路由

**udp.py / tcp.py 参数（新增）：**
```
--cipher none|chacha20-poly1305   # 加密方式，默认 none
--transport none|<mode>           # 分帧/可靠传输，默认 none
    udp: none=裸UDP, kcp=KCP 可靠传输
    tcp: none=心跳 JSON 文本行+原始数据, framed=TLV 分帧
--obfs none|xor|tls              # 混淆方式，默认 none
    none=不混淆
    xor=XOR 流混淆（可逆）
    tls=TLS 指纹混淆（伪装 HTTPS ClientHello）
--key <base64>                    # 对称密钥，client.py 登录后派生
```

**udp.py 参数（现有）：**
```
--nettype auto|tun|tap|fake|clientsocket   # 网络接口类型
--socketpath <path>               # Unix socket 路径
```

| appmode | udp.py --nettype | udp.py --socketpath | 行为 |
|---------|--------------|---------------------|------|
| tun | tun | `/tmp/p2p/alice/bob-tun.sock` | socket 指向 tun.py |
| voice | voice | `/tmp/p2p/alice/bob-voice.sock` | socket 指向 audio.py |
| hub | voice | `/tmp/p2p/alice/hub.sock` | 所有数据发给 hub，hub 内部路由 |
| hub | voice | `/tmp/p2p/alice/hub.sock` | 所有数据发给 hub，hub 内部路由 |

### 数据流分层（发送 / 接收）

**发送：**
```
app 原始数据（视频帧 / 音频帧 / IP 包）
  → 加密（逐包独立 nonce/IV，ChaCha20-Poly1305）
  → KCP（加 seg header：sn 序号、len、data）
  → UDP 发送
```

**接收：**
```
UDP 收到一个完整段
  → KCP（按 sn 排序、去重、重传请求）
  → 解密（逐包独立 nonce/IV）
  → app 原始数据
```

**原则：**
- KCP 处理的是加密后的 opaque bytes，不关心内容
- 加密在 KCP 之前（发送）/ 之后（接收），两层 seqnum 完全独立
- 心跳包（ping/pong）不走 KCP，在 KCP 之外单独处理

### util/kcp.py

封装 KCP 提供可靠传输：
```python
kcp = KCPChannel(sock)
kcp.send(ciphertext_bytes)      # KCP 自己加 seg header
kcp.recv() → ciphertext_bytes  # 排序去重后交付，app 再解密
```

### appmode voice

**已实现。数据流（双向）：**
```
发送方向（Alice）：
  麦克风/摄像头 → ffmpeg 编码（H.264/AAC）→ ffmpeg FLV 封装
    → 写入 pipe 或 unix socket
    → 加密（app 层）→ KCP → UDP

接收方向（Alice）：
  UDP → KCP → 解密（app 层）
    → 从 pipe 或 unix socket 读取 FLV
    → ffmpeg 解码 → 扬声器/屏幕
```

**app/video.py 的职责（每个 peer 各有一个实例）：**
- 本地：ffmpeg 捕获 + 编码 + FLV 封装 → 输出到 pipe/socket
- 远端：UDP 收密文 → KCP → 解密 → ffmpeg 解码播放
- **ffmpeg 天然处理 FLV 内部音视频时间戳，无需额外 AV sync**

**appmode voice：** 纯音频，用 ffmpeg 捕获 AAC + FLV 封装到 stdout，从 stdin 读取 FLV 播放

### 对称型 NAT + peer-reflexive

（见前文 ICE Peer-Reflexive 章节，已在 udp.py 实现）

