# TODO / 待研究

---

## L3 Switch 架构（Mesh VPN）

**目标：** 把 hub 改成 L3 Switch，支持多节点 mesh 路由，洞不通时走中继。

### 核心概念

```
192.168.250.x 扁平虚拟局域网（所有人同一 /24 网段）

switch (192.168.250.55)        — tun/tap 设备，拥有这个网段的路由表
udp_alice (192.168.250.1)       — udp.py，作为 switch 的"网线"插到端口，连 alice
udp_bob   (192.168.250.2)       — udp.py，作为 switch 的"网线"，bob 洞通
udp_karl  (192.168.250.3)       — udp.py，karl 洞不通，包要绕道

包到 switch：
  alice → 192.168.250.3：
    switch 查路由表：
      192.168.250.3/24 via udp_bob（Karl 不直连，走 Bob 中继）
    switch 封装包 → udp_bob 隧道
    bob 的 switch 收到 → 查表 → udp_karl → karl
```

**类比：** Tailscale = WireGuard P2P mesh + DERP relay（中继）。我们的 switch = Tailscale 的 DERP（中继）+ 扁平 L3 路由表。区别：Tailscale 优化到每个 peer 直连（NAT 穿透），我们暂时都走 switch 中继（简化模型）。

### 术语对比

| 传统网络 | p2pnet L3 Switch |
|---------|------------------|
| 以太网交换机 | switch.py（L3） |
| RJ45 网口 | udp.py / tcp.py（物理链路） |
| 网线 | udp.py ↔ switch Unix socket 连接 |
| 交换机端口 | switch 维护的 neighbor entry |
| Trunk 口（中继） | 洞通的 udp.py 链路 |
| 接入端口 | 新节点的第一条链路 |

---

## switch.py 设计

### 网络配置

```
tun 设备：192.168.250.55/24
广播地址：192.168.250.255
MTU：1400（考虑 UDP 封装）

switch 本身 IP：192.168.250.55
peer IP 分配（固定，协商得出）：
  alice  → 192.168.250.1
  bob    → 192.168.250.2
  karl   → 192.168.250.3
  ...以此类推
```

### switch.py 接口

```
switch.py --tun-ip 192.168.250.55        # tun 网卡 IP（不设则 tun 无 IP）
switch.py --switch-mode l3             # 交换模式：l2=MAC 表，l3=IP 表（默认），auto=自动判断
switch.py --type bindtcpsocket --base-port 15991  # 与 udpxxx.py 交互方式（默认 TCP）
switch.py --type unixsocket  # Unix socket 模式（默认 /tmp/p2pnet/switch-<pid>.sock）
```

**--type 参数（与 udpxxx.py 的交互方式）：**
- `bindtcpsocket`（默认）：switch bind TCP 127.0.0.1:15991+ 的端口，udpxxx.py 通过 `--socketpath` 收到连接地址
  ```
  例：switch --type bindtcpsocket --base-port 15991
      udpxxx.py --appmode switch --socketpath 127.0.0.1:15991
  ```
- `unixsocket`：switch bind 单个 Unix socket 文件（默认 /tmp/p2pnet/switch-<pid>.sock），udpxxx.py 通过 `--socketpath` 收到路径；连接建立后直接开始收发 raw IP 包，peer_ip 从第一包的 src IP 动态学习
  ```
  例：switch --type unixsocket
      udpxxx.py --appmode switch --socketpath /tmp/p2pnet/switch-<pid>.sock
  ```

内部：
  tun 设备（switch 的虚拟网卡）
  console：stdin/stdout（client.py 通过 pipe 通信，防其他进程干扰）
  port：TCP 127.0.0.1:15991+ 或 Unix socket（udpxxx.py 插"网线"的地方）

### 进程关系（仅供理解，不代表拓扑层级）

```
switch.py（switch 进程，拥有 tun 设备 192.168.250.55/24）
├─ console：stdin/stdout（连 client.py，pipe 方式，防干扰）
├─ card：    tun/tap（本地插口，本机 app 的流量进出）
├─ port1：   127.0.0.1:15991（udp_alice.py 连接这里，插上"网线" ↔ Switch B）
├─ port2：   127.0.0.1:15992（udp_bob.py   连接这里 ↔ Switch C）
└─ port3：   127.0.0.1:15993（udp_karl.py  连接这里 ↔ Switch C，洞不通走 port2 中继）
```

**port 编号：**
- card = tun/tap（本地插口，所有本机 app 的流量从这里进出）
- port1+ = 外部 peer 连接（udp.py / tcp.py / wireguard.py 插上的"网线"）

**对等理解：**
- Switch A ↔ udp_alice.py ↔ Switch B（alice 那边的网络）
- Switch A ↔ udp_bob.py   ↔ Switch C（bob）
- Switch A ↔ udp_karl.py  ↔ Switch C（karl，洞不通，走 bob 中继）
- **Switch A 眼里 Switch B/C/D 都是邻居，不是下属**

### udp.py 在 switch 模式下的行为

```
普通模式（udp bob）：
  udp.py --peeraddr x.x.x.x --peerport 7777 --localport 50001 --appmode fake
  udp.py 独立运行，自己发 ping/pong 打洞

switch 模式（appmode switch）：
  # switch 用 TCP 模式时（默认）：
  udp.py --appmode switch --socketpath 127.0.0.1:15991 --peer-ip 192.168.250.1
  # switch 用 Unix socket 模式时：
  udp.py --appmode switch --socketpath /tmp/p2pnet/switch-<switch-pid>.sock --peer-ip 192.168.250.1

  udp.py 作为 switch 的端口存在（透传，不关心 IP 包内容）
  udp.py 打洞成功后连 --socketpath（"插上网线"）
  udp.py ↔ switch：发 IP 包 / 收 IP 包
```

### switch.py port 设计

**TCP 模式（--type bindtcpsocket）：**
每个 port 是 TCP 127.0.0.1 的一个端口：

```
127.0.0.1:15991   ← udp_alice.py 连接（alice 的"网线"插 port1）
127.0.0.1:15992   ← udp_bob.py 连接
127.0.0.1:15993   ← udp_karl.py 连接
```

switch bind TCP 127.0.0.1:15991+，等待 udpxxx.py 连接（"插网线"）。
udpxxx.py 从 `--socketpath` 参数拿到连接地址，直接连上。

**Unix socket 模式（--type unixsocket）：**
单个 Unix socket 文件，多个 udpxxx.py 各用独立连接，直接收发 raw IP 包（无 JSON 握手）：

```
/tmp/p2pnet/switch-<pid>.sock   ← 所有 udpxxx.py 都连这个文件，各是独立连接
```

switch bind 这个文件，等待 udpxxx.py 连接。连接建立后直接开始双向二进制 IP 包收发，按 fd 编号标识端口。

### client.py ↔ switch 通信（pipe，防干扰）

client.py spawn 时 `pipe=True`，双方通过 stdin/stdout JSON 行协议通信：

```
# 查看路由表
→ {"cmd": "route"}
← {"ok": true, "routes": [...], "neighbors": [...], "tun_ip": "192.168.250.55"}

# 添加静态路由
→ {"cmd": "route_add", "dest": "192.168.250.3", "via": "bob"}
← {"ok": true}

# 查看状态
→ {"cmd": "status"}
← {"ok": true, "tun_ip": "...", "ports": ["alice", "bob"], "routes": {...}

# 关闭 switch
→ {"cmd": "quit"}
← {"ok": true}
```

不暴露额外 socket，避免其他进程连接进来干扰。

### 路由表

switch.py 维护 `routes: {peer_ip -> port_name}` 映射：
```
routes:
  192.168.250.1 → port_alice   # alice 注册或学习到的
  192.168.250.2 → port_bob
  192.168.250.3 → port_bob     # 非直连，走 bob 中继
```

**路由学习（动态，无需握手）：**
- **学习**：udpxxx.py 直接发 raw IP 包，第一个包的 src IP = peer's mesh IP（如 alice 发来第一包 src=192.168.250.1 → 记住 `192.168.250.1 → port_alice`）
- **静态**：管理员通过 console 命令 `route_add 192.168.250.3 port_bob` 手动指定

**收到 IP 包后的处理：**

从 **tun** 收到（本机要发包出去）：
```
提取 dst_ip
查 routes[dst_ip] → port_name
  找到    → 这个 port.sendall(ip包)  单播
  没找到  → 泛洪到所有 port（标准 L2 交换机行为；不会有风暴，隧道是点对点不会形成广播环路）
```

从 **port** 收到（alice/bob 发来的包）：
```
提取 src_ip → 学习 routes[src_ip] = 这个port
提取 dst_ip：
  所有包都注入 tun（交给 OS 路由表决定本地收还是转发）
  同时查 routes[dst_ip] → 找到就单播；找不到就泛洪（点对点隧道无广播环路，不会风暴）
```

**路由表是 IP → port 的映射，不是 port → port 的映射。**
peer 想发给谁，只关心目标 IP，不关心中间经过哪个 port。

### switch.py 架构（代码级）

```
switch.py:
  tun = Tun()                     # tun 设备，IP=192.168.250.55（TODO）
  port_server = tcp_port_listener(15991)   # TCP 127.0.0.1:15991+，等 udpxxx.py 插网线
  # 或 unix_port_listener("/tmp/p2pnet/switch-<pid>.sock")  # Unix socket 模式

  state:
    ports: {port_name -> conn}     # 插着的"网线"
    routes: {peer_ip -> port_name} # 路由表（IP → port）

  threads:
    card_listener（实现）：
      card.recv() → 解析 dst_ip/dst_mac → 按 --switch-mode 转发

    port_handler(port_name, conn):
      根据 --switch-mode 决定转发方式：
      - l2：纯 MAC 表（Ethernet 帧），查不到就泛洪
      - l3：纯 IP 表（IP 包），所有包 inject tun，查不到就泛洪
      - auto：先看 EtherType，IPv4/IPv6 → L3，其他 → L2

    console_listener:
      select([stdin]) → 读 JSON 命令 → 写 stdout JSON 响应
```

### IP 分配

**方案：集中分配**
- 每个用户登录时 server 分配一个固定 IP（基于用户名 hash 或配置文件）
- server 广播 `user_ip_map` 给所有在线用户：「alice=192.168.250.1, bob=192.168.250.2」
- switch 启动时从 server 获取自己的 IP（或者固定 192.168.250.55）
- 新 peer 加入时，server 通知所有 switch 更新路由

**不需要动态 ARP：** 所有人知道彼此 IP，直接查表转发。

---

## client.py 三重角色

client.py 同时扮演三个角色，**server 完全可选**：

### 1. WireGuard 管理员（admin socket）

连接 wireguard.py 的 admin socket，管理 peers：

```
client.py（admin 连接）
  ├─ wg alice → admin socket 发 add_peer
  ├─ wg bob   → admin socket 发 add_peer
  └─ wg       → （无参数）查看 peers 列表
```

### 2. Switch 管理员（stdin/stdout JSON）

```
client.py（console 连接）
  ├─ appmode switch  → 启动 switch.py 子进程
  ├─ route          → 读 switch 路由表
  └─ route_add      → 手动加路由
```

### 3. 服务器用户（WebSocket，可选）

```
client.py（server 连接）
  ├─ login              → 登录
  ├─ udp bob            → 请求 UDP P2P 连接
  ├─ tcp alice          → 请求 TCP P2P 连接
  └─ wg karl            → 请求 WireGuard P2P 连接
```

---

## 纯 P2P 模式（无 Server）

server 完全不需要，仅靠 wireguard.py 和 switch.py 就能组成扁平内网：

```
alice:  client.py + wireguard.py + switch.py
bob:    client.py + wireguard.py + switch.py
karl:   client.py + wireguard.py + switch.py
```

### Info 交换（手动/发现协议）

```
peer Info:
  mesh IP = 192.168.250.1
  WireGuard 公钥 = XXXX
  公网地址 = 1.2.3.4:51820
```

交换方式：mDNS / WiFi P2P / Bluetooth / 扫码 / 预设种子节点 / 手动输入

### 使用流程（无 server）

```bash
# 第一次：alice 手动把 Info 告诉 bob（任意方式）

# bob 的 client.py：
bob$ wg alice
  → wireguard.py 添加 peer alice，连 alice 公网地址，发 WireGuard 握手
  → 成功后 alice 和 bob 互通，switch 路由表自动学习

# 之后 alice/bob/karl 都在同一个 192.168.250.x 网段
# 完全不需要 server
```

---

## client.py 命令行接口

```
appmode                  # 显示当前模式
appmode switch           # 启动 switch（switch 进程拥有 tun）
appmode fake             # 恢复独立模式（switch 关掉）

udp <user>   - 请求与对方建立 UDP P2P 连接（switch 模式下：启动 udpxxx.py 插上对应 port）
tcp <user>   - 请求与对方建立 TCP P2P 连接
wg <user>   - 请求与对方建立 WireGuard P2P 连接（单进程多 peer）

route                   # 从 switch debug 读取路由表并显示
route_add <dest> <via>  # 手动添加静态路由
```

---

## 实现顺序

1. **switch.py** — tun 设备 + port socket 监听 + neighbor table + IP 转发
2. **udp.py switch 模式** — 连接 switch port socket，透传 IP 包
3. **client.py switch 管控** — 启动/关闭 switch，插拔网线（stdin/stdout pipe）
4. **console 协议** — route/neighbors/status/route_add 命令
5. **非直连路由** — Karl 洞不通时，switch 查表走 Bob 中继
6. **路由协议** — 简化方案：server 分发路由表；进阶：Babel/OLSR

---

## 大规模 Mesh（10+ peers）

**当前状态：** p2pnet 只做 pair-wise 直连，不含路由层。

**问题：**
- 全网状拓扑：N peers → 每人有 N-1 条 tunnel，总连接数 N×(N-1)/2，不可持续
- 不是每对 peers 都能打洞成功，需要 relay fallback
- 共用 TUN 接口时，多个 tunnel 进程写同一个 fd 有竞争风险

**已实现 / 进行中（switch 架构）：**
- `app/switch.py`（→ 待实现）
- 每个 udp.py / tcp.py = 一条物理网线，插到 switch 端口
- switch 维护路由表，按 IP 查下一跳
- 洞不通的节点走中继（switch 查路由表）

**待实现：**
- switch.py tun + port socket + neighbor table
- udp.py switch 模式（连接 switch port socket 透传 IP 包）
- client.py 管控 switch 生命周期（stdin/stdout pipe）
- console 协议（route/status/route_add 命令）
- 非直连路由（switch 查表走中继）

**路由协议可选：**
- Babel（轻量，支持有线/无线 mesh，易实现）
- OLSRv2（工业级，更复杂）
- 简化方案：中心 tracker 分发路由表（适合受控网络）

---

## Warcraft 3 IPX 支持

**问题：** 魔兽 3 局域网对战用 IPX/SPX 协议，不是 IP。TUN 只处理 IP 包，IPX 不通。

**方案 A：找 TCP/IP 版本**
- 魔兽 3 1.28+ 原生支持 TCP/IP，盗版/民间有 IPX-over-TCP 模拟器
- 最简单，改配置即可

**方案 B：TAP + 网桥封装**
- TAP 收到 Ethernet 帧，根据 Type 字段区分 IPv4 / IPX
- IPX 包通过额外封装的隧道到达对端 TAP
- 需要额外处理 IPX 广播（IPX 用广播做地址解析，NAT 穿透更复杂）

---

## 安全加密层

### 登录 vs session_key 推导

| 步骤 | 算法 | 输入 |
|------|------|------|
| **Login（challenge-response）** | `HMAC-SHA256(pw_hash, challenge)` | `pw_hash = SHA256(password + salt)`，`challenge` 来自服务器 |
| **session_key 推导** | `HKDF(pw_hash, info=challenge)` | 同上，`pw_hash` 取自服务器存储，`challenge` 同上 |

### P2P 打洞注册（临时消息加密）

```
服务器 → Alice (WS):  send_tcp_to_server / send_udp_to_server
服务器 → Bob   (WS):  send_tcp_to_server / send_udp_to_server

Alice → 服务器 (新开 TCP/UDP):  session_key 加密({"username": "alice", "signature": "ping"})
Bob   → 服务器 (新开 TCP/UDP):  session_key 加密({"username": "bob",   "signature": "ping"})

服务器两边都验证成功 → 从 TCP/UDP 头拿到双方公网地址 → 通知双方打洞
```

### Noise IK 握手（P2P Tunnel 加密）

```
Alice（initiator）                          Bob（responder）
  │  已知: Bob 的 static pubkey                  │
  │  互发 UDP 包打洞                             │
  │  -> e_a, {Alice 的 DH 公钥}                 │  用 Bob 的 static 公钥加密
  │              <- e_b, {Bob 的 DH 公钥}       │  用 Alice 的 static 公钥加密
  │  ECDH(a, B) = ECDH(b, A) = 共享密钥 S       │
  │  -> {cookie}  （PSK 加密，确认密钥）         │
  │  = 相同对称隧道密钥 =                        │
  │  后续所有 UDP 包: {8字节 nonce}{ChaCha20 密文}{tag} │
```

### udp.py / tcp.py 新增参数

```
--peerpubkey   <base64>   对方的 static 公钥（用于 ECDH）
--selfprivkey  <base64>   自己的 static 私钥（用于 ECDH + 签名认证）
```

---

## ICE Peer-Reflexive 支持（无需 relay）

### 现状问题

`thisisyourpeer_udp` 消息里 server 告诉 A：「B 的地址是 X:Port」，但对称型 NAT 会对不同目的地分配不同端口。

### 三个关键改动

#### 1. udp.py 支持多地址候选 + 同时双向连接性检查

- 收到 `thisisyourpeer_udp` 时同时拿到自己的 observed 地址
- udp.py 启动后**同时**向 peer 告知的所有候选地址发连接性探测
- 收到对方发来的任何 UDP 包，从包头记录实际来源地址 → peer-reflexive candidate

#### 2. udp.py 收到非预期来源的包时动态更新 peer 地址

- `recvfrom()` 拿到 `(data, addr)`
- 如果 `addr` ≠ 当前记录的 peer 地址，记录为 peer-reflexive candidate
- ping/pong 响应到 `addr`（收到的包的来源），而不是已知候选

---

## 目录结构

```
client/
├── client.py        # 总管理器：连服务器 + 解析命令 + 维护子进程
├── app/             # 业务层（--appmode）
│   ├── fake.py      # 测试用假 tun
│   ├── tun.py       # TUN 设备（Linux / macOS utun）
│   ├── tap.py       # TAP 设备（Linux 专用）
│   ├── tun_windows.py
│   ├── tap_windows.py
│   ├── clientsocket.py  # （已删除，功能内联到 remote/*.py）
│   ├── switch.py    # L3 Switch（mesh VPN，tun + 路由表 + port socket）
│   ├── audio.py     # 双向音频（ffmpeg RTMP/FLV）
│   └── video.py     # 音视频
├── remote/          # P2P 传输通道（无任何业务逻辑）
│   ├── udp.py       # P2P UDP 隧道
│   └── tcp.py       # P2P TCP 隧道
└── util/
    ├── crypto.py    # 密码学（HKDF / ECDH / ChaCha20-Poly1305）
    └── kcp.py       # KCP 可靠传输封装
```

### appmode 命令

```
appmode               # 显示当前模式
appmode fake          # 假 tun（测试用）
appmode switch       # 启动 switch.py（mesh VPN，L3 交换）
appmode tun [dev]     # TUN 模式（Linux/macOS utun）
appmode tap [dev]     # TAP 模式（Linux 专用）
appmode voice         # 双向音频（ffmpeg RTMP/FLV）
appmode video         # 音视频（RTMP 输入/输出）

udp <user>        # 发起 P2P UDP（switch 模式下：启动 udpxxx.py 插上对应 port）
tcp <user>        # 发起 P2P TCP
wg <user>         # 发起 P2P WireGuard（单进程多 peer）

route                 # 从 switch debug 读路由表
route_add <dest> <via>  # 手动添加静态路由
```

---

## WireGuard P2P（wireguard.py）

### 架构

wireguard.py 是 switch 的"加密网线"——无 TUN 网卡，纯加密传输：
```
wireguard.py:
  ↕ Unix socket → switch.py（raw IP bytes）
  ↕ WireGuard 加密 → peer

switch.py（tun0 = 192.168.250.55，所有流量都在 /24）
  ├─ socket → udp.py（明文 UDP）
  ├─ socket → tcp.py（明文 TCP）
  └─ socket → wireguard.py（WireGuard 加密）
```

### 与裸 UDP P2P 的区别

| | 裸 UDP | WireGuard |
|--|---------|-----------|
| 加密 | 无 | ChaCha20-Poly1305 |
| 密钥交换 | 无 | Noise IK 协议（完美前向保密） |
| 隧道维护 | 自己实现 | 自动 keepalive + 重握手 |
| MTU 分片 | 自己处理 | WireGuard 自动处理 |
| peer 管理 | 自己实现 | 内置多 peer 表 |

**WireGuard 没有内置打洞**，本质是 UDP，所以打洞逻辑仍在 server（`thisisyourpeer_wg`），server 只负责交换 WireGuard 公钥 + 公网地址。

### 单进程多 peer

wireguard.py 是单实例进程，通过 admin socket 管理多个 peer：
```
client.py:
  wg alice  → wireguard.py 未运行 → spawn + admin socket
  wg bob    → wireguard.py 已运行 → admin socket 发 add_peer
  wg karl   → 同上
```

admin socket 命令：
```
{"cmd": "add_peer", "name": "bob", "ip": "1.2.3.4", "port": 51820, "pubkey": "<bob公钥>"}
{"cmd": "list_peers"}
{"cmd": "remove_peer", "name": "bob"}
{"cmd": "get_pubkey"}
```

---

## 可插拔传输层（Pluggable Transport）

任何网络协议都可以作为 switch 的"网线"插上：

```
switch.py（tun0 = 192.168.250.55）
  ├─ socket → udp.py       （UDP 打洞，明文）
  ├─ socket → tcp.py       （TCP 打洞，明文）
  ├─ socket → wireguard.py （WireGuard 加密）
  ├─ socket → wifi.py      （WiFi P2P / Ad-hoc）
  ├─ socket → ble.py       （蓝牙 LE）
  ├─ socket → lorawan.py   （LoRaWAN 远距离）
  └─ socket → bt.py        （蓝牙 Classic）
```

### 每个 xxx.py 的共同接口

```
输入：raw IP bytes（来自 switch）
输出：物理层传输（WiFi/BLE/LoRa/UDP/TCP）

输入：物理层接收的数据
输出：raw IP bytes（写入 switch socket）
```

switch 不管物理层是什么，只负责 L3 路由。

---

## 纯 P2P 模式（无 Server）

### 发现协议

没有 server 时，用以下协议发现邻居：

| 协议 | 用途 |
|------|------|
| mDNS/Bonjour | 局域网广播发现 |
| WiFi P2P Discovery | 同频段 WiFi 节点发现 |
| Bluetooth Inquiry | 蓝牙设备发现 |
| LoRa CAD | 同频道 LoRa 节点载波侦听 |
| 手动扫码/输入 | 第一次交换 Info（IP + 端口 + 公钥） |
| 预设种子节点 | 启动时连几个已知地址 |

### 发现后的连接

```
alice 发现了 bob 和 karl
→ alice 的 wifi.py / ble.py / lorawan.py 各自建立了到 bob/karl 的物理 tunnel
→ 都插到 alice 的 switch
→ alice 的 routing 表自动学习：
    192.168.250.2 → wifi.py 连接（bob，直连高速）
    192.168.250.3 → ble.py 连接（karl，极近距离）
→ 同一个 /24 网段，物理路径不同，逻辑上完全透明
```

### "频率"概念

WiFi 频道、LoRa 频段、Bluetooth Channel——跟 TCP/UDP 端口一样是"插口编号"，discovery 负责扫描/连接这些插口。

---

## 最终形态

```
192.168.250.x 扁平网段
  每个人的 switch 都是这个网段的路由器
  每个人身上插着不同的"网线"：
    - WiFi P2P（近距离高速）
    - Bluetooth（极近距离）
    - LoRa（远距离低速）
    - WireGuard over UDP（互联网打洞）
  OS 路由表自动选最优路径
  app 完全不用关心走哪条物理通道
```

Tailscale = WireGuard P2P + DERP relay。
我们的 = 可插拔传输层 + switch 中继（穿透失败时）。
