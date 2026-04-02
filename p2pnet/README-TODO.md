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
