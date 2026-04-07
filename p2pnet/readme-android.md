# Android P2P 实现说明

本文档描述 Android 客户端如何照搬 Python client.py 的协议，实现 P2P UDP 打洞。

## 协议流程（对照 Python client.py）

### 1. WebSocket 登录（两步认证）

```
Android                          Server                           Python
  |                                |                                |
  |--- {"type":"login",          |                                |
  |    "username":"bob"} -------> |                                |
  |                                |--- challenge ----------------> |
  |                                |                                |
  |<-- {"type":"challenge",      |<-- {"type":"challenge",        |
  |    "challenge":"...",          |    "challenge":"...",          |
  |    "salt":"..."} ------------ |    "salt":"..."} -------------|
  |                                |                                |
  |--- {"type":"login",          |                                |
  |    "username":"bob",          |                                |
  |    "response":"hmac..."} ---> |                                |
  |                                |--- login_ok ------------------>|
  |<-- {"type":"login_ok",       |<-- {"type":"login_ok",         |
  |    "username":"bob"} -------- |    "username":"bob"} --------- |
```

- 第一步：发 `{"type":"login","username":"bob"}` → 服务器回 `challenge`
- 第二步：算 `response = HMAC-SHA256(SHA256(password+salt), challenge)` → 发 `{"type":"login","username":"bob","response":"..."}`
- 双方派生 `session_key = HKDF(pw_hash, pw_hash, challenge)`（从不网络传输）

### 2. 请求 P2P UDP 连接

用户点击 UDP 按钮 → 发：
```json
{"type":"p2pudp","target":"alice"}
```

### 3. 服务器要求发 UDP hello（`send_udp_to_server`）

服务器同时给双方发：
```json
{"type":"send_udp_to_server","udpport":10000}
```

**注意**：服务器**不**发 `server_ip`，Android 需用登录时保存的 `serverHost` 做 DNS 解析。

### 4. UDP Hello 线程（`startUdpHello`）

对照 `client/client.py` 的 `start_udp_hello()` 函数：

#### Phase 1: Burst（15 个包，30ms 间隔）
- 创建 `DatagramSocket(null).bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0))`，绑定 `0.0.0.0:port`（IPv4，和 Python 一致）
- 循环 15 次，每次发送带 signature 的包：
  ```json
  {"type":"p2pudp_hello","username":"bob","signature":"hmac_sha256_hex(session_key, b'ping')"}
  ```
- 间隔 `Thread.sleep(30)`

#### Phase 2: 维持阶段（每秒 1 个，最多 10 秒）
```
while (!stopFlag.get()):
    if (超时10s) return
    Thread.sleep(1000)
    if (stopFlag.get()) break
    seq++
    send p2pudp_hello with seq
```
**注意**：收到 `stopFlag` 后立即退出，不多发包。

#### 收到 `thisisyourpeer_udp` 时
服务器同时给双方发：
```json
{
  "type": "thisisyourpeer_udp",
  "name": "alice",
  "ip": "222.95.110.106",
  "port": 59283,
  "my_ip": "112.10.20.30",
  "my_port": 41244
}
```

Android 处理（WebSocket 线程）：
1. `_pendingPeerInfo = info`
2. `stopFlag.set(true)` 通知 hello 线程停止
3. **立即返回，不等 hello 线程**（避免阻塞 WebSocket 线程）

#### `onHelloDone` 回调（主线程）
- `startUdpHello()` 启动 hello 线程后**立即返回**，不 join
- hello 线程结束时在 finally 中 `Handler(Looper.getMainLooper()).post` 回调主线程
- 主线程判断 `_pendingPeerInfo` 是否为 null：
  - 非 null → socket 传给新 tab：`navigateTo(Page.UdpTest)` → `startUdpPeerSocket(page)`
  - 为 null → 关闭 socket（超时没人要）

### 5. `UdpTestPage` P2P UDP 双向 ping/pong

实现 P2P 建立后的双向通信：

- **主循环**：每秒发 `{"type":"ping","seq":N,"ts":本地ms时间}`
- **RTT 计算**：维护 `sentPings` map（seq → 发送时刻），收到 pong 时 `RTT = now - sentPings.remove(seq)`，和 Python 逻辑一致
- **接收**：收到 `ping` 回 `pong`（echo 收到的 seq 和 ts），收到 `pong` 查表算 RTT
- **sentPings 容量限制**：超过 100 条时删除最老的条目
- `startUdpPeerSocket()` 使用 `Dispatchers.IO` 避免 `NetworkOnMainThreadException`

## Android 代码结构

```
app/src/main/java/com/example/p2pnet/
├── data/
│   ├── local/
│   │   └── LocalPrefs.kt          # 存储用户名、服务器地址等
│   ├── remote/
│   │   └── WsClient.kt            # WebSocket + UDP hello 线程
│   └── repository/
│       └── P2pRepository.kt        # 业务层封装
└── ui/
    ├── login/
    │   ├── LoginViewModel.kt      # 登录、消息监听、P2P 发起
    │   └── LoginUiState.kt        # UI 状态
    ├── Pages.kt                    # Page 密封类、TabItem
    ├── UdpTestPage.kt             # P2P UDP tab（ping/pong）
    └── MainScreen.kt              # 主界面（底部 tab 栏）
```

## 关键设计决策

### 1. session_key 派生和签名
- `challenge` 时保存 `pendingSalt` + `pendingChallenge` + `pendingPwHash`（不能清 password）
- `login_ok` 时用 HKDF-SHA256 派生 `session_key = hkdf_sha256(pw_hash, pw_hash, challenge)`
- `p2pudp_hello` 包加 `signature = HMAC(session_key, b'ping')`，服务器验证通过才记录地址

### 2. Socket 绑定
- `DatagramSocket(null).bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0))` 尝试绑 IPv4
- Android 设备可能忽略 IPv4 绑定请求，底层仍创建 IPv6 dual-stack socket（`java.net.Inet6Address`）
- 实际发送时 Android 自动根据目标地址选择 IPv4 或 IPv6 路径，影响较小但不够干净
- `本机=:::port` 是 `sock.localAddress.hostAddress` 的 Android 系统返回值，不代表实际 IPv6 发送

### 3. 线程模型
- WebSocket 消息在 OkHttp 线程 → `handleMessage` → 直接调用 listener
- UDP hello 在独立 `Thread` → `finally` 通过 `Handler(Looper.getMainLooper())` 回调主线程
- P2P socket 收发在 `viewModelScope.launch(Dispatchers.IO)`（避免主线程网络 IO）
- listener 回调中更新 UI 状态（`StateFlow`）在主线程

### 4. 日志格式
- WebSocket 发出：`client: <原始 JSON>`
- WebSocket 收到：`server: <原始 JSON>`
- UDP 发送（Burst/Hold）：`android: UDP burst[N] → ...`
- P2P socket 发送：`send: <地址> <JSON>`
- P2P socket 收到：`recv: <地址> <JSON> [RTT=xxxms]`
- 系统：`android: P2P socket 启动 本机=... 对方=...`
- 消息历史末尾**不带** `\n`，LazyColumn 每行紧贴无多余空行

## Build

```bash
cd android
./gradlew assembleDebug
```

Debug APK 约 25MB，xz 极限压缩后约 5.8MB。

## 已解决的问题（Debug Log）

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| UDP 包没发出去 | `server_ip` 服务器没带，fallback 未实现 | `login()` 时保存 `serverHost`，`startUdpHello()` fallback DNS 解析 |
| `EADDRINUSE` | hello 线程和主线程竞争关闭 socket | hello 线程 finally 用 `stopFlag` 判断是否有人要 socket，超时才关 |
| `NetworkOnMainThreadException` | `sendto` 在主线程执行 | `viewModelScope.launch(Dispatchers.IO)` |
| IPv6 `:::port` 绑定 | `DatagramSocket()` 默认 IPv6 dual-stack | 尝试显式 `Inet4Address.getByName("0.0.0.0")` 绑定，Android 仍可能返回 Inet6Address（待进一步调试）|
| 签名验证失败 | 无 session_key 派生，`p2pudp_hello` 无 signature | HKDF 派生 session_key，发送时加 signature |
| challenge 后 password 被清 | 两次 auth 需要 password | 保存 `pendingPwHash`，login_ok 时用于派生 session_key |
| P2P RTT 显示 0ms | 错误地用 pong echo 的 ts 算 RTT | 改用本地 sentPings map 记录发送时刻，收到 pong 时查表 |
| 历史消息双倍行距 | 每条消息末尾带 `\n`，Text 里渲染出多余空行 | 消息字符串末尾不追加 `\n` |
| 新消息自动跳到底部 | `LaunchedEffect` 无条件 `animateScrollToItem` | 先判断用户是否已在底部，只有在底部时才滚动 |
| sentPings 无限增长 | 无容量限制 | 超过 100 条时删除最老的 |
| 日志箭头冗余 | `send: → ...` / `recv: ← ...` 和方向前缀重复 | 改为 `send: ...` / `recv: ...` |

## UI 布局

- **Compose + Material3**，非 XML
- 主页面 4 个 Card 横向 padding 4dp，块间距 6dp
- `UdpTestPage`：地址信息 Card + 日志 Card，双 Card 布局，横向 padding 4dp
- 消息字体 7sp，行高 8sp，标签列用 `wrapContentWidth()`（不再固定 64dp）

## TODO

- [ ] P2P 打洞成功后，hello socket 直接复用还是新建 socket（待确认 NAT 映射保持问题）
- [ ] Tab 关闭时正确停止 socket
- [ ] Tab 重开时重新发起 P2P 请求
