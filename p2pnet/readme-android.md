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

#### Burst 完成后检查
- 如果 `stopAfterBurst == true`（收到了 peer info）：**不关闭 socket**，退出循环（socket 所有权转移给 main thread）
- 否则进入维持阶段

#### Phase 2: 维持阶段（每秒 1 个，最多 10 秒）
```
while (udpRunning && elapsed < 10s):
    sleep(1000)
    if (stopAfterBurst) break   # 收到 peer info，退出
    send p2pudp_hello
```
**注意**：先 `sleep(1s)` 再检查 flag（和 Python 顺序一致）

#### 收到 `thisisyourpeer_udp` 时
服务器同时给双方发：
```json
{
  "type": "thisisyourpeer_udp",
  "name": "alice",
  "ip": "222.95.110.106",    // 对方公网 IP
  "port": 59283,              // 对方公网端口
  "my_ip": "112.10.20.30",   // 本机公网 IP
  "my_port": 41244            // 本机公网端口
}
```

Android 处理（WebSocket 线程）：
1. `stopAfterBurst = true`（通知 hello 线程停止）
2. `_pendingPeerInfo` 保存 info
3. **不等待** hello 线程退出，立即返回

#### `onHelloDone` 回调（主线程）
- hello 线程退出后，在主线程回调
- 调用 `consumeHelloSock()` 尝试拿走 socket
- 调用 `navigateTo(Page.UdpTest)` 创建 tab
- 调用 `startUdpPeerSocket(page)` 消费 hello socket

### 5. Socket 交接（`consumeHelloSock`）

**旧版问题**：finally 块在 `onHelloDone` 回调前就把 socket 关掉并设为 null，导致 main thread 拿到 null，被迫新建 socket 并绑定同一端口 → `EADDRINUSE`。

**修复后的 finally 块**：
```kotlin
} finally {
    udpRunning = false
    if (helloSock != null) {
        // 只有超时没人要时才关闭
        helloSock?.close()
        helloSock = null
    }
    // 如果 helloSock == null 说明已被 main thread 转移走，不关
    Handler(Looper.getMainLooper()).post {
        listener?.onHelloDone(info)
    }
}
```

`consumeHelloSock()` 在主线程调用：
```kotlin
fun consumeHelloSock(): Triple<DatagramSocket, String, Int>? {
    val s = helloSock ?: return null
    helloSock = null  // 转移所有权，finally 块就不会关了
    return Triple(s, helloSockPeerIp, helloSockPeerPort)
}
```

### 6. `UdpTestPage` P2P UDP 双向 ping/pong

实现 P2P 建立后的双向通信：

- **主循环**：每秒发 `{"type":"ping","seq":N,"ts":timestamp}`
- **接收**：收到 `ping` 回 `pong`，收到 `pong` 打印 RTT
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
- `DatagramSocket()` 默认绑 `:::port`（IPv6 all-interfaces）→ 换为显式绑 `0.0.0.0:port`（IPv4）
- 对 IPv4 peer 收发更可靠，和 Python client 行为一致

### 3. 线程模型
- WebSocket 消息在 OkHttp 线程 → `handleMessage` → 直接调用 listener
- UDP hello 在独立 `Thread` → `finally` 通过 `Handler(Looper.getMainLooper())` 回调主线程
- P2P socket 收发在 `viewModelScope.launch(Dispatchers.IO)`（避免主线程网络 IO）
- listener 回调中更新 UI 状态（`StateFlow`）在主线程

### 4. Socket 交接时机
- `stopAfterBurst = true` 在 WebSocket 线程设置
- finally 块**不**立即关 socket，而是等 main thread 通过 `consumeHelloSock()` 转移走后才关
- 超时情况下 finally 正常关闭 socket（此时无人转移）

### 5. 日志格式
- WebSocket 发出：`client: <原始 JSON>`
- WebSocket 收到：`server: <原始 JSON>`
- UDP 发送：`android: UDP burst[N] → ...` / `android: UDP keep-alive → ...`
- UDP 收到：`android: thisisyourpeer_udp 收到`
- P2P socket：tag=`UDP`（Log.e）
- 系统：`android: P2P socket 启动 本机=... 对方=...`

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
| `EADDRINUSE` | finally 块抢先关 socket，`consumeHelloSock()` 返回 null | finally 只在超时才关；正常流程由 main thread 的 `stopUdpPeerSocket()` 关 |
| `NetworkOnMainThreadException` | `sendto` 在主线程执行 | `viewModelScope.launch(Dispatchers.IO)` |
| IPv6 `:::port` 绑定 | `DatagramSocket()` 默认 IPv6 | 显式 `bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0))` |
| 签名验证失败 | 无 session_key 派生，`p2pudp_hello` 无 signature | HKDF 派生 session_key，发送时加 signature |
| challenge 后 password 被清 | 两次 auth 需要 password | 保存 `pendingPwHash`，login_ok 时用于派生 session_key |

## TODO

- [ ] `UdpTestPage` 实现完整 P2P UDP 隧道（app_listener + udp_listener 数据转发）
- [ ] Tab 关闭时正确停止 socket
- [ ] Tab 重开时重新发起 P2P 请求
