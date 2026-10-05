# Android 端（P2PNet Android）

安卓端一句话：**和 Python 的 `server/` + `client/` 协议一致，把打洞出来的 socket 交给可插拔的"用法"**。
UI 是 Compose + Material3（非 XML），代码全在 `android/app/src/main/java/com/example/p2pnet/`（37 个文件、约 8100 行）。

> 本文是安卓端的**唯一文档**：当前状态（目录 / 页面 / session / 配置 / 契约）+ 协议流程 + 关键设计决策 + 踩过的坑。
> 其它端：[readme-ios.md](readme-ios.md)（SwiftUI 复刻）、[readme-desktop.md](readme-desktop.md)（PyQt6 桌面壳）。
> 两端**协议字段、配置 JSON 键名、页面形态都对齐**。

---

## 1. 怎么编译 / 验证

```bash
cd android
./gradlew :app:compileDebugKotlin --offline     # 只查编译（日常用这个）
./gradlew assembleDebug                          # 出 APK
```

- minSdk 28 / Compose BOM 2024.09（UI 1.7.0、material3 1.3.0）/ Gradle 9.3.1 / AGP 9.1.0 / Kotlin 2.2.21；**可离线构建**。
- 开发过程**只做编译验证**：不装真机、不跑模拟器、不截图。（"Debug APK 约 25MB / xz 压缩后约 5.8MB"是早期记录，未复核。）

---

## 2. 目录与职责

```
com/example/p2pnet/
├── MainActivity.kt            # Activity：绑服务、启动前台的 P2pService、注册两个"拉起外部程序" hook
├── data/
│   ├── local/LocalPrefs.kt    # SharedPreferences：服务器/用户名 + 各配置页的 JSON 原文
│   ├── remote/WsClient.kt     # WebSocket 信令；hello socket（双栈）；按 type 分发消息
│   └── repository/P2pRepository.kt  # 业务层封装（登录/登出/list/各 send），透传配置
├── service/
│   ├── P2pService.kt          # 前台服务：WakeLock/WiFiLock/MulticastLock + 心跳诊断；**在这里创建 SessionManager**
│   └── SessionManager.kt      # **所有 session 的唯一 owner**（见 §4）
├── net/
│   ├── UdpSession.kt          # 一条打好的 UDP 洞：唯一读循环 + 收/发 + 关闭
│   ├── UdpSessionInfo.kt      # 卡片快照（kind / plan / isPreview / note / 五步布尔 / peerReplied / handedTo）
│   ├── LocalAddrs.kt          # 枚举本机 v4/v6（direct 用）
│   ├── IcmpPing.kt            # 可达性探测（direct 用）
│   └── NetFormat.kt           # host:port 格式化（v6 加方括号）
├── usage/                     # 可插拔"用法"：打好的洞交给谁
│   ├── Usage.kt               # 接口：attach(session, env) / detach(session)
│   ├── UdpTest.kt             # 唯一真正实现的：1s ping/pong + RTT
│   └── Tun.kt / Vswitch.kt / WireGuard.kt / Proxy.kt / Media.kt   # 桩：只记状态 + 打日志
├── ui/
│   ├── MainScreen.kt          # Scaffold：底部 6 个固定 tab + 页面分发 + **应用级日志浮层**
│   ├── AppLogOverlay.kt       # 悬浮在所有页面之上的 App 内日志（右下角按钮 + 90% 面板 + 缩放动画）
│   ├── Pages.kt               # Page 密封类 + TabItem（closable）
│   ├── PageConfig.kt          # 五个配置页的配置 data class（含 JSON 读写）
│   ├── UdpTestPage.kt         # UDP tab：地址块 + 消息历史
│   ├── WireGuardPage.kt       # WG 页：实现三档 + My Interface + Peer 列表
│   ├── SwitchPage.kt          # 虚拟交换机（m 对 n）
│   ├── VpnPage.kt             # 一对一 VPN（= switch 去掉网口卡）
│   ├── ProxyPage.kt           # 端口转发（-L 本机 listen / -R 本机 connect）
│   ├── MediaPage.kt           # 多媒体聊天（收流/推流 + 拉起外部程序）
│   └── login/
│       ├── LoginViewModel.kt  # 登录、日志、各页配置的读写、按钮路由（约 1080 行）
│       ├── LoginUiState.kt    # UI 状态（tabs / peers / 各页 config / udpSockets）
│       ├── MainPage.kt        # 主页：服务器卡 + 自由层（我卡 / 其他人卡 / 连线 / 中线 / socket 卡）
│       └── LoginData.kt       # MessageItem / Direction / PeerEntry
└── util/                      # Constants / Crypto
```

---

## 3. 页面：底部 tab

固定 **6 个**、**都不可关闭**（没有 `×`；`Pages.kt:56-61` 全部 `closable = false`，默认顺序在 `LoginUiState.kt:50-55`）。
临时页（UDP / 视频 / 聊天）`closable` 默认 true，`removeTab` 里有 `!closable` 守卫（`LoginViewModel.kt:882`）。

| tab | 页面 | 干什么 | 对应 Python |
|---|---|---|---|
| 主页 | `MainPage` | **自由层 = 整个内容区**：服务器卡（自由层内**顶部对齐、居中、不可拖动**；竖屏满宽 / 横屏居中占一半）+ 「我」卡（**默认在自由层正中**、可拖，用户名/密码 + `[登录/退出] [ping] [list]`）、其他人卡（`名字(ip:port)` + **direct/upnp/udp/tcp** 四个打洞按钮）、三种连线 + 屏幕几何中心横线、socket 卡（挂对应 peer 卡正下方，白色虚线相连） | — |
| media | `MediaPage` | 多媒体聊天：收流卡（协议 + 本机地址/端口，**只读、来自打洞结果**）、推流卡（协议 + 对端公网地址/端口 + 采集）、拉起应用卡 | `app/media.py` + `app/ffmpeg.sh` |
| proxy | `ProxyPage` | 端口转发：**配置卡首行 = `配置` + 通道数状态 + 启停按钮（与 vpn / switch 同一套版式）**，下面依次是 模式 `-L`（本机 listen）/`-R`（本机 connect）+ 协议 + 保活 + 洞地址/洞端口 + 该模式的地址端口（原来单独一行的 `运行中/已停止` 已删） | `app/proxy.py`（`-R` 那一半） |
| wireguard | `WireGuardPage` | 「实现」三档（自己实现 / 官方库 / 调系统程序）+ My Interface（IP/掩码、端口、私钥）+ Peer 列表（Endpoint/公钥/Preshared/AllowedIPs） | `app/wg-python.py` / `app/wg-calltool.py` |
| vpn | `VpnPage` | **一对一**：配置卡（card 设备 / tun 地址 / 交换模式 / MTU / 路由老化 / **末行「内嵌 DHCP」开关**）→ DHCP 卡（**仅开关打开时渲染**）；**没有网口那张卡** | `app/vpn.py` |
| switch | `SwitchPage` | **m 对 n** 虚拟交换机，页面顺序：**配置卡（第一行最右是启停按钮，版式与 vpn 一致；末行是「内嵌 DHCP」开关）→ DHCP 卡（仅开关打开时渲染）→ 拓扑卡**；拓扑卡（最后一张）把已插的洞画成一行网口格子（`portN` + 对端用户名 + 对端公网 ip:port；0 个时一个虚线空位；点网口 = 拔线，标题行**不放**启停按钮） | `app/switch.py` |

> **DHCP 卡片与配置卡片**：两张卡用**完全相同**的容器链 `Card(Modifier.fillMaxWidth(), RoundedCornerShape(8.dp))` → `Column(Modifier.padding(8.dp), Arrangement.spacedBy(4.dp))` → `Row(Modifier.fillMaxWidth(), Alignment.CenterVertically)`，
> 首行都是"左标签（`weight(1f)` / `Spacer(weight(1f))`）把右侧内容顶到同一个右边界" —— **结构上不可能不等宽**（两页、两张卡都没在任一侧加额外 margin/inset）。
> `dhcpEnabled` 在两页的配置里**默认 `false`**（`fromJson` 缺字段也回落 `false`），有 JVM 单测 `PageConfigDhcpDefaultsTest` 盯着。

---

## 4. session 生命周期与「用法」机制

`SessionManager` 活在 **`P2pService` 的服务作用域**里（`P2pService.kt:64 val sessionManager = SessionManager(sessionScope)`，
`MainActivity.kt:62` 把它 attach 给 ViewModel），所以**进后台 / Activity 重建都不受影响**，是 session 的唯一 owner。

### 4.1 接管链路（**以代码为准**）

```
WsClient.startUdpHello()  建 hello socket，绑好（首选 :: 双栈，失败退 0.0.0.0）
   └─ 回调 listener.onUdpSocketBound(sock, localIp, localPort)      WsClient.kt:246
        └─ LoginViewModel.adoptUdpSocket(...)                        LoginViewModel.kt:596
             └─ SessionManager.adopt(sock, pendingUdpTarget, localIp, localPort)   SessionManager.kt:81
                  ├─ 建 UdpSession + 卡片 UdpSessionInfo（seq 自增 id）
                  ├─ live[id] = session；_sessions.value += snapshot
                  └─ session.startReading(scope)    ← 唯一读循环
```

⚠️ **接管发生在"绑好那一刻"，不是"洞打通之后"**（早期文档里的 `beginHello` / `handOver(fd)` 这两个函数名**并不存在**）。
打洞后续进展由 `WsClient.onUdpSocketStep`（`WsClient.kt:45`）→ `LoginViewModel.kt:412` → **`markStep(sock, …)`**（`SessionManager.kt:220`）
往这张卡片上打勾——**`markStep` 按 socket 索引，不是按 id**。

### 4.2 五步进度

`markStep(SENT_TO_SERVER / SERVER_REPLIED / SENT_TO_PEER / PEER_REPLIED / HANDED_TO)`，通过 `StateFlow<List<UdpSessionInfo>>` 推给界面。
卡片第 3、4 步（"发给对端 / 收到对端回复"）由 1s 探测的收发结果打勾；`card.peerReplied` 打勾后，第 5 行的用法按钮才可点。

### 4.3 关闭语义（**别踩 double-close**）

- **adopt 之后**：`close(id)`（`SessionManager.kt:103`）/ `closeAll()`（194）是**唯一** owner 与关闭点；`close` 里先 `activeUsage.remove(id)?.detach(session)` 再 `session.close()`。
- **adopt 之前**（还没交给 SessionManager）：`WsClient` 会自己关——没等到 peer info 时在 `finally` 里 `sock.close()`（`WsClient.kt:271`）再回调 `onHelloDone(null, null, …)`；启动异常也关一次（280）。服务没就绪时由 `LoginViewModel` 直接关（600）。
- 所以准确表述是"**adopt 之后** SessionManager 是唯一 owner/关闭点"，不是"fd 全局只有一个关闭点"。

### 4.4 用法（usage）

`usage/Usage` 的接口**只描述「挂上 / 摘下」**（`attach(session, env)` / `detach(session)`），**不规定怎么收发、更不规定怎么保活**：
`UdpTest` 自己起 1s ping/pong，Tun/Vswitch 靠流量驱动，WireGuard 用它的 handshake + keepalive。

注册表在 `SessionManager.kt:64-68`：`usages`（6 个实例）+ `usageIds = udptest / tun / switch / wg / proxy / media`；
`attachUsage(id, usageId)`（575）/ `detachUsage(id)`（586）/ `detachAllUsages()`（593）。
目前**只有 `UdpTest` 是真的**，其余 5 个（Tun / Vswitch / WireGuard / Proxy / Media）都是「记状态 + 打 TODO 日志」。

卡片第 5 行 6 个按钮（`MainPage.kt:931-936`），`enabled` 直传 `card.peerReplied`；点谁就 `attachUsage`，
对应页面再按 `handedTo` 显示"通道 / 规则 / 网口"。路由在 `LoginViewModel.useUdpSocket`：

| 按钮 | 行为（`useUdpSocket` 行号） |
|---|---|
| `udptest` | 建/切 UDP tab，填本机绑定（653） |
| `wg` | 填公网/对端地址 → 跳 wireguard 页 → 按「实现」三档路由（667） |
| `switch` | 启停 switch（`switchRunning`）→ 跳 switch 页（673） |
| `proxy` | 启停 proxy（`proxyRunning`）→ 跳 proxy 页（682） |
| `tun` | 启停 vpn（`vpnRunning`）→ 跳 vpn 页（691） |
| `media` | 只接通道 → 跳 media 页（700） |

### 4.5 「打洞方式」与「用法」的区别（设计原则）

- **打洞方式**只出现在**其他人卡片**上：`direct / upnp / udp / tcp`——只负责"把路打通 / 看通不通"。
- **用法**只出现在 **socket 卡片第 5 行**（打洞成功之后）：`udptest / tun / switch / wg / proxy / media`——才做"应用"。
- 所以其他人卡片上**没有** wg/tun/switch 之类；socket 卡片上也**没有** direct/upnp。

---

## 5. 配置持久化

每个配置页一份 JSON 存进 `SharedPreferences`（`LocalPrefs`），键名固定（`util/Constants.kt:17-29`）：

| 键 | 页面 |
|---|---|
| `wg_config` | wireguard |
| `switch_config` | switch |
| `proxy_config` | proxy |
| `vpn_config` | vpn |
| `media_config` | media |

解析失败 / 字段缺失一律退回默认值（`ui/PageConfig.kt` 里每个 data class 自带 `fromJson` / `toJson`）。
**这套键名和 iOS 端逐一相同**（改它 = 跨端配置互拷失效）。
vpn 与 switch 字段集相同但**各存一份**，默认网段不同（vpn `10.0.0.x`、switch `192.168.250.x`）。

---

## 6. 协议流程（对照 `client/client.py` 与 `server/server.py`）

### 6.1 WebSocket 登录（两步认证）

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
- 双方派生 `session_key = HKDF(pw_hash, pw_hash, challenge)`（**从不网络传输**）

### 6.2 请求 P2P UDP 连接

用户点其他人卡片上的 `udp` → 发：

```json
{"type":"p2pudp","target":"alice"}
```

### 6.3 服务器要求发 UDP hello（`send_udp_to_server`）

服务器同时给双方发：

```json
{"type":"send_udp_to_server","udpport":10000}
```

**注意**：服务器**不**发 `server_ip`，安卓用登录时保存的 `serverHost` 做 DNS 解析。

### 6.4 UDP hello 线程（`WsClient.startUdpHello`）

**Phase 1 — Burst**：15 个包、间隔 30ms（`WsClient.kt:291-302`）。包体带签名：

```json
{"type":"p2pudp_hello","username":"bob","signature":"hmac_sha256_hex(session_key, b'ping')"}
```

**Phase 2 — 维持**：`while (!stopFlag.get())` 每 1000ms 补一个（`WsClient.kt:307-312`），最多 10 秒后自己收摊。
收到 `stopFlag`（服务器推来 peer 信息）后**立即退出，不多发包**。

绑定地址族：首选绑 `::`（双栈，显式 `setsockopt(IPV6_V6ONLY, 0)`），任何一步失败才退回 `0.0.0.0`。
⚠️ 绑 `::` 之后往 v4 目的地发必须走 v4-mapped（`::ffff:a.b.c.d`）；Java 的 `DatagramSocket.send()` 会自动转，这边不用手写。
（**旧描述**：早期曾尝试显式绑 `Inet4Address.getByName("0.0.0.0")`，但系统仍可能给 IPv6 dual-stack socket——现在是**故意**用双栈，不再靠系统猜。）

### 6.5 收到 `thisisyourpeer_udp`

服务器同时给双方发：

```json
{ "type": "thisisyourpeer_udp", "name": "alice",
  "ip": "222.95.110.106", "port": 59283,
  "my_ip": "112.10.20.30", "my_port": 41244 }
```

安卓处理（WebSocket 线程）：`_pendingPeerInfo = info` → `stopFlag.set(true)` → **立即返回，不等 hello 线程**（避免阻塞 WebSocket 线程）。

### 6.6 `onHelloDone` 回调（主线程）

- `startUdpHello()` 启动 hello 线程后**立即返回**，不 join；线程结束在 `finally` 里 `Handler(Looper.getMainLooper()).post` 回主线程。
- ⚠️ **旧行为**（已废）：主线程判断 `_pendingPeerInfo` → `navigateTo(Page.UdpTest)` → `startUdpPeerSocket(page)`。
  **现在**：socket 在**绑好那一刻**就被 `SessionManager.adopt` 接管（见 §4.1），界面只是自由层里多一张 **socket 卡片**——
  **不自动跳 tab、不自动交给任何用法**（要用户在第 5 行点）。

### 6.7 打洞完成后的探测

`SessionManager.startProbe()` 在**服务作用域**的 `Dispatchers.IO` 上跑，1 秒一个 `{"type":"ping","seq":N,"ts":…}`；
收到回包就把卡片第 3、4 步打勾（`SENT_TO_PEER` / `PEER_REPLIED`），**不做任何业务**，等用户选用法。
RTT 用本地 `sentPings`（seq → 发送时刻）查表算；容量超过 100 条删最老的。
`udptest` 用法挂上后用的就是**同一条循环**（不另起第二个）。

---

## 7. 关键设计决策

### 7.1 session_key 派生与签名
- `challenge` 时保存 `pendingSalt` + `pendingChallenge` + `pendingPwHash`（**不能清 password**）
- `login_ok` 时用 HKDF-SHA256 派生 `session_key = hkdf_sha256(pw_hash, pw_hash, challenge)`
- `p2pudp_hello` 加 `signature = HMAC(session_key, b'ping')`，服务器验证通过才记录地址

### 7.2 Socket 绑定（v4/v6 双栈）
- 首选 `DatagramSocket(null).bind(InetSocketAddress(InetAddress.getByName("::"), 0))`，并显式关掉 `IPV6_V6ONLY` → 一个 socket 同时收发 v4/v6
- 失败（某些 ROM / 内核不给）就退回 `0.0.0.0`（纯 v4）
- 卡片上「本机绑定」显示 `[::]:port` 或 `0.0.0.0:port` 是**正常**的——它表示**绑在任意网卡**上；真实网卡地址另有用处（media 页会列出来）

### 7.3 线程模型（**按代码现状**）
- WebSocket 消息在 OkHttp 线程 → `handleMessage` → 直接调 listener
- UDP hello 在独立 `Thread` → `finally` 用 `Handler(Looper.getMainLooper())` 回主线程
- **P2P socket 收发 / 探测循环在 `P2pService` 的服务作用域**（`SessionManager(sessionScope)`，`P2pService.kt:64`）——
  ⚠️ 早期文档写的 `viewModelScope.launch(Dispatchers.IO)` 是**老实现**，因为"按 Home 键后 socket 不再收发"那个 bug 才搬到服务作用域（见 §12）
- listener 回调里更新 UI 状态（`StateFlow`）仍在主线程

### 7.4 日志格式
前台展示的前缀由 `Direction` 渲染（`AppLogOverlay.kt:236-240`），**不是拼在文本里**：

| `Direction` | 渲染前缀 | 用于 |
|---|---|---|
| `CLIENT` | `client:` | WebSocket 发出 |
| `SERVER` | `server:` | WebSocket 收到 |
| `SYSTEM` | `android:` | 系统 / 各页消息 |
| `UDP_SEND` | `→ ` | UDP 发出 |
| `UDP_RECV` | `← ` | UDP 收到 |

文本里自带的前缀：`send: <地址> <JSON>` / `recv: <地址> <JSON> [RTT=xxxms]`（`UdpSession`）、
WireGuard 统一 `wg: `（集中在 `appendWgLog` 一处加）、direct 统一 `[direct] …` 且**每个地址单独一行**（好读好复制）。

- **所有日志都进同一个"App 内日志"**：右下角悬浮「日志」按钮点开的 90% 面板（`ui/AppLogOverlay.kt`），由 `MainScreen.kt:97` 渲染在所有页面之上。
  WG 页**没有**独立的"消息历史"；UDP tab 那份列表仍然只装 UDP 会话自己的日志。
- 消息历史末尾**不带** `\n`（否则 LazyColumn 会渲染出多余空行）。

---

## 8. WebSocket 消息一览（只收发服务端已有的 type，未新增）

| type | 方向 | 说明 |
|---|---|---|
| `login` / `challenge` / `login_ok` / `login_failed` | 双向 | 两步认证（见 §6.1） |
| `logout` | C→S | 只结束登录会话，**不断开 WebSocket**（`logout_ok` 收到也不处理） |
| `list` | C→S | 请求在线用户 |
| `list_result` | S→C | `WsClient` 不解析，原样交给 ViewModel；`tryParseListResult` 取出 peers 和"我的 ip:port" |
| `ping` / `pong` | 双向 | **应用层**心跳：发 `{"type":"ping","seq":N}` → 回 `{"type":"pong","seq":N}`（**不需要登录**，seq 原样带回）；「我」卡片的 `ping` 按钮走这条（`WsClient.sendAppPing`） |
| `p2pudp` / `send_udp_to_server` / `thisisyourpeer_udp` | 双向 | UDP 打洞（服务器推 `udpport`，**不发 `server_ip`**） |
| `p2pudp_hello` | C→S（UDP） | hello 包，带 `signature` |
| `p2ptcp` | C→S | TCP 打洞（**目前只显示流程预览，不发这个信令**） |
| `p2pdirect` / `p2pdirect_reply` | 双向 | direct 地址交换（`from` 由服务器填；**只有 IP 列表、没有端口**、不带签名） |

> 其它 type（`error` / `user_joined` / `user_left` …）目前**不处理**，落到 `when` 之外静默忽略（原始 JSON 仍会进 App 内日志）。
> `kicked`（被服务器踢下线）**已处理**：只取消登录状态、连接不断，见 §8.2。
> **WS 协议级心跳**是另一层，和应用层 `ping`/`pong` 不是一回事：OkHttp 的 `pingInterval(20s)` 自动发 `0x9` ping 帧，服务器原样回 `0xA` pong（payload 一致）；
> 连续收不到 pong 时 OkHttp 把连接判死并回调 `onFailure` → 记一行 `android: WS 心跳失败（20s 没收到 pong），连接已断开` 并把状态收回「未连接」。
> 每次心跳会在 App 内日志打**两行**（`N` 从 1 起、随连接重置；`android:` 前缀由日志管线加）：
> `android: WS 心跳：发出协议级 ping（第 N 次，间隔 20s）` /
> `android: WS 心跳：okhttp不会收到pong（OkHttp 不暴露 ping/pong 回调，无法观测应答）`
> ⚠️ **第二行是如实说明"收不到"，不是"收到"** —— OkHttp 的协议级 ping/pong **没有暴露任何回调**，
> 安卓端**无法观测应答**，所以**不打"收到 pong"**（那会是撒谎），只写"无法观测应答"。两点补充：
> 1. **发出行**由应用侧同节奏计时器打出（`LoginViewModel.startWsPingLog`，20s，随 `onConnected` 起、随 `onDisconnected`/`onDisconnect` 停），
>    节奏与 OkHttp 的 ping 相同，但**不是严格同一瞬间**，可能相差不到 1 个周期；
> 2. 连接仍会因"ping 20s 内没等到 pong"被 OkHttp 判死并回调 `onFailure`（→ 状态收回「未连接」，见上一行），
>    只是**这个过程没有回调可挂**，所以日志只能写"无法观测应答"。
>    连接已死（`WsClient.isOpen()` 为 false）时**一行都不打**。iOS / 桌面端能精确观测 pong，**只有安卓是这条"无法观测"路径**。
> 两行都由纯函数 `ui/login/WsHeartbeatLog.kt`（零 Android 依赖）生成，配 JVM 单测 `app/src/test/java/.../WsHeartbeatLogTest.kt`
> （6 个用例，含反向断言"**绝不出现** `收到协议级 pong`"，不用模拟器即可钉住）。
> `wghelp` **已废弃**：服务端 handler 早就注释掉，安卓端按钮/方法也已删除（发了只会收到 `unknown type`）。
> `WsClient.kt:104` 的 `_helloMode` 现在恒为 `"udp"`（wghelp 删除后它只剩一个值），属于待清理的历史遗留。

### 8.1 WS 自动重连（心跳失败 / 异常断开）

触发：连接**已建立**之后，因**协议级心跳失败**（OkHttp 判超时 → `onFailure`）或**异常断开**（非用户主动）→ 自动重连。
**不触发**：用户手动点「断开」；首次连接就失败（那时 `isConnected` 还是 false，保持现状）。

- **退避**：1s → 2s → 4s；**熔断**：60 秒滑窗内最多 **3** 次自动重连（滑窗+熔断是纯逻辑 `ui/login/WsReconnectPolicy.kt`，零 Android 依赖，配 JVM 单测 `app/src/test/.../WsReconnectPolicyTest.kt`）。
- **计数重置**：① 用户手动点「连接」；② 连接**稳定存活 ≥60 秒**（`startStableTimer`）。
- 过程日志（三端逐字一致，`android:` 前缀由管线加）：
  - 每次尝试：`WS 自动重连：第 N 次（60 秒窗口内）`
  - 成功：`WS 自动重连成功（第 N 次）`
  - 放弃：`WS 自动重连已放弃：60 秒内已重连 3 次仍失败（不再自动重连，请手动连接）`
- **重连成功后恢复登录**：断开前是已登录状态且内存里还有账号密码 → 走**现有登录流程**重新登录（服务端对同名重登是"踢掉旧连接、接受新连接"）；拿不到凭据 → 只恢复连接并明确打日志"需要手动重新登录"，**不假装已登录**。
- 状态显示：重连期间按"未连接"处理（沿用现有断线态），重连+登录恢复后再回到"已连接"。
- **旧服务端（没有 ping/pong）下**：心跳必然判失败 → 走自动重连 → 3 次后打"已放弃"。**这是预期行为**，没有特例。

### 8.2 被服务器踢下线（`kicked`）—— **不是断开**

服务器踢人时（同账号在别处登录）**只**发 `{"type":"kicked","message":...}` + 清 `username` + 从在线表移除：
**socket 不关、连接仍然活着、仍可收发**（再发消息会回 `not logged in`）。所以安卓这边：

- `WsClient.handleMessage` 加 `kicked` 分支：只清**登录会话**（`sessionKey`、登录过程的临时值）并回调 `listener.onKicked(message)`；
  **不动 `wsOpen`、不关连接**（心跳/协议级 ping 与心跳日志都继续跑）；
- `LoginViewModel.onKicked`：**只做两件事** —— 打日志 + 取消登录状态（`isLoggedIn=false`、清 `loggedInUsername`/`myIp`/`myPort`/`peers`、`closeAllUdpSockets()`）；
  **不排重连、不停心跳、不记任何"被踢标记"**（`onKicked` 里没有 `scheduleAutoReconnect` / `stopWsPingLog` / `disconnectOnly`）；
- 日志（四端逐字一致）：`被服务器踢下线（<服务端 message>）：登录已取消，不会自动重新登录`
- **没有"被踢标记"这回事**：踢的作用就是把状态从"已登录"打回"**已连接未登录**"，
  之后掉线自然只重连、不自动重登（判据只看断开前的最后状态）；用户之后手动登录成功，状态又变回"已登录"，
  再掉线自然又会自动重登 —— **状态即真相**；
- 规则表（权威）由纯逻辑 `ui/login/AutoReconnectRules.kt` 表达并单测（`shouldRelogin(reason, wasLoggedInBeforeDrop)`）：

| 断开前最后状态 | 连接 | 自动重连 | 自动重新登录 |
|---|---|---|---|
| 用户主动断开 | 主动关 | ❌ | ❌ |
| 已登录 | —— | ✅ | ✅（还需要凭据还在） |
| 已连接未登录（含"被踢之后"） | —— | ✅ | ❌ |

> 被踢本身**不产生"断开"**（连接还在），所以上表里没有"被踢"这一行；
> 它只是把状态推到第三行。另外：**重登失败不会循环重试**（`login_failed` 只记一行日志，重连策略只统计"断开"），等用户手动。

---

## 9. 两处「交给外部程序」的契约

都由 `MainActivity` 接上（要 Context / PackageManager），参数**全部来自打洞结果**：

1. **WG 页「调系统程序」**：`Intent(action)` + `setPackage(pkg)` + `extras(listen_port / peer_ip / peer_port / my_public_ip / my_public_port)`，
   优先 `queryIntentServices` 解析（`MainActivity.kt:138/142`）；action 在 manifest 的 `<queries>` 里声明（`AndroidManifest.xml:27-31`，Android 11+ 包可见性）。
   `listen_port` 必须是**打洞时那个本地端口**，对方必须 listen 在同一端口，NAT 映射才不废。
2. **media 页「拉起应用」**：优先 `packageManager.getLaunchIntentForPackage(pkg)`（196，对方 app 不用声明任何 action），
   没填包名时退化成按 action 找 Activity（213）；extras = `localaddr / localport / peeraddr / peerport / recv_proto / send_proto / capture`（185 起）。
   - `localaddr/localport` = 洞的本机侧；`peeraddr/peerport` = **对方路由器公网地址:端口**（对方内网地址不管）。

> iOS 侧没有 Intent：这两处都退化成自定义 URL scheme + `UIApplication.open`（media 那 7 个 query 名与上面的 extras 一一对应）。

---

## 10. 各页现状（哪些真、哪些只是壳）

| 功能 | 状态 |
|---|---|
| UDP 打洞 + 五步进度 + 1s 探测（ping/pong + RTT） | ✅ 真实现 |
| direct（地址枚举 + 可达性探测 + 三步进度 + 可达地址 + 被动 auto 应答） | ✅ 真实现（`net/LocalAddrs.kt` + `net/IcmpPing.kt`） |
| list / 登录 / 登出 / peers / 我卡(ip:port) | ✅ 真实现 |
| 六个配置页 + 配置持久化 + 按钮路由 | ✅ 真实现（界面 + 存盘 + 路由） |
| `udptest` 用法 | ✅ 真实现 |
| `tcp` / `upnp` | 🟡 只有流程预览卡片（`previewFlow`：不发信令、不建 socket、不占端口） |
| `tun`(vpn) / `switch` / `wg` / `proxy` / `media` 的真数据面 | ❌ 只有界面 + 配置 + 路由，真协议栈/转发留 TODO |
| WG 页三档的协议栈 | ❌ self/official 只写 TODO 日志；system 真发 Intent（对方 app 存在才会成功） |
| media 的媒体收发 | ❌ 不在本进程做：只把打洞参数交给外部聊天程序 |
| switch 的真转发 hub / DHCP 服务器 | ❌ 未实现（DHCP 只有开关 + 置灰的地址池/网关/DNS） |

---

## 11. 已知的坑 / 注意

- **洞的本机地址是"任意网卡"**：首选绑 `::`（双栈），失败退 `0.0.0.0`。所以 `localIp` 显示 `[::]` / `0.0.0.0` 是正常的，不是 bug；media 页会把本机真实网卡地址另列一行给人看。
- **fd 所有权**：`adopt` 之后由 `SessionManager` 独占（见 §4.3）；`adopt` 之前 `WsClient` / ViewModel 各自会 close。改这块小心 double-close。
- **`_helloMode` 恒为 `"udp"`**（历史遗留，待清理）。
- **前台服务**：Activity 绑服务；`onDestroy` 时 `sessionManager.closeAll()` + 取消作用域。按 Home 键后连接不断（WakeLock/WiFiLock + 前台通知）。
- **明文 ws**（非 wss）默认：登录是 challenge-response（不传密码），但业务消息是明文 JSON，**不要在不信任的网络上用**。
- ⚠️ **上下避让区是"纯黑"，但主题跟系统深浅色**：`P2pnetTheme` 用 `isSystemInDarkTheme()` + dynamicColor（Android 12+ 动态取色）。
  后果：**浅色模式下顶部/底部会出现两条很显眼的黑边**（深色模式下基本看不出来）；而且 `enableEdgeToEdge()`（`MainActivity.kt:73`，未指定 style）
  默认**按系统深浅色**决定系统栏图标明暗 → 浅色模式下状态栏图标是深色，压在纯黑带上几乎看不见。
  **待定**：(a) 整体强制深色主题（`P2pnetTheme(darkTheme = true)`，并把系统栏图标固定成浅色）；(b) 避让区改成跟随主题的深色表面色（浅色模式下就不是纯黑了）。当前实现按用户要求取"纯黑"。

---

## 12. 已解决的问题（Debug Log）

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| UDP 包没发出去 | `server_ip` 服务器没带，fallback 未实现 | `login()` 时保存 `serverHost`，`startUdpHello()` fallback DNS 解析 |
| `EADDRINUSE` | hello 线程和主线程竞争关闭 socket | hello 线程 finally 用 `stopFlag` 判断是否有人要 socket，超时才关 |
| `NetworkOnMainThreadException` | `sendto` 在主线程执行 | 收发放进 IO 作用域（**现为服务作用域**，见 §7.3） |
| IPv6 `:::port` 绑定 | `DatagramSocket()` 默认 IPv6 dual-stack | 曾尝试显式绑 `0.0.0.0`；**现在改为故意用双栈**（`::` + 关 `IPV6_V6ONLY`），失败才退 v4 |
| 签名验证失败 | 无 session_key 派生，`p2pudp_hello` 无 signature | HKDF 派生 session_key，发送时加 signature |
| challenge 后 password 被清 | 两次 auth 需要 password | 保存 `pendingPwHash`，login_ok 时用于派生 session_key |
| P2P RTT 显示 0ms | 错误地用 pong echo 的 ts 算 RTT | 改用本地 sentPings map 记录发送时刻，收到 pong 时查表 |
| 历史消息双倍行距 | 每条消息末尾带 `\n`，Text 里渲染出多余空行 | 消息字符串末尾不追加 `\n` |
| 新消息自动跳到底部 | `LaunchedEffect` 无条件 `animateScrollToItem` | 先判断用户是否已在底部，只有在底部时才滚动 |
| sentPings 无限增长 | 无容量限制 | 超过 100 条时删除最老的 |
| 日志箭头冗余 | `send: → ...` / `recv: ← ...` 和方向前缀重复 | 改为 `send: ...` / `recv: ...` |
| 登录按钮一直灰着点不了 | 退出登录时把 `password` 清空了，而按钮 enabled 要求密码非空 | 退出**不再清密码**；enabled 放宽成 `!loading && (isLoggedIn \|\| isConnected)` |
| 退出登录会把连接断掉 | `logout()` 里调了 `disconnectOnly()` 并停服务 | 改成 `logout(keepConnection = true)`：只发 `{"type":"logout"}`，**不断 WebSocket、不停服务**，重登复用同一条连接 |
| 按 Home 键后 UDP 不再收发 | session/socket/探测循环活在 ViewModel 作用域里，Activity 一停就被挂起 | 全部搬进 `P2pService` 的 `SessionManager`（服务作用域），VM 只观察 `StateFlow` |
| 洞打通后自动跳 tab / 自动交给用法 | 老逻辑在 `onHelloDone` 里直接 `navigateTo` + 起 ping | 只建卡片；**"应用"行为必须由用户在卡片第 5 行点** |
| WG 有独立的"消息历史" | 单独一个 `wgLogMessages` 流，别的页面看不到 | 删掉这个流，`appendWgLog` 直接写进 App 内日志（`wg: …` 前缀） |
| 日志按钮只在主页 | 浮层写在 `MainPage` 里 | 抽成 `ui/AppLogOverlay.kt`，由 `MainScreen` 在所有页面之上渲染 |
| direct 被写成"没 root 做不了 ICMP" | 想当然 | 实际用子进程调 `/system/bin/ping`（老 ROM 退回 `/system/bin/ping6`），**以输出里有没有 `ttl=` 判定**（退出码不可靠） |
| socket 卡片被撑到满屏高 | 卡片里用了 `fillMaxHeight()` + 标题 `weight(1f)` | 去掉，改为内容自适应（`IntrinsicSize.Max`） |
| **连接其实已经死了，界面还显示"已连接"** | `WsClient.onFailure` 只回调 `onError`，而 VM 的 `onError` 只设 `loading`/`error`，**没清 `isConnected`** | `onFailure` 里补一次 `listener?.onDisconnected()`（状态收回未连接），并把原因分成"心跳失败 / 连接失败"两种写进日志；`onDisconnected` 的日志也改成中文 |
| 长连接被中间设备静默掐断（收不到任何事件） | 没有任何心跳 | 两层：OkHttp `pingInterval(20, SECONDS)` 走协议级 WS ping（服务器回 pong），服务端另加应用层 `ping`/`pong`，「我」卡片加 `ping` 按钮可手动验 |
| 心跳失败/异常断开后只能靠用户手动重连 | 没有自动重连 | 加 `WsReconnectPolicy`（60s 滑窗内最多 3 次、退避 1s/2s/4s、超了熔断）+ 稳定 60s / 手动连接清零；重连成功后用内存凭据按现有流程重登，见 §8.1 |
| **重连只试了一次就停**（自己实现时差点漏掉） | 重连尝试本身失败时 `isConnected` 已经是 `false`，只按"之前连上过"判断就会被当成"首次连接失败"挡掉，退避链断掉 | 单独一个 `autoReconnectActive` 状态：**已在重连过程中**时，失败也继续按退避重试（直到熔断） |
| **被踢会被当成"被动断开"→ 自动重连 + 自动重登** | `kicked` 原来落到 `when` 之外被忽略，而那之后的断开会走"被动断开" | 加 `kicked` 分支：被踢**只取消登录状态**（连接不断、心跳不停）；之后掉线因为"断开前未登录"自然只重连不重登 —— **不引入任何"被踢标记"**（见 §8.2） |
| 早期误解：以为"被踢"服务器会关连接 | —— | 实际服务器**只发消息不关 socket**（连接还活着、还能收到 `not logged in`）；所以 `onKicked` 里**不许**动 `wsOpen`、不许停心跳 |

---

## 13. UI 布局

- **Compose + Material3**，非 XML。
- **vpn / switch / proxy 三页的配置卡首行是完全同一套模板**（容器、padding、行高、按钮全都一样，只有"状态文案"和状态变量不同）：
  `Card(fillMaxWidth, RoundedCornerShape(8.dp))` → `Column(Modifier.padding(8.dp), Arrangement.spacedBy(4.dp))` →
  `Row(fillMaxWidth, CenterVertically, Arrangement.spacedBy(6.dp))` = `Text("配置", labelMedium)` + `Text(状态文案, 10.sp, 运行时 primary)` + `Spacer(Modifier.weight(1f))` +
  `Button(height 26.dp, contentPadding h10v0, 运行时红底, 文案 停止/启动 10sp)`。
- **状态文案是两套词汇，别混用**（`ui/ChannelStatusText.kt`，两个兄弟函数，各有 JVM 单测）：
  - **vpn / proxy**（说的是"通道/洞"）→ `channelStatusText(N)`：空 `未接线` / 非空 `已接 N 条`；
  - **switch**（说的是"网口/插线"，与拓扑卡的 `已插 N 个`、`未插线`、`点网口 = 拔线` 保持一致）→ `portStatusText(N)`：空 `未插线` / 非空 `已插 N 个`。
  - 特意**不共用一个带"词汇参数"的函数**，并有一条单测断言两套文案互不相等 —— 防止以后被"顺手统一"成一套导致同页前后不一致。
- **"通道"明细行只在有通道时渲染**（vpn / proxy / media 三页，`if (channels.isNotEmpty())`）：
  **空态不占一行** —— "没有通道"已经由配置卡首行的状态（`未接线` / 已接 N 条）表达，再挂一句"通道：还没有"是重复。
  有通道时保留原格式（列出是哪些洞 + 数量；proxy 带条数）。**判据：首行状态已表达的空态文案 = 不渲染；含动态信息（列表/数量）的 = 保留。**
- **「内嵌 DHCP」那一行和普通字段行完全同构**（vpn / switch 都是，`NumberField` 是基准）：
  `Row(Modifier.fillMaxWidth().height(fieldHeight))` + `Arrangement.spacedBy(4.dp)` + `Text("内嵌 DHCP", 11.sp, Modifier.width(labelWidth))` + `Switch(Modifier.height(fieldHeight))` ——
  **行高 = `swFieldHeight`/`vpnFieldHeight`(30dp)**（不比 MTU / 路由老化 那些行高；`Switch` 被压到同一高度，否则它的 48dp 最小触摸目标会把行撑高），
  **开关的左边缘落在字段列上**（`labelWidth(84dp) + 4dp = 88dp`，与 `NumberField` 里文本框的左边缘一致），**不贴卡片右边界**。
- **主页**：服务器卡片固定顶部 + 下面一整块**自由层**——
  - **服务器卡是三行**（`MainPage.kt` 的 `ConnectionCard`）：
    1. **小字标签行**：`协议` / `服务器` / `端口`（11sp，比输入框正文 14sp 小一号，只起提示作用，左对齐到下面的控件）；
    2. **控件行**：**一个** ws/wss 切换按钮（文字 = 当前协议，默认 `ws`，点一下 `ws` ↔ `wss`；宽 62dp）+ 地址框（弹性，上限 **300dp**）+ 端口框（118dp，够显示 `10000`）；
       输入框内**不再重复** `服务器`/`端口` 字样（`CompactField` 的 `label` 传空 = 不画框内灰色前缀）；
    3. **连接行**：`未连接，点我连接` / `已连接，点我断开`（整宽，行为不变）；
  - **对齐做法**：第 1、2 行用**同一组列宽** + 同一个 `Arrangement.spacedBy(6dp)`，外面套 `fillMaxWidth().widthIn(max = 492dp)`（= 62 + 300 + 118 + 2×6）——
    宽屏时地址框正好 300dp，窄屏（手机）时整块收到卡片宽度、地址框靠 `weight(1f)` 自动变窄，两行**天然对齐**（不依赖任何"按内容自适应"的格子）；
    连接行在限宽块**之外**，仍然整宽。
  - **自由层 = 整个内容区**（`MainPage` 里就是 `FreeLayer(Modifier.fillMaxSize())`，**没有**外层 `Column` 了）：
    **服务器卡片画在自由层里面**（`align(TopCenter)`、顶部对齐、**不可拖动**、两侧 4dp 内边距），
    宽度**随窗口比例实时变化**（读 `BoxWithConstraints` 的 `areaW/areaH` → `serverCardWidthFraction`）：
    **竖屏（高 > 宽）= 满宽；横屏（宽 > 高）= 居中占一半**（左右各留 1/4 宽的空白带；正方形按竖屏算）。
    目的：**"自由层正中" = 整个内容区的正中**（= 用户要的"屏幕中心"）。
  - 「我」卡片（`我` 标题 + 用户名/密码，**默认在自由层正中**、可拖）、其他人卡片（随机落在上半区、可拖）、
  **屏幕几何中心横线**（按窗口 bounds 换算，保证落在屏幕正中）、
  **三种连线**：服务器↔我（未登录=白色虚线 / 登录后=绿色实线）、服务器↔其他每个人（绿色实线）、其他人卡片↔它的 socket 卡片（白色虚线）；
  socket 卡片挂在对应 peer 卡片正下方。连线起点 = **服务器卡片实测下沿**（卡片现在画在自由层里）。
  - **不许盖住服务器卡片**（A3）：限位按**服务器卡片实测矩形 + 6dp** 算（`avoidServerRectPx`）——
    卡片**要么落在左右空白带里**（横屏时纵向可以一直用到顶部），**要么完全在服务器卡片下方**；
    「我」卡片水平居中 ⇒ 必然与服务器卡片同列，所以"默认居中"与限位冲突时**以限位为准**（自动下移到它下面）。
- **底部 6 个固定 tab**（主页 / media / proxy / wireguard / vpn / switch，都不可关闭），临时页（UDP 等）可关。
- **悬浮（edge-to-edge）+ 上下两条纯黑"避让区"**（`MainScreen.kt`）：
  - `MainActivity` 调了 `enableEdgeToEdge()`，且 `targetSdk = 36` 在 Android 15+ **强制** edge-to-edge（所以**不要**去调 `setDecorFitsSystemWindows`，无效）；
  - 顶部避让区 = 状态栏那条：`Scaffold(containerColor = Color.Black)`，内容照常吃 `paddingValues`，上面露出的就是纯黑底色；
  - 底部避让区 = 导航栏那条：**inset padding 在外层、背景在内层**——
    `Column(Modifier.windowInsetsPadding(WindowInsets.navigationBars).background(surfaceVariant))`，
    所以导航栏那条露出的是 Scaffold 的纯黑底色，tab 行落在黑带之上（`LazyRow` 自己**不再**加 `.background(...)`，否则会出现断层）；
    ⚠️ Material3 1.3.0 的 `Scaffold` **只给"内容"加 inset**，自绘 `bottomBar` 必须自己处理 insets，否则 tab 行会被手势条/三键导航压住；
  - 两条避让区里**不放任何可交互控件**（触摸由系统处理：下拉通知栏 / 上滑手势）。
- **App 内日志**是应用级浮层（`AppLogOverlay`）：右下角「日志」按钮 + 90% 面板 + 从按钮缩放，浮在所有 tab 之上；**折叠时不吞触摸**。
- **direct 卡片的结果行**（渲染在 `MainPage.kt` 的 `card.note` 那段，字符串由 `SessionManager` 生成）：
  **一行一个地址**（v4 一组在前、v6 一组在后）、**每行不折行**（卡片宽度本来就按内容自适应，所以**不设宽度上限**）、
  **最多 10 条**（`SessionManager.DIRECT_NOTE_MAX_ADDRS`），超出的用一行暗色 `…还有 N 条` 收尾；可达地址行用绿色 `LinkGreen`。
  没有 `可达：` 前缀，也**没有** footer 说明行（都已删）。第 3 步 detail 仍是 `x/y 个地址可达`；探测始终 ping **全部**地址（显示截断不影响探测）。
- **"会发 WS 的按钮"统一门槛 = `isConnected`**（`list` / `ping` / 其他人卡片的 `direct` / `udp`）：
  `sendJson` 是**先 `onSend` 记日志、再 `ws?.send`**，没连上时后者是空操作 → 日志会出现一条**假的** `client: {...}`，所以必须按连接状态灰。
  例外（有意不 gate）：`upnp` / `tcp` 只画**本地**流程预览卡、不发 WS；登录/退出是 `!loading && (isLoggedIn || isConnected)`（等价于必须已连接）；
  服务器卡的「连接/断开」本身承担连接动作，只看 `!loading`。
- 各页横向 padding 4dp、块间距 6~8dp；卡片宽度按内容自适应（`IntrinsicSize.Max`）；消息字体 7sp、行高 8sp。

---

## 14. 代码规范

- **不修改 Python 代码**（`server/`、`client/`）、**不改协议**、**不新增消息 type**。
- **不执行 git 操作**（这个工作区没有 git 兜底）。
- 只做编译验证；**不安装、不调试、不跑模拟器**。
- UI 文案与注释一律中文，并与 iOS 端保持一致（页面形态、字号层级、措辞）。

---

## 15. TODO

- [ ] 五个"用法"（tun / switch / wg / proxy / media）的真数据面 —— 现在都只有界面 + 配置 + 路由（落点见 `usage/*.kt` 的注释）
- [ ] switch 的进程内转发 hub + 真 DHCP server
- [ ] `tcp` / `upnp` 的真打洞（现在只有 `previewFlow` 画的流程卡）
- [ ] 去掉 `_helloMode` 遗留；`UdpSessionInfo` 改名（它现在也承载 direct / tcp 预览卡）
- [ ] 清掉 `P2pService` 里的调试心跳日志（`IMPORTANCE_EMPTY` 弃用警告，`P2pService.kt:408`）
- [ ] media 的"只负责打洞"之外，把参数契约整理成给第三方聊天程序开发者看的公开文档
