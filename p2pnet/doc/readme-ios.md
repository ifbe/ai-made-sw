# iOS 端（P2PNet iOS）

iOS 端一句话：**安卓 UI 的 SwiftUI 复刻，和 Python 的 `server/` + `client/` 说同一套协议，把打洞出来的 socket 交给可插拔的"用法"**。
代码全在 `ios/p2pnet/`（36 个 `.swift`、约 6800 行），纯 SwiftUI + Foundation/UIKit/系统 socket，**没有任何第三方依赖**。

> 本文是 iOS 端的**唯一文档**：当前状态（目录 / 页面 / session / 配置 / 契约）+ 协议流程 + 关键设计决策 + 踩过的坑。
> 其它端：[readme-android.md](readme-android.md)（Compose，主力实现）、[readme-desktop.md](readme-desktop.md)（PyQt6 桌面壳）。
> 三端**协议字段、配置 JSON 键名、页面形态都对齐**；差异集中写在 §10。

---

## 1. 怎么编译 / 验证

```bash
# 在仓库根执行
xcodebuild -project ios/p2pnet.xcodeproj -scheme p2pnet -configuration Debug \
  -sdk iphonesimulator -derivedDataPath /tmp/p2pnet-dd CODE_SIGNING_ALLOWED=NO build

rm -rf /tmp/p2pnet-dd          # 编完删掉临时产物
```

- 目标 deployment target：**15.6**（`project.pbxproj` 里 project 级的 26.2 被 target 级的 15.6 覆盖）；`SWIFT_VERSION = 5.0`。
- `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` —— **整个模块默认 MainActor 隔离**，由此有三条约定：
  - 纯工具类型/函数（`UdpSocket`、`LocalAddrs`、`IcmpPing`、`formatHostPort`、`logDisplayText`、`UdpSessionInfo`…）都显式标 `nonisolated`，否则从后台队列调用全是警告（Swift 6 模式下是 error）；
  - 要在后台跑的东西标成 `nonisolated final class … : @unchecked Sendable`（`SessionManager`），内部可变状态由 `NSLock` 保护；
  - `UIApplication.shared` / `UIWindowScene` 本身是 MainActor 的，**不能**标 nonisolated（`ScreenMetrics` 就是例子）：只在 `onAppear` 取一次、缓存进 `@State`。
- `objectVersion = 77` + `PBXFileSystemSynchronizedRootGroup`：**新增 `.swift` 放进 `p2pnet/` 下对应目录即可，不用改 `project.pbxproj`**。
- 开发过程**只做编译验证**：不装 app、不跑模拟器、不截图。`Info.plist` / `project.pbxproj` 保持现状。

---

## 2. 目录与职责

```
ios/
├── Info.plist                  # 不动（不注册任何 URL scheme，外部程序契约见 §6）
├── p2pnet.xcodeproj/           # objectVersion 77，同步文件组（新文件自动收录）
└── p2pnet/
    ├── p2pnetApp.swift / ContentView.swift   # 入口：LocalPrefs → P2pRepository → LoginViewModel → MainScreen
    ├── Models/
    │   ├── Page.swift          # Page 枚举（main/udpTest/videoCall/chat/wireGuard/vswitch/proxy/vpn/media）+ TabItem(closable)
    │   ├── PageConfig.swift    # 五个配置模型：Wg/Switch/Proxy/Vpn/Media（JSON 键名与安卓**完全一致**）
    │   ├── UdpSessionInfo.swift# 卡片快照 + SessionStep（kind 区分 udp/tcp/upnp/direct）
    │   ├── PeerEntry.swift     # list_result 里的一个在线用户
    │   ├── MessageItem.swift   # App 内日志一行（方向 + 内容 + 时间）
    │   └── WireGuard.swift     # WG 页表单用的 WgInterface/WgPeer/WgConfig/TunnelStatus
    ├── Service/SessionManager.swift   # **所有 session 的唯一 owner**（见 §4）
    ├── Util/
    │   ├── UdpSocket.swift     # 地址族感知：openBound（绑 :: 双栈）/ send（v4 目的地自动 v4-mapped）/ localPort/localIp
    │   ├── LocalAddrs.swift    # getifaddrs 枚举本机 v4/v6（过滤 loopback/link-local/组播，保留私有，每族 ≤32）
    │   ├── IcmpPing.swift      # 非特权 ICMP（SOCK_DGRAM + IPPROTO_ICMP/ICMPV6），1s 超时、并发 ≤16、三档结果
    │   ├── Crypto.swift        # SHA-256 / HMAC-SHA256 / 登录 response / HKDF-SHA256 / 随机 base64
    │   ├── HostPort.swift      # formatHostPort：v6 自动加方括号
    │   ├── LogText.swift       # logDisplayText：给 {...} 内插 U+200B，避免无空格 JSON 被整块挤到下一行
    │   └── ScreenMetrics.swift # 窗口高度（画"屏幕几何中心"那条横线用）
    ├── Data/
    │   ├── Remote/WsClient.swift      # WebSocket(URLSessionWebSocketTask) + UDP hello 线程；收发所有信令
    │   ├── Remote/P2pRepository.swift # 封装 WsClient：登录/登出/断开、各 send、回调与配置透传
    │   └── Local/LocalPrefs.swift     # UserDefaults：服务器/用户名/登录态 + 五个配置 JSON
    └── UI/
        ├── MainScreen.swift    # 页面容器：ZStack{ 当前页 + AppLogOverlay } + 底部 tab 栏
        ├── Login/
        │   ├── LoginUiState.swift     # 全部界面状态（连接/登录、peers、socket 卡片、五份配置、*Running、tab 列表）
        │   ├── LoginViewModel.swift   # 界面逻辑：登录/登出/断开、配置读写、六种用法路由、两处外部程序拉起、tab 导航
        │   ├── MainPage.swift         # 主页：一整块自由层（服务器卡片是它内部顶部对齐的元素）
        │   └── FreeLayer.swift        # 自由层：连接线 + 我卡 + 其他人卡 + socket 卡（都可拖）
        ├── Components/
        │   ├── MainCards.swift        # 服务器卡（三行）/ 我卡 / 其他人卡 / CompactField / nodeLabel
        │   ├── SocketCard.swift       # socket 卡片三形态：UDP（五步+六个用法按钮）/ 预览（tcp、upnp）/ direct（三步+可达）
        │   ├── LogCard.swift          # 统一"消息历史"卡：贴底跟随 + JSON 折行，UdpTest 与 App 内日志共用
        │   └── AppLogOverlay.swift    # **应用级** App 内日志浮层（右下角「日志」按钮 + 90% 面板）
        └── Pages/                     # UdpTest / WireGuard / Switch / Proxy / Vpn / Media
```

---

## 3. 页面：底部 tab

**6 个固定页**（顺序固定、`closable = false`，不给 `×`）：

| 序 | 标题 | 页面 |
|----|------|------|
| 0 | `主页` | 自由层 = 整个内容区（服务器卡顶部对齐 + 我卡 / 其他人卡 / socket 卡） |
| 1 | `media` | 收流 / 推流（只读地址端口）+ 拉起外部聊天程序 |
| 2 | `proxy` | 端口转发：模式（正向 -L / 反向 -R）/ 协议 / 保活 / 洞地址端口 + 代理卡 |
| 3 | `wireguard` | 「实现」三档 + 外部 VPN 应用卡 + My Interface / Peer 列表 / 启动断开 |
| 4 | `vpn` | 一对一 tun/tap（= switch 页去掉网口卡） |
| 5 | `switch` | 虚拟交换机：两行交换机卡（网口）+ 配置卡 + DHCP 卡 |

**临时页**（`closable = true`，带 `×`）：UDP 测试页（点 socket 卡片上的 `udptest` 时创建/切过去）。
`videoCall` / `chat` 两个 `Page` case 与占位页仍在，但**当前没有入口**。

`LoginViewModel.navigateTo` 按 **case 类型**判重（对齐安卓的 `it.page::class == page::class`）：命中已有 tab 就切过去并把 page 刷新成新的一份（保留 `closable`），不会因为地址变了重复开 tab。

---

## 4. session 生命周期与「用法」

### 4.1 所有权

一条打洞产出的 socket（session）由 **`SessionManager` 独占持有**（没有前台 Service，它挂在 `LoginViewModel` 上，生命周期跟 ViewModel）。界面只拿快照：

```
hello 线程建 socket → onUdpSocketBound(fd, ip, port) → SessionManager.beginHello(fd)  → 卡片出现（第 1 步）
thisisyourpeer_udp → markStep(.serverReplied) → 填公网/对端地址（第 3 步）+ 启动 ping/pong 探测
探测循环 peer 回包 → markStep(.peerReplied)（第 5 步）→ 用法按钮才可点
```

界面侧 `observer` 回调把 `sessionsSnapshot()` 写进 `uiState.udpSockets`。

**对外的两条回调都保证在主线程送达**（`publish()` 本来就 `DispatchQueue.main.async`；`log()` 也做了线程判断，不在主线程就派发过去）——这是 `SessionManager` 的契约，因为落点都是 `@Published`。内部则相反：`SessionManager` 自己是 `nonisolated` + `NSLock`，**任何线程**都可以调它的方法（WebSocket 接收线程、hello 线程、direct 的 global 队列都会调）。

### 4.2 五步进度

`本机绑定`（卡片出现）→ `发给服务器` → `收到服务器回复` → `发给对端` → `收到对端回复`。
前四步任一没到，第 5 行的用法按钮**不可点**（`enabled = card.peerReplied`）。

### 4.3 关闭语义（别踩 double-close）

- 卡片右上角 `✕` → `SessionManager.close(id)` → 关 fd + 停探测循环 + 清 direct 状态。
- **fd 的唯一关闭点就是 `SessionManager.close/closeAll`**：hello 线程把 fd 交给上层时只做"所有权转移"（把 WsClient 那边的引用摘成 -1），**不在交接前 close**。
- 关 UDP tab 只 `detachAllUsages()`（摘掉用法），**不动 session**。

### 4.4 用法（usage）

`socketManager.usageIds = ["udptest", "tun", "switch", "wg", "proxy", "media"]`，卡片第 5 行按这个顺序出按钮。
点下去（`LoginViewModel.useUdpSocket`）：

| 用法 | 动作 | 跳到 |
|------|------|------|
| `udptest` | 建/切 UDP 页，填本机与公网地址 | UDP 临时页 |
| `tun` | 按 vpn 页配置启动/复用（`vpnRunning`）→ 日志「把 X 接成一对一通道」 | `vpn` |
| `switch` | 按 switch 页配置启动/复用（`switchRunning`）→ 日志「把 X 插到网口」 | `switch` |
| `wg` | 填地址 + 跳 wireguard 页 + 按「实现」三档路由 | `wireguard` |
| `proxy` | 按 proxy 页配置启动/复用（`proxyRunning`）→ 日志「把 X 接成通道」 | `proxy` |
| `media` | 只接通道（不启停）→ 日志「去 media 页点『拉起应用』」 | `media` |

最后统一 `attachUsage(id, usageId:)`：写入 `handedTo` 并打一条"已挂上"的日志。

**`handedTo` 是各页"通道/网口"的唯一事实来源**，不另存状态：

- `switch` → 网口列表（顺序即 port1..portN；**点网口 = 拔线**）
- `vpn` → 一对一通道（多于一条时红字提醒"一对一只要一条"）
- `proxy` / `media` → 通道列表（media 还用它的地址端口填只读框）
- `wg` → 用 WG 页的地址

### 4.5 「打洞方式」与「用法」的区别（设计原则）

- **打洞方式**挂在**其他人卡片**上：`direct` / `upnp` / `udp` / `tcp` —— 只负责"把洞打通"。
- **用法**挂在 **socket 卡片**第 5 行：打通之后才出现、才可点 —— 只负责"这条洞拿来干什么"。
- `direct` 是唯一"没有 socket 的真流程"：枚举本机地址 → 和服务器换地址（10s 超时）→ 并发 ICMP 探测；
  被动收到对方的 `p2pdirect` 会**自动回一份** `p2pdirect_reply`（两边同时点不会重复回）。
  **direct 只证明地址可达，不建隧道**，所以它没有用法按钮。
- `tcp` / `upnp` 目前只有**流程预览卡**（4 步计划），不发信令、不建 socket。

---

## 5. 配置持久化

五个配置各存一份 JSON 原文（键名与安卓一致）：

| key | 模型 | 关键默认值 |
|-----|------|-----------|
| `wg_config` | `WgPageConfig` | `impl=self`、`extPackage=""`、`extAction=com.p2pnet.action.START_VPN` |
| `switch_config` | `SwitchPageConfig` | `card=tun`、`tun_ip=192.168.250.55/24`、`mode=l3`、`mtu=1400`、`route_ttl=300`、DHCP 关 |
| `proxy_config` | `ProxyPageConfig` | `mode=R`、`proto=tcp`、`keepalive=20`、`bindAddr=0.0.0.0`、`lListen=127.0.0.1:8080`、`rTarget=127.0.0.1:` |
| `vpn_config` | `VpnPageConfig` | 同 switch 一套字段，但网段是 `10.0.0.x` |
| `media_config` | `MediaPageConfig` | `recvProto/sendProto=rtmp`、`capture=both`、`appPackage=""`、`appAction=com.p2pnet.action.MEDIA_CHAT` |

新增一个配置项要动四处：`Models/PageConfig.swift`（字段 + `toJson`/`fromJson`）→ `Data/Local/LocalPrefs.swift`（key）→ `Data/Remote/P2pRepository.swift`（透传）→ `LoginViewModel`（初始化读 + setter 写回）。`fromJson` 逐字段退默认，坏 JSON 不会让页面挂掉。

---

## 6. 协议流程

### 6.1 WebSocket 登录（两步认证 + session_key）

1. 连接（`ws://` 或 `wss://`，端口默认 10000）→ 发 `{"type":"login","username":…}`；
2. 服务端回 `{"type":"challenge","salt":…,"challenge":…}`；
3. 客户端算 `pw_hash = sha256(password + salt)`、`response = HMAC-SHA256(pw_hash_bytes, challenge_bytes)` → 再发 `{"type":"login","username":…,"response":…}`；
4. 服务端校验通过回 `{"type":"login_ok","username":…}`；
5. **两端各自在本地**派生会话密钥（从不传输）：`session_key = HKDF-SHA256(ikm = pw_hash, salt = pw_hash, info = challenge)`
   —— 服务端 `server.py:hkdf_sha256`、安卓 `WsClient.hkdfSha256`、iOS `Crypto.hkdfSHA256` 三份实现同一算法（已用 Python↔Swift 交叉 KAT 对齐十六进制值）。

⚠️ **踩过的坑**：iOS 曾经只声明 `sessionKey` 却忘记派生，于是 `p2pudp_hello` 里**不带 `signature` 字段**；服务端 `verify_session_signature()` 校验失败就 `continue`（连本机 UDP 公网地址都不记录）→ 双方地址凑不齐 → `thisisyourpeer_udp` 永不下发 → **UDP 洞永远打不通**。现在 `login_ok` 里用 `Crypto.hkdfSHA256(ikm: hexToBytes(pendingPwHash), salt: 同上, info: hexToBytes(pendingChallenge))` 派生，hello 带 `signature = HMAC-SHA256(session_key, "ping")`。**注意喂进去的是 hexDecode 后的字节，不是 hex 字符串本身的字节。**

### 6.2 消息类型

只收发三端**已有**的 type，**没有新增 type、没有改字段名**。

| type | 方向 | 说明 |
|------|------|------|
| `login` | C→S | 第一次带 username 取 challenge；第二次带 response |
| `list` | C→S | 取在线用户 |
| `logout` | C→S | 退出登录（**不断开 WebSocket**） |
| `p2pudp` | C→S | 请求 UDP 打洞 |
| `p2pudp_hello` | C→S(UDP) | 打洞探测包，带 `signature = HMAC(session_key,"ping")` |
| `p2ptcp` | C→S | 预留（点 tcp 只出预览，不发） |
| `p2pdirect` / `p2pdirect_reply` | C→S | direct 地址交换（`target`/`ipv4`/`ipv6`，无签名无端口） |
| `challenge` / `login_ok` / `login_failed` | S→C | 登录挑战与结果 |
| `send_udp_to_server` | S→C | 告知 UDP 端口 → 客户端开始发 hello |
| `thisisyourpeer_udp` | S→C | 对方地址 + 服务器眼里我的公网地址 |
| `list_result` | S→C | 在线用户列表 |
| `p2pdirect` / `p2pdirect_reply` | S→C | 对方转来的地址表（`from` 由服务器填） |

其它 type（如 `error`）落到 `handleMessage` 的 `default` 分支**被忽略**；`kicked` 已单独处理（见 §6.5）。

### 6.3 退出登录 / 断开连接（两条独立路径）

| | `onLogout()` | `onDisconnect()` |
|---|---|---|
| 网络 | `repository.logout(keepConnection: true)` → 发 `{"type":"logout"}`，**连接保留** | `repository.disconnectOnly()` → 真断连 |
| 状态 | `isLoggedIn/loggedInUsername/myIp/myPort/peers` | `isConnected/isLoggedIn/loading/myIp/myPort/peers` |
| 不动 | `isConnected`、已输入的密码、App 内日志、服务 | App 内日志 |
| 都做 | `closeAllUdpSockets()`（iOS：`sessionManager.closeAll()`） | 同 |

`P2pRepository.logout(keepConnection: Bool = false)`：`true` 发 `logout`，`false` 断开；之后都 `clearSession()` + 清 `loggedInUsername`。
「我」卡片的登录按钮 enabled 条件是 `!loading && (isLoggedIn || isConnected)` —— 登出后连接还在，所以**按钮不会灰死**。

### 6.5 连接保活与自动重连（带熔断）

- **心跳**：`WsClient.startHeartbeat()` 每 **20s** 发一次 WS 协议级 ping，`HeartbeatWatchdog` 10s 兜底；
  发出/收到/失败各一行日志（见 §12 相关两条坑）。
- **自动重连**：**连接已建立过**之后，因心跳失败或异常断开（`didCloseWith` / `didCompleteWithError` /
  接收失败）→ 自动重连；**用户手动点断开不重连**，**首次连接就失败也不重连**（保持原状）。
- **间隔与熔断**：尝试间隔 **1s → 2s → 4s**；`WsReconnectPolicy` 保证 **60 秒滑窗内最多 3 次**，
  超了打一行 `ios: WS 自动重连已放弃：60 秒内已重连 3 次仍失败（不再自动重连，请手动连接）`；
  过程日志 `ios: WS 自动重连：第 N 次（60 秒窗口内）`，成功 `ios: WS 自动重连成功（第 N 次）`。
- **计数清零**：① 用户手动点连接（`WsReconnectPolicy.noteManualConnect()`，`connect(isAutoReconnect: false)` 里调）；
  ② 连接**稳定存活 ≥60s**（`startStableTimer()` 到点调 `noteStable()`）。**自动重连自己不清零**，否则熔断永不触发。
- **被服务器踢下线（`kicked`）不是断开**：服务端只发 `kicked` + 清 username + 从 `online_users` 移除，**不关 socket** ——
  连接仍活着、仍可收发（再发消息回 `not logged in`）。所以客户端收到 `kicked` **不能**走断开收尾：
  **不关连接、不停心跳/看门狗、不排重连**；只做两件事：① 取消登录状态（`isLoggedIn=false`、清 `sessionKey`/用户名/密码、`sessionManager.closeAll()`，但**不动 `isConnected`**）；② 打日志
  `ios: 被服务器踢下线（<message>）：登录已取消，不会自动重新登录`。
- **"断开前最后状态"必须无条件记录**：`onDisconnected` 里是 `wasLoggedInBeforeDrop = uiState.isLoggedIn`（**赋值**，不是"已登录时置 true"）。写成后者的话它一旦为 true 就永远留着 —— 用户之后登出/被踢（`isLoggedIn` 变 false）再遇到一次被动断开，会被错误地用内存里还留着的凭据自动登回去。
- **自动重登的判据只看"断开前的最后状态"**（没有"被踢标记"这种东西，状态即真相）：
  `WsReconnectRules.shouldRelogin(event, wasLoggedIn:)` = `event == .passiveDrop && wasLoggedIn`，
  其中 `wasLoggedIn` 在断开那一刻取 `uiState.isLoggedIn`。于是：
  断开前已登录 → 重连 + 自动重登；断开前只是"已连接未登录" → 只恢复连接（日志 `ios: WS 自动重连：连接已恢复，断开前未登录，不自动重新登录`）；
  用户主动断开 → 都不做。**被踢不需要单列规则**（踢就是把状态从"已登录"打回"已连接未登录"，之后掉线自然落进"不重登"）。
- **重登失败不循环重试**：没有凭据时打一行 `ios: WS 自动重连：连接已恢复，但没有可用的凭据，需要手动重新登录` 就停；
  登录失败也只在日志里留一行（既有登录流程本来就没有重试循环）。
- **重连成功后恢复登录**：断开前是"已登录"且内存里还有用户名/密码 → 用保存的凭据走现有登录流程重新登录
  （文案 `ios: WS 自动重连：用保存的凭据重新登录`）
  （服务端对同名重登是"踢旧连接、接受新连接"）；拿不到凭据 → 只打一行说明需要手动重新登录，**不假装已登录**。
- **状态显示**：重连期间沿用断线态（`isConnected = false`），重连并登录恢复后才回到"已连接"。
- `WsReconnectPolicy` 与 `HeartbeatWatchdog` 都放在 `Util/HeartbeatWatchdog.swift`（Foundation-only，
  可 `swiftc` 单独编译做断言）；策略里注入了 `now` 闭包，测试才能断言 60s 滑窗。

### 6.4 direct 的可达性探测

- 枚举本机 v4/v6（`LocalAddrs`，每族 ≤32）→ `p2pdirect` 发给服务器 → 等对方地址（10s 超时）；
- 到齐后并发探测（`IcmpPing`，并发 ≤16、每个地址 1s 超时），结果三档：**可达 / 不可达 / 本机无法执行 ICMP**（建不了 ICMP socket 或没权限）；
- 日志按地址逐条打（一行一个），卡片末行写 `可达：…` 或 `0/N 个地址可达`。

---

## 7. 两处「交给外部程序」的契约

两处都用**自定义 URL scheme + `UIApplication.shared.open(url, options:[:], completionHandler:)`**（用回调 Bool 判断有没有 app 接走）。**不改 `Info.plist`、不用 `canOpenURL`**；参数全部取自打洞结果，开之前先写进 App 内日志。

**1）wireguard 页「调系统程序」**（`WgPageConfig.impl == "system"`）

```
p2pnetvpn://start?listen_port=…&peer_ip=…&peer_port=…&my_public_ip=…&my_public_port=…
```

scheme 取 `extPackage`（留空 = `p2pnetvpn`），host 固定 `start`；`listen_port` 必须是**打洞时那个本地端口**，否则 NAT 映射作废。
`extAction` 保留 JSON 键以便三端配置对照，但 iOS 拼 URL 时不用它，只在日志里体现。

**2）media 页「拉起应用」**（7 个 key，与安卓 `MainActivity.launchMediaApp` 的 extras 一致）

```
p2pnetmedia://start?localaddr=…&localport=…&peeraddr=…&peerport=…&recv_proto=…&send_proto=…&capture=…
```

- `localaddr`/`localport` = 本机侧（洞的本机地址/端口）；`peeraddr`/`peerport` = **对方路由器公网**地址/端口（对方内网地址不用管）；
- scheme 取 `appPackage`（留空 = `p2pnetmedia`），host 固定 `start`。

---

## 8. 日志

- **统一进 App 内日志浮层**：`UI/Components/AppLogOverlay.swift`，由 `MainScreen` 放在页面内容之上（`ZStack { 当前页; AppLogOverlay }`）→ **切到任何 tab 都能看到、都能点开**；浮层只占"内容区"那一层，底部 tab 栏在它下面的 `VStack` 里，不会被盖住。
- 折叠时只剩右下角「日志」按钮；展开是 **90% × 90%** 面板，以右下角为锚点从按钮放大/缩回（0.26s）。
- **折叠时"遮罩 + 面板"整块不插入视图树**（`if expanded { … }` + `.transition(.scale(scale:0.06, anchor:.bottomTrailing).combined(with:.opacity))`）：既不可能吞触摸，也保证那个带 `ScrollView`/`PreferenceKey`/`scrollTo` 的面板在折叠时**完全不参与布局**（安卓也是 `if (progress > 0.001f)` 才组合）。
- 面板内容：标题「App 内日志」、清空 / 📋复制（复制用原文，不含零宽空格）/ ✕；列表用 `LogCard`，自带"贴底跟随"（iOS 15.6 没有滚动阶段 API，用 `GeometryReader` + `PreferenceKey` 判最后一行可见 + `simultaneousGesture` 判手动滚动）。
- **wireguard 页没有自己的消息历史**：`appendWgLog(text)` 直接写进 App 内日志（`appendMessage(.system, "wg: \(text)")`）。
- 日志**跨连接保留**：只有日志面板的「清空」（`clearMessages()`）才清；登出、断开都不清。

---

## 9. 卡片层（主页自由层）

- **服务器卡片**（自由层内**顶部对齐、不可拖动**，三行）：**宽度按内容区宽高比实时算** —— 竖屏（高>宽，含相等）占满宽、两侧各留 4pt；横屏（宽>高）**占一半宽且水平居中**（左右各 1/4 空白带，见 `ContentLayout.serverCardFrame`）。第一行小字标签 `协议 / 服务器 / 端口`；第二行 `[ws]`（**一个按钮**，点一下在 ws↔wss 之间切）+ 地址框 + 端口框；第三行连接/断开按钮。两行用**同一组列宽**（协议 62、地址弹性≤300、端口 118、间距 6）保证标签正对控件。
- **「我」卡片**：**默认落在整块自由层（= 整个内容区）正中**，拖动把手是**标题行**（`我(ip:port)`）；用户名/密码标签在框外；下面一行「登录/退出」+「ping」+「list」。几何抽在 `MeCardGeometry`（`Util/ScreenMetrics.swift`，Foundation-only 纯函数，可单独 swiftc 断言）：横向 ±(可用宽−卡片宽)/2，纵向相对**中心锚点**对称、两端 margin=0；上侧受**服务器卡片实际矩形**限制（水平相交时让到它下沿，横屏的左右 1/4 空白带可一直用到顶部 —— A3）；**装不下时以限位为准**（卡片被推到服务器卡片下方）。
- **其他人卡片**：位置由名字哈希伪随机（只在上半区、进程内稳定），拖动把手也是**标题行**；下面是 `direct/upnp/udp/tcp` 四个打洞按钮。
- **socket 卡片**：挂在对应其他人卡片正下方（第一次量到尺寸时冻结基准位置），右上角 `✕` 关闭；这张卡是**整卡可拖**（和安卓一致）。
- **连线**（画在最底层）：服务器下沿→我卡（未登录白虚线 / 登录后绿实线）、服务器下沿→其他人卡标题中心（绿实线）、其他人卡底边→它对应的 socket 卡（白虚线）；再加一条**屏幕几何中心**的贯通横线（用窗口高度算，不是自由层中心）。

---

## 10. 与 Android 的差异

| 方面 | Android | iOS |
|------|---------|-----|
| 交给外部程序 | `Intent` + `startActivity` / `getLaunchIntentForPackage` / `PackageManager` + manifest `<queries>` | 自定义 URL scheme + `UIApplication.open`；`extPackage`/`appPackage` 语义是 **URL scheme**，JSON 键名保持一致 |
| direct 的 ICMP | 子进程调 `/system/bin/ping`，看输出里有没有 `ttl=` | 非特权 `socket(AF_INET/AF_INET6, SOCK_DGRAM, IPPROTO_ICMP/ICMPV6)` 自组 echo request（`SOCK_RAW` 要 root，不用） |
| 消息历史"贴底跟随" | Compose `canScrollForward` + `isScrollInProgress` | `GeometryReader` + `PreferenceKey`（iOS 15.6 没有 `scrollPosition`/`onScrollGeometryChange`） |
| 长 JSON 折行 | 显示时插 U+200B | 同一套做法（`logDisplayText`，只认 `{` 不认 `[`） |
| session 归属 | 前台 `Service` 里的 `SessionManager`（进后台/Activity 重建都不丢） | 没有前台 Service，`SessionManager` 挂在 `LoginViewModel`（`ObservableObject`）上 |
| 并发模型 | 协程 + 主线程 Handler | 默认 MainActor 隔离；纯工具显式 `nonisolated`，`SessionManager` 用 `NSLock` + `@unchecked Sendable` |
| 退出登录 / 断开 | 发 `logout` 保持连接 / `disconnectOnly()` | 已对齐（见 §6.3） |

---

## 11. 已知限制 / TODO

点下去会在 App 内日志里写 TODO 的地方：

- **WireGuard 三档只有 UI + 路由**：`自己实现` / `官方库` 只写 TODO（官方库那档**没有引入任何依赖**，接它需要 SPM + NetworkExtension target）；`调系统程序` 会真的拼 URL 并 `open`，对方 app 不存在时走"没找到"分支。
- WG 页的 My Interface / Peer 卡与「启动/断开」按钮：只把配置拼成文本 + 写日志，没有真隧道。
- **switch 的真转发 hub 没做**：`switchRunning` 只是页面状态；网口编排（`handedTo` 驱动的 port1..portN、点口拔线）是真的。
- **VPN（tun）没有真 tun/tap 与协议栈**：`vpnRunning` 只是页面状态。
- **proxy 的真转发没做**：`-L` 监听 / `-R` connect、保活都还没跑起来。
- **media 的媒体收发全在外部程序里**：iOS 只负责打洞 + 把参数递出去。
- **tcp / upnp 只有流程预览**：不建 socket、不发信令。
- DHCP：switch / vpn 页只有开关，地址池/网关/DNS 三个框置灰。
- `videoCall` / `chat` 占位页没有入口。

---

## 12. 踩过的坑（都是真修过的）

| 问题 | 原因 / 修法 |
|------|-------------|
| 打洞成功后 socket 用不了 | hello 线程在把 fd 交给上层**之前**就 close 了。改成**所有权转移**（只把 WsClient 的引用摘成 -1），fd 的唯一关闭点放 `SessionManager.close/closeAll` |
| 本机端口显示成乱码 | `sin_port` 是网络字节序，原来写成 `Int(sin_port).bigEndian`。改成 `UInt16(bigEndian:)`，并按 socket 实际地址族解析（双栈读 `sockaddr_in6`） |
| 发 `wghelp` 只收到 error | 服务端 `handle_wghelp` 早已注释掉。整条路径（按钮/`onWghelp`/`sendWghelp`/`_helloMode="wg"`/死分支）已删，wg 入口改成 socket 卡片上的按钮 |
| hello socket 只能跑 v4 | 改成优先绑 `::` 双栈（显式关 `IPV6_V6ONLY`），失败退 `0.0.0.0`。**注意**：BSD 不接受在 AF_INET6 socket 上用 `sockaddr_in` 发 v4（Java 会自动转、C 不会），所以发送统一走 `UdpSocket.send`，v4 目的地写成 v4-mapped |
| 断开时上层收不到通知 | `didCloseWith` 参数写成 `closeCode: Int`，与协议要求"nearly matches"→ 回调可能根本不被调用。改成 `URLSessionWebSocketTask.CloseCode` |
| 点 proxy/vpn/media 开出重复 tab | `samePageKind` 是 `switch(a,b){…default:false}`，加了 `Page` case 漏补就认不出已有固定 tab（编译器不报错）。已补齐 |
| **拖「我」卡片一拖整页卡死** | 拖动把手用了 `DragGesture` 的默认坐标空间 **`.local`**，而卡片位置又由这个手势的位移驱动 → 卡片一移动，坐标系跟着动，`translation` 里混进"卡片自己刚移的那段"，形成**每帧写状态→卡片再移**的振荡回路，主线程被占满、触摸再也进不来（所以"点标题行没事、一拖就死"，且没有崩溃日志 = hang）。修法：`DragGesture(minimumDistance: 2, coordinateSpace: .global)` —— 固定参照系；三个把手（我卡/其他人卡/socket 卡）都改了 |
| 同一张卡片被两层手势抢 | 我卡/其他人卡的标题行本来就有拖动手势，我又在 FreeLayer 给整卡挂了一层（安卓的 `dragHandle` 是**只有挂它的那一行能拖**）。整卡那层已删；socket 卡保留整卡手势（安卓就是整卡可拖） |
| **心跳失败那句日志在三端里只有安卓出现，iOS 什么都不显示** | `URLSessionWebSocketTask.sendPing` 的回调**只在"收到 pong"或"出错"时触发**；对端**不回 pong**（老服务端不支持 WS 协议级 ping）时回调**永远不触发** —— 既没有 error、也没有任何代码执行，于是既不判死也不打日志。本机实测（真 `URLSessionWebSocketTask` + 最小 Python WS 服务端）：不回 pong 时回调 12s 内从未触发、服务端确实收到了 `opcode=0x9`；回 pong 时回调 0.00s 触发。修法：抽出 `Util/HeartbeatWatchdog.swift`（`arm/complete/cancel`），每次发 ping 前 `arm()` 一个 **10s** 看门狗，`complete(nil)` 收到 pong 就取消、`complete(error)` 立即判死、看门狗到期（10s 没等到 pong）也判死，三条路都汇到 `handleHeartbeatFailure`（打 `ios: WS 心跳失败，连接已断开（…）` + 停心跳 + 清状态 + `onDisconnected`）。⚠️ 看门狗的 `leeway` 一开始给了 1s，导致 0.3s 的小超时根本测不出来，已改成 100ms |
| **连接被静默回收后界面一直显示"已连接"**（`receive()` 不返回也不报错，`onDisconnected()` 永不触发） | `timeoutIntervalForRequest` 对 WS 的 `receive` 不生效，中间设备（NAT/防火墙）把连接悄悄丢掉时既没有 `.failure` 也没有 `didCloseWith`。修法：加 **WS 协议级心跳** —— `DispatchSourceTimer` 每 **20s**（三端统一）调一次 `wsTask.sendPing { error in }`。每次**真的发出**之前打一行 `ios: WS 心跳：发出协议级 ping（第 N 次，间隔 20s）`收到 pong 再打一行 `ios: WS 心跳：收到协议级 pong（第 N 次）` 与它配对 —— **N 是「对应那一次 ping」的序号**（`sendPing` 之前先把 `heartbeatSeq` 捕获成局部常量，否则回调触发时计数器可能已经涨到下一次，日志会张冠李戴）；N 从 1 起、随连接重置；被看门狗挡下而跳过的那一轮既不「发」也不「收」，两行都不打；**失败时只打** `ios: WS 心跳失败，连接已断开（…）`（不打「收到」），然后停心跳 + 清 `isConnected/isReceiving` + cancel task/session + `listener?.onDisconnected()`（走和正常关闭同一套收尾，界面因此变成"未连接"）。**收到 pong 不打日志**（否则每 20s 刷一行）。断线**不做自动重连**（本轮只保证状态正确） |
| **iOS 的 UDP 打洞完全不通**（日志里只有 `startUdpHello EARLY RETURN!`，"给服务器 udp 端口发消息"那步一个包都不发） | 服务端 `send_udp_to_server` **只发 `udpport`、从不发 `server_ip`**（`server/server.py` 里 `server_ip` 0 处命中），而 iOS 原来只读那个字段 → `serverIp` 恒为空 → `startUdpHello()` 第一句就 early return。安卓有兜底（`InetAddress.getByName(serverHost)`），iOS 全树**没有任何 DNS 解析**（`getaddrinfo`/`CFHost` 0 处），而且 `sendto` 喂域名本来就发不出去（实测 `send(ip:"localhost")` → `-1 errno=22 EINVAL`）。修法：新增 `UdpSocket.resolveHost(_:)`（`getaddrinfo(AF_UNSPEC)`、`getnameinfo(NI_NUMERICHOST)`、v4 优先、去 v6 scope），在 `startUdpHello()` 判空之前解析 `serverHost` 兜底，并打日志（成功 `serverIp fallback resolved: <ip> from <host>`、失败 `serverIp fallback failed: <host>`，措辞与安卓一致） |
| **iOS 报「10.87.159.224 可达」，但电脑 ping 不通那个地址** | `pingOnce` 里 `recvfrom(fd, &buf, buf.count, 0, nil, nil)` 第 5 个参数是 `nil`（不取来源），判定只看 `type == 129/0` → **只要这个 socket 上收到任何 ICMP echo reply 就判可达**，不管是谁回的（安卓是子进程调系统 `ping`，它自己校验，所以安卓的结论可信）。修法：`recvfrom` 用 `sockaddr_storage` 取回来源，**按二进制**与目标地址比对（v6 字符串有多种压缩/大小写写法，比字符串会误判），只认来源相符的回包；不符则**丢弃并继续等**、同时打一行日志 `ios: [direct] ping <ip> ← 忽略来自 <真实来源> 的回包（来源不符）`，命中时 `Result.detail` 写成 `echo reply from <来源>` —— 这样"真通了"和"其实没通"在日志里一眼可辨。顺带实测确认：**Darwin 上无法校验 ICMP id**（`getsockname()` 在 sendto 前后都返回端口 0，id 是内核私下分配的），所以没做 id 校验，也没留"看起来在验、实际永远跳过"的假检查 |
| **direct 自测不对称：安卓 ping 得通 iOS 的 v4，iOS 只 ping 得通安卓的 v6** | Darwin 上 `SOCK_DGRAM` + `IPPROTO_ICMP`（**v4**）的 `recvfrom` 回包**带 20 字节 IPv4 头**（Linux 会帮我们剥掉），原来按"`buf[0]` 就是 ICMP type"读 → 读到的是 IP 头的 `0x45`，永远匹配不上 echo reply（type 0）→ v4 全判"不可达"；而 ICMPv6 的回包**不带** IPv6 头，`buf[0]` 就是 129，所以 v6 一直是对的。修法：读 type 前按 **IHL**（`buf[0] & 0x0f) * 4`）跳过 IPv4 头（用 IHL 而不是硬编码 20，兼容带选项的头）。**另一条同时实测到的**：v4 的校验和**必须自己算**，Darwin 内核不会替 dgram ICMPv4 重算（留 0 时 sendto 成功但一个回包都收不到） |
| **点 `direct` 立即卡死**（Xcode 只给一句 `[SwiftUI] Publishing changes from background threads is not allowed`） | `SessionManager.log()` 原来是在**调用它的那个线程**上同步回调 `onLog`，而落点 `udpLog()` 写的是 `@Published var udpSockMessages`。调 `log()` 的却大量是后台线程：`startDirect()` 的 `DispatchQueue.global` 块（枚举地址/等地址/超时）、`onDirectFromPeer()`（WsClient 的 **WebSocket 接收线程**）、`startProbe()` 探测循环（每秒 send/recv 各一条）。后台线程写 `@Published` → SwiftUI 未定义行为/重入 → 界面卡死；`list` 不卡是因为它的回调本来就 `DispatchQueue.main.async` 了。修法：**`log()` 内部判线程，不在主线程就派发到 main**，并在 ViewModel 的两条接线上加了同样的兜底（顺手把 `observer` 里的 `MainActor.assumeIsolated` 换成安全跳转——那个 API 不在主线程会直接 trap 成崩溃） |
| 日志浮层折叠时吞整页触摸 | 面板常驻（缩到 0.06 + 透明）时必须 `.allowsHitTesting(expanded)`；后来进一步改成**折叠时不插入**（见 §8），彻底没这个问题 |
| JSON 被整块挤到下一行 | 行断开按"词"来，无空格 JSON 是一整个词。显示时在 `{...}` 内插零宽空格 U+200B（复制仍用原文） |
| 「登录按钮灰死」 | enabled 曾只看 `isLoggedIn`，登出后按钮变灰点不回去。现在与安卓一致：`!loading && (isLoggedIn \|\| isConnected)` |

---

## 13. 代码规范

- **内嵌 DHCP 的开关在「配置」卡最后一行**（`内嵌 DHCP` + Toggle，默认关）；**关着时整张 DHCP 卡不渲染**，`dhcpEnabled` 在 `SwitchPageConfig` / `VpnPageConfig` 里默认 `false`。DHCP 卡首行与配置卡首行**同构等宽**（同为 `VStack(alignment:.leading, spacing:)` + `.padding(8)` + 行内 `.frame(maxWidth: .infinity, alignment: .leading)` + `Spacer(minLength: 6)`）。
- **配置卡首行三页统一**（vpn / switch / proxy）：`配置`（左）+ **数量状态** + `Spacer(minLength: 6)` + **启停按钮（最右，同一行）**，整行 `.frame(maxWidth: .infinity, alignment: .leading)`；按钮配色一致（运行时红底、字「停止」）。**不再用 `运行中 / 已停止`** —— 运行状态由按钮文案表达。数量状态按页面的单位取词：**vpn / proxy 用通道数**（`未接线` / `已接 N 条`），**switch 用网口数**（`未插线` / `已插 N 个`，与同页拓扑卡用词一致）。
- **空态文案若已被别处状态表达，就整行不渲染**（不是换文案）：vpn/proxy/media 三页的「通道：…」那行只在**有通道时**才渲染（`if !channels.isEmpty { Text(channelText) }`）—— 空的通道状态由配置卡首行（`未接线` / `已接 N 条`）或只读地址框（`打洞后自动带出`）表达。**含动态信息的行要留**（有通道时的列表、`⚠️ 一对一只要一条` 纠错提示）。
- **开关类行与字段行同构**：`内嵌 DHCP` 这类「标签 + 开关」的行也用字段行的写法 —— `HStack(spacing: 4)` + 标签列（本页同一个 `labelWidth` / `vpnLabelWidth`）+ 控件紧跟其后 + 行尾 `Spacer(minLength: 0)`；**不要用 `Spacer` 把开关顶到最右边**，也**不要**单独加高行高。（`scaleEffect` 只缩放绘制、不改布局，右边的溢出正好落在空白里。）
- **界面上不放解释性文字**：字段标签、单位、状态、按钮、错误提示、必要的最短操作提示（如「点网口 = 拔线」「洞端口留空 = 用 session 的端口」）保留；**讲 python 端文件、讲"去主页第几行怎么点"、讲实现现状/架构的长句一律不要**（信息写进代码注释）。日志里也不要写"到主页怎么点"这种导航提示。
- UI 文案、日志、注释一律**中文**，并尽量与安卓对齐（日志前缀 `ios:` ↔ 安卓 `android:`）；状态变化要进日志（`appendMessage(.system, …)`），别静默失败。
- 只用 **iOS 15.6** 可用的 API；不引第三方依赖；新文件直接放对应目录（同步文件组，不用改 pbxproj）。
- **拖动位移必须用 `.global` 坐标空间**（§12 那条坑），并且"被拖的视图"不要同时被两层手势接管。
- **跨线程回调一律回主线程再碰 UI 状态**：任何从后台队列/系统回调（`URLSessionWebSocketTask` 的接收线程、hello 线程、`DispatchQueue.global`）里调到 ViewModel 的东西，写 `@Published` 前必须 `DispatchQueue.main.async`（或 `Thread.isMainThread` 判断后跳转）。`SessionManager` 已经统一保证了这点（见 §4.1），新增回调时照抄这个写法；**别用 `MainActor.assumeIsolated`** ——它只做断言，不在主线程会直接崩。
- 纯工具类型标 `nonisolated`；需要后台执行的类用 `nonisolated final class … : @unchecked Sendable` + `NSLock`。
- **WS 连接断了要自动重连，但必须有熔断**：统一走 `WsReconnectPolicy`（60s 滑窗 / 最多 3 次 / 间隔 1·2·4s），计数只在**手动连接**或**稳定存活 60s** 时清零 —— **自动重连自己不能清零**。用户手动断开、首次连接就失败都不重连。
- **任何"等对端回包"的检测都必须有超时兜底**：系统回调（`sendPing`、`receive`、各种 completion）**不保证一定会被调用** —— 别把状态收尾只挂在回调里。统一用 `HeartbeatWatchdog`（`arm/complete/cancel`）这类看门狗，超时和报错走**同一个**收尾函数。
- **WS 连接必须有协议级心跳**（`WsClient.startHeartbeat()`，**20s** 一次 `sendPing`；发之前打「第 N 次」、收到 pong 打「收到（第 N 次）」两行配对（序号要用 `sendPing` 前捕获的局部常量），被跳过的那轮两行都不打），因为 `receive()` 在连接被静默回收时不会返回也不会报错；心跳失败必须接到断开处理上。要发**应用层** ping（`{"type":"ping","seq":N}`）请用 `WsClient.sendAppPing(seq:)`，两者别混。另外：**要给日志看的手写报文别用 `JSONSerialization` 拼字典**（键序不稳定），手工拼字符串更可控。
- **外部传进来的"主机名"在使用前必须解析成 IP 字面量**：`sendto`/`inet_pton` 只认字面量，喂域名是 `-1 errno=22`。统一走 `UdpSocket.resolveHost(_:)`（内部 `getaddrinfo`）；**别指望服务端给 `server_ip`** —— 它只发 `udpport`。
- **ICMP 收包必须校验来源地址**（`recvfrom` 的 `sockaddr_storage` + 与目标**按二进制**比对），别只看 `type == 129/0` —— 否则任何 echo reply 都会被当成本目标的回包（曾因此误报一个不可达地址"可达"）。
- **Darwin 的 ICMP 有两条和 Linux 不一样的地方**（都在 `IcmpPing.swift` 里，别当冗余删掉）：v4 收包要先按 **IHL 跳过 IPv4 头**再读 ICMP type（v6 不用）；v4 的**校验和必须自己算**（内核不替 dgram ICMPv4 重算）。
- 改动后必须编译通过（0 error），编完删 `/tmp/p2pnet-dd`。
