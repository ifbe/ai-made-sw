# P2PNet Android

## 项目概述

- **路径**: `/Users/ifbe/Desktop/code/ifbe/ai-made-sw/p2pnet/android/`
- **目标**: Android 客户端实现 P2P UDP 打洞，与 Python server/client 互通；支持 WireGuard tunnel 建立

## 架构

### 核心组件

| 文件 | 职责 |
|------|------|
| `WsClient.kt` | WebSocket + UDP hello 线程，stopFlag 中断机制，处理 wghelp/p2pudp 消息 |
| `LoginViewModel.kt` | P2P ping/pong 逻辑，sentPings，消息日志，tab 导航，WireGuard tunnel 管理 |
| `P2pRepository.kt` | 封装 WsClient，提供 login/sendWghelp/sendP2pUdp 等接口 |
| `UdpTestPage.kt` | P2P tab UI，Card 布局，LazyColumn 消息历史 |
| `MainPage.kt` | 主页 UI，消息字体/间距，wghelp/udp/chat 按钮 |
| `WireGuardPage.kt` | WireGuard tab UI，支持多 peer、消息历史、独立日志流 |
| `Pages.kt` | 页面类型定义：Main / UdpTest / VideoCall / Chat / WireGuard |
| `LoginUiState.kt` | UI 状态，包含 tabs 列表 |

### Tab 类型

- `MainPage` — 主页，日志显示，按钮（list / wghelp / udp / chat）
- `UdpTestPage` — P2P UDP 测试页，双向 ping/pong，RTT 显示，消息历史
- `WireGuardPage` — WireGuard tunnel 页，支持多 peer、独立日志流

### 数据类型

```kotlin
data class WgInterface(
    val myIp: String = "10.0.0.2/24",
    val myPort: Int = 51820,
    val privateKey: String = "",
    val peers: List<WgPeer> = emptyList()
)

data class WgPeer(
    val id: String = UUID.randomUUID().toString(),
    val endpoint: String = "",        // "IP:Port"
    val publicKey: String = "",         // Peer 公钥
    val presharedKey: String = "",      // 预共享密钥（可选）
    val allowedIPs: String = "0.0.0.0/0",
    val status: TunnelStatus = TunnelStatus.DISCONNECTED
)

// 兼容旧接口（单 peer）
data class WgConfig(
    val myIp: String, val myPort: Int, val myPrivateKey: String,
    val peerEndpoint: String, val peerPublicKey: String,
    val peerPresharedKey: String = "", val allowedIPs: String = "0.0.0.0/0",
    val dns: String = "8.8.8.8", val mtu: Int = 1420
)
```

### WebSocket 消息类型

| type | 方向 | 说明 |
|------|------|------|
| `login` | C→S | 登录 |
| `wghelp` | C→S | 请求 WireGuard 打洞帮助 |
| `p2pudp` | C→S | 请求 UDP 打洞 |
| `thisisyourpeer_udp` | S→C | 服务器推送 peer 信息 |
| `send_udp_to_server` | S→C | 服务器告知 UDP 端口 |
| `p2pudp_hello` | C→S | UDP 打洞探测包（签名） |

### `_helloMode` 标识

- `"udp"` — 普通 P2P UDP 打洞 → 创建 UdpTest tab
- `"wg"` — WireGuard 打洞 → 更新 WireGuard tab 并自动建立 tunnel

## WireGuard 流程

### 自动模式（wghelp）

1. 用户在主页点击 `wghelp` 按钮
2. `sendWghelp(target)` → 设置 `_helloMode = "wg"` → 发送 `{"type": "wghelp", "target": target}`
3. 服务器返回 `thisisyourpeer_udp`，触发 `stopFlag.set(true)` 中断 hello 线程
4. `onHelloDone` 被调用，mode=`"wg"` → 找到 WireGuard tab，更新 `Page.WireGuard(peerIp, peerPort, myIp, myPort)`
5. **WireGuardPage 检测到 peerIp 非空，自动进入"自动模式"**，peer endpoint 预填对方地址
6. 用户点击"启动 WireGuard" → `startWgTunnelAuto()` → 生成 WireGuard 配置并建立 tunnel

### 手动模式

用户手动进入 WireGuard tab（不经过 wghelp），可动态添加多个 Peer：
- Endpoint (IP:Port)
- Peer 公钥
- Preshared Key（可选）
- Allowed IPs

点击"启动 WireGuard" 调用 `startWgTunnelManual(WgInterface)` 建立 tunnel。

### Tunnel 连接/断开

整个 WireGuard tunnel 是整体开/关的：
- **顶部一个连接按钮** — 未连接时显示"启动 WireGuard"，已连接时显示"已连接 — 点击断开"（红色按钮）
- peers 只是配置文件里的条目，删除 peer 只是从配置中移除，不影响 tunnel 本身

### 消息历史

WireGuard 有独立的日志流 `wgLogMessages`，与其他页面（UdpTestPage 等）不共享。包含：
- 点击"启动 WireGuard"时的日志
- 密钥生成日志
- 连接成功/失败日志
- 断开 tunnel 日志

### 默认配置

- 默认 1 个 Peer（可动态添加多个）
- 手动模式默认填入 placeholder 值供演示/调试

## 代码规范

- **不修改 Python 代码**
- **不执行 git commit**
- **不修改 server 端代码**

## 待修问题

- [ ] Tab 关闭时正确停止 socket
- [ ] Tab 重开时重新发起 P2P 请求
- [ ] Android UDP socket 显示 IPv6（但通信正常）
- [ ] WireGuard 真正的 Curve25519 密钥生成
- [ ] WireGuard tunnel 实际建立逻辑（有 root / VpnService / go-backend）
- [ ] 自动模式需要从 wghelp 响应中获取对方公钥
