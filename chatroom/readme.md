# Chatroom - Android & iOS 终端聊天 App

## 项目概述

多 Tab 聊天终端 App，每个 Session 是一个多参与者聊天室，支持：

| 类型 | 图标 | Android | iOS | 说明 |
|------|------|---------|-----|------|
| **SERIAL** | 🔌 | ✅ 完整实现 | ⚠️ UI stub（iOS 不支持 USB 串口） | 串口通信 |
| **PTY** | 🖥️ | ✅ 完整实现 | ⚠️ stub（iOS 沙盒限制） | 本地伪终端 |
| **SSH** | 🔐 | ⚠️ UI 配置 | ⚠️ UI 配置 | SSH 连接 |
| **TELNET** | 📡 | ✅ 完整实现 | ✅ 完整实现 | TELNET 连接 |
| **SOCKET** | 🌐 | ✅ 完整实现 | ✅ 完整实现 | TCP/UDP socket 客户端 |
| **BBS** | 💬 | ⚠️ UI 配置 | ⚠️ UI 配置 | 论坛/BBS |
| **AI** | 🤖 | ✅ 完整实现 | ✅ 完整实现 | OpenAI 兼容 API |
| **OPENCLAW** | 🦞 | ⚠️ UI 配置 | ⚠️ UI 配置 | 本地 OpenClaw gateway |
| **BLUETOOTH** | 📱 | ⚠️ UI stub（Android Central） | ⚠️ UI stub（iOS Peripheral） | BLE 直接通信（无中转） |
| **INFRARED** | 💡 | ⚠️ UI 配置 | ⚠️ UI 配置 | 红外遥控 |
| **SMART_DEVICE** | 🏠 | ⚠️ UI 配置 | ⚠️ UI 配置 | 智能家居设备 |

**消息路由**：用户发一条 → 广播给 Session 内所有参与者 → 各参与者自行处理并回复 → 回复也广播给所有人。

**iOS 项目路径**：`/Users/ifbe/Desktop/code/ifbe/ai-made-sw/chatroom/ios/`
**Android 项目路径**：`/Users/ifbe/Desktop/code/ifbe/ai-made-sw/chatroom/android/`

---

## 架构（Android + iOS 共用）

### 核心原则
- 所有参与者类型共用同一套 UI 层
- UI 通过统一接口与底层通信，不感知对方类型
- 系统消息（连接状态等）用 `isInfo=true` 小灰字居中显示，不带气泡
- 用户发的消息广播给所有参与者（类似群聊）

### 数据模型

#### ParticipantType
- Android: `enum class ParticipantType(val icon: String)`
- iOS: `enum ParticipantType: String, CaseIterable, Identifiable`

#### Message
- Android: `data class Message(...)`
- iOS: `struct Message: Identifiable, Equatable`

### 气泡布局（iOS 与 Android 一致）

| 位置 | padding | 字体 | 说明 |
|------|---------|------|------|
| 右侧（自己） | 14pt horizontal, 10pt vertical | 15pt, 白色 | 蓝色气泡 |
| 左侧（PTY/SSH） | 4pt horizontal, 10pt vertical | **7pt monospace** | 容纳 80 字符 |
| 左侧（其他） | 4pt horizontal, 10pt vertical | 15pt | 白色气泡 |
| Info 灰字 | 8pt horizontal, 4pt vertical | 12pt, #AAAAAA, 居中 | 调试信息 |

**Info 灰字格式**（调试关键）：
- 收到消息：`📥 接收 len=X hex=XX XX XX...`（hex 只显示前 8 字节）
- 发送消息：`📤 发送: xxx`

---

## iOS 目录结构

```
ios/chatroom/
├── chatroomApp.swift              # @main App 入口
├── ContentView.swift              # SwiftUI ContentView → MainContainerView
├── Models/
│   ├── ParticipantType.swift     # 参与者类型枚举
│   ├── Message.swift              # Message + ChatInputMode
│   ├── ParticipantConfig.swift    # 参与者配置
│   └── Vt100Style.swift           # ANSI 样式
├── Core/
│   ├── SessionManager.swift       # 全局 Session 管理（@MainActor）
│   └── Vt100Parser.swift          # ANSI escape 解析
├── Participants/
│   ├── Participant.swift           # 参与者协议
│   ├── SocketParticipant.swift    # TCP/UDP socket（NWConnection）
│   ├── TelnetParticipant.swift    # TELNET + 自动登录
│   ├── AiParticipant.swift        # HTTP OpenAI API
│   └── BluetoothParticipant.swift # 蓝牙（stub）
└── UI/
    ├── MainContainerView.swift    # 主容器（TabView + TabBar，含关闭按钮）
    ├── Home/
    │   ├── HomeView.swift         # 首页（编辑卡片列表）
    │   └── EditingCardData.swift  # 编辑卡片数据
    └── Chat/
        ├── ChatView.swift         # 聊天界面（5种输入模式）
        ├── MessageRowView.swift   # 消息行（气泡/灰字）
        ├── BubbleShape.swift       # 自定义气泡形状（每角不同半径）
        ├── DirectionPadView.swift  # 方向键 + 数字键盘
        └── AxisView.swift          # 3D 坐标轴（UIViewRepresentable）
```

---

## iOS 实现状态

### ✅ 已实现

**SOCKET**：`SocketParticipant.swift`
- 使用 Apple `Network` 框架（`NWConnection`），与 waterinbox 一致
- TCP: `NWConnection(to: using: .tcp)`，state handler 监听连接状态
- UDP: `NWConnection(to: using: .udp)`
- 发送：`conn.send(content: data, completion: .contentProcessed)`
- 读取：`conn.receive(minimumIncompleteLength: 1, maximumLength: 4096)` 循环
- 状态消息：`🔗 TCP 正在连接...` → `🔗 TCP 已连接` → `❌ TCP 连接失败: xxx`

**TELNET**：`TelnetParticipant.swift`
- TCP Socket 连接
- 自动登录（等 `login:` 提示发用户名，等 `password:` 发密码）
- 接收数据缓存分行处理

**AI**：`AiParticipant.swift`
- HTTP POST `/v1/chat/completions`
- `choices[0].message.content` 读取回复
- 收到响应先显示 hex debug info，再显示内容

**消息列表排序**：`ChatView.MessagesListView`
- `Spacer().frame(minHeight: geo.size.height - 20, maxHeight: .infinity)` 顶部弹性空间
- 少量消息时靠下显示，靠近输入区；多消息时旧消息滚到上方
- 行为与 Android `stackFromEnd=true` + RecyclerView 一致

**输入模式**：`ChatInputMode` 枚举（`.text` / `.remote` / `.dim3` / `.voice` / `.file`）
- text: 普通文本输入
- remote: 方向键 + 数字键盘（DirectionPadView）
- dim3: 3D 轴控制（AxisView），带 X/Y/Z +/- 按钮
- voice: TODO 占位符
- file: TODO 占位符

**3D AxisView**：`AxisView.swift`
- `AxisUIView`（UIView）画三根轴（红X/绿Y/蓝Z），Z轴斜向 45 度
- `fillPaint = UIColor.clear` 避免 `cgColor` 访问崩溃
- 6 个旋转按钮，字号 14pt，圆角 16pt（修复了48pt过大的问题）

**VT100 解析**：`Vt100Parser.swift`
- CSI SGR 序列解析（ANSI 颜色 + bold + underline）
- 30/31.../37/39 前景色，40/41.../47/49 背景色
- iOS 15 兼容（不用 iOS 16+ API）

**Session 管理**：`SessionManager.swift`
- `@MainActor` 单例
- `sessions: [String: [ParticipantConfig]]`
- `messages: [String: [Message]]`

**Home 页面**：
- `AddParticipantCard`：蓝色描边卡片，替代浮动 `+` 按钮
- Socket 协议按钮：TCP/UDP，绿色=`#4CAF50` 选中，灰色=`#CCCCCC` 未选中，白色文字

### ⚠️ Stub / TODO

**PTY**：`PtyParticipant.swift` — iOS 沙盒无法访问 `/dev/ptmx`，stub 只显示 info 消息

**SERIAL**：`SerialParticipant.swift` — iOS 不支持 USB 串口，stub 显示 info

**BLUETOOTH**：`BluetoothParticipant.swift` — BLE 直接通信（Android Central ↔ iOS Peripheral，无需中转）

**PTY 真机支持**：在 macOS Simulator 上可以用 `Process` + `forkpty()` 实现本地 shell

---

## Android 目录结构

```
android/app/src/main/java/com/example/chatroom/
├── MainActivity.kt
├── core/
│   ├── Models.kt
│   └── SessionManager.kt
├── participants/
│   ├── PtyNative.kt / ptmx.c           # JNI /dev/ptmx
│   ├── SerialNative.kt / serial.c      # JNI /dev/tty*
│   ├── SocketParticipant.kt
│   ├── TelnetParticipant.kt
│   ├── AiParticipant.kt
│   └── BluetoothParticipant.kt
├── ui/
│   ├── home/HomeFragment.kt + EditingCardData.kt
│   ├── chat/ChatFragment.kt + MessageAdapter.kt
│   └── common/SessionPagerAdapter.kt + SessionTabBar.kt + ParticipantAdapter.kt
└── vt100/Vt100Parser.kt
```

---

## 气泡布局细节（Android）

| 位置 | margin | padding | 字体大小 |
|------|--------|---------|---------|
| 右侧（自己） | marginEnd=1dp | paddingHorizontal=14dp | 15sp |
| 左侧（PTY/SSH） | marginStart=1dp, marginEnd=4dp | paddingHorizontal=4dp | **7sp** |
| 左侧（其他） | marginStart=1dp, marginEnd=32dp | paddingHorizontal=14dp | 15sp |

---

## 蓝牙协议与平台支持

| 协议 | Android | iOS | Windows | macOS | Linux | 说明 |
|------|---------|-----|---------|-------|-------|------|
| **Classic Bluetooth (BT)** | ✅ | ❌ | ✅ | ✅ | ✅ | 传统蓝牙，支持 SPP/RFCOMM |
| **SPP (Serial Port Profile)** | ✅ | ❌ | ✅ | ✅ | ✅ | 蓝牙串口透传，RFCOMM 通道 |
| **RFCOMM** | ✅ | ❌ | ✅ | ✅ | ✅ | Classic BT L2CAP 之上的串口封装 |
| **BLE Central** | ✅ | ✅ | ✅ | ✅ | ⚠️ | 主设备，扫描连接 Peripheral |
| **BLE Peripheral** | ❌ | ✅ | ⚠️ | ✅ | ⚠️ | 从设备，广播被连接（Android 6.0+ 有 Location 限制） |
| **Nordic UART Service (NUS)** | ✅ | ✅ | ✅ | ✅ | ✅ | BLE GATT 透传，跨平台通用 |
| **BLE SPP 替代方案** | ✅ | ✅ | ✅ | ✅ | ✅ | 通过 NUS 或自定义 GATT 实现 BLE 串口透传 |

**iOS 不支持 Classic Bluetooth / SPP / RFCOMM**，只能使用 BLE。

**Android 不支持 BLE Peripheral 模式**，只能当 Central。

### 跨平台 BLE 直接通信方案

| 组合 | 可行？ | 方案 |
|------|--------|------|
| Android ↔ Android | ✅ | Classic BT SPP，或双方 BLE Central ↔ BLE Peripheral |
| iOS ↔ iOS | ✅ | 双方 BLE Central ↔ BLE Peripheral |
| **Android ↔ iOS** | ✅ | **Android Central + iOS Peripheral**（BLE，无中转） |
| Android ↔ Windows | ✅ | Classic BT SPP |
| iOS ↔ Windows | ⚠️ | Windows 不支持连接 iOS Peripheral，需要第三方工具或 BLE dongle |
| macOS ↔ iOS | ✅ | 双方均支持 BLE Peripheral |

### chatroom 蓝牙设计

**最终目标**：Android Central ↔ iOS Peripheral BLE 直接通信，无第三方中转。

架构：
- iOS: `CBPeripheralManager` 充当 Peripheral，广播自定义 GATT Service
- Android: `BluetoothAdapter` 充当 Central，扫描并连接 iOS Peripheral
- 数据透传：自定义 GATT characteristic 读写（替代 SPP/RFCOMM）

限制：
- iOS Peripheral 模式只能在 App 前台运行
- Android 扫描 BLE 设备需要地理位置权限

---

## 已知限制

- **iOS PTY**: iOS 沙盒禁止访问 `/dev/ptmx`，真机无法使用；Simulator 上可用 `Process.forkpty()`
- **iOS SERIAL**: iOS 不支持 USB Host API，无法访问 USB 串口
- **SSH**: 仅有 UI 配置，无实际连接实现（Android/iOS）
- **BLUETOOTH 直接通信架构**：iOS Peripheral（CBPeripheralManager）广播 ↔ Android Central（BluetoothAdapter）连接，无需第三方中转。iOS App 必须在前台运行。Android 扫描 iOS 设备需要地理位置权限（6.0+）。
- **图片/视频消息**: 未实现
- **PTY/SERIAL**: Android 需要 root