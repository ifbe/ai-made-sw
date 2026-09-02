# Chatroom iOS 平台细节

iOS 端专属实现细节。**通用架构 / 跨端概念**（数据模型 / 气泡布局 / VOICE mode / FILE mode / AI STT / Binary dispatch 等）见 [`readme.md`](./readme.md)，**变更日志**见 [`change.md`](./change.md)，**踩坑汇总**见 [`gotchas.md`](./gotchas.md)。

---

## iOS 目录结构

```
ios/chatroom/
├── chatroomApp.swift              # @main App 入口 + BackgroundTaskManager（beginBackgroundTask）
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
│   ├── SocketParticipant.swift    # TCP/UDP socket（NWConnection + TCP keep-alive）
│   ├── TelnetParticipant.swift    # TELNET + 自动登录
│   ├── AiParticipant.swift        # HTTP OpenAI API（text/stt/tts 三 subType）+ static queryModels(GET /v1/models) + ModelQueryError
│   ├── EchoParticipant.swift      # 自测复读机（纯客户端 + delaySeconds）
│   └── BluetoothParticipant.swift # 蓝牙（stub）
└── UI/
    ├── MainContainerView.swift    # 主容器（ZStack + opacity + 自定义 TabBar）
    ├── Home/
    │   ├── HomeView.swift         # 首页（编辑卡片列表）
    │   └── EditingCardData.swift  # 编辑卡片数据
    └── Chat/
        ├── ChatView.swift         # 聊天界面（6种输入模式）
        ├── MessageRowView.swift   # 消息行（气泡/灰字）
        ├── BubbleShape.swift       # 自定义气泡形状（每角不同半径）
        ├── DirectionPadView.swift  # 遥控 qwe 方向键 + 数字键盘 + FlexibleGrid3x3（撑满父容器）
        ├── Dim3PadView.swift      # 三维模式专用：ArrowPadView（↖↑↗←◉→↙↓↘ +/-）+ AxisView（UIKit X/Y/Z 轴）
        └── DragHandleBar.swift    # 拖拽 handle（UIPanGestureRecognizer，UIViewRepresentable）
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
- **TCP keep-alive**（`NWProtocolTCP.Options`）—— `keepaliveIdle=30 / keepaliveCount=3 / keepaliveInterval=10`，OS 层 socket option 代发 TCP probe，app 不发任何字节（**不污染数据流**，跟 Android 一致）

**TELNET**：`TelnetParticipant.swift`
- TCP Socket 连接
- 自动登录（等 `login:` 提示发用户名，等 `password:` 发密码）
- 接收数据缓存分行处理

**AI**：`AiParticipant.swift`
- HTTP POST `/v1/chat/completions`
- `choices[0].message.content` 读取回复
- 收到响应先显示 hex debug info，再显示内容
- **subType 三选一**（2026-08-26）：`text`（chat completions）/ `stt`（`/v1/audio/transcriptions` SSE 流式 ASR）/ `tts`（`/v1/audio/speech` 返回 audio bytes 走 audio 气泡）
- `tts` 模式多一个 `voice` 构造参数（默认 `alloy`，可配）
- **static `queryModels(ip:port:apiKey:)`**（2026-08-27）：GET `/v1/models` 拉模型列表，无状态、供主页编辑卡片弹框选模型用。错误走 `ModelQueryError: LocalizedError`

**ECHO 复读机**（2026-08-26）：`EchoParticipant.swift`
- 纯客户端、无网络 / 无 fd / 无需配置
- `sendInput(text)` / `sendBinary(data)` 都原样回一条 ECHO 类型的镜像消息
- `delaySeconds: Float = 0.5`（DispatchQueue.main.asyncAfter），可设 0 即时回吐
- 用于测试 chat 页面 + 消息广播链路时不用起真实服务

**WS binary audio 气泡**（2026-08-26）：`WsParticipant.swift`
- 原来 `dispatchBinary` 只给 `image/*` 贴气泡，audio/* 只贴 info
- 改为 image/audio 都贴 imageBytes 气泡（adapter 用 BlobSniffer 嗅探 mime）

**图片全屏查看器**（2026-08-26）：`MessageRowView.swift` 内嵌 `FullscreenImageView`
- SwiftUI 原生 `.fullScreenCover(isPresented:)` 实现，点图片 → 黑底 scaledToFit → 点任意位置 → dismiss
- 不需 Info.plist 额外配置

**Emoji / 头像**：🔁（ECHO / 复读 loop）/ 🪞（echo 镜像）备选

**消息列表排序**：`ChatView.MessagesListView`
- iOS 17+：`ScrollView.defaultScrollAnchor(.bottom)`原生 sticky-bottom
- iOS 15-16：退到旧 Spacer.maxHeight 路径（仅在 iOS 17+ 之后的运行环境拖拽才卡）
- 行为与 Android `stackFromEnd=true` + RecyclerView 一致

**输入模式**：`ChatInputMode` 枚举（`.empty` / `.text` / `.remote` / `.dim3` / `.voice` / `.file`）
- empty: 中央实时显示 `width × height`（黑字、size 28、居中）
- text: 普通文本输入
- remote: **方向键（qwe）** + 数字键盘（1-9），用 `DirectionPadView`
- dim3: **箭头键（↖↑↗←◉→↙↓↘）+ +/-** + `AxisView`（X/Y/Z 轴）
- voice: TODO 占位符
- file: TODO 占位符

**遥控 vs 三维 9 宫格分家**（2026-07）：
- **遥控模式**：左 `DirectionPadView`（qwe 字母键，是 PC WASD 左手位）+ 右 `NumPadView`（1-9）
- **三维模式**：左 `ArrowPadView`（↖↑↗←◉→↙↓↘ 箭头 + 上下两块 +/- 实心按钮）+ 右 `AxisView`
- 两个 9 宫格不再混用：**qwe 是遥控专属**，**箭头是三维专属**

**3×3 网格撑满父容器**（`FlexibleGrid3x3`，在 `DirectionPadView.swift`）：
- 内部 `GeometryReader` 取父容器 size，cell 边长 = `min(W, H) / 3`，cells 永远正方形
- `ArrowPadView` 的中间 3×3 网格同款算法，+/- 按钮宽度按父宽 50%（保持跟网格左对齐）
- 父容器变大变小、整个 3×3 跟着等比缩放

**3D AxisView**：`Dim3PadView.swift`（合并了之前的 `AxisView.swift` + `ArrowPadView.swift`）
- `AxisUIView`（UIView）画三根轴（红X/绿Y/蓝Z），Z轴斜向 45 度
- `fillPaint = UIColor.clear` 避免 `cgColor` 访问崩溃
- 6 个旋转按钮，字号 14pt，圆角 16pt

**拖拽 handle**：`DragHandleBar.swift`
- **用 `UIPanGestureRecognizer`（UIViewRepresentable），不走 SwiftUI gesture**——见 gotchas #4《iOS 拖拽 handle 死锁与解法》
- 手势取起点高度 `.began`，cumulative translation `.changed`：`next = startHeight - t.y`
- 上下限由 `ChatView` 的 `availableHeight`（GeometryReader 给的真实高度）算出，不用 `UIScreen.main.bounds.height`

**主页架构（2026-07-05）**：`MainContainerView.swift`
- **不用 TabView**。原本 `.page` style 自带横向 swipe、会和拖拽手势死锁；默认 `.automatic` 又会冒出系统 tab bar
- 改用 **`ZStack` + `opacity(selectedTab==id ? 1:0) + allowsHitTesting(selectedTab==id)`**
- 所有 Home/Chat 页面常驻 view 树（`ForEach(chatSessions, id: \.self)` 保身份稳定），切 tab 不重建 view、不重连 TCP
- 底部 TabBar 仍负责程序化切 `selectedTab`，没有 swipe 手势、没系统 tab bar

**VT100 解析**：`Vt100Parser.swift`
- CSI SGR 序列解析（ANSI 颜色 + bold + underline）
- 30/31.../37/39 前景色，40/41.../47/49 背景色
- iOS 15 兼容（不用 iOS 16+ API）

**Session 管理**：`SessionManager.swift`
- `@MainActor` 单例
- `sessions: [String: [ParticipantConfig]]`
- `messages: [String: [Message]]`

**后台任务扩展**：`chatroomApp.swift` 的 `BackgroundTaskManager`
- 监听 `scenePhase`：进入后台时 `UIApplication.shared.beginBackgroundTask(withName:expirationHandler:)` 申请 ~30s 后台运行时间
- 回到前台 `endBackgroundTask` 释放
- 这段时间内 `NWConnection` 仍活跃，TCP keep-alive 由 OS 在 socket 层自动发
- **iOS 没有 Android `TcpForegroundService` 的等价物**——长期后台保活需要 Background Modes capability + 推送唤醒，当前未做

**Home 页面**：
- `AddParticipantCard`：蓝色描边卡片，替代浮动 `+` 按钮
- Socket 协议按钮：TCP/UDP，绿色=`#4CAF50` 选中，灰色=`#CCCCCC` 未选中，白色文字

### ⚠️ Stub / TODO

**PTY**：`PtyParticipant.swift` — iOS 沙盒无法访问 `/dev/ptmx`，stub 只显示 info 消息

**SERIAL**：`SerialParticipant.swift` — iOS 不支持 USB 串口，stub 显示 info

**BLUETOOTH**：`BluetoothParticipant.swift` — BLE 直接通信（Android Central ↔ iOS Peripheral，无需中转）

**PTY 真机支持**：在 macOS Simulator 上可以用 `Process` + `forkpty()` 实现本地 shell

---

## 当前输入区设计（iOS，2026-07 镜像 Android）

iOS 端（`ChatView.swift`）跟 Android 几乎一一对应。根容器是 SwiftUI `GeometryReader`，里面是 `VStack`：messagesList（聊天气泡列表，剩下空间）+ inputArea（输入区，含 handle + 6 种 inputBar 之一）。

### 顶部 handle 行：spinner + 拖拽 + 最大化

`inputArea` 顶部 `handleRow`（36pt 高，背景 `#F5F5F5`）：

```
[Menu 📝文字 ▾]   [拖拽（整片中段可拖）]   [⤢ / ⤡]
```

- **Menu**（`modeMenuButton`）：SwiftUI `Menu` 装的 6 种模式选器，比 Android Spinner 简单
- **拖拽 label**（`dragHandle`）：`DragHandleBar` UIViewRepresentable，**走 UIKit UIPanGestureRecognizer**，不走 SwiftUI gesture（见 gotchas #4《iOS 拖拽 handle 死锁与解法》）
- **`⤢` / `⤡` 按钮**：右侧最大化 toggle。当前状态图标 + view 切换逻辑在 `toggleMaximize()` / `applyMaximizeState()` 里

### 下面 6 种 inputBar 在 `currentInputContent` 里 switch

`@ViewBuilder private var currentInputContent: some View { switch currentInputMode { ... } }`，任一时刻只有一个 inputBar 实际被渲染。

| enum | iOS 渲染 | 说明 |
|---|---|---|
| `EMPTY` | `emptyInputBar` | 中央黑字 `size 28` 居中，实时显示 `{W}pt × {H}pt` |
| `TEXT` | `textInputBar` | `TextField` + 发送按钮 |
| `REMOTE` | `remoteInputBar` | 左 `DirectionPadView`（qwe 字母 9 宫格）+ 中间 1pt 灰线 + 右 `NumPadView`（1-9） |
| `DIM3` | `dim3InputBar` | 左 `ArrowPadView`（↖↑↗←◉→↙↓↘ + +/-）+ 中间 1pt 灰线 + 右 `AxisView`（X/Y/Z 轴） |
| `VOICE` | `voiceInputBar` | AVAudioRecorder（16 kHz / mono / 16-bit PCM）；权限申请切到 mode 时立刻弹 |
| `FILE` | `fileInputBar` | `📁 选择文件发送`按钮（任意文件，UIDocumentPickerViewController `forOpeningContentTypes: [.item]`） |

### 拖拽上下限（iOS per-mode）

`minHeightByMode`（`ChatView.swift`），均为 inputBar **内容**最小 pt（不含 handle 36pt）。总 inputArea min = `handleHeight + 此值`。

| 模式 | 最小内容 pt | 最小 inputArea pt | 横屏表现（landscape TabView ≈ 300pt） |
|---|---|---|---|
| EMPTY | 0 | 36 | ✓ 只剩 handle |
| TEXT | 44 | 80 | ✓ 一行字高度 |
| REMOTE | 120 | 156 | ✓ 两个 3×3 网格可读 |
| DIM3 | 160 | 196 | ✓ 适配 300pt 横屏 |
| VOICE / FILE | 44 | 80 | ✓ |

> **2026-07-05 改动**：原值是 empty=80 / text=110 / remote=200 / dim3=280（与 Android 对齐，pt）。横屏下 316pt > 300pt，**拖不动**。改为上表后，竖屏不受影响（竖屏可用 740pt+），横屏可拖。

### 3×3 网格撑满父容器（iOS 专属）

跟 Android `layout_weight=1` + `rowWeight=1 columnWeight=1` 不同，iOS 用 `GeometryReader` 算 cell 边长：

```swift
struct FlexibleGrid3x3: View {
    var body: some View {
        GeometryReader { geo in
            let side = min(geo.size.width, geo.size.height) / 3
            VStack(spacing: 2) { ForEach(0..<3) { row in
                HStack(spacing: 2) { ForEach(0..<3) { col in
                    RemoteButton(...).frame(width: side, height: side)
                }}}}} .frame(width: side*3 + 4, height: side*3 + 4)
            .position(x: geo.size.width/2, y: geo.size.height/2)
        }
    }
}
```

- cell 边长 = `min(W, H) / 3`，cells 永远正方形
- 整个 3×3 在父容器内**居中**（`.position`）
- 父容器变大变小、整个网格跟着等比缩放

`ArrowPadView`（dim3 左）的中间 3×3 同款算法；+/- 按钮宽度 = 父宽 × 50%。

### dim3 模式 cluster 强制居中（2026-07-05）

inputArea 被拖到很高时（远超 cluster 所需），cluster（+ / 9 宫格 / -）要在 ArrowPadView **纵向居中**：

```swift
VStack(spacing: 0) {
    Spacer(minLength: 0)
    solidButton("+").frame(width: btnW, height: btnH)
    VStack(spacing: 2) { ... 3×3 ... }.frame(width: gridSide, height: gridSide)
    solidButton("-").frame(width: btnW, height: btnH)
    Spacer(minLength: 0)
}
```

公式：
```
minSide = min(W, H)
cell    = (minSide - 4) / 4
btnH    = (minSide - 4) / 8
cluster = cell×3 + 4 + btnH×2 = minSide  ✓ 严格贴满
```

竖屏：cluster = 200pt，ArrowPadView 高 244pt，spacer 上下各 22pt。
横屏：cluster = 264pt，ArrowPadView 高 264pt，spacer 0pt。

---

## iOS TCP 后台保活（`beginBackgroundTask`）

iOS 没有 Android `TcpForegroundService` 的等价物——任意 app 不能在后台无限运行。我们能做的：

### 长期后台保活（未实现）

需要 Background Modes capability + 推送唤醒：

| 模式 | 难度 | 说明 |
|---|---|---|
| `voip` | 高 | 要 VoIP push 证书；Apple 查得严 |
| `audio` | 中 | 需要播声音（可以静默）；Apple 查得越来越严 |
| `processing` | 中 | `BGTaskScheduler` 周期性任务，不连续保活 |
| `URLSession.background(...)` | 低 | **仅 HTTP**，TCP 不适用 |

当前 **iOS 上按 Home 后只能撑 ~30s**，之后系统可能挂起 app、关 NWConnection。要「锁屏 5 分钟 TCP 还连着」这种行为需要选一个 Background Mode 类型 + 推送唤醒。

### 权限配置

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE" />
<uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
<uses-permission android:name="android.permission.WAKE_LOCK" />
```

`CHANGE_NETWORK_STATE` 是 **`connectedDevice` 类型的"设备权限"**——`targetSdk=35` + `connectedDevice` 要求**至少一个**设备权限（`BLUETOOTH_*` / `NFC` / `CHANGE_NETWORK_STATE` / `CHANGE_WIFI_STATE` / USB 等），TCP socket 对应 `CHANGE_NETWORK_STATE`。**漏掉 startForeground 抛 SecurityException**。

---

## 数据模型 iOS

```swift
// ParticipantType.swift
enum ParticipantType: String, CaseIterable, Identifiable {
    case echo = "ECHO"
    case serial = "SERIAL"
    case pty = "PTY"
    case ssh = "SSH"
    case telnet = "TELNET"
    case socket = "SOCKET"
    case bbs = "BBS"
    case ai = "AI"
    case agent = "AGENT"
    case bluetooth = "BLUETOOTH"
    case infrared = "INFRARED"
    case smartDevice = "SMART_DEVICE"
    var id: String { rawValue }
    var icon: String { /* emoji */ }
    var displayName: String { /* 名称 */ }
}

// Message.swift
struct Message: Identifiable, Equatable {
    let id: String
    let senderId: String
    let senderType: ParticipantType
    let senderName: String
    let content: String
    let isInfo: Bool
    let imageBytes: Data?     // 二进制复用字段，adapter 用 BlobSniffer 分流 image/audio/text
    let timestamp: Date
}
```

---

## VOICE mode（iOS 部分）

### `Core/VoiceRecorder.swift`

- `AVAudioRecorder` 写到 `cacheDir/voice_{uuid}.wav` 临时文件
- iOS 17+ 走 `AVAudioApplication.requestRecordPermission`，低版本（项目 deployment target = 15.6）走 `AVAudioSession.requestRecordPermission` + continuation 桥接
- Session 类别 `.playAndRecord`（options: `.defaultToSpeaker`, `.allowBluetooth`）
- Info.plist 加 `INFOPLIST_KEY_NSMicrophoneUsageDescription`（**唯一允许的 pbxproj 改动**，其它配置一字不动）

### 播放（iOS 部分）

- `AudioMessagePlayer.shared`（单例 `AVAudioPlayer` + `AVAudioPlayerDelegate` 驱动 cleanup）
- 音频气泡是 SwiftUI `Button`，点按钮调 `AudioMessagePlayer.shared.play(...)`

---

## AI STT subtype（iOS 部分）

### 主页 UI

- `HomeView.swift` `aiFields` 末尾加一行 `Picker`（`.pickerStyle(.segmented)`），tag `text` / `stt`
- `EditingCardData` 加 `aiSubType: String = "text"`，`toConfig()` 写 `subType=...`
- ChatFragment connect 时读 `config.params["subType"] ?? "text"` 传进 `AiParticipant` 构造函数

### AiParticipant：`subType="stt"` 时多一个 `sendVoice(wavData)` API

- iOS：用 **URLSession.shared.bytes(for:)** async API（iOS 15+）做 SSE 流式解析，手写 multipart body（**iOS 没有 OkHttp 也没 URLSession 内建 multipart**，boundary 自己拼）
- `model.ifBlank { "Qwen3-ASR-0.6B-4bit" }` 做默认值

---

## FILE mode（iOS 部分）

- `PHPickerViewController`（`config.filter = .images`）→ `UIDocumentPickerViewController(forOpeningContentTypes: [.item])`
- 按钮文案 `📷 选择图片发送` → `📁 选择文件发送`
- iOS 没有 `/sdcard/` 概念（沙盒 + iCloud Drive），起始位置由系统默认
- URL 从 `.sheet` 回调里取，安全作用域读 bytes（`url.startAccessingSecurityScopedResource()` + `Data(contentsOf:)`）

---

## Binary dispatch（iOS 代码）

```swift
private func broadcastBinaryToParticipants(_ data: Data) {
    let configs = sessionManager.getParticipants(sessionId)
    for config in configs {
        switch config.type {
        case .socket: activeParticipants[config.id]?.sendBinary(data)
        case .ai:
            let subType = config.params["subType"] ?? "text"
            if subType == "stt", let ai = activeParticipants[config.id] as? AiParticipant {
                ai.sendVoice(data)
            }
        default: break
        }
    }
}
```

要点：`sendBinary` 必须是 `Participant` 协议的 **requirement**（不是只放 extension 里）——Swift 对 extension method 是静态分派，调 `participant?.sendBinary(data)` 会永远调到 `Participant.sendBinary` 默认 no-op，调不到 `EchoParticipant.sendBinary` / `WsParticipant.sendBinary` 的 override。见 [`gotchas.md`](./gotchas.md) #4。