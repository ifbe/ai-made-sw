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
| **AI** | 🤖 | ✅ 完整实现 | ✅ 完整实现 | OpenAI 兼容 API；subType `text`（chat）/ `stt`（audio transcriptions） |
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
- 收到 WS binary blob：`📥 接收 type=blob len=N hex=XX XX XX...`，紧跟 `🔍 检测 type=<mime> size=<W>x<H>`（image/* 才有 size），最后 image/audio/* 额外贴气泡
- 发送文本：`📤 发送: xxx`
- 发送音频（含录音 / 选 wav 文件）：`📤 发送 type=audio/wav len=N duration=X.XXXs`（**单位是秒，3 位小数**；之前是 ms，去掉 ms 单位是用户要求）
- STT 流式响应（每个 chunk 一条）：`📥 STT: <chunk>`（`<asr_text>...</asr_text>` 是 Qwen3-ASR 服务端 marker，不去它，原样显示）
- TTS 合成中（用户发文本 → AI 走 /v1/audio/speech）：`🔄 TTS 合成中...` → 服务端响应后 `📥 TTS 接收 type=<detected> len=N hex=...` → 音频气泡
- ECHO 自测复读机：`🔁 Echo 已连接（自测模式 · 延迟 <label>）`，`<label>` 是 `默认 0.5s` 或 `Ns`（默认 0.5 简化显示）；binary 接收同 WS 那两条
- 发送图片（含其他 binary）：`📤 发送 type=<detected> size=<W>x<H> len=N`
- **系统错误**（Service 启动失败 / onDestroy / OEM 强杀）:
  - `❌ 前台服务启动失败: SecurityException: ...`
  - `❌ TcpForegroundService.onDestroy count=1 原因=前台服务被系统强杀（startedFlag=true）→ TCP 连接被主动断开`

  Service 内部走 `SessionManager.addMessage` + 当前活跃 callback，ChatFragment 下次 `onStart` 拉历史时**显示在聊天区**。

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
- **用 `UIPanGestureRecognizer`（UIViewRepresentable），不走 SwiftUI gesture**——见下节《iOS 拖拽 handle 死锁与解法》
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
│   ├── AiParticipant.kt                # HTTP OpenAI API（text/stt/tts 三 subType）+ companion.fetchModels(GET /v1/models)
│   ├── EchoParticipant.kt              # 自测复读机（postDelayed）
│   └── BluetoothParticipant.kt
├── ui/
│   ├── home/HomeFragment.kt + EditingCardData.kt
│   ├── chat/ChatFragment.kt + MessageAdapter.kt + FullscreenImageActivity.kt
│   └── common/SessionPagerAdapter.kt + SessionTabBar.kt + ParticipantAdapter.kt
└── vt100/Vt100Parser.kt
```

---

## 当前输入区设计（Android，2026-07 重构）

输入区是**上下分割，不是浮层 overlay**。根容器是 `LinearLayout vertical`，聊天列表 `weight=1`，输入区是一个高度可调的子节点 `LinearLayout id=inputArea`。

### 顶部 handle 行：spinner + 拖拽 + 最大化

`inputArea` 顶部 36dp 高的 handle 行（背景 `#F5F5F5`）：

```
[Spinner 📝文 ▾]   [拖拽（整片中段可拖）]   [⤢ / ⤡]
```

- **Spinner**：6 种模式选择器（从原始 5 个内嵌收敛到这一处，唯一一个）
- **“拖拽”标签**：`match_parent_width` × `match_parent_height` 的 TextView，整片中段接收 `MotionEvent`，ACTION_DOWN 记起点，ACTION_MOVE 实时改 inputArea 高度，ACTION_UP 收尾。命中区域 ≥ 240dp × 36dp（主流 ListView touch target ~48dp 的好几倍）
- **`⤢` / `⤡` 按钮**：右侧最大化 toggle。当前状态图标 + view 切换逻辑在 `applyMaximizeState()` 里。

### 下面一个 `FrameLayout` 装 6 种 inputBar

`FrameLayout id=visibleInputBar` 下面叠 6 个 `match_parent_width` × `match_parent_height` 的 `LinearLayout`，任一时刻只有 `currentInputMode` 那个 `VISIBLE`、其余 `GONE`。

| enum 顺序 | spinner label | 内容 |
|---|---|---|
| `EMPTY`（第 0 位） | `⬜空白` | 中央一个 TextView，实时显示 `{width}dp × {height}dp`。拖拽 inputArea 高度时文本同步跳。 |
| `TEXT` | `📝文` | `EditText`（多行 `maxLines=6` + `gravity=top`）+ 发送按钮 |
| `REMOTE` | `🎮遥` | 左 9 宫格字母键 `q w e / a s d / z x c` + 中间 1dp 灰线 + 右 9 宫格数字 `1-9` |
| `DIM3` | `📐三` | 油门 `±` + 中央 9 宫格方向键 + 中间 1dp 线 + 右 `AxisView`（6 轴） |
| `VOICE` | `🎤语` | 单按钮"未在录音，点我开始"→ 录音中切"取消/发送"双按钮；16 kHz / mono / 16-bit PCM |
| `FILE` | `📁文` | `📁 选择文件发送`按钮（任意文件，SAF `*/*` mime 通配；API 33+ 起步位置为 `/sdcard/`，旧版本 fallback 默认） |

### 拖拽上下限（per mode）

| 模式 | 最小高度 (dp) Android | 最小高度 (pt) iOS |
|---|---|---|
| TEXT | 110 | 44 |
| REMOTE | 200 | 120 |
| DIM3 | 280 | 160 |
| VOICE | 80 | 44 |
| FILE | 80 | 44 |
| EMPTY | 80 | 0 |

计算公式：handle (36dp) + 该模式内容所需的 padding。上限 = `screenH − 60dp(一行 chat) − 36dp(handle)`，保证聊天列表**始终留一行**。

拖动到模式最小值后**不再缩**、不放宽到固定档位。最大化后拖拽也被锁。

### 遥控 9 宫格字母布局说明

中间一列 `w / a / s / d` 是 PC 玩家的 **WASD 左手位**（w 前进 / a 左 / s 倒 / d 右），用来接盘控制小车：

- 按字母键发出去的**是方向**字符串（`↑↓←→↖↗↙↘◉`）
- 按 `1`-`9` 发对应数字串

之前这一格是 `↖↑↗/←◉→/↙↓↘`，2026-07 重做成字母键，进离车玩家更顺手。

### 三维 `AxisView` 标签变化

`AxisView.kt` 6 个旋转按钮原画 `⟲`/`⟳`（顺/逆时针符号），重做成纯文字：

| 回调 | 显示 | 发送 |
|---|---|---|
| `onXRotateCW` (X+ 红) | `x+` | `x` |
| `onXRotateCCW` (X− 红) | `x−` | `X` |
| `onYRotateCW` (Y+ 绿) | `y+` | `y` |
| `onYRotateCCW` (Y− 绿) | `y−` | `Y` |
| `onZRotateCW` (Z+ 蓝) | `z+` | `z` |
| `onZRotateCCW` (Z− 蓝) | `z−` | `Z` |

> 小写 = 正方向转，大写 = 反方向转。`btnText.textSize` 从 48 降到 28 适配 2 字符宽度。Z 轴原来把 `onZRotateCW` 画成 `⟲`（调转了顺逆），这次顺手修。

### 最大化行为

点 `⤢` 后：

1. `handleLabel.isEnabled = false` → 按下/禁用变深灰，触摸返回 `false` → **拖拽被锁**
2. `recyclerView.visibility = GONE`
3. `inputArea.layoutParams.height = MATCH_PARENT` → 撑满整个窗口
4. 按钮本身变 `⤡`

点 `⤡` 还原：

1. `handleLabel.isEnabled = true`
2. `recyclerView.visibility = VISIBLE`
3. `inputArea.height` 还原到上次拖出来的高度（`lastNonMaximizedHeightPx`）；首次进入则还原到当前模式 min

### `EMPTY` 模式的尺寸文本实时更新

`updateEmptySize()`：读 `emptyText.parent.width` / `.height`，换算 dp 后写到 TextView。

- 拖拽时：`setInputAreaHeightPx()` 里 `inputArea.post { updateEmptySize() }` —— `requestLayout()` 只排队，等下个 frame 再读才拿到新值
- 切模式时同样 `post` 一帧

用途：调试观察“inputArea 在不同模式 + 不同拖拽下到底是多大”。

## 自动滚动（贴底跟随）

`ChatFragment` 加了一个状态机：

- `messageList: MutableList<Message>` —— RecyclerView 实际数据源，不再 `SessionManager.getMessages(...).toList()` + DiffUtil 全量重算
- `autoScroll: Boolean` —— 是否贴底
- `RecyclerView.OnScrollListener` 每次滚重算 `autoScroll = isAtBottom()`（容差 3 项）

新消息到达（**ListAdapter + submitList 时序正确**）：

```kotlin
adapter.submitList(messageList.toList()) {
    // submitList 是异步的，itemCount 要等 diff commit 到主线程后才更新，
    // 所以 scrollToPosition 必须放 commitCallback 里，否则滚到旧 size-1
    if (autoScroll && messageList.isNotEmpty()) {
        recyclerView.scrollToPosition(messageList.size - 1)
    }
}
```

**坑**：`MessageAdapter` 继承自 `ListAdapter<Message, …>`（`AsyncListDiffer`）。不能用 `notifyItemInserted(pos)`——只通知 RecyclerView UI，内部 list 不变 → **渲染空白**。必须 `submitList(newList)`。**SwiftUI 那边没这个坑**（`@State` + `ForEach` 等号赋值就重渲染）。

效果：在底部 → 自动跟随新消息；上滑看历史 → 新消息安静进来不打断；滑回到底又重新跟随。

### Fragment 重建后拉历史

`loadMessages()` 从 `SessionManager` 拉跨 fragment 重建前的消息。ViewPager2 销毁/重建 ChatFragment 时需要。

**支持追加**（不 clear 已有）：
- `messageList.isEmpty()` → clear + addAll（首次创建）
- `messageList` 已有 → 按 `id` 去重，只 add 不在的（**切回前台时拉新**——service 写的诊断消息也能拉到）

切回前台时 `onStart` 会调 `loadMessages()`，所以 service 在后台写的 `❌` 灰色诊断消息切回 app 后会出现在聊天区。

## VOICE mode（Android + iOS 同步）

切到 VOICE mode 时立刻申请 `RECORD_AUDIO` 权限；权限通过后初始化 `VoiceRecorder`，离开 mode 或 `onStop/onDisappear` 时 release。

### 固定录音参数

- 采样率 16000 Hz
- 声道：单声道
- 采样位深：16-bit PCM
- 每秒字节数 = 32000

### Android `core/VoiceRecorder.kt`

- `AudioRecord`（API 24+ 走 `MediaRecorder.AudioSource.VOICE_RECOGNITION`，关闭 AGC/NS；低版本回退 `MIC`）
- 后台线程持续读 PCM 到 `ByteArrayOutputStream`
- `stop()` 把 PCM 包成 WAV（44 字节 RIFF/fmt/data header，little-endian）
- `release()` 释放 `AudioRecord` + 反激活 `AVAudioSession`
- `Manifest.permission.RECORD_AUDIO` 检查 + `ContextCompat.checkSelfPermission`

### iOS `Core/VoiceRecorder.swift`

- `AVAudioRecorder` 写到 `cacheDir/voice_{uuid}.wav` 临时文件
- iOS 17+ 走 `AVAudioApplication.requestRecordPermission`，低版本（项目 deployment target = 15.6）走 `AVAudioSession.requestRecordPermission` + continuation 桥接
- Session 类别 `.playAndRecord`（options: `.defaultToSpeaker`, `.allowBluetooth`）
- Info.plist 加 `INFOPLIST_KEY_NSMicrophoneUsageDescription`（**唯一允许的 pbxproj 改动**，其它配置一字不动）

### 播放（气泡点击）

- Android：`AudioMessagePlayer`（单例 `MediaPlayer` + cacheDir 临时 WAV）
- iOS：`AudioMessagePlayer.shared`（单例 `AVAudioPlayer` + `AVAudioPlayerDelegate` 驱动 cleanup）
- 气泡渲染用 `BlobSniffer.detectType` 嗅探 mime：image/* 走图片，audio/* 走音频气泡（▶ 播放 + 时长 `%.3fs` 秒）

### duration 单位约定

- 气泡内时长显示：`%.3fs`（秒，3 位小数），从 PCM 字节数算 `pcmBytes / 32000`
- info 行格式：`📤 发送 type=audio/wav len=N duration=X.XXXs`（同上公式）

### STT 与录音的衔接

录音完成后由 `sendVoiceRecording` 调 `broadcastBinaryToParticipants(wavBytes)`，**STT AI 分发逻辑在 `broadcastBinaryToParticipants` 内部**（见下节《Binary dispatch 架构》）。

## AI STT subtype（Android + iOS 同步）

主页参与卡类型 = AI 时新增 `aiSubType` 字段（编辑卡 + `toConfig()`），可选 `"text"`（默认）/ `"stt"`。

### 主页 UI

- Android：`item_editing_card.xml` `layoutAiModels` 后加 `layoutAiSubType`（一行 LinearLayout + Spinner，display=`["文本", "语音转文字"]` / value=`["text", "stt"]`）
- iOS：`HomeView.swift` `aiFields` 末尾加一行 `Picker`（`.pickerStyle(.segmented)`），tag `text` / `stt`
- ChatFragment connect 时读 `config.params["subType"] ?: "text"` 传进 `AiParticipant` 构造函数

### AiParticipant：`subType="stt"` 时多一个 `sendVoice(wavData)` API

- Android：用 **OkHttp**（已在 deps）做 `MultipartBody` 上传 + SSE 流式响应（`response.body?.source()?.readUtf8Line()`），每段贴 `📥 STT: <chunk>` info、最后贴 AI reply
- iOS：用 **URLSession.shared.bytes(for:)** async API（iOS 15+）做 SSE 流式解析，手写 multipart body（**iOS 没有 OkHttp 也没 URLSession 内建 multipart**，boundary 自己拼）
- 两者都用 `model.ifBlank { "Qwen3-ASR-0.6B-4bit" }` 做默认值

### HTTP 接口（两端一致）

```
POST http://{ip}:{port}/v1/audio/transcriptions
Headers: Authorization: Bearer {apiKey}
Form: model=<text> + stream=true + file=voice.wav (audio/wav)
stream=true  → SSE: data: {"text": "<chunk>"} ...
stream=false → {"text": "<full>"}
```

`<asr_text>...</asr_text>` 是 Qwen3-ASR 服务端给文本内容包的 marker，**不去它，原样显示**（用户明确要求"只是提问，不是让你过滤掉"）。

## FILE mode（任意文件）

### Android

- Launcher 从 `ActivityResultContracts.GetContent()`（image/*）改成 `OpenDocument` + `arrayOf("*/*")`
- 按钮文案 `📷 选择图片发送` → `📁 选择文件发送`
- 自定义 `OpenDocumentAtSdCard` ActivityResultContract（包在 ChatFragment 内 `private class`）：API 33+ 通过 `DocumentsContract.EXTRA_INITIAL_URI` 把系统选择器起步位置强制到 `/sdcard/`；低版本（项目 `minSdk=28`）fallback 默认（通常是 Downloads/Recent）

### iOS

- `PHPickerViewController`（`config.filter = .images`）→ `UIDocumentPickerViewController(forOpeningContentTypes: [.item])`
- 按钮文案 `📷 选择图片发送` → `📁 选择文件发送`
- iOS 没有 `/sdcard/` 概念（沙盒 + iCloud Drive），起始位置由系统默认
- URL 从 `.sheet` 回调里取，安全作用域读 bytes（`url.startAccessingSecurityScopedResource()` + `Data(contentsOf:)`）

### 渲染

`MessageAdapter` / `MessageRowView` 的 `bindContent` 用 `BlobSniffer.detectType` 嗅探 mime：
- `image/*` → 图片气泡（原路径零改动）
- `audio/*` → audio 气泡（▶ 播放 + 时长秒）
- 其它 → 文本 fallback

## Binary dispatch 架构（重要，Android + iOS 对称）

**调用方只调一句 `broadcastBinaryToParticipants(bytes)`，分发逻辑集中**：

```
handlePickedImage / sendVoiceRecording / handlePickedURL / handlePickedData
        │
        ▼
broadcastBinaryToParticipants(bytes)
        │
        ├─→ .socket  → Participant.sendBinary
        │             （WS override 真正发 binary frame；TCP/UDP TODO no-op）
        ├─→ .ai      → subType=="stt" ? AiParticipant.sendVoice : no-op
        │             （接 /v1/audio/transcriptions，SSE 流式响应）
        ├─→ .agent   → break
        │             （openclaw 暂无 binary 行为；架构位置已留）
        ├─→ .echo    → EchoParticipant.sendBinary(bytes)
        │             （复读机：原样回吐收到的 bytes，adapter 按 mime 决定渲染分支）
        └─→ default  → break
                     （PTY/SERIAL/SSH/TELNET/BLUETOOTH：binary no-op）
```

**设计要点**：
- caller **不** 也不应该知道哪些参与者类型对 binary 敏感 —— 加新参与者类型只改 broadcast 一个函数
- 2026-08-11 用户拍板 dispatch 行为"AI 给 AI 发，WS 给 WS 发，两个都在就给两者都发，各自 onMessage 处理不一样"，落到代码就是上面这个 switch
- 之前 STT dispatch 散在 `sendVoiceRecording` + `handlePickedImage` 两个 caller 里手动循环 `SessionManager.getParticipants`，违反 DRY；refactor 后完全集中

### Android

```kotlin
private fun broadcastBinaryToParticipants(bytes: ByteArray) {
    val configs = SessionManager.getParticipants(sessionId)
    configs.forEach { config ->
        when (config.type) {
            ParticipantType.SOCKET -> { /* WS / TCP / UDP */ }
            ParticipantType.AI -> {
                val subType = config.params["subType"] ?: "text"
                if (subType == "stt") {
                    (activeParticipants[config.id] as? AiParticipant)?.sendVoice(bytes)
                }
            }
            else -> { /* PTY/SERIAL/SSH/TELNET/BLUETOOTH：no-op */ }
        }
    }
}
```

### iOS

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

---

## TCP 后台保活（前台服务）

**问题**：Android 切到后台后，进程可能被 LMK 杀 / Doze 冻结网络，TCP socket 跟着断。对端 netcat 看到 ECONNABORTED 或 FIN。

**修法**（**不发送任何心字节节，绝不污染数据流**）：
- TCP participant 在 `TcpForegroundService` 里跑
- Service 是前台服务（`foregroundServiceType="connectedDevice"`）
- 加 `FOREGROUND_SERVICE_CONNECTED_DEVICE` + `CHANGE_NETWORK_STATE` 权限
- 加 `PARTIAL_WAKE_LOCK`（10 分钟超时，靠 service 重启续期）
- `connectParticipants` SOCKET 分支走 `service.addTcpParticipant(...)`，**不**在 ChatFragment 内创建
- ChatFragment `onStop` 只 unbind，**不** stop service——**切后台后 service 仍在前台跑**
- ChatFragment `onStart` 重新 bind + `registerCallback`，消息从 `SessionManager` 拉历史
- `onDestroy`（用户关 tab）才 `removeTcpParticipant` → 最后一个 TCP 离开时 `stopSelf`

**触发规则**：0→1 TCP 加入时 `startForeground`、1→0 时 `stopForeground` + `stopSelf`。**没 TCP 的会话（纯 PTY 等）不启前台服务**，不打扰用户。

**多 session 共享**：service 用 `configId` 索引 participant，`sessionId` 索引 callback。多 tab 共享一个 service。

**Service 重启策略**：
- `START_REDELIVER_INTENT`：被系统杀后**自动重启**
- `onTaskRemoved`：用户从"最近任务"滑掉时**自启 service**

**错误信息推到聊天区**：所有 service 异常（startForeground 失败 / onDestroy / onTaskRemoved restart 失败）都写一个 `isInfo=true` Message 到 SessionManager + 当前活跃 callback，下次 ChatFragment `onStart` 拉历史时**显示在聊天区**。

## 当前输入区设计（iOS，2026-07 镜像 Android）

iOS 端（`ChatView.swift`）跟 Android 几乎一一对应。根容器是 SwiftUI `GeometryReader`，里面是 `VStack`：messagesList（聊天气泡列表，剩下空间）+ inputArea（输入区，含 handle + 6 种 inputBar 之一）。

### 顶部 handle 行：spinner + 拖拽 + 最大化

`inputArea` 顶部 `handleRow`（36pt 高，背景 `#F5F5F5`）：

```
[Menu 📝文字 ▾]   [拖拽（整片中段可拖）]   [⤢ / ⤡]
```

- **Menu**（`modeMenuButton`）：SwiftUI `Menu` 装的 6 种模式选器，比 Android Spinner 简单
- **拖拽 label**（`dragHandle`）：`DragHandleBar` UIViewRepresentable，**走 UIKit UIPanGestureRecognizer**，不走 SwiftUI gesture（见下节《iOS 拖拽 handle 死锁与解法》）
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

## iOS 拖拽 handle 死锁与解法（重要）

### 症状

`ChatView` 嵌在 `TabView(.page(...))` 里，原本用 SwiftUI `DragGesture + @GestureState + highPriorityGesture` 实现拖拽。出现两个问题：

1. **按拖拽条 app 立即死锁**（不是 200ms 卡顿，是整个 app 任何手势都没响应）
2. **第二次 fix**（用 `setTranslation(.zero) + lastTranslationY` 算每帧增量）→ app 不卡了，但拖拽只动一个 frame 的距离（~10px），松开再拖还是 10px

### 真根因

**SwiftUI `DragGesture`（任何变种：`.highPriorityGesture` / `.simultaneousGesture` / `@GestureState`）和父级 `TabView(.page)` 的 page-swipe 手势争用同一个 gesture-arbitration 队列，iOS 17+ 上会进入真死锁**。SwiftUI 没有完整 API 能干净绕开。

第二次的「只动 10px」是另一个独立 bug：**`UIPanGestureRecognizer.translation` 是 cumulative since last `setTranslation`**（**不是** since gesture began），自己又维护一份 `lastTranslationY`，两套参考系错位 → `delta = t.y - lastTranslationY` 从第二帧开始恒为 0。

### 解法

1. **拖拽 handle 走 UIKit 原生手势**：`UIPanGestureRecognizer` 包进 `UIViewRepresentable`（`DragHandleBar.swift`）。UIKit 手势**独立**于 SwiftUI 的 gesture-arbitration 队列，跟 TabView 的 page-swipe 可以共存，是 Apple 自家 framework 间的标准协作方式。
2. **不调 `setTranslation(.zero)`**——直接用 `.translation` 的 cumulative 语义：`.began` 捕获 `startHeight`，`.changed` 用 `next = startHeight - t.y`。
3. **同时把 `TabView(.page)` 替成 `ZStack + opacity`**——见下节《iOS 主页架构》。

## iOS 主页架构（ZStack 替代 TabView）

`MainContainerView` 不用 `TabView`：

- `TabView(.page(...))` 自带横向 swipe 切页 → 会和拖拽手势争用、死锁
- `TabView` 默认 `.automatic` style → 底部多出一个系统 tab bar（用户不想要的灰白区域）

改成：

```swift
VStack(spacing: 0) {
    ZStack {
        HomeView(onSessionCreated: { sessionId in openSession(sessionId) })
            .opacity(selectedTab == "home" ? 1 : 0)
            .allowsHitTesting(selectedTab == "home")

        ForEach(chatSessions, id: \.self) { sessionId in
            ChatView(sessionId: sessionId)
                .opacity(selectedTab == sessionId ? 1 : 0)
                .allowsHitTesting(selectedTab == sessionId)
        }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)

    Divider()
    tabBar  // 自定义底部 TabBar，点选程序化改 selectedTab
}
```

- 所有 Home/Chat 页面常驻 view 树，`ForEach(id: \.self)` 保身份稳定
- 切 tab 不重建 view、不重连 TCP
- 隐藏的页面 `.allowsHitTesting(false)` 防止触摸穿透误触
- 没 swipe 手势、没系统 tab bar、纯 SwiftUI、无 UIKit 桥

## iOS TCP 后台保活（`beginBackgroundTask`）

iOS 没有 Android `TcpForegroundService` 的等价物——任意 app 不能在后台无限运行。我们能做的：

### 1. TCP keep-alive（`SocketParticipant.swift`）

```swift
let tcpOptions = NWProtocolTCP.Options()
tcpOptions.keepaliveIdle = 30       // 30s 空闲后开始发 probe
tcpOptions.keepaliveCount = 3
tcpOptions.keepaliveInterval = 10
let parameters = NWParameters(tls: nil, tcp: tcpOptions)
tcpConnection = NWConnection(to: endpoint, using: parameters)
```

OS 层代发 TCP probe（**不**是 app 层心跳字节），跟 Android `socket.keepAlive=true` 等价，**不污染数据流**。iOS 对非 Background Modes app 可能会被 OS 覆盖，但设上不亏。

### 2. 后台任务扩展（`chatroomApp.swift` / `BackgroundTaskManager`）

```swift
.onChange(of: scenePhase) { newPhase in
    BackgroundTaskManager.shared.handleScenePhase(newPhase)
}
```

- 进入后台：`UIApplication.shared.beginBackgroundTask(withName:expirationHandler:)` 申请 ~30s 后台运行时间
- 回到前台：`endBackgroundTask` 释放
- 这段时间内 `NWConnection` 仍活跃，TCP keep-alive 由 OS 自动发
- 过期回调里主动 endBackgroundTask，避免被系统警告

### 3. 长期后台保活（未实现）

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

## 配置变更不重建、软键盘撑出

`AndroidManifest.xml` `MainActivity`：

```xml
<activity
    android:name=".MainActivity"
    android:configChanges="orientation|screenSize|screenLayout|keyboardHidden|smallestScreenSize|uiMode|navigation|density|fontScale|layoutDirection"
    android:windowSoftInputMode="adjustResize"
    android:exported="true">
```

- `configChanges` 列全了 → 旋转 / 主题 / 字号都**不重建**，保留：socket 连接、PTY fd、当前 mode、拖出的 inputArea 高度、最大化状态
- `adjustResize` → 键盘弹出时窗口整体收缩。`EditText`（在 `inputBarText` 里 `MATCH_PARENT_HEIGHT`）自动胀到 inputArea 整个可用高度，底部＝键盘顶，**始终可见**

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

## 2026-08-27 模型查询弹框 + AI HTTP 整合到 `AiParticipant`

**摘要**：今天两件事——主页 AI 卡片的「查询模型」交互从「点查询多出一行 Spinner」改成「点查询 → 查不到不弹 / 查到弹 AlertDialog 点选回填」；同时把主页查询用的 HTTP（GET `/v1/models`）从 UI 层 / 独立服务文件搬进 `AiParticipant`，让「查询 / 发送 / 结果解析」三段 AI HTTP 逻辑全部集中在同一个文件。Android + iOS 对齐，`xcodebuild` + `./gradlew assembleDebug` 都过。

### 1. 模型查询从「多出一行 Spinner」改为「弹框点选回填」」

之前主页 AI 卡片查模型：点「查询模型」按钮 → 下面多出一行「模型列表：」 + Spinner，用户从 Spinner 里选一个 → 自动回填到模型输入框。**冗余**（多一个 layout 行 + 多一次选择步骤）。

现在：点按钮 → 查得到 → 弹框列出所有模型 → 点选 → 回填 + 关弹框；查不到 → 只 Toast「未查到模型」/「查询失败」，不弹任何框。

- **Android**：`item_editing_card.xml` 删 `layoutAiModels`（模型列表 + Spinner 整行）；`ParticipantAdapter.kt` `btnQueryModels.setOnClickListener` 里 `models.isEmpty()` 只 Toast、`else` 走 `AlertDialog.Builder.setItems(...) { _, which -> inputAiModel.setText(models[which]) }`
- **iOS**：`HomeView.swift` `aiFields` 尾部挂 `.confirmationDialog("选择模型", isPresented: $showModelPicker)`（iOS 15+ 行动面板，iOS 16+ 默认 slide-up，从下往上出）+ `.alert("查询模型", isPresented: $showQueryAlert)`（仅查不到 / 失败时出，点「知道了」返回）

### 2. AI HTTP 全部进 `AiParticipant`

之前查询 HTTP 散落两处（Android 在 UI `ParticipantAdapter.kt`，iOS 在 `Core/ModelQueryService.swift`），跟 send / parse 同名却不在一起，改协议要翻三个文件。今天收拢：

| 端点 | Android | iOS |
|---|---|---|
| GET `/v1/models` | `AiParticipant.Companion.fetchModels` | `AiParticipant.queryModels`（static） |
| POST `/v1/chat/completions` | `AiParticipant.sendChatCompletion` | `AiParticipant.doChatRequest` |
| POST `/v1/audio/transcriptions` | `AiParticipant.sendVoiceToText` | `AiParticipant.doSttRequest` |
| POST `/v1/audio/speech` | `AiParticipant.sendTextToSpeech` | `AiParticipant.doTtsRequest` |

具体改动：

- **Android** `participants/AiParticipant.kt`：`companion object` 加 `fetchModels(ip, port, apiKey, callback)`，background 跑网络、main thread 回调（callback 签名 `(httpCode, models, errorMsg)`，errorMsg != null 表示网络异常）。`ui/common/ParticipantAdapter.kt` 加 import，click handler 内联 HTTP 全删，改成调 `AiParticipant.fetchModels(...)`，handler 只剩 UI 关注点（按钮 enable / Toast / AlertDialog / 回填）
- **iOS** `Participants/AiParticipant.swift`：文件顶部加 `enum ModelQueryError: LocalizedError`（invalidURL / nonHTTPResponse / http(Int) / network(String) / parseFailed 五个 case，错误描述走 `errorDescription`）；类内加 `static func queryModels(ip:port:apiKey:) async -> Result<[String], ModelQueryError>`（URLSession + JSONSerialization）。`UI/Home/HomeView.swift` 调 `ModelQueryService.fetch(...)` → `AiParticipant.queryModels(...)`，UI 代码不动。`Core/ModelQueryService.swift` **删除**

这样「OpenAI 兼容的所有 HTTP 调用」全部集中在 `AiParticipant`——Android 是 class + companion，iOS 是 class + static。主页查询弹框 / Toast 这类 UI 关注点仍然留在 adapter / view 里，这是有意为之：**HTTP 归 `AiParticipant`，UI 归 UI 层**。

### 3. iOS 端踩坑记录

第一次 build 报 `type 'String' does not conform to protocol 'Error'`，因为 `Result<[String], String>` 的 failure 必须是 `Error` 协议。**修法**：定义 `enum ModelQueryError: LocalizedError`，callback caller 走 `error.errorDescription ?? "未知错误"`。

### Build 结果

- Android：`./gradlew assembleDebug` → **BUILD SUCCESSFUL**（5s）
- iOS：`xcodebuild -project chatroom.xcodeproj -scheme chatroom -sdk iphonesimulator -configuration Debug -destination 'generic/platform=iOS Simulator' build CODE_SIGNING_ALLOWED=NO` → **BUILD SUCCEEDED**

## 2026-08-26 同步（TTS 子类型 + ECHO 复读机 + 图片全屏 + 收方 audio bubble + 移除 USER）

**摘要**：今天主要把 Android 端已有的 chat 增强（WS audio bubble / 图片全屏 / TTS / ECHO 主类型）镜像到 iOS 端，同时重构两个细节（音频气泡只按钮可点、移除 `ParticipantType.USER` + 修 spinner 错位）。Android + iOS 行为对齐，`xcodebuild` + `./gradlew assembleDebug` 都过。

### 1. WS binary receive 现在 `image/*` 和 `audio/*` 都贴气泡

之前 `WsParticipant.dispatchBinary` 只给 image 贴气泡，audio 收到只贴 info 灰字。今天扩到两个都贴（adapter 靠 `BlobSniffer.detectType` 分流）。

```swift
// iOS WsParticipant.swift
let isImage = detected.hasPrefix("image/")
let isAudio = detected.hasPrefix("audio/")
if isImage || isAudio {
    let mediaMsg = Message(..., imageBytes: data)
    onMessage?(mediaMsg)
}
```

Android 端 `WsParticipant.kt` 同款改动。

### 2. 图片全屏查看器

- **Android**：新建 `ui/chat/FullscreenImageActivity.kt`，黑底 + `ImageView.ScaleType.FIT_CENTER`，状态栏 / 导航栏涂黑，点任意位置（ImageView）→ `finish()` 回到 chat。在 `AndroidManifest.xml` 注册（`@android:style/Theme.Black.NoTitleBar.Fullscreen`）
- **iOS**：`MessageRowView.swift` 内嵌 `FullscreenImageView`，用 SwiftUI 原生 `.fullScreenCover(isPresented:)`，**不需 Info.plist 额外配置**。点击流程：
```swift
Image(...).onTapGesture { showFullscreen = true }
    .fullScreenCover(isPresented: $showFullscreen) {
        FullscreenImageView(imageData: data)
    }
```

适配器层面：`MessageAdapter.kt`（Android）/ `MessageRowView.swift`（iOS）的 image 分支都加 `imgContent.setOnClickListener` / `.onTapGesture`。**音频气泡的播放按钮走原生 Button（iOS） / MaterialButton（Android）**，本身就可点，不需要额外包装

### 3. 音频气泡点击行为

最初我把整个 `audioContent` 行（按钮 + 时长 + 空白）都做成可点，结果用户纠正：「不是点气泡播放 / 点气泡放大，是点音频播放，点图片放大」 → **只让按钮是触发器，时长文字 / 气泡空白不响应点击**。

Android：`MessageAdapter.kt` 删掉 `audioContent.setOnClickListener`，只留 `btnAudioPlay.setOnClickListener`
iOS：音频气泡已经是 `Button { AudioMessagePlayer.shared.play(...) }`，天然只按钮可点，无需改

### 4. AI TTS 子类型（text → stt → tts）

之前 AI 卡片 subType 只有 `text` / `stt`，今天加 `tts`，实现文字转语音。

- **路径**：`POST http://<ip>:<port>/v1/audio/speech`，Body `{model, input, voice}`，Bearer Token。**OpenAI 兼容**，用户已用 `Qwen3-TTS-12Hz-0.6B-Base-4bit` + `voice=alloy` 测过
- **AiParticipant 重构**：`sendInput(text)` 拆成 dispatcher，`subType==tts` → `sendTextToSpeech()`，否则 → `sendChatCompletion()`。**stt 走 sendVoice 不走 sendInput**
- **返回音频字节**塞进 `Message.imageBytes`，adapter 用 BlobSniffer 嗅探成 `audio/*` → 音频气泡，跟 WS / STT 那条路径对齐
- **Info 灰字**：`🔄 TTS 合成中...` → `📥 TTS 接收 type=<mime> len=N hex=...` → 音频气泡

两端 `subTypesDisplay` / `subTypesValue` 都扩成 `["文本", "语音转文字", "文字转语音"]` / `["text", "stt", "tts"]`。

### 5. AI TTS 的 voice 输入框

之前 voice 字段硬编码 `alloy`。今天让用户在首页 AI 卡片填值，仅在 `subType=tts` 时显示：

- `item_editing_card.xml` 加 `layoutAiVoice` + `inputAiVoice` EditText（紧跟 `layoutAiSubType`）
- `HomeView.swift` 在 `aiFields` 里 tts 时多显示 `voice:` 输入（SwiftUI `if card.aiSubType == "tts" { ... }`）
- `EditingCardData` 加 `aiVoice: String = "alloy"`；`toConfig()` 写 `voice=...`（仅 tts 且非默认才写，保持 params 简洁）
- `ChatFragment.kt` / `ChatView.swift` 抽 `val voice = config.params["voice"] ?? "alloy"` 传给 AiParticipant 构造
- `AiParticipant` 构造加 `voice: String = "alloy"` 参数，`sendTextToSpeech` 用 `voice.ifBlank { "alloy" }`

### 6. ECHO 主类型（自测复读机）

新主类型 `ECHO("🔁")`，纯客户端复读机，**用来测试 chat 页面 + 消息广播链路时不用起真实服务**：

- 用户发什么文本，它把同样的文本作为一条消息贴回来
- 文本输入 → `sendInput`；二进制输入 → `sendBinary`（image / audio / 其他都原样回吐，adapter 嗅探 mime 决定渲染）
- 不需要任何配置（ip / port / apiKey 都不需要）
- Android：`Participants/EchoParticipant.kt` 用 `Handler.postDelayed`；iOS：`Participants/EchoParticipant.swift` 用 `DispatchQueue.main.asyncAfter`
- 主页 spinner 选 ECHO 后整张卡片只剩「类型 +取消按钮」（通用参数 / IP / 端口那些 layout 全 GONE）
- `ParticipantType` enum 加在 `.user` 之前的位置，icon `🔁`（repeat/loop 箭头，直白对应「原样回吐」）

### 7. ECHO binary 支持

EchoParticipant 实现 `sendBinary(bytes)`：跟 WS `dispatchBinary` 同款贴 `📥 Echo 接收 type=blob len=N hex=...` + `🔍 Echo 检测 type=...` + imageBytes 消息。**不管 mime 都返**——PDF / ZIP / 任意 binary 也走 self-test 链路

ChatFragment / ChatView 的 `broadcastBinaryToParticipants` switch 加 `case .echo → activeParticipants[config.id]?.sendBinary(data)`

### 8. ECHO 延迟（自测节奏控制）

让 ECHO 不立即回吐，方便看到「发送完还在加载」的中间态，验证 inputArea 不被对方消息顶走：

- **单位 1s，默认 0.5，可输入浮点数**
- Android：`EditingCardData.echoDelay: Float = 0.5f` + `layoutEchoDelay`（`numberDecimal` 输入框，仅 ECHO 时显示）+ `postDelayed(..., (delaySeconds * 1000).toLong().coerceAtLeast(0L))`
- iOS：`EditingCardData.echoDelay: Float = 0.5` + `echoFields` 视图（`.decimalPad` 键盘）+ `DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int((delaySeconds * 1000).rounded())))`
- `toConfig()` 写 `delay=...`（仅非默认 0.5 才写，保持简洁）
- `EchoParticipant` 加 `delaySeconds: Float = 0.5` 构造参数
- `connect()` 提示文案带延迟值：`🔁 Echo 已连接（自测模式 · 延迟 默认 0.5s）` 或 `延迟 1.5s`

### 9. ParticipantType.USER 移除 + spinner 错位修复

**根因**：重排 enum（USER 挪到第一位）后，`HomeFragment` 的 `typeSpinner.setSelection(pos)` 用的 `ParticipantType.entries.indexOf(it)` 拿到**全枚举下标**，但 spinner adapter 是 filter 过（去 USER）的列表——**差 1 位**，SOCKET 默认跑到了 BBS，3 个类型 params 字段都错位（ECHO 显示 host:port user:xxx、SERIAL 显示 延迟(s)、等等）

**修法**：
- `Models.kt` / `ParticipantType.swift` 直接删 `USER("👤")`（它只在内部用来标 `Message.senderType` 内部字段「self」，`SelfViewHolder` / `SelfMessageRow` 根本不渲染 senderType）
- iOS 端 `selectableCases = allCases`（去 `.user` 的 filter 没意义了）
- `ChatFragment.kt` / `ChatView.swift` 那 8 处 `senderType = ParticipantType.USER` / `.user` 全部换成 `.socket`（占位，纯文本复读机时改成 .echo 同理）
- 删除后下标自动对齐，spinner 选择逻辑不再 off-by-one

iOS 端本身用 `Picker.tag(type)`（不是 index），本来就没 bug；删 `.user` 是为了**和 Android 行为对齐 + 简化 enum**

### iOS 端文件登记（特殊处理）

iOS 端 Xcode 项目用了 **`PBXFileSystemSynchronizedRootGroup`**（Xcode 16+ 特性，pbxproj line 12-16 + 51-53），整个 `chatroom/` 目录被自动同步进编译。**新增 `EchoParticipant.swift` 不需要手动改 pbxproj**，只要放进 `chatroom/Participants/` 就行。

### 今日踩坑汇总（README 长期记录）

1. **doc 注释里写 `image/*` 或 `audio/*` 会触发 Kotlin 解析器误判**：`/*` 在块注释内部被当嵌套块注释开始，后面整个文件被吃成注释，build 报一堆 `Unresolved reference mainHandler / sendTextToSpeech / sendChatCompletion` 级联错误。**修法**：注释里写 mime 路径用 `image/...` 占位，别写真实 glob。**今天踩了 2 次**（AiParticipant 的 `audio/* 渲染音频气泡` 注释 + EchoParticipant 的 `audio/* 渲染音频气泡` 注释）
2. **`edit` tool 的 batch 行为**：任一 edit 的 oldText 对不上时**整个 batch 都不应用**（原子回滚）。涉及多个文件 batch 时，要么同一文件单独 batch，要么各 edit 一次成功再继续。**今天踩了 3 次**：USER 删除 batch（ChatFragment `handlePickedImage` 20 空格缩进 oldText 没对）、ChatView 8 处替换 batch（`sendDirectionLabel` 4 空格缩进 oldText 没对）、AI voice/delay/ECHO 接线 batch（空 oldText 没匹配）
3. **WS 收 audio 之前漏贴气泡**：跟 Android `WsParticipant.dispatchBinary` 同款 bug，接收方只贴 info 灰字不发气泡，需要手动补 imageBytes 消息

### Build 结果

- Android：`./gradlew assembleDebug` → **BUILD SUCCESSFUL**（4 次：TTS 完后、ECHO 完后、删 USER 完后、最终压缩前）
- iOS：`xcodebuild -project chatroom.xcodeproj -scheme chatroom -sdk iphonesimulator -configuration Debug -destination 'generic/platform=iOS Simulator' build CODE_SIGNING_ALLOWED=NO` → **`** BUILD SUCCEEDED **`**
- Android APK：`xcodebuild` 等价的产物在 `android/app/build/outputs/apk/debug/app-debug.apk`，xz -9 压到 7.6MB（33MB → 23%）后通过 `send-file-to-feishu.sh` 发飞书

---

## 已知限制

- **iOS PTY**: iOS 沙盒禁止访问 `/dev/ptmx`，真机无法使用；Simulator 上可用 `Process.forkpty()`
- **iOS SERIAL**: iOS 不支持 USB Host API，无法访问 USB 串口
- **SSH**: 仅有 UI 配置，无实际连接实现（Android/iOS）
- **BLUETOOTH 直接通信架构**：iOS Peripheral（CBPeripheralManager）广播 ↔ Android Central（BluetoothAdapter）连接，无需第三方中转。iOS App 必须在前台运行。Android 扫描 iOS 设备需要地理位置权限（6.0+）。
- **图片/视频消息**: 未实现
- **PTY/SERIAL**: Android 需要 root
- **Android TCP 后台保活 vs OEM 省电策略**：`TcpForegroundService` 能在标准设备上后台保持 TCP socket。但**国内厂商（华为/小米/OPPO/vivo/一加）有自家省电策略**，可能直接杀主进程，不走 `onTaskRemoved` 路径。**用户需在系统设置给 chatroom 加白名单**：
  - 华为/荣耀：设置 → 电池 → 启动管理 → 关掉 chatroom "自动管理"
  - 小米/红米：设置 → 电池 → 应用电池节省 → chatroom 选"无限制"
  - OPPO/realme：设置 → 电池 → 后台高耗电 → 允许 chatroom
  - vivo/iQOO：设置 → 电池 → 后台高耗电 → 允许 chatroom
  - 一加：设置 → 电池 → 电池优化 → chatroom 选"不优化"
  - 三星：设置 → 电池 → 后台使用限制 → chatroom 选"不优化"

  加完白名单后切到桌面 netcat 不再断。**chatroom 不会绕过系统**——`android:process=":tcp_service"` 试过会引入 SessionManager 跨进程不一致 + LocalBinder 跨进程失效问题，已撤。代码层面只走前台服务。