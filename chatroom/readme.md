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
│   ├── AiParticipant.swift        # HTTP OpenAI API
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
│   ├── AiParticipant.kt
│   └── BluetoothParticipant.kt
├── ui/
│   ├── home/HomeFragment.kt + EditingCardData.kt
│   ├── chat/ChatFragment.kt + MessageAdapter.kt
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
| `VOICE` | `🎤语` | TODO 占位 |
| `FILE` | `📁文` | TODO 占位 |

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
| `VOICE` | `voiceInputBar` | TODO 占位 |
| `FILE` | `fileInputBar` | TODO 占位 |

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