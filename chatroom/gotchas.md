# Chatroom 工程踩坑汇总

按主题组织，每条带「现象 → 根因 → 修法 → 教训」结构。详细的项目说明见 [`readme.md`](./readme.md)，变更日志见 [`change.md`](./change.md)。

---

## 1. Kotlin 解析器在 doc 注释里把 `image/*`、`audio/*` 误判为嵌套块注释

**日期**：2026-08-26
**影响**：build 报一堆 `Unresolved reference mainHandler / sendTextToSpeech / sendChatCompletion` 级联错误（实际上是注释吃掉了大半个文件）

**现象**：

在 Kotlin 文件的 `/** ... */` doc 注释里写 `image/*` 或 `audio/*`（mime 通配符）做示例，**编译整个文件失败**，错误信息看起来像符号全部丢失。

**根因**：

`/*` 在 Kotlin 块注释内部被解析器当成「嵌套块注释开始」。注释里一旦写了 `image/*` 或 `audio/*`，`*` 紧跟 `/` 触发嵌套块注释语法，**后面整个文件被吃成注释**，直到下一个匹配的 `*/`。后续真实代码全部变成注释，build 报级联 unresolved reference 错误。

**修法**：

注释里写 mime 路径用 `image/...` 占位，别写真实 glob：
- ❌ `* 渲染 audio/* 音频气泡`
- ✅ `* 渲染 audio/... 音频气泡`

**踩坑频率**：2026-08-26 当天踩了 2 次（`AiParticipant.kt` 的 `audio/* 渲染音频气泡` 注释 + `EchoParticipant.kt` 的 `audio/* 渲染音频气泡` 注释），两次都得 `git checkout` + 重写注释恢复。

---

## 2. `edit` tool 的 batch 原子回滚行为

**日期**：2026-08-26
**影响**：多个文件批量改动时只要有一个 oldText 对不上，全部 batch 不应用，浪费迭代次数

**现象**：

跨多个文件、每个文件多处的 edit batch，**任一 edit 的 oldText 对不上时整个 batch 都不应用**（原子回滚），没有任何部分成功提示。

**根因**：

edit tool 的 batch 行为是 all-or-nothing —— batch 里任何一个失败就整体不应用，保证文件不会处于「改了一半」的中间态。

**修法**：

涉及多个文件 batch 时，**要么同一文件单独 batch**（一个文件的多个 edit 放一起），**要么各 edit 一次成功再继续**（每次成功后再说下一个）。绝对不要把所有文件的所有 edit 塞一个 batch。

**踩坑频率**：2026-08-26 当天踩了 3 次：
- USER 删除 batch（`ChatFragment.handlePickedImage` 20 空格缩进 oldText 没对）
- ChatView 8 处替换 batch（`sendDirectionLabel` 4 空格缩进 oldText 没对）
- AI voice/delay/ECHO 接线 batch（空 oldText 没匹配）

每次都得拆成小 batch 重试。

---

## 3. WS 收 audio 之前漏贴气泡

**日期**：2026-08-26
**影响**：WebSocket 推送 wav 文件给接收方只贴 info 灰字，不发气泡，无法播放

**现象**：

`WsParticipant.dispatchBinary` 收到二进制数据时，只给 `image/*` 贴气泡，`audio/*` 收到只贴 info 灰字，**用户在 chat 界面看不到音频气泡也无法播放**。

**根因**：

dispatchBinary 只判断 `isImage`，没判断 `isAudio`，audio 走 fallback 路径只贴 info。

**修法**：

iOS `WsParticipant.swift` + Android `WsParticipant.kt` 都加 `isAudio` 分支：
```swift
let isImage = detected.hasPrefix("image/")
let isAudio = detected.hasPrefix("audio/")
if isImage || isAudio {
    let mediaMsg = Message(..., imageBytes: data)
    onMessage?(mediaMsg)
}
```

image/audio 都贴 imageBytes 消息，adapter 用 `BlobSniffer.detectType` 自动分流渲染。

**踩坑频率**：2026-08-26 首次发现，镜像 Android 修复时同步改 iOS。

---

## 4. iOS 拖拽 handle 死锁 + 「只动 10px」双坑

**日期**：2026-07-05
**影响**：`ChatView` 嵌在 `TabView(.page(...))` 里，拖拽 inputArea 手把直接死锁；fix 完拖拽变成「只动 10px」

### 现象

`ChatView` 嵌在 `TabView(.page(...))` 里，原本用 SwiftUI `DragGesture + @GestureState + highPriorityGesture` 实现拖拽。出现两个问题：

1. **按拖拽条 app 立即死锁**（不是 200ms 卡顿，是整个 app 任何手势都没响应）
2. **第二次 fix**（用 `setTranslation(.zero) + lastTranslationY` 算每帧增量）→ app 不卡了，但拖拽只动一个 frame 的距离（~10px），松开再拖还是 10px

### 根因

两个独立 bug：

**Bug 1（死锁）**：SwiftUI `DragGesture`（任何变种：`.highPriorityGesture` / `.simultaneousGesture` / `@GestureState`）和父级 `TabView(.page)` 的 page-swipe 手势**争用同一个 gesture-arbitration 队列**，iOS 17+ 上会进入真死锁。SwiftUI 没有完整 API 能干净绕开。

**Bug 2（只动 10px）**：第二次 fix 时用了 `UIPanGestureRecognizer` + 自己维护 `lastTranslationY`，但 `UIPanGestureRecognizer.translation` 是 cumulative since last `setTranslation`（**不是** since gesture began），两套参考系错位 → `delta = t.y - lastTranslationY` 从第二帧开始恒为 0。

### 修法

1. **拖拽 handle 走 UIKit 原生手势**：`UIPanGestureRecognizer` 包进 `UIViewRepresentable`（`DragHandleBar.swift`）。UIKit 手势**独立**于 SwiftUI 的 gesture-arbitration 队列，跟 TabView 的 page-swipe 可以共存，是 Apple 自家 framework 间的标准协作方式。
2. **不调 `setTranslation(.zero)`**——直接用 `.translation` 的 cumulative 语义：`.began` 捕获 `startHeight`，`.changed` 用 `next = startHeight - t.y`。
3. **同时把 `TabView(.page)` 替成 `ZStack + opacity`**——见下条《iOS 主页架构 ZStack 替代 TabView》。

---

## 5. iOS 主页架构 ZStack 替代 TabView

**日期**：2026-07-05
**影响**：让拖拽 handle UIKit 手势能跟 tab 切换共存，同时去掉系统 tab bar

### 为什么不用 `TabView`

`MainContainerView` 不用 `TabView`：

- `TabView(.page(...))` 自带横向 swipe 切页 → 会和拖拽手势争用、死锁（见上条 #4）
- `TabView` 默认 `.automatic` style → 底部多出一个系统 tab bar（用户不想要的灰白区域）

### 改成 ZStack + opacity + 自定义 tab bar

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

### 效果

- 所有 Home/Chat 页面常驻 view 树，`ForEach(id: \.self)` 保身份稳定
- 切 tab 不重建 view、不重连 TCP
- 隐藏的页面 `.allowsHitTesting(false)` 防止触摸穿透误触
- 没 swipe 手势、没系统 tab bar、纯 SwiftUI、无 UIKit 桥

---

## 6. Android TCP 后台保活 vs OEM 省电策略

**日期**：2026-07
**影响**：标准设备后台保活 OK，但国内厂商会直接杀主进程不走 `onTaskRemoved`

### 现象

`TcpForegroundService` 能在标准设备上后台保持 TCP socket。但**国内厂商（华为/小米/OPPO/vivo/一加）有自家省电策略**，可能直接杀主进程，不走 `onTaskRemoved` 路径。

### 修法

代码层面只走前台服务，**chatroom 不会绕过系统**：

```kotlin
// 启动前台服务
startForeground(NOTIFICATION_ID, notification)
```

`android:process=":tcp_service"` 试过会引入 SessionManager 跨进程不一致 + LocalBinder 跨进程失效问题，已撤。

### 用户需在系统设置给 chatroom 加白名单

- 华为/荣耀：设置 → 电池 → 启动管理 → 关掉 chatroom "自动管理"
- 小米/红米：设置 → 电池 → 应用电池节省 → chatroom 选"无限制"
- OPPO/realme：设置 → 电池 → 后台高耗电 → 允许 chatroom
- vivo/iQOO：设置 → 电池 → 后台高耗电 → 允许 chatroom
- 一加：设置 → 电池 → 电池优化 → chatroom 选"不优化"
- 三星：设置 → 电池 → 后台使用限制 → chatroom 选"不优化"

加完白名单后切到桌面 netcat 不再断。

---

## 7. iOS TCP keep-alive + 后台任务扩展

**日期**：2026-07
**影响**：iOS 不像 Android 有前台服务，靠 NWProtocolTCP.Options + beginBackgroundTask 撑住后台 TCP

### iOS 端 TCP keep-alive（`SocketParticipant.swift`）

```swift
// NWProtocolTCP.Options
let tcpOptions = NWProtocolTCP.Options()
tcpOptions.connectionTimeout = 10
tcpOptions.keepaliveIdle = 30        // 30s 无活动开始发 probe
tcpOptions.keepaliveCount = 3        // 连续 3 次 probe 失败断连
tcpOptions.keepaliveInterval = 10    // probe 间隔 10s
```

**OS 层 socket option 代发 TCP probe**，app 不发任何字节（**不污染数据流**，跟 Android 一致）。

### 后台任务扩展（`chatroomApp.swift` / `BackgroundTaskManager`）

```swift
// 进入后台时开启 task assertion
var bgTask: UIBackgroundTaskIdentifier = .invalid
bgTask = UIApplication.shared.beginBackgroundTask(withName: "chatroom-tcp") {
    UIApplication.shared.endBackgroundTask(bgTask)
    bgTask = .invalid
}
```

`beginBackgroundTask` 给 app ~30s 后台时间，期间 NWConnection 仍可收发数据；超时后系统挂起 app。

### 跟 Android 对齐的两条限制

- **iOS 不像 Android 有前台服务 + 用户加白名单**——iOS 后台保活是系统决定的
- **chatroom 不会用 `voip` 推送**——App Store 审核会拒

### 长期后台保活未实现

iOS 没有「永久后台」机制。`BackgroundTask` + `keep-alive` 只能撑 ~30s，之后系统会挂起 app。**真正长连接需要走 voip 推送或 APNs**——chatroom 不做这层。

---

## 8. Android `configChanges` + `adjustResize` 配置

**日期**：2026-07
**影响**：旋转 / 主题 / 字号 / 软键盘都不能重建 Activity

### `AndroidManifest.xml` `MainActivity`

```xml
<activity
    android:name=".MainActivity"
    android:configChanges="orientation|screenSize|screenLayout|keyboardHidden|smallestScreenSize|uiMode|navigation|density|fontScale|layoutDirection"
    android:windowSoftInputMode="adjustResize"
    android:exported="true">
```

### 为什么这么写

- `configChanges` 列全了 → 旋转 / 主题 / 字号都**不重建**，保留：socket 连接、PTY fd、当前 mode、拖出的 inputArea 高度、最大化状态
- `adjustResize` → 键盘弹出时窗口整体收缩。`EditText`（在 `inputBarText` 里 `MATCH_PARENT_HEIGHT`）自动胀到 inputArea 整个可用高度，底部＝键盘顶，**始终可见**

### 替代方案为啥不选

- 用 `adjustPan` → 窗口整体上移，但 inputArea 会被键盘遮挡一半
- 不写 `configChanges` → 旋转 / 主题切换会重建 Activity，socket 断开 + PTY fd 丢失 + inputArea 高度被重置