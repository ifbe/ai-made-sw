# iOS 工程说明

复刻自 `android/` 的同一套 App（象棋 / 国际象棋 / 围棋 / 五子棋），**协议与 Android 逐字节一致**，可以和 Android 端互相联机。
设计规格见 [ios/design.md](ios/design.md)；两端共同的协议、联机行为以 [android.md](android.md) 为准，本文只记 iOS 侧的差异与做法。

## 构建

- Xcode 26.3 / `SWIFT_VERSION = 5.0` / **`IPHONEOS_DEPLOYMENT_TARGET = 16.6`**
  （注意：**target 级**是 16.6，工程级是 26.2 —— 改设置别改错那一层。因为目标 16.6，
  `@Observable`、`onGeometryChange`、`Text.strokeWidth` 这些 iOS 17+ API 一律不能用）
- **零第三方依赖**：SwiftUI + Combine + UIKit + `Network.framework`
- 工程用的是 `PBXFileSystemSynchronizedRootGroup`（`objectVersion = 77`）：
  **`ios/chess/` 下新增的 `.swift` 会自动进 target，不用改 `project.pbxproj`**
- `project.pbxproj` 只改过一处：加了 `INFOPLIST_KEY_NSLocalNetworkUsageDescription`（Debug / Release 各一条）。
  Info.plist 是**自动生成**的（`GENERATE_INFOPLIST_FILE = YES`），所以只能这样加键；
  也正因为如此，**不能用 `NSAppTransportSecurity`**（字典键没法用 `INFOPLIST_KEY_` 表达）——
  我们干脆两端都走 `Network.framework`，压根不受 ATS 约束

```bash
cd ios

# ① 模拟器编译（日常验证用；DerivedData 落在工作区内，避开沙箱）
xcodebuild -project chess.xcodeproj -scheme chess -sdk iphonesimulator \
  -configuration Debug -derivedDataPath .build/DerivedData CODE_SIGNING_ALLOWED=NO build

# ② 真机 SDK 编译（只验证能编过，不签名）
xcodebuild -project chess.xcodeproj -scheme chess -sdk iphoneos \
  -configuration Debug -destination 'generic/platform=iOS' \
  -derivedDataPath .build/DerivedDataDevice \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

- **真机安装/运行请用 Xcode**：签名要访问 login keychain，从沙箱里跑 `xcodebuild` 会
  `Command CodeSign failed ... errSecInternalComponent`
- 看日志：Xcode 控制台；或 Mac 的 `Console.app` 选中设备后过滤 `com.ifbe.aimadesw.chess`
  （我们的 `os.Logger` subsystem，category 是 `ChessApp`）——**记得勾「操作 → 包括信息消息」**，
  不然 `logger.info` 看不到
- 命令行装/启动（绕开 Xcode 的调试器，排查启动问题很有用）：

```bash
# 先列设备，把 Identifier 那一列复制下来
xcrun devicectl list devices

DEV=<粘贴 Identifier>
xcrun devicectl device install app --device "$DEV" <chess.app 路径>
xcrun devicectl device process launch --console --device "$DEV" com.ifbe.aimadesw.chess
```

## 代码结构

```
ios/chess/
  App/
    ChessApp.swift            @main；App.init 里打第一行启动日志（纯诊断）
    RootView.swift            根：ZStack(黑底) + 四个棋盘 + 四角控件
    Layout.swift              四角控件容器 + 安全区
    Theme.swift               全部配色 / 圆角 / 字号 / 内边距 / 文案常量
  Game/
    Protocol/                 ★ 与 Android 逐字节一致：GameKind / BoardPos / PieceRef / MoveEvent / EnvelopeCodec
    Core/                     Game 协议、Gesture、DragOverlay、BoardSnapshot、MoveEventSink、LocalSession
    Share/Stone/              围棋 + 五子棋共用：BoardGeometry / StoneGame / StoneProtocol
    Xiangqi/                  XiangqiGeometry / XiangqiGame / XiangqiProtocol
    IntlChess/                IntlChessGeometry / IntlChessGame / IntlChessProtocol
  Views/
    StoneBoardView.swift      19 路 / 15 路同一个 View（参数不同）
    XiangqiBoardView.swift
    IntlChessBoardView.swift
    NetBarView.swift          左下角 [服/客][地址][开始/状态]
    LogPanelView.swift        右下角可折叠日志
    TabBarView.swift          左上角四个标签
  Net/
    Session.swift             protocol Session（send / listen / close）+ LinkState
    NetAddress.swift          本机局域网 IP（getifaddrs）、地址与端口解析
    WsSession.swift           一个类兼服务端与客户端（NWListener / NWConnection + NWProtocolWebSocket）
  Log/
    AppLog.swift              环形缓冲 + 订阅 + os.Logger；另有 StartupClock（启动计时，纯诊断）
```

## 分层约定（改代码前先看这条）

和 Android 侧一一对应，只是语言换了：

- `Game / Protocol / Geometry` **不 import 任何 UI 框架**（只有 `Game` 为了 `@Published` import `Combine`），
  纯 Swift → 可以**直接用 `swiftc` 编成 macOS 命令行程序跑**。这是本工程最重要的验证手段，见下面「怎么验证」
- `XxxBoardView` **只负责画 + 报手势**，不自己改盘面、不 import `Net/`
- 事件由 `XxxGame` 产生（`onGesture` 先改本地状态，再把要广播的事件返回），`Net` 只认 `MoveEvent`
- 依赖方向：`Views / RootView → Game/Core → Game/Protocol`，`Net → Game/Protocol`
- `Game` 继承 `ObservableObject` 只是为了 SwiftUI 能订阅刷新（§13.3），每个实现类里
  有一个 `@Published private var revision` + `didChange()`，任何改变渲染结果的操作都碰一下它

## 视图与布局

- 根视图刻意保持朴素：

```swift
ZStack {
    Theme.pageBackground.ignoresSafeArea()   // 全屏纯黑
    boardPages.ignoresSafeArea()             // 棋盘：拿全屏尺寸算几何
    CornerControls(...)                      // 四角控件：留在安全区里，四角再各让开 12pt
}
```

  前两个 `ignoresSafeArea()` 是为了让棋盘按**整屏**算几何（和 Android 的 match_parent 一致）；
  第三个不忽略，于是天然就是「安全区 + 12pt」，不用手算 insets
- ⚠️ `CornerControls` 里那个铺满屏的 `Color.clear` 是**尺寸锚点**，必须 `.allowsHitTesting(false)`，
  否则它会吃掉全屏触摸（`Color` 是会绘制的视图，命中区域就是整块矩形）
- ⚠️ **键盘避让不要自己做**：系统会把根视图底部安全区抬高，`CornerControls` 跟着缩小、
  下面那一行自动移到键盘上方。自己再加一层 padding 会抬两次（见 [gotcha.md](gotcha.md) 第 18 条）
- 页面切换用 `switch`：**同一时刻只有当前页在渲染树里**（§4.1），但四页的 `@StateObject` 棋局一直在，切走再切回棋还在
- 横竖屏：棋盘要不要转 90° **只看视图宽高比**（`w > h`），不是设备方向，所以 iPad 横竖屏都支持也不会错乱
- 棋盘一律用 `Canvas { ctx, size in ... }` 画（§13.1），手势用
  `DragGesture(minimumDistance: 0)` + `.contentShape(Rectangle())`；`DragGesture` 没有独立的
  `touchDown`/`cancel`，所以视图层用 `@State dragging` 自己实现 Android 那套状态机（§8.1）

## 权限

| 键 | 用途 | 备注 |
|---|---|---|
| `NSLocalNetworkUsageDescription` | 局域网联机 | iOS 14+ 第一次连局域网会弹框；**没有这个键弹框都不弹、连接直接被拒** |

- **不需要** `NSBonjourServices`：我们不做 mDNS 发现，只连手输的固定 IP
- **不需要** multicast entitlement：那是做 Bonjour 发现才要的
- 被拒后拿到的错是 `POSIX 50 (ENETDOWN)`，界面上提示「缺少本地网络权限」（见 [gotcha.md](gotcha.md) 第 16 条）
- ATS 不用管：客户端也走 `NWConnection`，不经过 `URLSession`，明文 `ws://` 不受 ATS 约束（§14.1）

## 联机实现

Android 侧是 Java-WebSocket；iOS 侧**两端都用 `Network.framework`**（`NWListener` + `NWProtocolWebSocket`，
客户端 `NWConnection` + `NWProtocolWebSocket`）——这样协议处理逻辑只写一遍，而且不受 ATS 限制。

- 一个 `WsSession` 管四种棋：报文里带 `game`，收到后由 `RootView.routeRemote` 按棋种分发
- 服务端：接住客户端事件 → 应用到本地盘面 → 转发给**其它**客户端（不回发送者）；
  并缓存每个棋种最后一包全量盘面（`lastBoard`），新客户端一连上就先推给它
- 客户端：⚠️ **必须用 URL endpoint**：`NWConnection(to: .url(url), using: params)`。
  WebSocket 协议内部是拿 endpoint 里的 URL 拼握手请求行的，用 `.hostPort` 会拿到 null endpoint 直接崩
  （见 [gotcha.md](gotcha.md) 第 15 条）
- 位置流（`dragMoved`）只留最新一条、按 **30Hz**（`DispatchSourceTimer`）发送；发关键事件前先 flush，
  保证「先动、后落」
- 服务端监听前开 `allowLocalEndpointReuse`（对应 Android 的 `SO_REUSEADDR`），并显式绑 IPv4 通配地址
  （`requiredLocalEndpoint = .hostPort(host: .ipv4(.any), port:)`，绑不上就退回只给端口）
- 所有网络回调都在 `WsSession` 内部的串行队列上；`onState` 回调**不在主线程**，UI 侧自己
  `DispatchQueue.main.async`
- 联机期间 `UIApplication.shared.isIdleTimerDisabled = true` 保持屏幕常亮（§4.7）

## 协议

**和 Android 完全一致，一个字都不能改**（格式、字段、事件类型、盘面编码、坐标单位见
[android.md](android.md) 的「协议」一节，那边是单一事实来源）。

iOS 侧对应文件：`Game/Protocol/{GameKind,BoardPos,PieceRef,MoveEvent,EnvelopeCodec}.swift`。

改协议时的规矩：**两端一起改，然后跑「怎么验证」里的黄金向量比对**——它会逐字节对比两端的编解码结果，
比人眼可靠。

## 怎么验证

iOS 侧没有单元测试 target，用三条**可复现脚本**代替（都在 `ios/.build/verify/`，
⚠️ 这个目录被 `ios/.gitignore` 忽略了，所以只在本地存在，见 [todo.md](todo.md)。
命令都在**仓库根目录**执行）：

```bash
ios/.build/verify/run-android.sh    # ① 编译 android/ 里的纯逻辑 Kotlin，生成「黄金向量」基准
ios/.build/verify/run-ios.sh        # ② 跑 iOS 侧同一份脚本并 diff（必须逐字节一致）
ios/.build/verify/run-ws-smoke.sh   # ③ 在 macOS 上真起服务端 + 客户端，跑联机端到端冒烟
```

1. **黄金向量比对**（`run-android.sh` + `run-ios.sh`）：两端跑**同一份 dump 脚本**，输出 272 行，
   覆盖 3 种几何 × 4 种屏幕尺寸的所有尺寸/命中/坐标换算、`EnvelopeCodec` 五类事件编解码 + 11 条脏报文、
   四种棋的完整手势脚本（走子/弹回/吃子/拖出棋盘/托盘/换手/重置）、`apply` 回放、初始盘面串。
   做法：用 Gradle 发行版自带的 `kotlin-compiler-embeddable` 直接编 `android/` 里那份**纯逻辑** Kotlin
   （不需要跑 gradle、不需要设备），Swift 侧用 `swiftc` 编成 macOS 命令行程序，`diff` 两边输出
2. **联机端到端冒烟**（`run-ws-smoke.sh`）：`WsSession.swift` 只依赖 Foundation + Network，
   所以能直接在 macOS 上跑。它验证：客户端握手（就是会崩的那条路径）、服务端转发且不回发送者、
   「新客户端一连上就收到缓存的 board」、reset 广播、**关掉服务再立刻开不报 `Address already in use`**、
   以及按钮状态文案（`服务中·0/1/2`、`已连接`、`已关闭`）
3. **真机**：`xcodebuild` 编译 + Xcode 安装；启动问题看 `StartupClock` 那几行日志（见下）

### 启动计时怎么看

`ChessApp.init` / `RootView.body` / `RootView.onAppear` / 首帧上屏 各打一行
`启动计时 N ms ...`，N 是**从进程创建时刻**算起的（`sysctl(KERN_PROC_PID)` 取 `p_starttime`，
不是我们代码第一次执行的时间）。判读规则：

- `App.init` 那行就很大 → 时间花在 **dyld / 系统加载**，与我们代码无关
- `App.init` 很小、`onAppear` 才变大 → 花在**我们的视图 / 首帧**

真机（iPad6,7，Debug）实测：`1400ms App.init` + 250ms 视图构建 + 506ms 首帧 = 共 2221ms，
其中 1400ms 是 Debug 专属的 `chess.debug.dylib` 加载、506ms 里含 Debug 默认开启的
Metal API Validation。**Release 不含这些**；详细数字与提速办法见 [gotcha.md](gotcha.md) 第 20 条。

## 与设计文档不一致的地方（一律以 Android 源码为准）

| 设计文档 | Android 源码 / 实际 | iOS 怎么做的 |
|---|---|---|
| §6.1 `subdivisions = lines + 1` | `BoardGeometry` 的**默认值其实是 20**，但 `StoneBoardView` 显式传 `lines + 1` | Swift 默认值取 `lines + 1`（跟 App 行为一致）。照默认值写会让五子棋格子从 24.375pt 变 19.5pt |
| §7.1 象棋第 1 层是「方块 + 边框」 | `boardBorderPaint` 声明了却从未使用，**Android 象棋盘没有边框** | 照源码不画（想补就一行 `ctx.stroke`） |
| §7.8 「对端拖动也显示悬停」 | `drawHover` 先判**视图层** `dragging`，对端拖时是 false | 照源码：只有本地拖才显示悬停圈 |
| §12.2 `收到握手请求 <远端>：<路径>，UA=<UA>` | `NWProtocolWebSocket.setClientRequestHandler` 只给「子协议 + 附加头」，拿不到路径 / UA | 记能拿到的部分；远端地址记在「客户端接入」那行 |
| §11.4 出错文案 | 没有「服务端绑定失败」这一条 | 用「服务出错」 |
| §7.2 `sp` = 跟随系统字号 | iOS 不需要棋盘字号缩放 | 按 pt 处理（牌子字用 `@ScaledMetric`） |

## 加一种新棋

1. 新建 `Game/xxx/`，照抄三件套：`XxxGame`（实现 `Game`）、`XxxProtocol`、`XxxGeometry`
2. `Game/Protocol/GameKind.swift` 加一个 `case`（`rawValue` 是上线进报文的名字，**别随便改，
   要和 Android 同时改**）
3. 新建 `Views/XxxBoardView.swift`（`Canvas` 画 + `DragGesture` 报手势，照抄现有三个之一）
4. `RootView`：加一个 `@StateObject` 棋局、`boardPages` 里加一个 `case`、`routeRemote` 里加一个分支、
   `resetCurrentPage` 里加一个分支；`Theme.Text` 加标签文案
5. 跑黄金向量（`run-ios.sh`）确认盘面编解码和坐标换算与 Android 一致

## 已知限制

- **服务端只在 App 前台工作**：iOS 切后台很快挂起，socket 就停了（和 Android 侧的前台服务问题是同一件事，
  见 [todo.md](todo.md)）。现在只有「联机期间屏幕常亮」这个补偿
- Debug 构建在 2017 年的 iPad 上冷启动约 2.2 秒（全是 Debug 专属开销，见上文）
- 真机验收（§15 清单里的画面 / 手感 / 跨平台互通）还没逐条走完，见 [todo.md](todo.md)
