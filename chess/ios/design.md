# iOS 复刻设计文档

把 `android/` 里这个 App **完整复刻成 iOS 版**所需的全部细节。
目标：**逐像素、逐行为一致** —— 同一台 iPhone / iPad 上和 Android 版看起来一样、操作手感一样、能互相联机（iOS↔Android 也要能连，所以报文协议必须一模一样）。

- 参考实现（唯一权威）：`android/app/src/main/java/com/example/chess/`
- 数值来源：Android 源码里的常量，本文档里的每个数字都能在那边对上
- 协议部分（第 10、11 节）**必须严格照抄**，否则跨平台连不上
- 视觉部分（第 4~8 节）照着抄就不会跑偏
- 第 13、14 节是 iOS 侧的技术选型和平台坑，是实现建议而非约束

---

## 1. 产品总览

一个**黑底、全屏、四个棋种**的对弈 App：

| 页面 | 棋种 | 棋盘 | 棋子来源 |
|---|---|---|---|
| 象棋 | 中国象棋（红先） | 9 路 × 10 路交叉点，中间楚河汉界，两端九宫 | 开局就在盘上 |
| 国际象棋 | Chess（白先） | 8 × 8 方格 | 开局就在盘上 |
| 围棋 | Go（黑先） | 19 路交叉点 | 棋盘外托盘，每色 180 颗 |
| 五子棋 | Gomoku（黑先） | 15 路交叉点 | 棋盘外托盘，每色 180 颗 |

三种对局模式：

1. **单机面对面**：一台设备，两人轮流拖；
2. **局域网联机**：一台当服务端（服），其它当客户端（客），一个 WebSocket 连接承载全部四种棋；
3. （无 AI、无规则校验、无胜负判定）

四条贯穿全局的行为约定：

- **只判断轮次**，不做任何走法合法性校验；
- **盘上的子谁都能拿起来拖**（包括不是自己回合时），但「不该这一方下」时松手会**弹回原位**；
- **吃子有两种**：走到对方子上直接吃掉（象棋 / 国际象棋）；把子**拖出棋盘**＝被吃，直接消失（四种棋都支持，且不换手）；
- **拖动全程只是"浮层"**：在松手之前一个字节都不改盘面，所以网络丢包绝不会搞乱棋局。

---

## 2. iOS 工程现状与目标结构

现状（Xcode 模板空壳）：

```
ios/
  chess.xcodeproj/
  chess/
    chessApp.swift        ← SwiftUI App 入口（保留，改 body 指向新的 RootView）
    ContentView.swift     ← 模板占位，删掉换成 RootView
    Assets.xcassets/
```

工程配置（`project.pbxproj` 现状，保持即可）：

- `IPHONEOS_DEPLOYMENT_TARGET = 16.6`
- `SWIFT_VERSION = 5.0`
- `TARGETED_DEVICE_FAMILY = "1,2"`（iPhone + iPad）
- `PRODUCT_BUNDLE_IDENTIFIER = com.ifbe.aimadesw.chess`

建议的目标结构（和 Android 的包结构一一对应，方便对照改 bug）：

```
ios/chess/
  App/
    ChessApp.swift            @main
    RootView.swift            根：ZStack(黑底) + 四个棋盘 + 标签栏 + 重置 + 联机条 + 日志框
    Layout.swift              四角控件 + 安全区（safeAreaInsets）处理
    Theme.swift               全部配色 / 圆角 / 字号 / 内边距常量（对照 §5）
  Game/
    Core/
      Game.swift              protocol Game、Gesture、DragOverlay、BoardSnapshot、MoveEventSink
      LocalSession.swift      本机事件流水（不联网时用，也方便回放）
    Protocol/                 ★ 必须与 Android 完全一致
      GameKind.swift
      BoardPos.swift          1/256 格定点坐标
      PieceRef.swift
      MoveEvent.swift
      EnvelopeCodec.swift     key=value 信封编解码
    Share/Stone/
      BoardGeometry.swift
      StoneGame.swift
      StoneProtocol.swift
    Xiangqi/
      XiangqiGeometry.swift  XiangqiGame.swift  XiangqiProtocol.swift
    IntlChess/
      IntlChessGeometry.swift  IntlChessGame.swift  IntlChessProtocol.swift
  Views/
    StoneBoardView.swift      围棋 / 五子棋共用（19 路 / 15 路由参数决定）
    XiangqiBoardView.swift
    IntlChessBoardView.swift
    NetBarView.swift          左下角 [服/客][地址][开始/状态]
    LogPanelView.swift        右下角可折叠日志
    TabBarView.swift          左上角四个标签
  Net/
    Session.swift             protocol Session（send / listen / close）
    NetAddress.swift          本机局域网 IP、地址与端口解析
    WsSession.swift           WebSocket 房间：服务端 + 客户端
  Log/
    AppLog.swift              环形缓冲 + 订阅（界面日志框 + os.Logger）
```

---

## 3. Android → iOS 文件对照

| Android | iOS | 内容 |
|---|---|---|
| `game/share/protocol/*.kt` | `Game/Protocol/*.swift` | 信封、坐标、棋子身份、四种棋的枚举 |
| `game/share/core/Game.kt` | `Game/Core/Game.swift` | `Game` 协议、`Gesture`、`DragOverlay`、`BoardSnapshot` |
| `game/share/stone/BoardGeometry.kt` | `Game/Share/Stone/BoardGeometry.swift` | 石头棋盘几何 + 星位表 |
| `game/share/stone/StoneGame.kt` | `Game/Share/Stone/StoneGame.swift` | 石头棋盘面 + 规则 |
| `game/share/stone/StoneProtocol.kt` | `Game/Share/Stone/StoneProtocol.swift` | 盘面 / 坐标编解码 |
| `game/xiangqi/XiangqiGeometry.kt` | `Game/Xiangqi/XiangqiGeometry.swift` | 象棋几何（含牌子位置） |
| `game/xiangqi/XiangqiGame.kt` | `Game/Xiangqi/XiangqiGame.swift` | 象棋盘面 + 规则 + 初始局面 |
| `game/xiangqi/XiangqiProtocol.kt` | `Game/Xiangqi/XiangqiProtocol.swift` | 90 字符盘面 + 坐标 |
| `game/guojixiangqi/IntlChess*.kt` | `Game/IntlChess/*.swift` | 国际象棋同上 |
| `game/xiangqi/XiangqiBoardView.kt` | `Views/XiangqiBoardView.swift` | 只画 + 报手势 |
| `game/guojixiangqi/IntlChessBoardView.kt` | `Views/IntlChessBoardView.swift` | 同上 |
| `game/share/stone/StoneBoardView.kt` | `Views/StoneBoardView.swift` | 同上（含托盘） |
| `game/weiqi/GoBoardView.kt` | 参数：`lines = 19, kind = .weiqi` | 19 路配置 |
| `game/wuziqi/GomokuBoardView.kt` | 参数：`lines = 15, kind = .wuziqi` | 15 路配置 |
| `net/Session.kt` | `Net/Session.swift` | 联机接口 |
| `net/NetAddress.kt` | `Net/NetAddress.swift` | 本机 IP、地址解析 |
| `net/ws/WsSession.kt` | `Net/WsSession.swift` | WebSocket 房间（服 + 客） |
| `log/AppLog.kt` | `Log/AppLog.swift` | 特殊日志缓冲 |
| `MainActivity.kt` | `RootView.swift` + `NetBarView.swift` + `LogPanelView.swift` | 壳 + 联机条 + 日志框 |
| `res/values/strings.xml` | `Theme.swift` 里的文案常量 | 全部文案见 §5.5 |

---

## 4. 界面布局

### 4.1 整体

- 根视图：**纯黑**背景，全屏（忽略安全区绘制，控件自己让开）
- 四个棋盘页叠在一起，同一时刻只有一个可见（其余从渲染树里移除）
- 四个角的控件叠在棋盘**上层**，z 序：棋盘 < 重置 < 联机条 < 日志框 < 标签栏

### 4.2 四角控件与安全区

所有四角控件的基础外边距都是 **12pt**，再各自加上对应的安全区（`safeAreaInsets`）：

| 控件 | 位置 | 外边距 |
|---|---|---|
| 标签栏 `TabBar` | 左上 | `12 + safeArea.left`，`12 + safeArea.top` |
| 重置按钮 | 右上 | `12 + safeArea.right`，`12 + safeArea.top` |
| 联机条 `NetBar` | 左下 | `12 + safeArea.left`，`12 + safeArea.bottom` |
| 日志框 `LogPanel` | 右下 | `12 + safeArea.right`，`12 + safeArea.bottom` |

> Android 侧是 `setOnApplyWindowInsetsListener` 里改 margin；iOS 用 `GeometryReader` 的 `safeAreaInsets` 或 `.safeAreaPadding()` 同理。

### 4.3 左上角标签栏

横向排列四个按钮，顺序固定：**象棋 / 国际象棋 / 围棋 / 五子棋**。

按钮样式（Android 里叫 `TabButton`，下面所有小按钮都用它）：

| 属性 | 值 |
|---|---|
| 内边距 | 左右 10pt，上下 7pt |
| 字号 | 13pt |
| 圆角 | 18pt |
| 按钮间距 | 4pt（最后一个后面不加） |
| 非当前页 | 底 `#E61A1A1A`，1pt 边 `#4DFFFFFF`，字 `#F0F0F0` |
| 当前页 | 底 `#E6B24C`，无边框，字 `#2A2110` |
| 点击反馈 | 白色 20% 水波纹（Android ripple）；iOS 用 `Button` 默认高亮或自绘 |

### 4.4 右上角重置按钮

- 文案：`↺ 重置`
- 字号 14pt，字色 `#EF9A9A`
- 内边距 左右 12pt / 上下 8pt，圆角 22pt，底 `#E61A1A1A`，1pt 边 `#4DFFFFFF`
- 行为：**重置当前正在看的那一页**（摆回开局，并广播一条重置事件）

### 4.5 左下角联机条

三个控件横排，垂直居中：

```
[ 服 ] [ 192.168.5.103:8765        ] [ 开始服务 ]
  按钮        地址框（宽 130pt）            按钮
```

| 控件 | 规格 |
|---|---|
| 模式按钮 | `TabButton` 样式；文案 `服` / `客`；右侧间距 6pt；点击切换（连着呢不准切） |
| 地址框 | 宽 **130pt**；`bg_tab` 样式（底 `#E61A1A1A`、1pt 边 `#4DFFFFFF`、圆角 18pt）；左右内边距 10pt、上下 7pt；字号 13pt；字色 `#F0F0F0`；占位色 `#80FFFFFF`；**单行、URI 键盘** |
| 动作按钮 | `TabButton` 样式；左侧间距 6pt；文案见表 §11.4 |

地址框的取值规则（**服 / 客各记各的**，见 §11.5）：

- 该模式本次启动**没输入过** → 填默认值 `本机局域网IP:8765`（服、客两个模式都是这个默认值）
- 该模式本次启动**输入过** → 保持用户输入的那个，切模式不丢
- 服模式实际监听 `0.0.0.0:端口`（端口从框里取）；框里的 IP 只是给对端看的
- 客模式按框里的地址去连

### 4.6 右下角日志框

默认**折叠**成一个 `日志` 小按钮（`TabButton` 样式）；点一下展开成面板，按钮文案变 `收起`。

展开面板：

| 属性 | 值 |
|---|---|
| 尺寸 | 宽 **280pt**，高 **170pt** |
| 底色 | `#E6101418` |
| 描边 | 1pt `#66E6B24C` |
| 圆角 | 10pt |
| 内边距 | 8pt |
| 正文 | **等宽字体**，10pt，色 `#D8E8FF`，行距 +2pt，可选中复制 |
| 滚动 | 垂直滚动，每次追加后**自动滚到底** |
| 与按钮间距 | 6pt |

面板显示的是 `AppLog` 的全部内容（最长保留 200 行，见 §12）；新日志到达时若面板已展开要立即刷新。

### 4.7 屏幕常亮

**联机期间**（开了服务或连着对端）保持屏幕常亮：iOS 用 `UIApplication.shared.isIdleTimerDisabled = true`，关闭连接 / 退出时恢复 `false`。
原因见 §14.3。

---

## 5. 视觉规范

### 5.1 界面配色

| 用途 | 值 |
|---|---|
| 页面底色 | `#000000` |
| 小按钮底 | `#E61A1A1A` |
| 小按钮边 | `#4DFFFFFF` |
| 小按钮字（非当前） | `#F0F0F0` |
| 当前标签底 | `#E6B24C` |
| 当前标签字 | `#2A2110` |
| 重置按钮字 | `#EF9A9A` |
| 强调色（轮到谁走的黄框、悬停提示、日志框边） | `#E6B24C` |
| 地址框占位色 | `#80FFFFFF` |
| 日志面板底 | `#E6101418` |
| 日志正文 | `#D8E8FF` |

### 5.2 象棋配色

| 用途 | 值 |
|---|---|
| 棋盘底（鹅黄） | `#FFE999` |
| 棋盘边 | `#E0C67E` |
| 横竖线 / 九宫 / 星位 | `#3A3226` |
| 楚河汉界文字 | `#8A7748` |
| 棋子面 | `#FFFBF0` |
| 红方环 / 红字 | `#C0392B` |
| 黑方环 / 黑字 | `#1F1F1F` |
| 悬停（可落） | `#3A3226` |
| 悬停（放不下） | `#C62828` |

### 5.3 国际象棋配色

| 用途 | 值 |
|---|---|
| 浅格 | `#F0D9B5` |
| 深格 | `#B58863` |
| 棋盘边框 | `#6B4A2F` |
| 白子填充 / 描边 | `#FFFFFF` / `#3A3226` |
| 黑子填充 / 描边 | `#1B1B1B` / `#EFE6D5` |
| 悬停（可落 / 放不下） | `#40E6B24C` / `#40C62828`（半透明填充整格） |
| 牌子文字 | `#FFFFFF` |

### 5.4 围棋 / 五子棋配色

| 用途 | 值 |
|---|---|
| 棋盘底（鹅黄） | `#FFE999` |
| 棋盘边 | `#E0C67E` |
| 横竖线 / 星位 | `#3A3226` |
| 黑子填充 / 描边 | `#0A0A0A` / `#3A3A3A` |
| 白子填充 / 描边 | `#F2F2F2` / `#9E9E9E` |
| 数量文字 | `#FFFFFF` |
| 悬停（可落 / 放不下） | `#3A3226` / `#C62828` |

### 5.5 全部文案

```
象棋 / 国际象棋 / 围棋 / 五子棋          （四个标签）
↺ 重置                                  （右上角）
服 / 客                                 （左下角模式按钮）
开始服务 / 开始连接                      （动作按钮，未联机时的两种文案）
启动中… / 连接中…                        （启动 / 连接过程中）
服务中·N                                 （服务端已启动，N = 已连客户端数）
已连接                                   （客户端连上了）
连接失败 / 连接已断开 / 已关闭            （失败 / 断开 / 手动关闭）
地址不对 / 缺少本地网络权限               （参数或权限问题）
日志 / 收起                               （右下角折叠按钮）
对方地址，如 192.168.5.213:8765           （客模式地址框占位文字）
192.168.1.7:8765                        （服模式地址框占位文字）
楚 河 / 汉 界                            （象棋河界上的字）
x180                                     （托盘剩余数量，格式 x{n}）
黑方 / 红方                              （象棋两端牌子）
黑方 / 白方                              （国际象棋两端牌子）
帅 / 将                                  （象棋牌子里的棋子）
♚                                        （国际象棋牌子里的王，白方用白填充）
```

---

## 6. 棋盘几何（核心，必须逐字照抄公式）

三种几何都遵循一个原则：**棋盘永远居中，长短边各按规则分配格数**；
「格子中心 = 落点」或「格子 = 方格」由棋种决定。

### 6.1 围棋 / 五子棋 `BoardGeometry`

输入：视图尺寸 `(w, h)`、路数 `lines`（围棋 19、五子棋 15）、`subdivisions = lines + 1`。

```
boardSize = min(w, h)                  // 棋盘是正方形
boardLeft = (w - boardSize) / 2        // 居中
boardTop  = (h - boardSize) / 2
cell      = boardSize / subdivisions   // ← 注意是 lines+1，所以四周各留半格
stoneRadius = cell * 0.46              // 盘上的子
pieceRadius = stoneRadius * 1.08       // 托盘里的子、以及拖动中的子（两者必须一样大）
```

落点坐标（第 i 条线在第 i 个格子的**正中心**）：

```
gridX(col) = boardLeft + (col + 1) * cell      // col ∈ [0, lines-1]
gridY(row) = boardTop  + (row + 1) * cell
```

于是最外圈离正方形边正好一格，`lines = 19` 时中心点就是 `(9, 9)`。

**托盘在哪两侧**（本 App 的核心自适应规则）：

```
sideSpace     = boardLeft      // 左右各剩多少
verticalSpace = boardTop       // 上下各剩多少
trayOnSides   = boardLeft > boardTop       // true = 托盘在左右（横屏/平板）
trayStrip     = trayOnSides ? boardLeft : boardTop

trayCenterX(黑) = trayOnSides ? boardLeft / 2 : w / 2
trayCenterX(白) = trayOnSides ? w - boardLeft / 2 : w / 2
trayCenterY(黑) = trayOnSides ? h / 2 : boardTop / 2
trayCenterY(白) = trayOnSides ? h / 2 : h - boardTop / 2
```

即：竖屏手机（棋盘占满宽）→ 黑托盘在棋盘**上方**、白托盘在**下方**；
横屏 / 平板（棋盘占满高）→ 黑在**左**、白在**右**。

**星位**（`starPoints(lines)`，返回 `[col,row]` 数组）：

| 路数 | 星位 |
|---|---|
| 19（围棋） | 3×3 共 9 个：col/row ∈ {3, 9, 15} 的所有组合 |
| 15（五子棋） | 5 个：`(3,3) (11,3) (3,11) (11,11) (7,7)` |
| 13 | 5 个：`(3,3) (9,3) (3,9) (9,9) (6,6)` |
| 9 | 5 个：`(2,2) (6,2) (2,6) (6,6) (4,4)` |

**像素 ↔ 棋盘语义坐标**（协议里用的就是后者，见 §10.3）：

```
cellXAt(px) = (px - boardLeft - boardSize/2) / cell
cellYAt(py) = (py - boardTop  - boardSize/2) / cell
pxOfCell(cx) = boardLeft + boardSize/2 + cx * cell
pyOfCell(cy) = boardTop  + boardSize/2 + cy * cell
```

**命中测试**：`isInsideBoard(x,y)` = 在正方形内；命中落点用四舍五入：

```
col = clamp(round((x - boardLeft) / cell - 1), 0, lines-1)
row = clamp(round((y - boardTop ) / cell - 1), 0, lines-1)
index = row * lines + col        // 不在正方形内 → -1（= 拖出棋盘）
```

### 6.2 象棋 `XiangqiGeometry`

棋盘是 **9 路 × 10 路**，方向固定「短边 9 路、长边 10 路」，格子边长取两条限制里更小的：

```
shortSide = min(w, h)
longSide  = max(w, h)

cell = min( shortSide / 9,  longSide / 10 * 0.8 )
```

- `shortSide / 9`：棋盘最多占满短边；
- `longSide / 10 * 0.8`：长边方向最多占 80%，也就是**长边两端永远各留 ≥10%** 给按钮和「该谁走」的指示框。

> 为什么要两条：细长屏（手机竖屏）由第一条决定、棋盘占满短边；越接近正方形第二条越紧
> （例如短边/长边 = 0.89 时光靠短边/9 长边只剩 1% 余量，牌子放不下），此时棋盘自动缩小。

行列与旋转：

```
cols = (w <= h) ? 9 : 10        // 竖屏 9 列 × 10 行；横屏（平板）整块转 90°：10 列 × 9 行
rows = (w <= h) ? 10 : 9
rotated = (cols == 10)

boardWidth  = cols * cell
boardHeight = rows * cell
boardLeft   = (w - boardWidth) / 2
boardTop    = (h - boardHeight) / 2
```

落点（同样落在格子中心）：

```
gridX(col) = boardLeft + (col + 0.5) * cell
gridY(row) = boardTop  + (row + 0.5) * cell

screenCol(file, rank) = rotated ? rank : file
screenRow(file, rank) = rotated ? file : rank
pieceX(file, rank) = gridX(screenCol(file, rank))
pieceY(file, rank) = gridY(screenRow(file, rank))
```

**楚河汉界带**：`riverStart / riverEnd` = 第 4 / 5 条线的位置（`gridY(4)`、`gridY(5)`；旋转时是 `gridX(4)`、`gridX(5)`）。

**九宫**：`file ∈ [3,5]` 且 `rank ∈ [0,2]` 或 `[7,9]`，画两条对角线：
`(3,base)-(5,base+2)` 和 `(5,base)-(3,base+2)`，`base = 0` 和 `base = 7`。

**语义坐标 ↔ 像素（含旋转）**：

```
cellXAt(px, py) = rotated ? (py - boardTop - boardHeight/2)/cell : (px - boardLeft - boardWidth/2)/cell
cellYAt(px, py) = rotated ? (px - boardLeft - boardWidth/2)/cell : (py - boardTop - boardHeight/2)/cell
pxOfCell(cx, cy) = rotated ? boardLeft + boardWidth/2 + cy*cell : boardLeft + boardWidth/2 + cx*cell
pyOfCell(cx, cy) = rotated ? boardTop + boardHeight/2 + cx*cell : boardTop + boardHeight/2 + cy*cell
```

**棋盘外两端牌子（指示框）**：

```
badgeStrip = rotated ? boardLeft : boardTop

sideAnchorX(black) = !rotated ? w/2 : (black ? boardLeft/2 : w - boardLeft/2)
sideAnchorY(black) =  rotated ? h/2 : (black ? boardTop/2  : h - boardTop/2)

// 牌子上的字要转多少度才正对着坐在那一端的玩家
sideTextRotation(black) = !rotated ? (black ? 180 : 0) : (black ? 90 : -90)

// 棋子上的字朝当前该走的一方
pieceTextRotation(redToMove) = sideTextRotation(black = !redToMove)
```

**命中**：`indexAt(x,y)` 不在棋盘矩形内返回 -1，否则吸附到最近落点（`round`，与 §6.1 同构，行列制 9）。

### 6.3 国际象棋 `IntlChessGeometry`

```
boardSize = min(w, h)            // 棋盘区就是 min(w,h) 的正方形
boardLeft = (w - boardSize) / 2
boardTop  = (h - boardSize) / 2
cell      = boardSize / 8
rotated   = (w > h)              // 横屏（平板）整块转 90°，黑方在左、白方在右
```

方格与坐标（`file ∈ [0,7]` 从左到右、`rank ∈ [0,7]` 第 8 横排到第 1 横排）：

```
screenCol(file, rank) = rotated ? rank : file
screenRow(file, rank) = rotated ? file : rank
squareLeft(file, rank) = boardLeft + screenCol * cell
squareTop (file, rank) = boardTop  + screenRow * cell
squareX   = squareLeft + cell/2       // 方格中心（放棋子）
squareY   = squareTop  + cell/2

// a1 是深色：file 0, rank 7 → (0+7)%2 = 1
isDarkSquare(file, rank) = ((file + rank) % 2 == 1)
```

语义坐标 ↔ 像素、牌子位置 / 旋转、`pieceTextRotation(whiteToMove)` 与 §6.2 **完全同构**（把 `boardWidth/boardHeight` 换成 `boardSize`）。

**居中后的语义坐标范围**（协议用）：`x, y ∈ [-3.5, +3.5]`。

纯棋盘内的命中：`indexAt` 不在正方形内返回 -1，否则 `floor` 到所在格（注意：这里是**向下取整**，不是四舍五入）。

---

## 7. 绘制规范

### 7.1 层序（从下往上）

**围棋 / 五子棋**
1. 鹅黄棋盘方块（`boardLeft/Top` 起，边长 `boardSize`）+ 边框描边
2. 横竖各 `lines` 条线（从 `gridX(0)` 到 `gridX(lines-1)`，星位同样只画在盘内）
3. 星位实心圆
4. 已经落在盘上的棋子（**跳过正在被拖的那一颗的原位**）
5. 悬停提示圈（拖动中才有）
6. 黑白两个托盘（圆 + `x{剩余}` 文字 + 当前方的黄框）
7. 拖动中的棋子（本地和对端拖的都画在这儿）

**象棋**
1. 鹅黄棋盘方块 + 边框
2. 外框完整矩形 + 内部线（**竖向线在河界处断开**；`rotated` 时改成横向线断开）
3. 两端九宫斜线
4. 河界文字「楚 河」「汉 界」
5. 棋子（跳过被拖的那一颗）
6. 悬停提示圈
7. 两端牌子（黑 / 红，当前方带黄框）
8. 拖动中的棋子

**国际象棋**
1. 8×8 方格（浅 / 深交替）
2. 棋盘外框描边
3. 棋子字形（跳过被拖的那一颗）
4. 悬停高亮（半透明填充整格）
5. 两端牌子（黑 / 白，当前方带黄框）
6. 拖动中的棋子

### 7.2 线宽 / 半径 / 字号公式

| 元素 | 公式 |
|---|---|
| 象棋棋盘边 | `max(1dp, cell * 0.05)` |
| 象棋线 / 九宫 | `max(1dp, cell * 0.03)` |
| 象棋棋子环 | `max(2dp, cell * 0.045)` |
| 象棋棋子半径 | `cell * 0.42` |
| 象棋棋子文字 | `radius * 1.1`（绕棋子中心旋转 `pieceTextRotation`） |
| 象棋河界文字 | `cell * 0.42` |
| 象棋牌子文字 | `max(16sp, cell * 0.42)` |
| 石头棋盘边 | `max(1dp, cell * 0.05)` |
| 石头线 | `max(1dp, cell * 0.035)` |
| 石头星位半径 | `max(2.5dp, cell * 0.11)` |
| 石头棋子半径 | `stoneRadius = cell * 0.46` |
| 棋子环描边 | `max(1dp, cell * 0.05)` |
| 托盘文字 | `max(15sp, cell * 0.5)` |
| 国际象棋边框 | `max(2dp, cell * 0.05)` |
| 国际象棋字形大小 | `cell * 0.8`（拖动时 `× 1.1`） |
| 白子描边 / 黑子描边 | `max(2dp, cell * 0.035)` / `max(1.5dp, cell * 0.022)` |
| 牌子文字 | `max(16sp, cell * 0.42)` |
| 悬停圈线宽 | `max(2dp, cell * 0.06)` |
| 黄框线宽 | `2dp` |

> `dp` = 逻辑点（iOS 的 pt 直接对应）；`sp` = 会跟随系统字号缩放的单位，iOS 可用 `UIFontMetrics` 或直接按 pt 处理（本 App 只需要 UI 缩放，不影响棋盘）。

### 7.3 棋子图形

**象棋**：圆形棋子。

```
半径 r = cell * 0.42
填充圆：色 #FFFBF0
描边圆：半径 r - 线宽/2，色 红 #C0392B / 黑 #1F1F1F，线宽 max(2dp, cell*0.045)
文字：红方 车马相仕帅炮兵，黑方 车马象士将士象马车/炮/卒（见 §9.1），居中于圆心，
      字号 r * 1.1，绕圆心按 pieceTextRotation 旋转
```

**国际象棋**：用 Unicode 实心字形，靠颜色区分黑白。

```
'K' → ♚   'Q' → ♛   'R' → ♜   'B' → ♝   'N' → ♞   'P' → ♟
白子：先按 #FFFFFF 填充，再描 #3A3226；黑子：填充 #1B1B1B，描 #EFE6D5
画法：先描边后填充（描边线宽见 §7.2），字号 = cell * 0.8，垂直居中于方格中心，
      绕中心按 pieceTextRotation 旋转
```

**围棋 / 五子棋**：实心圆 + 细描边（见 §5.4 配色）。

### 7.4 棋子移动方向（棋盘旋转时）

棋盘在 `rotated` 时整块转 90°，**只有牌子文字和棋子文字按 §6.2 的公式转**；
棋盘线条、九宫、河界、方格都是按 `screenCol/screenRow` 映射后正常画的（相当于整盘转了 90°，但**不是**用画布旋转）。

### 7.5 当前该谁走的两处提示（必须都有）

1. **两端牌子**：只有当前该走那一方的牌子外面套一个**黄色矩形框**；另一方无框（**不要变暗**，之前踩过"看不清"的坑）
2. **棋子文字朝向**：整盘棋子的字都朝当前该走的一方（象棋 / 国际象棋；围棋/五子棋没有字）

牌子内容与尺寸：

```
strip = badgeStrip
radius = min(cell * 0.42, strip * 0.38)
label = 象棋: 黑方 / 红方    国际象棋: 黑方 / 白方
gap = radius * 0.5
textWidth = 测宽(label)
groupWidth = radius * 2 + gap + textWidth

在 anchor 处旋转 sideTextRotation 后绘制（整个牌子作为一个整体旋转）：
  圆：圆心 (anchor.x - groupWidth/2 + radius, anchor.y)，半径 radius，
      内容 = 象棋: 帅/将；国际象棋: ♚（白方用白填充）
  文字：x = 圆心.x + radius + gap，垂直居中于 anchor.y
  黄框（仅当前方）：把 (圆 + 文字) 的包围盒向外扩 radius * 0.45，线宽 2dp，色 #E6B24C
```

### 7.6 托盘（只有围棋 / 五子棋）

```
radius = pieceRadius = cell * 0.4968
圆心 = (trayCenterX(color), trayCenterY(color))     // 见 §6.1
文字 = "x{剩余数量}"，色 #FFFFFF，字号 max(15sp, cell*0.5)

若 trayOnSides（托盘在左右）：
    圆画在空带正中；文字在圆的正下方、水平居中
    基线 y = 圆心y + radius + radius*0.45 - ascent
否则（托盘在上下）：
    圆 + 文字作为一组整体水平居中：groupLeft = w/2 - (radius*2 + gap + textWidth)/2
    文字在圆的右侧、垂直居中：x = 圆心x + radius + gap, y = 圆心y - (ascent+descent)/2

当前方的托盘：黄框 = 包围盒向外扩 radius * 0.4，线宽 2dp，色 #E6B24C
命中区域：上面这个包围盒再向外扩 12pt（所以按黄框里任意位置都能开始拖）
```

### 7.7 拖动浮层（`DragOverlay`）

- 位置来自 `DragOverlay.cellX/cellY`（**棋盘语义坐标**），画之前用 §6.2 / §6.1 的 `pxOfCell/pyOfCell` 换回像素；
- 本地拖动和**对端拖动**画法完全一样（这样才能"看见对方乱动"）；
- 被拖的那颗子**原位不画**（渲染时跳过 `drag.from`），只画浮层这一颗；
- 松手后立即清空浮层，棋子在目标点上。

### 7.8 悬停提示

| 棋种 | 形状 | 可落（黄/墨） | 放不下（红） |
|---|---|---|---|
| 围棋 / 五子棋 | 圆环，半径 `stoneRadius * 1.15` | `#3A3226` | `#C62828` |
| 象棋 | 圆环，半径 `cell*0.42*1.12` | `#3A3226` | `#C62828` |
| 国际象棋 | 整格半透明填充 | `#40E6B24C` | `#40C62828` |

「可落」的判定 = **当前有拖动浮层** 且 **被拖的子的 side == 当前该走的 side** 且 **目标不是自己的子**。
本地拖动和对端拖动都显示悬停（对端拖时本机只是看，但指示也一致）。

---

## 8. 交互状态机

### 8.1 手势

用一套 `Gesture`（和 Android 一一对应）：

```swift
enum Gesture {
    case pickUp(index: Int)                        // 拿起盘上第 index 个落点/格子上的子
    case pickUpNew(side: Int, cellX: Float, cellY: Float)  // 从托盘拿一颗新子（只有石头棋用）
    case dragTo(cellX: Float, cellY: Float)        // 拖动中
    case drop(cellX: Float, cellY: Float, targetIndex: Int) // 松手；targetIndex = -1 表示盘外
    case cancel                                    // 手势被系统取消
}
```

触摸处理（三种棋盘视图一致）：

```
touchDown:  index = indexAt(point)
            if index >= 0 && hasPieceAt(index)      → 记 dragging = true，发 .pickUp(index)
            else if 石头棋 && 命中当前方的托盘        → dragging = true，发 .pickUpNew(side, 托盘中心的语义坐标)
            else                                    → 不接管这个手势（返回 false / 不消费）
touchMove:  if !dragging → 忽略
            hoverIndex = indexAt(point)             // 只影响提示圈
            发 .dragTo(cellXAt(point), cellYAt(point))
touchUp:    if !dragging → 忽略
            发 .drop(cellXAt, cellYAt, indexAt(point))   // 盘外自然是 -1
            dragging = false, hoverIndex = -1
touchCancel:if !dragging → 忽略
            发 .cancel
```

要点：

- `dragging` 只是**视图层的**标志（决定后续事件要不要接），和棋局状态无关；
- 手指按下时必须 `requestDisallowIntercept`（iOS 上用 `DragGesture(minimumDistance: 0)` + `.highPriorityGesture` 避免被父容器抢）；
- 拖动过程中**不修改盘面**（见 §9）。

### 8.2 松手判定（唯一的行为规则）

`Game` 收到 `.drop` 后按下面判定；**`committed` 表示"这一步被采纳"**，随后一定跟一条全量棋盘事件。

**象棋 / 国际象棋**

| 条件 | 结果 |
|---|---|
| `targetIndex < 0`（拖出棋盘） | **被吃**：把这颗子从盘上移除，**不换手**，`committed = false` + 全量棋盘 |
| `targetIndex == from`（点一下没动） | 弹回原位，不换手 |
| 被拖的子的 side ≠ 当前该走的 side | 弹回原位（"不该自己走"） |
| 目标是**自己的子** | 弹回原位（放不下） |
| 目标是空格 | 落子，**换手**，`committed = true` + 全量棋盘 |
| 目标是**对方的子** | **直接吃掉**（覆盖），换手，`committed = true` + 全量棋盘 |

**围棋 / 五子棋**

从**盘上**拿起来的子：

| 条件 | 结果 |
|---|---|
| `targetIndex < 0` | **被吃**：从盘上移除，**数量不回托盘、不换手**，+ 全量棋盘 |
| `targetIndex == from` | 弹回 |
| 该色 side ≠ 当前该走 side | 弹回 |
| 目标**已有子** | 弹回（不做"走过吃"） |
| 目标是空交叉点 | 挪过去，换手，+ 全量棋盘 |

从**托盘**拿的新子：

| 条件 | 结果 |
|---|---|
| `targetIndex < 0` | 相当于放回托盘，什么都不变 |
| 目标已有子 | 放不下，什么都不变 |
| 目标是空交叉点 | 落子，该色剩余数量 **-1**，换手，+ 全量棋盘 |
| 该色剩余数量 = 0 | 按不动（`pickUpNew` 直接忽略） |
| 不是当前该走的一方 | 按不动（托盘不可拖） |

### 8.3 关键设计：拖拽是"浮层"，不改盘面

**按下时不改盘面**，只在 `Game` 里记一个 `drag`：

```swift
struct DragOverlay {
    let piece: PieceRef
    let from: Int        // 原来在哪个落点/格子（渲染时跳过这一格）
    var cellX, cellY: Float
    let byMe: Bool       // true = 本机在拖；false = 对端在拖
}
```

好处：网络位置流丢了/晚了/乱了都**不会**破坏棋局；只有 `board` 全量事件会改盘面。

### 8.4 重置

- 右上角按钮 → 重摆当前页开局，并广播 `reset` + 一条全量 `board`；
- 收到对端的 `reset` → 本地也重摆（双方的开局是确定的，不用传盘面）。

### 8.5 页面切换

左上角四个标签，点了就切换；**每页各自保留自己的棋局**（互不影响），切走再切回来棋还在。

---

## 9. 状态模型与初始局面

### 9.1 象棋 `XiangqiGame`

```
索引：index = rank * 9 + file         // rank 0 = 黑方底线（屏幕上方），rank 9 = 红方底线
颜色：EMPTY = 0, RED = 1, BLACK = 2
side：RED → 0（先手）, BLACK → 1（后手）
存储：colors[90]（EMPTY/RED/BLACK）、pieces[90]（棋子种类或空）
轮次：redToMove: Bool，初始 true（红先）
```

棋子种类与显示名：

| 种类 | 红 | 黑 |
|---|---|---|
| ROOK | 车 | 车 |
| HORSE | 马 | 马 |
| ELEPHANT | 相 | 象 |
| ADVISOR | 仕 | 士 |
| KING | 帅 | 将 |
| CANNON | 炮 | 炮 |
| PAWN | 兵 | 卒 |

开局摆放：

```
rank 0 (黑)：车 马 象 士 将 士 象 马 车        （file 0..8）
rank 2 (黑)：炮 在 file 1 和 7
rank 3 (黑)：卒 在 file 0,2,4,6,8
rank 6 (红)：兵 在 file 0,2,4,6,8
rank 7 (红)：炮 在 file 1 和 7
rank 9 (红)：车 马 相 仕 帅 仕 相 马 车
```

### 9.2 国际象棋 `IntlChessGame`

```
索引：index = rank * 8 + file         // rank 0 = 黑方底线（屏幕上方），rank 7 = 白方底线
颜色：EMPTY = 0, WHITE = 1, BLACK = 2
side：WHITE → 0（先手）, BLACK → 1（后手）
存储：colors[64]、types[64]（KING/QUEEN/ROOK/BISHOP/KNIGHT/PAWN）
轮次：whiteToMove: Bool，初始 true（白先）
```

开局摆放：

```
rank 0 (黑)：r n b q k b n r
rank 1 (黑)：8 个兵
rank 6 (白)：8 个兵
rank 7 (白)：R N B Q K B N R
```

### 9.3 围棋 / 五子棋 `StoneGame`

```
索引：index = row * lines + col
颜色：EMPTY = 0, BLACK = 1, WHITE = 2
side：BLACK → 0（先手）, BLACK 先走
存储：grid[lines*lines]（EMPTY/BLACK/WHITE）、ids[lines*lines]（每颗子的自增编号，0 = 无子）
数量：blackRemaining、whiteRemaining，初始各 180
轮次：blackToMove: Bool，初始 true
```

- 围棋参数：`lines = 19, kind = .weiqi`
- 五子棋参数：`lines = 15, kind = .wuziqi`
- 两者共用同一份实现，只有路数和 `kind` 不同

### 9.4 观察者 / 状态外提

Android 侧的分层约定在 iOS 上照抄：

- `XxxGame`（数据 + 逻辑）**不依赖 UI 框架**，纯 Swift 值语义 / 简单类，可单测；
- `XxxBoardView` **只负责画 + 报手势**，不自己改盘面；
- 事件由 `Game` 产生：`onGesture` 先改本地状态，再把「要广播的事件」返回给调用方；
- `apply(event)` 只处理**对端**来的事件，不回灌自己的事件。

Swift 里建议：

```swift
protocol Game {
    var kind: GameKind { get }
    var turn: Int { get }                       // 0 = 先手, 1 = 后手
    func snapshot() -> BoardSnapshot
    func hasPieceAt(_ index: Int) -> Bool
    var drag: DragOverlay? { get }
    func onGesture(_ g: Gesture) -> [MoveEvent] // 本地已生效
    func apply(_ e: MoveEvent)
    func reset() -> [MoveEvent]
}
```

---

## 10. 协议（跨平台必须逐字节一致）

### 10.1 传输

- WebSocket **text 帧**，**一条事件一帧**，UTF-8
- 不加换行、不做分帧拼接（帧边界就是消息边界）

### 10.2 信封格式

```
v1|game=xiangqi|seq=12|t=drag_move|side=0|name=车|id=54|x=1280|y=-1152
v1|game=weiqi|seq=13|t=board|board=..b.w..|turn=1|counts=179,180
```

- 用 `|` 分段，第一段固定是版本号 `v1`；
- 其余段是 `key=value`，解析时按需取，**缺字段 / 脏数据一律丢弃这条报文，不要崩**；
- 值里不能出现 `|`（盘面串和棋子名都不含它）；
- `name` 允许是空串（`name=` 后面直接是下一个 `|`）。

### 10.3 字段语义

| 字段 | 含义 |
|---|---|
| `game` | 棋种 id：`xiangqi` / `intl_chess` / `weiqi` / `wuziqi` |
| `seq` | 发送方自增序号（去重 / 丢过期包用；服务端可以重新盖章） |
| `t` | 事件类型，见下表 |
| `side` | `0` = 先手（象棋红 / 国际象棋白 / 围棋五子棋黑），`1` = 后手 |
| `name` | 棋子名字，**给人看的**：象棋是汉字（`车`/`帅`…），国际象棋是字母（`K`/`Q`…），石头是空串 |
| `id` | 棋子**唯一标识**：有名字的用「拿起来时所在的落点下标」；石头用自增落子号 |
| `from` | 这子原来在哪个落点/格子（只有 `drag_start` 有） |
| `x`,`y` | 相对棋盘中心的**棋盘语义坐标**，单位 **1/256 格**，有符号 int |
| `committed` | `1` = 这一步被采纳；`0` = 弹回 |
| `board` | 全量盘面字符串（编码见 §10.4） |
| `turn` | 接下来该谁走，`0` / `1` |
| `counts` | 剩余数量，逗号分隔（石头棋是 `黑,白`），其它棋种为空 |

### 10.4 事件类型

| `t` | 结构 | 说明 |
|---|---|---|
| `drag_start` | `side,name,id,from,x,y` | 从盘上拿起一颗子 |
| `drag_move` | `side,name,id,x,y` | 拖动中的实时位置（高频、可丢） |
| `drag_end` | `side,name,id,x,y,committed` | 松手 |
| `board` | `board,turn,counts` | **全量盘面**：落子 / 吃子 / 拖出棋盘 / 重开之后都发这一包 |
| `reset` | — | 重开一局（双方各自摆回开局） |

> 没有任何"走法"事件：接收方永远**照抄全量盘面**，所以跨平台不会因为规则实现差异而错位。

### 10.5 坐标（`BoardPos`）

- 相对**棋盘中心**，单位 **1/256 格**，用整数（避免浮点误差；1/256 格在 1080p 上 ≈ 0.2~0.5 像素）；
- **x 沿 file / 列方向（向右为正）、y 沿 rank / 行方向（向下为正）** —— 是"棋盘语义坐标"而不是屏幕坐标，所以横屏棋盘转 90° 也不影响对端理解；
- 各种棋的落点范围：

| 棋种 | x | y |
|---|---|---|
| 象棋 | `[-4, +4]`（整数） | `[-4.5, +4.5]`（半整数） |
| 国际象棋 | `[-3.5, +3.5]` | `[-3.5, +3.5]` |
| 围棋 19 路 | `[-9, +9]` | `[-9, +9]` |
| 五子棋 15 路 | `[-7, +7]` | `[-7, +7]` |

编码：`x = round(cellX * 256)`；解码：`cellX = x / 256.0`。拖动中可能超出范围（拖到棋盘外 = 被吃）。

### 10.6 盘面编码（各棋种的 `board` 字符串）

**象棋**：90 个字符，`index = rank*9 + file` 顺序。

```
'.'  空
红方大写：R 车 / N 马 / B 相 / A 仕 / K 帅 / C 炮 / P 兵
黑方小写：r 车 / n 马 / b 象 / a 士 / k 将 / c 炮 / p 卒
```

**国际象棋**：64 个字符，`index = rank*8 + file` 顺序。

```
'.'  空
白方大写：K Q R B N P
黑方小写：k q r b n p
```

**围棋 / 五子棋**：`lines * lines` 个字符，`index = row*lines + col` 顺序。

```
'.'  空     'b' 黑     'w' 白
```

### 10.7 棋子身份（`PieceRef`）

- `name` 用于**人类可读**（日志 / 调试）；
- `id` 才是**唯一标识**：
  - 象棋 / 国际象棋：**拿起来时所在的落点下标**（同名的两个车/马靠它区分）；
  - 围棋 / 五子棋：**自增落子序号**（被提掉的子会让序号出现空洞，所以它是计数器而不是数组下标）；
- 接收 `drag_start` 时要校验：该位置上确实有子、且名字对得上，否则忽略（防止乱包把浮层画错）。

---

## 11. 联机实现规格

### 11.1 一个连接管四种棋

- 报文里带 `game`，收到后按棋种分发给对应页面；
- **服务端和客户端是同一个类的两种用法**（Android 是 `WsSession`），协议完全一样。

### 11.2 服务端职责

1. 监听 `0.0.0.0:端口`（默认 8765，端口来自地址框）；
2. 收到某客户端的事件 → 先**应用到自己盘面**（`handleMessage` → 交给本地 `Game`）→ 再**转发给其它客户端**（**不回给发送者**，避免他收到自己的回放）；
3. **缓存每个棋种最后一包 `board`**；新客户端一连上（握手成功）就把这些缓存全推过去 —— 这样中途加入 / 重连的人立刻对齐盘面；
4. 连接进来/断开要更新状态栏文案（`服务中·N`）。

### 11.3 客户端职责

1. 连上 `ws://<地址框内容>`；
2. 本地事件发给服务端；
3. 收到的事件交给自己的 `Game`。

### 11.4 按钮文案（状态机）

| 状态 | 按钮文字 | 点击行为 |
|---|---|---|
| 未联机（服） | `开始服务` | 启动服务 |
| 未联机（客） | `开始连接` | 连接 |
| 启动 / 连接中 | `启动中…` / `连接中…` | 关闭 |
| 服务端已运行 | `服务中·N`（N = 已连客户端数，随进出更新） | 关闭服务 |
| 客户端已连上 | `已连接` | 断开 |
| 出错 / 断开 | `连接失败` / `连接已断开` / `地址不对` / `缺少本地网络权限` | 重试或关闭 |
| 手动关闭后 | 回到 `开始服务` / `开始连接` | — |

### 11.5 地址框规则

- **服 / 客两个模式各记各的**（本次 App 启动内有效，不跨启动持久化）；
- 某个模式**没输入过** → 填默认值 `本机局域网IP:8765`（两个模式都是这个默认值）；
- 某个模式**输入过** → 始终保持用户输入的那个，切模式不丢、也不被自动覆盖；
- 程序自己回填的默认值**不算**"输入过"（需要一个 `isSettingProgrammatically` 标志区分）；
- 服务端实际监听 `0.0.0.0:端口`（**端口从框里取**，非法就退回 8765）；框里的 IP 只是给对端看的；
- 客户端把框里的内容解析成 `ws://host:port`：允许省略 `ws://` 前缀、允许不写端口（补 8765）、解析失败就报 `地址不对`。

### 11.6 本机 IP 探测

```
遍历所有网络接口，取「已启用、非 loopback、IPv4、私有网段」的地址；
优先 192.168.*，没有就取其它私有网段，都没有就返回 nil（界面显示 0.0.0.0）。
```

### 11.7 高频位置流的合并（重要）

- 拖动时本地 `MotionEvent` 频率可达 60~120Hz，**不能全发**；
- 做法：`drag_move` 只保留"最新一条"，由一个 **30Hz（33ms）** 的定时器发出；
- 发送**非** `drag_move` 的关键事件（`drag_start` / `drag_end` / `board` / `reset`）之前，**先把攒着的位置 flush 掉**，保证"先动、后落"的顺序；
- 不做重传：位置流丢了，下一条或随后的 `board` 会自动纠正。

### 11.8 其他

- 服务端监听前打开 `SO_REUSEADDR`（Android 侧是 `isReuseAddr = true`；iOS 用 `NWListener` 的
  `allowLocalEndpointReuse = true`）。**不开的话**：之前的连接留下 TIME_WAIT，关掉服务再立刻开就会
  `Address already in use`；
- 显式绑 IPv4 通配地址（`0.0.0.0`），因为发给对端的也是 192.168.x.x；
- 联机期间保持屏幕常亮（§4.7）。

---

## 12. 日志（"特殊日志"）

### 12.1 规格

- 只记**特殊事件**（连接、断开、出错、权限、启停），**不记**高频动作（拖动位置一条都不记）；
- 每行格式：`HH:mm:ss  <内容>`（本地时间）；
- 环形缓冲，最多保留 **200 行**；有多个订阅者（界面日志框），新增 / 清空都要推送；
- 订阅回调可能在网络线程，界面自己切主线程；
- iOS 上同时输出到 `os.Logger`（Android 侧是 logcat tag `ChessApp`），方便 `xcrun simctl spawn booted log stream` 或 Xcode console 看。

### 12.2 内容清单（照抄，便于两端对照排查）

```
应用启动，本机地址 <ip 或「（没有局域网 IP）」>
本机局域网地址：<ip>
切换为服务端模式 / 切换为客户端模式
需要「本地网络」权限（…），正在申请… / 已获得「本地网络」权限 / 「本地网络」权限被拒绝：…
开始服务：监听 0.0.0.0:<port>（仅 IPv4）
服务已启动，实际监听 0.0.0.0:<port>
收到握手请求 <远端地址>：<资源路径>，UA=<User-Agent>
客户端接入 <远端地址>，当前 <N> 个；已推送 <M> 个棋种的盘面
客户端断开 <远端地址>（code=<c> <reason>），当前 <N> 个
服务出错：<异常类名> <message>
服务启动失败：<异常类名> <message>
开始连接：<ws://地址>
已连接：<host>:<port>
连接断开（code=<c>，reason=<r>）
连接失败：<异常类名> <message>
发送失败（队列满或连接已关闭）
开始服务：端口 <port>，对端请连 <框里的地址>
地址不合法：<框里的内容>
已关闭服务 / 已断开连接
```

---

## 13. iOS 实现建议（技术选型）

### 13.1 渲染

- **SwiftUI + `Canvas`** 最省事：Android 那套 `onDraw` 可以一比一搬成 `Canvas { ctx, size in ... }`；
  每页一个 `BoardView: View`，内部状态变化时重绘（`@State` / `@ObservedObject`）。
- 需要 0 依赖的话也可以 `UIViewRepresentable` 包 `UIView` + `draw(_:)`；
  但 `Canvas` 已经够用（本 App 只有圆、线、文字、矩形）。
- 坐标换算直接用 §6 的公式，单位从 dp 换成 pt（数值完全一致）。

### 13.2 手势

```swift
.gesture(
    DragGesture(minimumDistance: 0)
        .onChanged { v in ... }     // 需要区分"第一次 changed"当作 touchDown
        .onEnded   { v in ... }     // 当作 touchUp
)
```

- `DragGesture` 没有独立的 touchDown / cancel：用 `@State var dragging` 在第一次 `onChanged` 里做
  `pickUp`，`onEnded` 里做 `drop`；视图消失 / 被取消时补一个 `.cancel`；
- 手指按下时如果落在托盘/棋子上要"接管"手势，别让父容器（比如 TabView / ScrollView）抢走。

### 13.3 状态与并发

- `Game` 用**引用类型**（`final class`）+ `@Published` / `ObservableObject` 最方便：网络线程收到事件后
  切主线程 `apply` 再刷新；
- 网络收发用 `Task` + `actor`；所有 UI 更新 `@MainActor`；
- `AppLog` 用单例 + `NSLock`（或 `@MainActor` 缓冲 + 后台队列），保持"任意线程可调用"。

### 13.4 网络

| 方向 | 建议方案 |
|---|---|
| 客户端 | `URLSessionWebSocketTask`（最省事）或 `NWConnection` + `NWProtocolWebSocket` |
| 服务端 | `NWListener` + `NWProtocolWebSocket`（Network.framework 原生支持 WebSocket 协议，不用手写握手） |

- **服务端必须用 Network.framework**（iOS 没有"监听端 WebSocket 库"的常规选择；`NWListener` +
  `NWProtocolWebSocket` 就是标准做法）；
- 拿到文本消息 → 解析信封 → 按 §11.2 转发 / 应用；
- 客户端如果选 `URLSessionWebSocketTask`，**注意 ATS**（见 §14.1）；选 `NWConnection` 则不受 ATS 影响。

### 13.5 目录与命名

按 §2 的结构；枚举 `GameKind` 的 `id` 必须和 Android 一致（`xiangqi` / `intl_chess` / `weiqi` / `wuziqi`）。

---

## 14. iOS 平台坑（每一个都真踩过或极易踩）

### 14.1 ATS：`ws://` 明文

iOS 的 App Transport Security 会拦明文连接。**如果客户端用 `URLSessionWebSocketTask` 连 `ws://192.168.x.x:8765`**，
必须在 Info.plist 里放行：

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <!-- 允许连接局域网（私有网段 / .local / 不带域名的主机） -->
    <key>NSAllowsLocalNetworking</key><true/>
    <!-- 实在不行再退到全放开（开发用，上架会被问） -->
    <!-- <key>NSAllowsArbitraryLoads</key><true/> -->
</dict>
```

用 `NWConnection` / `NWListener`（Network.framework）则**不受 ATS 约束**。

### 14.2 本地网络权限（iOS 14+）—— 和 Android 16 那个坑对等

- iOS 14 起，App 访问**局域网**（连局域网 IP、做 Bonjour 发现）会触发系统弹窗；
- 必须在 Info.plist 里声明用途说明，否则**弹窗不出现、连接直接被拒**：

```xml
<key>NSLocalNetworkUsageDescription</key>
<string>用于在局域网内与其他设备联机对弈</string>
<!-- 只做 Bonjour/mDNS 发现时才需要下面这两项 -->
<key>NSBonjourServices</key>
<array><string>_chess._tcp</string></array>
```

- 只连固定 IP（手输地址）**不需要** multicast entitlement；做 Bonjour 发现才需要
  `com.apple.developer.networking.multicast`；
- 用户拒绝后要到「设置 → 隐私与安全性 → 本地网络」里手动打开 → **界面上要提示**（对应 Android 的
  "缺少本地网络权限" 文案）；
- 这个弹窗的时机：**第一次真正发起局域网连接时**。所以别在启动时就静默失败，要在日志里写清楚。

### 14.3 后台挂不住

- iOS 切后台后 App 很快被挂起（`beginBackgroundTask` 只有 ~30s 宽限），**服务端 socket 会停**；
- 所以：**服务端只能在 App 前台时工作**（Android 侧这一点也还没做前台服务，见 `todo.md`）；
- 必须做的补偿：联机期间 `UIApplication.shared.isIdleTimerDisabled = true` 保持屏幕常亮，
  并（可选）提示用户"别切后台"。

### 14.4 方向锁

- Android 用 `screenOrientation="nosensor"`（锁自然方向）；
- iOS 在 Target → General → Deployment Info 里只勾选需要的方向（iPhone 竖屏 / iPad 横屏），
  或 Info.plist 的 `UISupportedInterfaceOrientations`；
- **注意**：棋盘"横屏整块转 90°"的判断依据是**视图的宽高比**（`w > h`），不是设备方向 —— 所以
  即使 iPad 横竖屏都支持也不会错乱。

### 14.5 字体

- 中文棋子字：系统字体即可（`.system(size:)`），不用内嵌字体；
- 日志面板用**等宽字体**（`.monospaced` / `UIFont.monospacedSystemFont`）；
- 棋子文字要**绕自身中心旋转**（`Canvas` 里 `ctx.translateBy` + `ctx.rotate` + 画 + `restore`），
  和 Android 的 `canvas.rotate(deg, cx, cy)` 等价。

### 14.6 键盘与输入框

- 地址框在**左下角**：弹键盘时可能被遮住。建议键盘出现时把联机条整体上移（或让输入框
  `becomeFirstResponder` 时滚动到可见）；
- 输入框设 `keyboardType = .URL`、`autocorrectionType = .no`、`autocapitalizationType = .none`
  （对应 Android 的 `inputType="textUri"`）。

### 14.7 其它

- 数值计算统一用 `Float`/`CGFloat`，**协议坐标用 Int**（§10.5），别用 Double 传来传去；
- 「半格」概念：象棋纵向是 `±4.5`，所以坐标里会出现 `x.5` 格 —— 用 `1/256` 格整数就没有小数问题；
- 摸到"点了没反应"先看日志框（§12），别猜网络。

---

## 15. 复刻验收清单

按顺序自测，每条都能对应到本文章节：

**界面**
- [ ] 页面纯黑，四个标签（象棋 / 国际象棋 / 围棋 / 五子棋）在左上，当前页黄底深字（§4.3）
- [ ] 右上角「↺ 重置」只重置当前页（§4.4、§8.4）
- [ ] 左下角 `[服/客][地址][开始/状态]`，右下角默认只有「日志」小按钮（§4.5、§4.6）
- [ ] 四角控件都让开刘海 / 状态栏 / 底部横条（§4.2）
- [ ] 切页回来棋局还在（§8.5）

**棋盘与棋子**
- [ ] 围棋 19 路、五子棋 15 路、象棋 9×10、国际象棋 8×8，尺寸与配色对得上（§5、§6、§7）
- [ ] 围棋 / 五子棋的星位数量正确（19 路 9 个、15 路 5 个）（§6.1）
- [ ] 象棋有楚河汉界（竖线断开）、两端九宫斜线（§7.1）
- [ ] 国际象棋 a1 是深色、横屏整块转 90°（§6.3）
- [ ] 竖屏手机黑托盘在上、白在下；横屏黑在左、白在右（§6.1、§7.6）
- [ ] 托盘棋子和拖动中的棋子**一样大**（§6.1）
- [ ] 两端牌子：当前方带黄框，字朝那一端的玩家（180° / ±90°）（§7.5）
- [ ] 整盘棋子的字朝当前该走的一方（§7.4）

**交互**
- [ ] 只有当前该走的一方的托盘能拖；另一方按不动（§8.2）
- [ ] 盘上的子谁都能拖；不该自己走时松手弹回（§8.2）
- [ ] 象棋 / 国际象棋走到对方子上＝吃掉；走到自己子上＝弹回（§8.2）
- [ ] 四种棋都能把子拖出棋盘＝被吃；围棋/五子棋被提的子不回托盘、不换手（§8.2）
- [ ] 拖动中目标点有悬停提示，颜色能区分"能落 / 放不下"（§7.8）
- [ ] 点一下没动不换手（§8.2）

**联机**
- [ ] 服模式启动后显示 `服务中·0`，有客户端接入变 `服务中·1`（§11.4）
- [ ] 客模式填对方地址能连上，显示 `已连接`（§11.4）
- [ ] 一台 iOS、一台 Android 能连起来对下（协议一致，§10）
- [ ] 对端拖动时本机能看见那颗子被拿着走（位置流，§7.7、§11.7）
- [ ] 落子后双方盘面一致；中途加入的客户端能立刻看到当前盘面（缓存推送，§11.2）
- [ ] 关掉服务再立刻开，不会 `Address already in use`（§11.8）
- [ ] 地址框：服/客各记各的、没输入过填本机 IP:8765（§11.5）

**平台**
- [ ] 第一次联机会弹「本地网络」权限，拒绝后界面有提示（§14.2）
- [ ] `ws://` 明文不被 ATS 拦（§14.1）
- [ ] 联机期间屏幕不自动熄灭（§4.7）
- [ ] 日志框能看到和 Android 一致的连接日志（§12）

---

## 16. 附：Android 侧源码索引

实现时对照这些文件（都在 `android/app/src/main/java/com/example/chess/`）：

| 文件 | 看什么 |
|---|---|
| `game/share/protocol/EnvelopeCodec.kt` | 报文编解码（逐字段） |
| `game/share/protocol/MoveEvent.kt` | 五类事件的字段定义 |
| `game/share/protocol/BoardPos.kt` | 1/256 格定点坐标 |
| `game/share/protocol/PieceRef.kt` | 棋子身份约定 |
| `game/share/core/Game.kt` | `Game` 契约、`Gesture`、`DragOverlay` |
| `game/share/stone/BoardGeometry.kt` | 石头棋盘几何 + 星位表 |
| `game/share/stone/StoneGame.kt` | 石头棋规则（含吃子与数量） |
| `game/share/stone/StoneProtocol.kt` | 石头棋盘面 / 坐标编解码 |
| `game/xiangqi/XiangqiGeometry.kt` | 象棋几何（含牌子位置与旋转） |
| `game/xiangqi/XiangqiGame.kt` | 象棋开局与规则 |
| `game/guojixiangqi/IntlChessGeometry.kt` | 国际象棋几何（深浅格、旋转） |
| `game/guojixiangqi/IntlChessGame.kt` | 国际象棋开局与规则 |
| `net/ws/WsSession.kt` | 服务端转发 / 缓存 / 30Hz 合并 / 状态回调 |
| `net/NetAddress.kt` | 本机 IP 探测、地址与端口解析 |
| `log/AppLog.kt` | 日志缓冲与订阅 |
| `MainActivity.kt` | 四角控件接线、权限申请、状态文案 |

界面数值（配色 / 圆角 / 尺寸 / 文案）来自：

- `android/app/src/main/res/layout/activity_main.xml`
- `android/app/src/main/res/values/{strings,themes,dimens}.xml`
- `android/app/src/main/res/drawable/{bg_tab,bg_tab_active,bg_switch_button,bg_log_panel}.xml`

相关文档：[readme.md](../readme.md)、[android.md](../android.md)、[gotcha.md](../gotcha.md)、[todo.md](../todo.md)
