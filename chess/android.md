# Android 工程说明

## 构建

- AGP 9.3.0 + Gradle 9.5（wrapper），`compileSdk`/`targetSdk = 37`，`minSdk = 28`
- 依赖只有四个：`appcompat`、`core-ktx`、`material`、`Java-WebSocket:1.6.0`
- 直接构建即可（`gradle/gradle-daemon-jvm.properties` 里已改成 `toolchainVersion=21`，本机就有，零下载）：

```bash
cd android && ./gradlew :app:assembleDebug
```

  （如果哪天把 `toolchainVersion` 改回 25，就会卡在下载 115 MB 的 JDK 上 —— 见 [gotcha.md](gotcha.md) 第 9 条）

- 只跑测试：把 `:app:assembleDebug` 换成 `:app:testDebugUnitTest`（9 个纯 JVM 测试，秒级）
- 看日志：`adb logcat -s ChessApp:V AndroidRuntime:E`

## 代码结构

```
android/app/src/main/java/com/example/chess/
  MainActivity.kt                 标签栏 + 四页切换 + 重置 + 联机条 + 日志框
  game/
    share/protocol/               跨棋种的「信封」：GameKind / BoardPos / PieceRef / MoveEvent / EnvelopeCodec
    share/core/                   Game 契约、Gesture、DragOverlay、BoardSnapshot、MoveEventSink、LocalSession
    share/stone/                  围棋 + 五子棋共用：StoneGame / StoneProtocol / StoneBoardView / BoardGeometry
    xiangqi/                      XiangqiGame / XiangqiProtocol / XiangqiBoardView / XiangqiGeometry
    guojixiangqi/                 IntlChessGame / IntlChessProtocol / IntlChessBoardView / IntlChessGeometry
    weiqi/GoBoardView.kt          19 路的薄子类
    wuziqi/GomokuBoardView.kt     15 路的薄子类
  net/
    Session.kt                    联机接口（send / listen / close）
    NetAddress.kt                 本机局域网 IP、地址与端口解析
    ws/WsSession.kt               WebSocket 房间：服务端 + 客户端二合一
  log/AppLog.kt                   特殊日志缓冲（界面日志框 + logcat）
```

每种棋的目录里固定四个文件：**数据/逻辑（`XxxGame`）、协议（`XxxProtocol`）、视图（`XxxBoardView`）、几何（`XxxGeometry`）**。

## 分层约定（改代码前先看这条）

- `XxxGame` / `XxxProtocol` / `XxxGeometry` **不许 import android**，纯 Kotlin → 能直接 JVM 单测
- `XxxBoardView` **只负责画 + 报手势**，不许自己改盘面、不许 import `net/`
- 事件由 `XxxGame` 产生（`onGesture` 先改本地状态，再把要广播的事件返回），`net` 只认 `MoveEvent`
- 依赖方向：`View / MainActivity → game/share/core → game/share/protocol`，`net → game/share/protocol`

## 视图与布局

- 四个页面都是全屏自定义 View，叠在一个黑底 `FrameLayout` 里，靠 `visibility` 切换
- 左上角标签栏、右上角重置、左下角联机条、右下角日志框，都是叠在上层的普通 View；
  用 `setOnApplyWindowInsetsListener` 让开状态栏 / 刘海 / 底部导航栏
- 页面锁自然方向（`screenOrientation="nosensor"`），所以每个页面只需要一套布局
- 棋盘几何：围棋 / 五子棋是 `min(w,h)` 的居中方块；象棋是 9×10 路、格子 = `min(短边/9, 长边/10×0.8)`；
  国际象棋是 `min(w,h)` 的 8×8 方块。横屏（平板）时象棋和国际象棋会把棋盘转 90°

## 权限

| 权限 | 用途 | 备注 |
|---|---|---|
| `INTERNET` | 联机 socket | 普通权限，安装即授予，**不会弹窗** |
| `ACCESS_LOCAL_NETWORK` | Android 16+ 访问局域网 | **运行时权限**，`API >= 36` 才申请；没有它局域网全被拦 |

## 联机实现

- 一个 `WsSession` 管四种棋：报文里带 `game`，收到后按棋种分发给对应页面的 `submitRemote`
- 服务端：接住客户端事件 → 应用到自己盘面 → 转发给**其它**客户端（不回发送者）；
  并缓存每个棋种最后一包全量盘面，新客户端一连上就先推给它
- 客户端：本地事件发给服务端；收到的事件交给自己的 `Game`
- 位置流（`DragMoved`）只留最新一条、按 **30Hz** 发送；发关键事件前先 flush，保证「先动、后落」
- 落子后发**全量盘面**（`BoardChanged`），接收方直接照抄，不做任何规则计算

## 协议（`EnvelopeCodec`）

一行文本、一个 WebSocket text 帧一条：

```
v1|game=xiangqi|seq=12|t=drag_move|side=0|name=车|id=54|x=1280|y=-1152
v1|game=weiqi|seq=13|t=board|board=..b.w..|turn=1|counts=179,180
```

| 类型 | 字段 | 说明 |
|---|---|---|
| `drag_start` | side,name,id,from,x,y | 拿起一颗子 |
| `drag_move` | side,name,id,x,y | 拖动中的实时位置（高频、可丢） |
| `drag_end` | …,committed=0/1 | 松手；1 = 被采纳 |
| `board` | board,turn,counts | 全量盘面（落子/吃子/拖出棋盘/重开之后） |
| `reset` | — | 重开一局（双方各自摆回开局） |

- **坐标**：`BoardPos` = 相对棋盘中心的**棋盘语义坐标**，单位 1/256 格（int，避免浮点）。
  x 沿 file/列、y 沿 rank/行，所以横屏棋盘转 90° 也不影响对端理解。
  象棋 x∈[-4,4]、y∈[-4.5,4.5]；国际象棋 ±3.5；围棋 ±9；五子棋 ±7
- **棋子身份**：`PieceRef{side, name, id}` —— 有名字的用名字（`车`、`Q`），
  `id` 才是唯一标识（有名字的用起点下标，同名的两个车靠它区分；石头没名字，用自增落子号）
- `side`：0 = 先手（象棋红 / 国际象棋白 / 围棋五子棋黑），1 = 后手
- **盘面编码**：象棋 90 字符（`.` 空，红方大写 `R N B A K C P`、黑方小写）；
  国际象棋 64 字符（白方大写 `K Q R B N P`、黑方小写）；围棋/五子棋 `lines²` 字符（`.`/`b`/`w`）

## 加一种新棋

1. 新建 `game/xxx/`，照抄四个文件：`XxxGame`（实现 `Game` 接口）、`XxxProtocol`、`XxxGeometry`、`XxxBoardView`
2. `protocol/GameKind` 里加一个枚举值（`id` 是上线进报文的名字，别随便改）
3. 写盘面编解码和坐标换算（`XxxProtocol`），加个 `XxxGameTest`
4. `MainActivity`：加一个标签、一个页面 View、`routeRemote` 里加一个分支
5. `res/layout/activity_main.xml` 里把新 View 叠进 `FrameLayout`

## 测试

留了 9 个纯 JVM 测试（`app/src/test/...`）：象棋 / 国际象棋 / 石头的盘面逻辑与几何、报文往返、
地址解析、日志缓冲。它们不碰 Android、秒级跑完，`./gradlew :app:testDebugUnitTest` 即可。
按钮调试：Android Studio 里直接跑 `app` 模块；或 `adb install -r app/build/outputs/apk/debug/app-debug.apk`。
