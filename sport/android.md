# Android 工程说明

## 构建

- AGP **9.4.0** + Gradle **9.6.0**（wrapper），`compileSdk` / `targetSdk = 37`，`minSdk = 28`
- 依赖：`appcompat`、`core-ktx`、`material`、`Java-WebSocket:1.6.0`
- `gradle/gradle-daemon-jvm.properties` 里 `toolchainVersion=21`。**原来写的是 25**，但本机
  `/Library/Java/JavaVirtualMachines` 只有 8/10/11/17，25 一个都没有，Gradle 就会去 foojay
  下 115 MB 的 Temurin 25 —— 所以改成了 21（`~/.gradle/jdks` 里已经有现成的）。
  AGP 9.4.0 自己只要 JDK 17+ 就能跑（class 文件版本 61），21 完全够。

```bash
cd android && ./gradlew assD && ./gradlew insD
```

产物：`android/app/build/outputs/apk/debug/app-debug.apk`。
用 Android Studio 直接打开 `android/` 构建也可以。

- 只跑测试：把 `:app:assembleDebug` 换成 `:app:testDebugUnitTest`（纯 JVM，秒级）
- 看日志：`adb logcat -s SportApp:V AndroidRuntime:E`

## 代码结构

```
android/app/src/main/java/com/example/sport/
  MainActivity.kt              四个标签 + 重排 + 联机条 + app 内日志框
  log/AppLog.kt                日志环形缓冲（界面日志框 + logcat）
  net/
    Session.kt                 联机接口（send / listen / close）+ LinkState
    NetAddress.kt              本机局域网 IP、地址与端口解析
    ws/WsSession.kt            WebSocket 房间：服务端 + 客户端二合一
  sport/
    share/protocol/            跨球种的「信封」：SportKind / Coord / PlayerRef / SportEvent / SportCodec
    share/court/               共用底座：
      CourtGeometry.kt         场地 → 屏幕的比例尺与坐标换算（纯 Kotlin）
      CourtSpec.kt             场地尺寸 + 配色（每个项目一个实例）
      CourtArc.kt              画弧时的方向判定（纯 Kotlin）
      PlayerToken.kt           一名球员：号码 + 球场坐标
      CourtView.kt             底色/外框/中线/中圈 + 令牌 + 球 + 拖动 + 收发事件
    football/                  FootballCourt / FootballFormation / FootballView
    basketball/                BasketballCourt / BasketballFormation / BasketballView
```

每种球固定三个文件：**场地数据（`XxxCourt`）、开局站位（`XxxFormation`）、视图（`XxxView`）**。

## 分层约定（改代码前先看这条）

- `CourtGeometry` / `CourtArc` / `CourtSpec` / `PlayerToken` / `protocol/*` / `NetAddress` / `AppLog`
  **不许 import android**，纯 Kotlin → 能直接 JVM 单测
- `XxxView` **只负责画 + 报手势**：不许自己判断规则、不许 import `net/`
- 本地手势 → 事件由 `CourtView.onLocalGesture()` 产出（先改本地状态，再把事件返回），`net` 只认 `SportEvent`
- 依赖方向：`View / MainActivity → share/court → share/protocol`，`net → share/protocol`
- `XxxView` 需要给底座提供场地参数时，**必须实现 `spec()` 函数、只返回常量**（原因见 [gotcha.md](gotcha.md) 第 2 条）

## 球场几何

比例尺照搬象棋棋盘那条规则，把「格子」换成「米」：

```
比例尺 = min( 屏幕短边 / 球场短边 ,  屏幕长边 × 0.8 / 球场长边 )
```

- 屏幕比球场更**细长** → 第一条生效：球场短边铺满屏幕短边；
- 屏幕更**方** → 第二条生效：球场长边最多占屏幕长边的 80%（两端各留 10% 黑带放队牌）。

所以同一个几何接不同项目会自动换挡：足球（长宽比 1.544）在手机上走第一条，
篮球（1.867）在 1080×2400 上走第二条（此时两个方向都留黑边）。

坐标约定：**球场坐标 = 米，原点在球场中心，x 沿长边、y 沿短边**；屏幕方向只决定
长轴映射到哪一维（竖屏竖着、横屏横着），**不做 90° 旋转**（球场转了球门就跑边线上去了）。
上线时再换算成毫米整数（`Coord`）。

## 联机实现

- 一个 `WsSession` 管四种球：报文里带 `sport`，收到后按球种分发给对应页面的 `submitRemote`
- 服务端：接住客户端事件 → 转发给**其它**客户端（不回发送者）；并缓存**每种球**最后一包全量状态，
  新客户端一连上就先推给它
- 客户端：本地事件发给服务端；收到的事件交给自己的 `CourtView`
- 位置流（`DragMoved`）只留最新一条、按 **30Hz** 发送；发关键事件前先 flush，保证「先动、后落」
- 落位后发**全量状态**（`StateChanged`），接收方直接照抄坐标，不做任何计算
- 身份只认 `(side, 号码)`：对端的阵型顺序不必跟本机一样

## 协议（`SportCodec`）

一行文本、一个 WebSocket text 帧一条：

```
v1|sport=football|seq=12|t=drag_move|side=-1|num=0|x=1234|y=-567
v1|sport=football|seq=13|t=state|ball=0,0|p=0:1:-50000:0;0:2:-35000:-22000;1:9:9500:0
```

| 类型 | 字段 | 说明 |
|---|---|---|
| `drag_start` | side,num,x,y | 拿起一个人 / 球（x,y 是原位，接收方用它画影子） |
| `drag_move` | side,num,x,y | 拖动中的实时位置（高频、可丢） |
| `drag_end` | …,committed=0/1 | 松手；1 = 被采纳 |
| `state` | ball,p | 全量状态：球 + 所有人（`side:num:x:y` 用 `;` 连） |
| `reset` | — | 摆回开球站位（双方各自算，不传坐标） |

- **坐标**：`Coord` = 相对球场中心的球场坐标，单位**毫米整数**（足球场 105 米 = 105000，int 装得下）
- **身份**：`PlayerRef{side, number}`；`side` 0 = 主队、1 = 客队、**-1 = 球**
- 不引 JSON 库：手写这套不到 150 行，零依赖，而且**纯 JVM 就能单测**（`org.json` 在单测里是空壳）

## 加一种新球

1. 新建 `sport/xxx/`，写三个文件：`XxxCourt`（场地线真实米数）、`XxxFormation`（站位）、
   `XxxView`（实现 `spec()` / `sportKind()` / `initialPlayers()` / `drawMarkings()`）
2. `protocol/SportKind` 里加一个枚举值（`id` 是上线进报文的名字，别随便改）
3. `MainActivity`：加标签、加页面 View、`Page` 枚举里加一项；`res/layout/activity_main.xml` 里把 View 叠进 `FrameLayout`
4. `CourtView` 一般**不用改** —— 底色、外框、中线、中圈、令牌、球、拖动、收发事件都在底座里

## 测试

`./gradlew :app:testDebugUnitTest`，目前 **7 个测试类、47 个用例**，全部纯 JVM：

| 测试 | 用例 | 盯什么 |
|---|---|---|
| `CourtGeometryTest` | 12 | 比例尺四条分支、坐标往返、任何屏幕尺寸都不溢出 |
| `SportCodecTest` | 11 | 报文往返、脏数据不能崩、身份与坐标精度 |
| `BasketballCourtTest` | 9 | FIBA 尺寸换算（篮筐 1.575、罚球线 5.8、底角 0.9……）、左右半场镜像 |
| `CourtArcTest` | 6 | 角球弧必须是 90°、三分弧必须走大弧、半圆两边分别倒向哪一侧 |
| `AppLogTest` | 4 | 日志环形缓冲与监听通知 |
| `NetAddressTest` | 4 | 地址与端口解析 |
| `ExampleUnitTest` | 1 | 模板自带 |

## 离线编译检查（本机没有完整 Gradle 环境时）

不用起 Gradle 也能验一遍 Kotlin 能不能编、测试能不能过：

- 编译器：`~/.gradle/caches/.../kotlin-compiler-embeddable-2.2.10.jar`
- 纯 Kotlin 部分（`protocol/*` + `net/*` + `log/AppLog.kt`）直接编
- 带 Android 的部分：拿 `$ANDROID_HOME/platforms/android-37.0/android.jar`
  + `~/.gradle/caches/*/transforms/**/classes.jar`（168 个），再按 `res/` 生成一个最小 `R` 桩
- 注意 `androidx.lifecycle` 的 `classes.jar` 可能不在 transforms 里，缺它会报一堆
  `cannot access 'LifecycleOwner'` —— 那是**误报**，不是代码问题
