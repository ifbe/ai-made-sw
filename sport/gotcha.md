# 踩过的坑

按「症状 → 原因 → 解决」记，都是真踩过的。

## 1. 屏幕其余部分必须纯黑

**症状**：第一版球场画完，四周没铺底色，屏幕上留着系统窗口的默认灰。

**原因**：自定义 View 只画了 `boardRect` 那一块，`onDraw` 之外没人管。

**解决**：`activity_main.xml` 的根 `FrameLayout` 写 `android:background="@android:color/black"`，
主题里 `android:windowBackground` 也是黑的，三层都黑，才不会漏。

## 2. Kotlin 初始化顺序：基类构造时读到子类的 `null` 属性（**崩过一次**）

**症状**：一进页面就闪退。

```
Caused by: NullPointerException: Attempt to invoke virtual method
  'float ...CourtSpec.getBallStartLong()' on a null object reference
    at CourtView.<init>(CourtView.kt:69)
    at FootballView.<init>(FootballView.kt:29)
```

**原因**：底座把场地参数写成了**子类的抽象属性**：

```kotlin
// 基类
protected abstract val spec: CourtSpec
protected var ballX: Float = spec.ballStartLong   // ← 基类构造时执行
// 子类
override val spec: CourtSpec = CourtSpec(...)     // ← 要等基类构造完才执行
```

Kotlin 的顺序是「基类构造 → 子类构造」，所以基类跑第 69 行时子类的 `spec` 还没赋值，读到 null。

**解决**：改成**抽象函数**（虚调用，基类构造时就能调到子类实现）：

```kotlin
protected abstract fun spec(): CourtSpec
protected var ballX: Float = spec().ballStartLong

// 子类只返回常量，不读任何字段
override fun spec(): CourtSpec = CourtSpec(...)
```

**这条约束要一直守住**：`spec()` / `sportKind()` / `initialPlayers()` 里**不能读子类自己的属性**，
那时候它们也还没初始化。`CourtView` 里的颜色常量（`lineColor` 等）也是因为这个，
从 `companion object` 挪成了实例字段并放在最前面。

**为什么之前没发现**：抽底座之后我只做了编译和 JVM 单测，而单测只覆盖 `CourtGeometry` /
`CourtArc` / `AppLog` 这些纯 Kotlin 类 —— 这个坑在**构造函数**里，测试碰不到。教训：
Android View 的构造必须真装上跑一次，或者至少 eyeball 一遍初始化顺序。

## 3. 画弧的「从 A 到 B」有两条路，判反了两个角

**症状**：足球场的四个角球弧里，**左下和右上画成了 270° 的大弧**，左上和右下是对的。

**原因**：判方向用的是「候选弧中点离某个**点**的距离」。角球弧的**圆心就顶在角点上**，
离场地中心很远，两条候选路径的中点离场地中心几乎一样近 → 挑错。

**解决**：
1. 改成比**方向**（中点方向 vs「弧心 → 鼓出方向」的夹角），而不是比距离；
2. 鼓出方向用**向量**而不是点 —— 角球弧想要的方向就是「角点 → 场地中心」这条斜对角，
   弧心本身没法用一个跟它不同的点表示；
3. 抽成纯 Kotlin 的 `CourtArc.angles()`，配 `CourtArcTest` 把四个角钉死。

## 4. 平分时挑错：三分线被画成 478°

**症状**：三分弧绕了整整一大圈。

**原因**：扫 `90°` 和扫 `-270°` 的**中点方向完全一样**，得分都是精确的 1.0，
而旧代码 `score > bestScore` 在平分时保留了先出现的那个。

**解决**：平分时取**扫过角度更小**的那个（`CourtArc` 里的 `TIE_EPSILON` 分支）。

## 5. 半圆没法用「往哪边鼓」判方向

**症状**：罚球圈的两个半圆、合理冲撞区，一开始都画反了。

**原因**：半圆两端正好隔着 180°，两条候选路径的中点方向是**垂直**的 ——
只给一个方向，数学上分不出要哪半个。

**解决**：半圆一律走 `CourtView.drawArc(..., fromX, fromY, sweep)` **明说**扫哪 180°。
另外注意：**半圆两端必须在垂直于「对开方向」的那个轴上** —— 罚球圈是左右对开的，
两端就得放在上下（`(ftl, ±r)`）。我第一版把两端放在左右，结果弧在端线方向完全不动。

## 6. Gradle 工具链：只有这个工程要 JDK 25

**症状**：`./gradlew assD` 会卡在
`Downloading toolchain from URI https://api.foojay.io/...`，要下 115 MB。

**原因**：`gradle-daemon-jvm.properties` 里 `toolchainVersion=25`，而本机
`/Library/Java/JavaVirtualMachines` 只有 8/10/11/17，`~/.gradle/jdks` 里只有 21。
**别的工程要 17 或 21，所以它们不用下** —— 不是配置不一样，是版本正好都有。

**解决**：把 `toolchainVersion` 改成 **21**（本机已有，零下载）。
AGP 9.4.0 自己只要 JDK 17+（jar 里 6134 个 class 全是版本 61），21 完全够。

**顺带**：把 `org.gradle.java.installations.paths` 写进**工程的** `gradle.properties`
**没用** —— daemon JVM 的解析发生在读工程配置之前。要生效得放全局 `~/.gradle/gradle.properties`。

## 7. `Failed to exec spawn helper`（`./gradlew insD` 装不上）

**症状**：

```
[adb]: Cannot run program ".../platform-tools/adb": Failed to exec spawn helper:
       pid: 7310, exit code: 1, error: 0 (none)
```

**原因**：不是 adb 坏了（`adb version` 手跑正常），是**长期存活的 Gradle daemon 脚下被换了 JDK**。
时间线：daemon 19:17 启动 → 21:43 Android Studio **原地更新了自带的 JBR**（`jspawnhelper`、
`libjli.dylib`、`bin/java` 全被替换）→ 之后 daemon 每次 fork 子进程都失败。
提示里那句 "Spawn helper ran into JDK version mismatch" 说的就是这个。

**解决**：

```bash
./gradlew --stop     # 杀掉老 daemon，下次会起新的
```

Android Studio 自己的进程也一样，**重启 Studio** 即可。
兜底可以用传统 fork 机制绕开 jspawnhelper：

```bash
./gradlew insD -Dorg.gradle.jvmargs=-Djdk.lang.Process.launchMechanism=FORK
```

## 8. Android 16+ 访问局域网要单独申请权限（联机最大的坑）

**症状**：客户端连不上局域网，而同一台手机上 `targetSdk = 35` 的 App 完全正常。

**原因**：Android 16（API 36）起有 **Local Network Protection**：`targetSdk >= 36` 的应用
**必须声明并在运行时申请** `android.permission.ACCESS_LOCAL_NETWORK`，否则访问局域网设备
（主动连出去、被对端连进来都算）会被系统拦掉。本项目 `targetSdk = 37`。

**解决**：`AndroidManifest` 里声明 + `MainActivity.toggleSession()` 里运行时申请
（只在 `Build.VERSION.SDK_INT >= 36` 时才申请，老系统上这个权限不存在，申请会直接返回拒绝）。

## 9. 别用 `nc -vz` 判断服务端是否正常

TCP 三次握手是**内核**用 listen backlog 完成的 —— App 被冻结、甚至根本没在处理连接，
`nc -vz` 照样 `succeeded!`。唯一可信的信号是**应用日志里有没有「收到握手请求 / 客户端接入」**
（`adb logcat -s SportApp`）。

## 10. `Address already in use` 但没别的程序占端口

`Java-WebSocket` 的 `WebSocketServer` 默认不开 `SO_REUSEADDR`，上次连接留下的 `TIME_WAIT`
会让下次启动失败。启动前 `server.isReuseAddr = true`，关闭用 `stop(1000)`。

## 11. `usesCleartextTraffic` 管不到 WebSocket

它只约束**遵守平台策略的 HTTP 栈**（`HttpURLConnection`、OkHttp、WebView）。
裸 socket 自己实现的握手（Java-WebSocket）不受影响。真被明文策略拦住时会**立刻抛异常**，
而不是卡住。

## 12. 正则删代码差点让画面全黑

**症状**：我（AI）用正则清理两个没用到的帮手函数时，正则多吞了一段，
把 `onDraw()` 和 `invalidateIfVisible()` 一起删了。**编得过**，但画面会全黑。

**怎么发现的**：写了个脚本数「每个函数定义的行号与起止、`{}` 是否闭合、有没有异常长的函数」——
发现 `invalidateIfVisible` 占了 100 多行（把 `onDraw` 吞进去了）。

**教训**：批量删代码之后，除了编译和跑测试，**再数一遍结构**（成员数量、括号闭合、函数体长度）。
编译通过不等于东西还在。

## 13. 描述弧的方向时，屏幕角度 ≠ 球场角度

竖屏时长边竖着放，屏幕角度和球场坐标下的角度**差 90°**。写测试时拿屏幕角度直接当球场角度算中点，
会得出完全错误的结论。要么全程在屏幕坐标里算，要么记得换算 —— 别混着用。
