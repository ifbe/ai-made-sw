# 踩过的坑

按「症状 → 原因 → 解决」记，都是真踩过的。

## 1. Android 16+ 访问局域网要单独申请权限（本项目最大的坑）

**症状**

- 客户端：`failed to connect to /192.168.x.x(port 8765)`，连不上；而**同一台手机**上另一个 `targetSdk = 35` 的 App 连同一个服务端完全正常
- 服务端：电脑 `nc -vz <手机IP> 8765` **成功**，但发 WebSocket 握手过去永远没有 `101` 回应，手机日志里连「收到握手请求」都不出现

**原因**

Android 16（API 36）起有 **Local Network Protection（本地网络保护）**：`targetSdk >= 36` 的应用
**必须声明并在运行时申请 `android.permission.ACCESS_LOCAL_NETWORK`**，否则访问局域网设备
（主动连出去、被对端连进来都算）会被系统拦掉。本项目 `targetSdk = 37`，那个能通的 App 是 35，
所以一个通一个不通 —— 跟 WebSocket 库、跟网络环境都没关系。

**解决**

```xml
<uses-permission android:name="android.permission.ACCESS_LOCAL_NETWORK" />
```

再加上运行时申请（见 `MainActivity.toggleSession()`）：只在 `Build.VERSION.SDK_INT >= 36` 时才申请，
老系统上这个权限不存在，申请会直接返回拒绝，会把用户卡住。

## 2. `nc -vz` 成功 ≠ App 能处理连接

TCP 三次握手是**内核**用 listen backlog 完成的：只要监听 socket 还在内核里，即使 App 已经被冻结、
甚至根本没在处理连接，`nc -vz` 照样 `succeeded!`。所以「能连上端口」不能证明 App 正常，
唯一可信的信号是**应用日志里有没有「收到握手请求 / 客户端接入」**。

## 3. Java-WebSocket 默认 `reuseAddr = false` → `BindException: Address already in use`

**症状**：关掉服务后立刻再开，报 `Address already in use`，可系统里并没有别的程序听这个端口。

**原因**：之前的连接留下的 `TIME_WAIT` 还没过期，而 `WebSocketServer` 默认不开 `SO_REUSEADDR`。

**解决**：`start()` 之前 `server.isReuseAddr = true`；关闭用 `stop(1000)`（带超时）。

## 4. `usesCleartextTraffic` 管不到 WebSocket

它只约束**遵守平台策略的 HTTP 栈**（`HttpURLConnection`、OkHttp、WebView）。
裸 socket 自己实现的握手（Java-WebSocket）不受影响。真被明文策略拦住时会**立刻抛异常**
（`UnknownServiceException: CLEARTEXT communication ... not permitted`），而不是卡住。
本项目已经加上 `android:usesCleartextTraffic="true"`，只是为了将来换库/加 HTTP 接口。

## 5. `failed to connect to /192.168.5.213(port 8765)` 里的斜杠不是解析错误

那是 Java `InetSocketAddress.toString()` 的格式 `<主机名>/<IP>:<端口>`；我们填的是纯 IP、
没有主机名，所以只剩前导 `/`。地址解析完全正常。

## 6. 屏幕熄灭 / App 进后台 → socket 没人处理

Android 会冻结后台 App（cached app freezer）：内核照旧完成 TCP 握手，但没有任何线程去读数据，
表现和「网络不通」一模一样。现在联机期间用 `FLAG_KEEP_SCREEN_ON` 保持屏幕常亮；
要**息屏也能当服务端**必须上**前台服务 + partial wakelock**（还没做，见 [todo.md](todo.md)）。

## 7. `INTERNET` 权限从来不弹窗

它是安装即授予的普通权限，Android 不会为它弹申请框。所以「没看到联网权限弹窗」是正常的；
反过来，`ACCESS_LOCAL_NETWORK`（第 1 条）是运行时权限，会弹框。

## 8. 手测 WebSocket 服务端的正确姿势

- `nc -vz <ip> <port>`：只测 TCP 通不通（而且如第 2 条所说，不能证明 App 在处理）
- `printf 'GET / HTTP/1.1\r\nHost: …\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' | nc <ip> <port>`
  → 正常应立即返回 `HTTP/1.1 101 Switching Protocols` 和 `Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`
- `curl -i --max-time 5 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" http://<ip>:<port>/`
- 浏览器 Console（**必须从 http 页面发起**，https 页面会被当混合内容拦掉）：
  `new WebSocket('ws://<ip>:<port>')`
- **`nc -l <port>` 当服务端是测不出客户端是否正常的**（它不会回 WebSocket 握手，客户端只会一直「连接中」）
- 装不上 `wscat`（npm 超时）可以换镜像：`npm config set registry https://registry.npmmirror.com`

## 9. Gradle：JDK 25 工具链下载被别的进程占锁

`gradle/gradle-daemon-jvm.properties` 要求 `toolchainVersion=25`，本机没有 JDK 25，
Gradle 去 foojay 下载时可能被别的进程（Android Studio）占着锁而失败：

```
Timeout waiting to lock OpenJDK25U-jdk_x64_mac_hotspot_25-any-vendor-25.0.3_9.tar.gz
```

**解决**：直接用 Android Studio 自带的 JBR 25，并关掉自动下载（见 [android.md](android.md) 的构建命令）。

## 10. 别用 ping 延迟猜网络问题

排查过程中曾 Ping 出 65ms（局域网正常 1~5ms），据此怀疑电脑上有 VPN/代理 —— 后来证明是**误导**：
真正的根因是第 1 条的权限。**先看应用日志（`ChessApp` tag / 右下角日志框），再谈网络。**
