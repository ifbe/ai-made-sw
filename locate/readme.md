# locate · 旅迹（实时队友定位）

把各自手机的 GPS 位置实时共享到同一张地图上：能看到队友在哪、朝哪走，能给队友（和自己）设目标点，点一下飞过去。

一个 Python 服务端 + 三个界面完全一致的客户端（Android / iOS / 网页版），协议互通，可以混着用。

## 子目录

**`server/`** — Python 3 服务端
`server.py` 一个进程同时干三件事：WebSocket 实时通道（广播位置和目标）、HTTP 的 `/api/challenge` 挑战响应认证、把 `static/` 当网页版发出去。默认监听 `9999`。
`secret.py` 是账号管理脚本（`python3 secret.py add 用户名`），账号存在 `passwd.json`。

**`server/static/`** — 网页版客户端（Leaflet）
不用装 App，浏览器打开 `http://<服务器>:9999/` 就能用。界面和安卓/iOS 同一套：准备页结束直接进地图；未登录时地图顶部悬浮 4 行登录矩形（服务器地址/用户名/密码/登录）；登录后左上角「本地」（右上角带「退出登录」）+ 右上角「同服人数」，左下角是可折叠、可拖动改大小的日志矩形。

**`android/`** — 安卓 App（Kotlin + Compose，minSdk 28 / targetSdk 36）
- `ui/login/LoginActivity.kt`：启动准备页（预热加密存储、申请定位权限、最短展示时间），结束后直接进地图
- `ui/map/MapActivity.kt`：地图页，也是唯一的主界面（登录表单是悬浮在地图顶部的矩形，不再是单独一页）
- `ui/map/MapViewImpl.kt`：地图本体是 WebView + Leaflet（`app/src/main/assets/html/map.html`），十字星、日志矩形、左右两个面板都是原生 View 画在 WebView 上层
- `service/LocationTrackerService.kt`：前台服务，持续定位并上报（约 5 秒一次）
- `data/`：认证、WebSocket、加密存储；`util/AppLog.kt`：界面左下角日志用的内存日志缓冲

**`ios/`** — iOS App（SwiftUI + MapKit，iOS 15.6+，`locate.xcodeproj`）
- `views/login/SplashView.swift`：准备页；`views/map/`：地图页（`MapViewRepresentable` 包 MKMapView，`MapContainerView` 拼各层浮层）
- `overlays/`：十字星+中心坐标、左下角日志矩形、左上「本地」和右上「同服人数」面板
- `services/`：WebSocket、认证、定位（含指南针朝向）、Keychain 存储
- `utils/AppLog.swift`：同上的日志缓冲（和安卓行为保持一致）

**`client/`** — 命令行 GPS 客户端 `client.py`
只用 Python 标准库，用来在没有第二台手机时模拟一个在线队友：定时上报坐标，支持 WS/WSS，默认坐标是尼莫点。调试多人在线时很有用。

**`esp32/`** — 预留目录，还没有代码。

## 三端共用的东西

- **认证**：`POST /api/challenge` 拿 `challenge` + `salt` → 用密码算出 `response` → WebSocket 发 `login`，服务器回 `login_success` + `token`
- **消息**：`user_list` / `user_joined` / `user_left` / `update_position` / `update_target` / `force_logout`（同账号在别处登录会把前一个踢下线）
- **坐标**：地图瓦片用的是高德（GCJ-02），手机 GPS 给的是 WGS-84，国内要转一次再画（`wgs84_to_gcj02`，iOS/Android 按当前地区判断）
- **界面**：三端一套 —— 金色 △ 是本地 GPS 的自己，蓝色 ↑ 是服务器上每个人的位置（含自己那份回显），橙色虚线是到目标的连线

## 跑起来

```bash
cd locate/server
python3 secret.py add 用户名        # 加一个账号
python3 server.py                   # 起服务，浏览器开 http://localhost:9999/
```

Android / iOS 里的服务器地址默认是 `https://deepstack.tech:9999`（`Constants.DEFAULT_SERVER_URL`），换自己的服务器改这个常量，或者 App 里登录矩形第一行直接填。
