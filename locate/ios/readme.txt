# locate iOS

基于 MapKit 的实时位置共享 App，对应 Android 版的 WebView + Leaflet 架构。

## 架构对比

| | Android | iOS |
|---|---|---|
| 地图 | WebView + Leaflet | MKMapView + SwiftUI Overlay |
| 协议 | WebSocket + HTTP challenge | 完全一致 |
| 坐标 | WGS84→GCJ02（国内） | 同上 |
| 后台 | foreground service | background location |

## 项目结构

```
locate/
├── ContentView.swift          # 根视图：Login or Map
├── locateApp.swift            # @main 入口
├── models/
│   ├── User.swift             # 用户模型
│   ├── ServerMessage.swift    # WebSocket 消息解析
│   └── MapUiState.swift       # UI 状态
├── services/
│   ├── KeychainStorage.swift  # Token 存储
│   ├── WebSocketService.swift # WebSocket 连接
│   ├── AuthService.swift      # HTTP challenge 认证
│   └── LocationManager.swift  # CLLocationManager + GCJ02 转换
├── views/
│   ├── login/
│   │   ├── LoginView.swift
│   │   └── LoginViewModel.swift
│   └── map/
│       ├── MapViewModel.swift       # 主逻辑
│       ├── MapViewRepresentable.swift # UIKit 桥接
│       ├── MapContainerView.swift   # SwiftUI 容器
│       ├── UserAnnotation.swift     # MKAnnotation
│       └── UserAnnotationView.swift # 箭头绘制
├── overlays/
│   ├── CrosshairOverlay.swift    # 十字丝（经度/纬度/海拔三行）
│   ├── ConnectionStatusView.swift # 状态图标
│   └── UserListPanel.swift       # 右上角队友列表 + 左上角本地面板
└── utils/
    ├── Constants.swift           # 常量
    └── Crypto.swift              # PBKDF2 认证
```

## 认证流程

1. POST `/api/challenge` → 获取 `challenge` + `salt`
2. PBKDF2(salt, password, challenge) → `response`
3. WebSocket 发送 `login` 消息
4. 服务器返回 `login_success` + token
5. 后续请求带 token

## 2026-05-17 本次更新总结

### iOS UI 修复

**四角坐标计算**
- `updateCorners` 改用 zoom 参数（来自 `regionDidChangeAnimated`）计算 `latitudeDelta` / `longitudeDelta`，不再依赖 `region.span`

**右上角卡片高度**
- 去掉 `ScrollView`（会撑满屏幕），改用固定高度 `30 + 36×用户数 + 16`
- 位置改为 `VStack + HStack + Spacer` + `.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)`

**左上角/右上角卡片宽度同步**
- 新增 `@State private var userListWidth: CGFloat = 100`
- `UserListPanel` 由 computed 改为外部传入的 `let panelWidth: CGFloat`
- `LocalSettingsPanel` 宽度也绑定到同一 `userListWidth`

**onTapMyLocation 偶尔不跳**
- 之前依赖 `userLocation` state 中转，可能有时延
- 改为直接从 `locationManager.getCurrentPosition()` 取坐标
- fallback 分支加上 WGS84→GCJ02 转换 `gcj02Convert()`

**GPS 定位权限**
- 通过 `INFOPLIST_KEY_NSLocationWhenInUseUsageDescription` 在 Xcode 项目中直接添加
- 启用 `GENERATE_INFOPLIST_FILE = YES`

**本地位置显示**
- `showsUserLocation = false` 关闭系统蓝点
- 新增 `selfLocationAnnotation`（`isSelf=true` 的 `UserAnnotation`）渲染本地金色空心三角

**本地箭头方向**
- 旋转从 `headingRad - .pi/2` 改为 `-headingRad`（和服务器 ↑ 一致）
- 本地空心三角：emoji `△` (U+25B3) + `scaleBy(x: 0.65, y: 1)` 压扁 X 轴变尖
- 服务器箭头：`↑` (U+2191)

**十字星旁三行坐标**
- 中心坐标显示改为：经度 / 纬度 / 海拔（altitude 从 `getCurrentPosition()?.altitude` 获取）
- 字体从 14pt → 10pt，`.offset(y: -60)` 保持在十字丝上方

**设目标按钮**
- 改用 `setTarget(lat: centerLat, lng: centerLng)` 报十字星中心坐标给服务器
- 新增 `MapViewModel.setTarget()` 方法

**左上面板字体/行距**
- "我的位置"/"设目标"文字从 13pt → 11pt
- 左右 padding 从 10 → 6，vertical 保持 6
- `onTapMyTarget` 有 DEBUG log

### Android UI 修复

**十字星旁三行坐标**
- `CrosshairView.onDraw` 改为三行：经度 / 纬度 / 海拔（白底红框）
- `MapView` 接口新增 `updateAltitude(altitude: Double?)`
- `LocationTrackerService.sendUpdate()` 每次 GPS 更新调用 `mapView?.updateAltitude(pos.altitude)`
- 文字抬高 `textY = cy - size - 120f`，不遮挡十字星

**本地空心三角 emoji**
- Android 本地箭头从 Canvas Path 改为 emoji `△` (U+25B3)
- `canvas.scale(0.65f, 1f)` 压扁 X 轴变尖
- 服务器 `↑` 箭头保持原样不变

## 编译

```bash
cd locate/ios
xcodebuild -project locate.xcodeproj -scheme locate -configuration Debug build
```