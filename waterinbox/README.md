# Waterinbox

把手机想象成一个装了一半水的密封盒子，屏幕是玻璃面。通过手机传感器的实时姿态，渲染出从屏幕这面"透视"进去看到的水面形状。

## 效果

- **屏幕朝上**：水在盒子底部，抬头看到的是水面的俯视图（长方形）
- **屏幕朝下**：水贴在玻璃上，低头看到水面近在眼前（全屏蓝色）
- **倾斜手机**：水面随之倾斜，形状由重力方向和盒子姿态共同决定；总体积不变

无流体模拟——水面永远瞬间达到静止状态（重力方向改变 → 水面立刻水平）。

## 项目结构

```
waterinbox/
├── android/                    # Android 版（Kotlin + OpenGL ES 3.0）
│   └── app/src/main/java/com/example/waterinbox/
│       ├── math/
│       │   └── BoxMath.kt      # 水面多边形计算 + fusion 函数 + gravity 向量
│       ├── sensor/
│       │   └── SensorManager.kt # 传感器读取 + 欧拉角/轴角计算
│       ├── renderer/
│       │   └── BoxSpace.kt      # OpenGL ES 3.0 渲染（箭头/木筏/水面/水体）
│       ├── socket/
│       │   └── SocketManager.kt # UDP 发送
│       └── ui/
│           └── UISpace.kt      # 四按钮四面板 UI（调用 getBoatVertices 显示 8 点坐标）
└── ios/                        # iOS 版（Swift + Metal）
    ├── project.yml             # XcodeGen 配置
    ├── waterinbox.xcodeproj/   # 生成的项目
    └── waterinbox/
        ├── waterinboxApp.swift       # App 入口
        ├── ContentView.swift         # 主视图（Metal + UI 叠加）
        ├── Info.plist
        ├── Assets.xcassets/
        ├── metal/
        │   └── MetalRenderer.swift   # Metal 渲染器
        ├── sensor/
        │   └── SensorManager.swift   # iOS 传感器 + CMMotionManager
        ├── math/
        │   ├── BoxMath.swift         # 水面多边形计算
        │   └── FusionAlgorithm.swift # 融合算法（ENU 坐标系）
        ├── socket/
        │   └── SocketManager.swift   # TCP/UDP 通信（Network.framework）
        └── ui/
            └── UISpace.swift         # 四按钮四面板 UI
```

## 核心原理

### 坐标系

**盒子空间（Box Space）**
- x ∈ [-W/2, W/2]，y ∈ [-H/2, H/2]，z ∈ [-D/2, D/2]
- 屏幕在 z = +D/2，中心在 (0, 0, 0)
- boxD = min(W, H) / 2

**视图/投影**
- View: z_view = -z_box（相机在盒子顶部俯视）
- Proj: ortho, x/y/z → [-1, 1] NDC
- World: 单位矩阵
- MVP = P · V · I

### 四元数顺序

内部存储和传递统一用 **[qx, qy, qz, qw]** 顺序（C 惯例，qw 是标量部分）。

### ENU 坐标系（iOS 与 Android 共享）

iOS 和 Android 都使用 ENU 坐标系（不要被 Android 代码中 NED 注释误导——那些注释是错的，实际实现是 ENU）。

**gyro / accel 符号约定：**
```
gx =  gyro.x
gy =  gyro.y
gz =  gyro.z
ax = -accel.x   // 负号使加速度方向与重力相反（anti-gravity）
ay = -accel.y
az = -accel.z
```

### 重力向量（世界 → 机体）

用四元数逆旋把世界重力 (0, 0, -1) 变换到机体坐标：

```
gX =  2*(qy*qw + qz*qx)
gY = -2*(qy*qz + qw*qx)
gZ = -1 + 2*(qx² + qy²)
```

### 水面多边形

1. 水面法线 n = normalize(g_local)（重力方向）
2. 平面方程：dot(n, p) = 0（经过盒子中心）
3. 求平面与盒子 12 条棱的交点 → 交点列表
4. 按角度排序 → 凸多边形
5. 以多边形质心为原点，逐对顶点画显式三角形

## 渲染架构

### iOS Metal vs Android OpenGL ES

| 功能 | iOS (Metal) | Android (OpenGL ES 3.0) |
|------|-------------|------------------------|
| 3D 渲染 | MTKView + MTLRenderPipelineState | GLSurfaceView + GLES30 |
| 顶点格式 | Metal vertex descriptor | glVertexAttribPointer |
| Uniform 传递 | setVertexBytes / setFragmentBytes | glUniformMatrix4fv |
| 深度格式 | depth32Float | GL_DEPTH_COMPONENT24 |

### 渲染开关（UI 可控）

`MetalViewController` 暴露 6 个标志位，由 UI 面板右上角 ◎ 开关控制：

| 标志 | 默认 | 说明 |
|------|------|------|
| `drawWorldAxes` | true | 世界坐标系轴调试射线（红/绿/蓝） |
| `drawGravityArrow` | true | 重力箭头 |
| `drawMagnetArrow` | true | 磁力箭头（0.6x 重力箭头长度） |
| `drawBoat` | true | 木筏 8 点顶点 |
| `drawWaterSurface` | true | 水面 polygon |
| `drawWaterBody` | true | 水下半透明 quad |

### 渲染顺序

1. **重力箭头**（pipelineStateArrow）
2. **磁力箭头**（pipelineStateArrow，0.6x 长度）
3. **木筏**（pipelineStateArrow）
4. **世界坐标轴射线**（pipelineStateArrow）
5. **水面 polygon**（pipelineStateWaterSurface，alpha=0.5）
6. **水下水体**（pipelineStateWater，depth write 关闭）

### 水体深度着色（Water Body Shader）

水面以下的部分，根据垂直深度决定颜色：

```metal
depth = n · P
if (depth <= 0.0) discard_fragment();
factor = pow(0.98, depth / 10.0)
t = clamp(depth / 30.0, 0.0, 1.0)
color = lerp(浅蓝(0.5, 0.7, 1.0), 深蓝(0.12, 0.35, 0.90), t) * factor
```

## 传感器融合算法

四个可选算法（`FusionConfig.algorithm`），与 Android 完全一致：

| 算法 | 函数 | 说明 |
|------|------|------|
| `madgwick` | `fuse_madgwick` | Madgwick 梯度下降校正 |
| `mahony3` | `fuse_mahony3` | 纯陀螺仪积分，无 accel 校正 |
| `mahony6` | `fuse_mahony6` | Mahony PI 校正，末尾调用 fuse_mahony3 |
| `ekf` | `fuse_ekf` | **占位实现**，当前等同于 gyro-only 积分 |

当前默认：`mahony6`

默认参数：
- Madgwick beta = 0.5
- Mahony Kp = 1.0, Ki = 0.0（integral windup 禁用）

## UI 面板布局

四按钮四面板结构（与 Android 完全一致）：

| 位置 | 按钮 | 展开内容 |
|------|------|---------|
| 左上 | ▼ | 传感器数据：dt / Gyro / Accel / Mag / gyroCorr / accelCorr / magCorr / **qFused** / **qFixed** / Euler / AxisA / WrdX / WrdY / WrdZ / Grav / 8个船角顶点 / 水面多边形点 |
| 右上 | ▼ | 渲染开关（◎）：坐标轴 / 重力箭头 / 磁力箭头 / 小船 / 水面 / 水体 — 展开在按钮左侧 |
| 左下 | ▲ | MH3/MH6/MDW/EKF 切换 + YAW:none/mag 切换 + kp/ki/beta 参数面板 — 展开在按钮上方 |
| 右下 | 已连接/未连接 + ▲ | IP/端口/协议/内容 选择器 — 展开在按钮上方 |

点击算法按钮循环切换融合算法；点击 YAW 按钮循环切换 yaw 修正模式（none ↔ mag）。

## Socket 通信

TCP/UDP 可选（`SocketManager.protocol_`）：

| contentType | 格式 | 说明 |
|-------------|------|------|
| `quaternion` | `qx,qy,qz,qw` | 四元数 |
| `measure` | `gx,gy,gz,ax,ay,az,mx,my,mz,ms` | 传感器原始值 |

iOS 使用 Network.framework（NWConnection）实现。

## TODO

### iOS 近期

- [ ] IOS的accel不带重力？

### Android 近期

- [ ] **EKF 实现**（`fuse_ekf`）：完整实现 Extended Kalman Filter
  - 状态量：四元数(4) + gyro_bias(3) = 7维
  - 预测步：基于陀螺仪的四元数运动学 + bias 随机游走
  - 校正步：加速度计测量（重力方向）+ 磁力计（yaw 绝对参考）
  - 协方差矩阵传播，状态更新后重归一化
  - 参考：Sebastian Madgwick 的 MAV 项目或 PX4 的 ESKF 实现
