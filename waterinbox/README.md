# Waterinbox

把手机想象成一个装了一半水的密封盒子，屏幕是玻璃面。通过手机传感器的实时姿态，渲染出从屏幕这面"透视"进去看到的水面形状。

## 效果

- **屏幕朝上**：水在盒子底部，抬头看到的是水面的俯视图（长方形）
- **屏幕朝下**：水贴在玻璃上，低头看到水面近在眼前（全屏蓝色）
- **倾斜手机**：水面随之倾斜，形状由重力方向和盒子姿态共同决定；总体积不变

无流体模拟——水面永远瞬间达到静止状态（重力方向改变 → 水面立刻水平）。

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

### ENU / NED 坐标系转换

Android 传感器输出 ENU 坐标系，Madgwick/Mahony C 代码使用 NED 坐标系，需要转换：

**gyro / accel ENU → NED（Body 轴映射）：**
```
gx_ned =  gy_enu
gy_ned =  gx_enu
gz_ned = -gz_enu
ax_ned =  ay_enu
ay_ned =  ax_enu
az_ned = -az_enu
```

**quaternion ENU → NED（Hamilton 乘法）：**
```
Q_ENU_TO_NED = [0, √2/2, √2/2, 0]   // [w, x, y, z]
q_ned = Q_ENU_TO_NED ⊗ q_enu
```

**quaternion NED → ENU：**
```
Q_NED_TO_ENU = [0, -√2/2, -√2/2, 0]
q_enu = Q_NED_TO_ENU ⊗ q_ned
```

### 四元数输出（quatFused / quatFixed）

融合输出 `quatFused` 经过 yaw 修正后得到 `quatFixed`，两者都在 UI 面板上实时显示：

| 字段 | 来源 | 说明 |
|------|------|------|
| `quatFused` | Mahony3/6 / Madgwick / EKF | 融合后的四元数 |
| `quatFixed` | `fixYaw(quatFused)` | yaw 修正后的四元数（用于渲染和 Socket） |

yaw 修正算法（`FusionConfig.yawAlgorithm`）：
- `none` — 不修正
- `mag` — 磁力计 yaw 修正

---

### 重力向量（世界 → 机体）

用四元数逆旋把世界重力 (0, 0, -1) 变换到机体坐标：

```
gX =  2*(qy*qw + qz*qx)
gY =  2*(qz*qy - qx*qw)
gZ = -(qw² + qz² - qx² - qy²)
```

### 水面多边形

1. 水面法线 n = normalize(g_local)（重力方向）
2. 平面方程：dot(n, p) = 0（经过盒子中心）
3. 求平面与盒子 12 条棱的交点 → 交点列表
4. 投影到水面 2D 平面，按角度排序 → 凸多边形
5. 以多边形质心为原点，逐对顶点画显式三角形

## 渲染架构

### 渲染开关（UI 可控）

`BoxSpace` 暴露 6 个 `@Volatile var` 标志位，由 UI 面板右上角 ◎ 开关控制：

| 标志 | 默认 | 说明 |
|------|------|------|
| `drawWorldAxes` | true | 世界坐标系轴调试射线（红/绿/蓝） |
| `drawGravityArrow` | true | 重力箭头（绿色 shaft + 红色 cone） |
| `drawMagnetArrow` | true | 磁力箭头（短箭头，0.6x 重力箭头长度） |
| `drawBoat` | true | 木筏 8 点顶点 |
| `drawWaterSurface` | true | 水面 polygon |
| `drawWaterBody` | true | 水下半透明 quad |

### 渲染顺序

1. **重力箭头**（programArrow，drawGravityArrow 控制）
2. **磁力箭头**（programArrow，drawMagnetArrow 控制，0.6x 长度）
3. **木筏**（programArrow，drawBoat 控制）
4. **世界坐标轴射线**（programArrow，drawWorldAxes 控制）
5. **水面 polygon**（programWaterSurface，drawWaterSurface 控制，alpha=1.0 不透明，`GL_POLYGON_OFFSET_FILL` 避免 z-fighting）
6. **水下水体**（programWater，drawWaterBody 控制，depth write 关闭）

### 水体深度着色（Water Body Shader）

水面以下的部分，根据垂直深度决定颜色：

```
depth = n · P   // n̂ = 重力方向（归一化），P = 像素 box space 位置
n · P ≤ 0  → 水上 discard
n · P > 0  → 水下，depth = n · P
factor = 0.97^(depth / 10)
t = clamp(depth / 30, 0, 1)   // maxDepth = 30（盒子对角线半长）
color = lerp(浅蓝, 深蓝, t) * factor
alpha = 0.85
```

- 水面附近（depth≈0）：浅蓝 (0.5, 0.7, 1.0)
- 水底（depth=maxDepth）：深蓝 (0.12, 0.35, 0.90)
- 越深 factor 越小（水越暗）

### Shader 程序

| 程序 | 用途 |
|------|------|
| `programWaterSurface` | 水面 polygon，纯色浅蓝不透明 |
| `programWater` | 水体 screen quad，depth-based 深度着色半透明 |
| `programArrow` | 重力箭头 + 木筏 + 坐标系轴（共用同一 shader） |
| `programWaterSurface` | 水面 polygon，纯色浅蓝不透明 |
| `programWater` | 水体 screen quad，depth-based 深度着色半透明 |

### 深度处理

- 所有绘制开启 `GL_DEPTH_TEST`
- 水面不透明，深度写入开启
- 水体半透明，深度写入关闭（depth write = false）避免水体遮挡水面
- `GL_POLYGON_OFFSET_FILL` 用于水面 polygon，避免与坐标系轴的 z-fighting

## 传感器融合算法

四个可选算法（`FusionConfig.algorithm`）：

| 算法 | 函数 | 说明 |
|------|------|------|
| `madgwick` | `fuse_madgwick` | Madgwick 梯度下降校正 |
| `mahony3` | `fuse_mahony3` | 纯陀螺仪积分，无 accel 校正 |
| `mahony6` | `fuse_mahony6` | Mahony PI 校正，末尾调用 fuse_mahony3 |
| `ekf` | `fuse_ekf` | **占位实现**，当前等同于 gyro-only 积分 |

当前默认：`mahony6`

默认参数：
- Madgwick beta = 0.5
- Mahony Kp = 1.0, Ki = 0.0（ integral windup 禁用）


## TODO

### 近期

- [ ] **EKF 实现**（`fuse_ekf`）：完整实现 Extended Kalman Filter
  - 状态量：四元数(4) + gyro_bias(3) = 7维
  - 预测步：基于陀螺仪的四元数运动学 + bias 随机游走
  - 校正步：加速度计测量（重力方向）+ 磁力计（yaw 绝对参考）
  - 协方差矩阵传播，状态更新后重归一化
  - 参考：Sebastian Madgwick 的 MAV 项目或 PX4 的 ESKF 实现


- [ ] 水面 polygon 优化：确保水面边缘与屏幕边缘对齐

### 长期

- [ ] EKF 调参：协方差矩阵 Q/R 的合理取值
- [ ] 性能优化：水面多边形预计算缓存

## UI 面板布局

四按钮四面板结构：

| 位置 | 按钮 | 展开内容 |
|------|------|---------|
| 左上 | ▼ | 传感器数据：dt / Gyro / Accel / Mag / gyroCorr / accelCorr / magCorr / **qFused** / **qFixed** / Euler / AxisA / WrdX / WrdY / WrdZ / Grav / 8个船角顶点 / 水面多边形点 |
| 右上 | ▼ | 渲染开关（◎）：坐标轴 / 重力箭头 / 磁力箭头 / 小船 / 水面 / 水体 — 展开在按钮左侧 |
| 左下 | ▲ | MH3/MH6/MDW/EKF 切换 + YAW:none/mag 切换 + kp/ki/beta 参数面板 — 展开在按钮上方 |
| 右下 | 已连接/未连接 + ▲ | IP/端口/协议/内容 选择器 — 展开在按钮上方 |

点击算法按钮循环切换融合算法；点击 YAW 按钮循环切换 yaw 修正模式（none ↔ mag）。

## 文件结构


android/app/src/main/java/com/example/waterinbox/
├── math/
│   ├── BoxMath.kt          # 水面多边形计算 + 所有 fusion 函数 + gravity 向量
│   └── (FusionConfig.kt)   # 已被内联到 BoxMath.kt (FusionConfig/FusionState object)
├── sensor/
│   └── SensorManager.kt    # 传感器读取 + fusion 选择 + 欧拉角/轴角计算（SensorData 内联在此）
├── renderer/
│   └── BoxSpace.kt         # OpenGL ES 3.0 渲染（箭头、木筏、水面、水体）
│                           # 暴露 6 个 draw flag：`drawWorldAxes / drawGravityArrow / drawMagnetArrow / drawBoat / drawWaterSurface / drawWaterBody`
├── socket/
│   └── SocketManager.kt   # UDP 发送，non-blocking 队列
└── ui/
    └── UISpace.kt          # 四按钮四面板 UI 叠加层（调用 BoxSpace.getBoatVertices() 显示 8 点坐标）
```

## Socket 通信

UDP 发送，contentType 两档：

| contentType | 格式 | 说明 |
|-------------|------|------|
| `quaternion` | `qx,qy,qz,qw` | 四元数 |
| `measure` | `gx,gy,gz,ax,ay,az,mx,my,mz,ms` | 传感器原始值 |

发送队列：`LinkedBlockingQueue<String>(100)`，非阻塞 `offer()` 写入，IO coroutine 轮询 `poll(5ms)` 发送。队列满时丢弃最旧数据，不阻塞传感器线程。


IP/Port 可在 UI 面板中直接编辑（右下角面板）。
