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

### 渲染顺序

1. **Axes + arrows** — 不透明，depth test 开启
2. **Water surface** — 浅蓝 (0.5, 0.7, 1.0)，alpha=1.0（不透明），`GL_POLYGON_OFFSET_FILL` 避免 z-fighting
3. **Water body** — 半透明，depth write 关闭（不写入深度缓冲，只读），`GL_BLEND` 开启

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
| `programArrow` | 重力箭头 + 坐标系轴 |

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

**已知限制**：纯 6 轴（无磁力计）在 pitch > 60° 时 accel 误差无法区分 pitch 和 yaw，导致三轴乱转。加磁力计可解。

## TODO

### 近期

- [ ] **EKF 实现**（`fuse_ekf`）：完整实现 Extended Kalman Filter
  - 状态量：四元数(4) + gyro_bias(3) = 7维
  - 预测步：基于陀螺仪的四元数运动学 + bias 随机游走
  - 校正步：加速度计测量（重力方向）+ 磁力计（yaw 绝对参考）
  - 协方差矩阵传播，状态更新后重归一化
  - 参考：Sebastian Madgwick 的 MAV 项目或 PX4 的 ESKF 实现

- [ ] 磁力计支持：给 mahony6/madgwick 加磁力计 yaw 绝对参考，解决大角度乱转问题

- [ ] 水面 polygon 优化：确保水面边缘与屏幕边缘对齐

### 长期

- [ ] EKF 调参：协方差矩阵 Q/R 的合理取值
- [ ] 性能优化：水面多边形预计算缓存

## 文件结构

```
android/app/src/main/java/com/example/waterinbox/
├── math/
│   ├── BoxMath.kt          # 水面多边形计算 + 所有 fusion 函数 + gravity 向量
│   └── (FusionConfig.kt)   # 已被内联到 BoxMath.kt (FusionConfig/FusionState object)
├── sensor/
│   ├── SensorManager.kt    # 传感器读取 + fusion 选择 + 欧拉角/轴角计算
│   └── SensorData.kt       # 传感器数据结构
├── renderer/
│   └── BoxSpace.kt         # OpenGL ES 3.0 渲染
└── ui/
    └── UISpace.kt          # 调试叠加层
```

## 测试脚本

```
waterinbox/
├── test_madgwick6.py   # Madgwick 迭代收敛测试
└── test_mahony6.py      # Mahony 迭代收敛测试
```

用法：
```bash
python3 test_madgwick6.py [qx] [qy] [qz] [qw] [gx] [gy] [gz] [ax] [ay] [az]
python3 test_mahony6.py  [qx] [qy] [qz] [qw] [gx] [gy] [gz] [ax] [ay] [az]
```

默认：q=(0,0,0,1), gyro=(0,0,0), accel=(0.05, 0.03, 9.78), 100次迭代

输出：最终四元数 + 轴角（方便直观理解旋转方向和大小）

## C 参考代码

- `ahrs.mahony.c` — Mahony 6轴/9轴融合（含 magnetometer 参考实现）
- `ahrs.madgwick.c` — Madgwick 梯度下降
- `libmath.rotation.c` — 基础旋转数学

路径：`/Users/ifbe/Desktop/code/ifbe/42/library/libsoft1/libauto/estimate/ahrs/`

## 历史

### 2026-04-26

**坐标系修复**
- Madgwick ENU/NED 转换：quaternion 用 Hamilton 乘法 `[0, √2/2, √2/2, 0] ⊗ q_enu`，gyro/accel 用 `[gy, gx, -gz]`
- `halfvz` 公式补上负号：-(qw² + qz² - 0.5)，与 C 代码一致
- `fuse_mahony3` 重写为正确 Kotlin 语法（之前是 C 代码直接复制粘贴的混写 bug）

**渲染重构**
- `toNDC` 散乱调用 → 标准 MVP 矩阵管线（World=I, View=z_neg, Proj=ortho）
- `drawDebugLine` 方向向量归一化问题修复
- `boxD = min(W, H) / 2`，箭头尺寸按 boxD 比例缩放
- 坐标系轴 debug 线段加粗（线宽 `0.05f → boxD * 0.025f`）

**水体着色**
- 新增两个独立 shader：`programWaterSurface`（水面）和 `programWater`（水体）
- 水面：polygon 画法，纯色浅蓝 (0.5, 0.7, 1.0)，alpha=1.0，不透明
- 水体：screen quad 按 `n·P` 算深度，lerp 浅蓝→深蓝，`0.97^(depth/10)` 衰减，alpha=0.85，半透明
- 渲染顺序优化：轴→水面→水体，depth write 管控避免 z-fighting
- `precision highp float`（32位浮点）用于水体 shader

**UI**
- 叠加层 `UISpace.kt`（原 `SensorOverlay.kt`）字段重排：dt→gyro组，AccelR→WorldAxis→WaterPoly之间
- 删除了重复的 `AccelR` 行（与最上方 Accel 重复）
- 按钮循环顺序：madgwick → mahony3 → mahony6 → ekf → madgwick

**文件改名**
- `renderer/WaterRenderer.kt` → `renderer/BoxSpace.kt`
- `ui/SensorOverlay.kt` → `ui/UISpace.kt`