# iOS 端设计文档：从零复刻安卓（UI 与逻辑完全一致）

> 目标：iOS 端的**功能、代码分层、UI 布局与交互**与安卓端逐项一致。
> 本文按"先看懂、再动手"的顺序写：平台差异 → 架构对应 → 关键实现 → UI 精确规格 → 里程碑与验收。
> 强烈建议先读 [gotcha.md](gotcha.md)：安卓端踩过的坑，iOS 上有一半会以另一种形式再来一次。

---

## 0. 验收标准（可逐条勾）

- [ ] 面板默认只显示 8 个小按钮（推流 / 本地录制 / 封装 / 视频编码 / 音频编码 / 视频采集 / 字幕 / 音频采集）+ 左下角"📋 特殊日志" + 右下角启停按钮
- [ ] 点按钮 → **从该按钮的矩形形变放大**到居中的 80% 卡片；点 ✕ 或点卡片外 → **缩回对应按钮**
- [ ] 按钮 4 态配色：默认 `#546E7A` / 运行中 `#43A047` / 故障 `#E53935` / 未启用 `#9E9E9E`
- [ ] 摄像头/麦克风选"关闭" → 对应**采集+编码**按钮变灰；字幕选"关闭" → 字幕按钮变灰；协议选"关闭" → 推流按钮变灰
- [ ] 右下角单键状态机：`已停止 → 开启中… → 推流中 → 停止中… → 已停止`
- [ ] 各模块页控件与安卓**一一对应**（见第 7 节清单）
- [ ] 预览画面 = 收流端画面（同向、不拉伸、不裁剪、不旋转），与系统自动旋转开关无关
- [ ] 只推音频 / 只推视频（把另一路选"关闭"）
- [ ] 本地录制：默认开启，落到 `Documents/pusher.mp4`（可在"文件"App 里看到），同名覆盖，停止后弹出"录制已保存"
- [ ] 「app 特殊日志」+ 推流/封装/录制数据预览 + 音频波形（1 秒/200 点）
- [ ] 崩溃落盘（下次启动可查看上一次崩溃栈）

---

## 1. 平台差异（**动手前必须先知道**）

| 主题 | 安卓 | iOS | 影响 |
|---|---|---|---|
| **后台相机** | 前台服务（`camera` 类型）可继续采集 | ❌ **iOS 不允许后台使用相机**（`UIBackgroundModes: audio` 只能保音频） | **"锁屏继续推视频"在 iOS 上做不到**，只能：保音频 / 保持前台。这是平台硬限制，别白费力气 |
| **预览方向** | 相机给预览带 buffer transform、给编码器不带 → 必须自己反向补偿（本项目最坑的点） | ✅ 方向由**你自己按连接设置**：`AVCaptureConnection.videoRotationAngle` 可**分别**设预览与输出 | iOS 简单得多：**两个连接设同一个角度** → 天然"所见即所推" |
| **前置镜像** | 预览被系统镜像、编码器不镜像 → 要手动 `scaleX=-1` | `AVCaptureConnection.isVideoMirrored`（预览默认 true、输出默认 false） | 想和收流端一致 → **两个连接都设 false**（或都 true），别只用默认值 |
| **编码** | MediaCodec（Surface 输入） | VideoToolbox（`VTCompressionSession`，CVPixelBuffer 输入） | CSD 获取方式不同（iOS 从 `CMFormatDescription` 取） |
| **音频** | AudioRecord + MediaCodec AAC | `AVCaptureAudioDataOutput`/AVAudioEngine + `AudioConverterRef` | 采样率/声道处理类似 |
| **公共目录** | `/sdcard/Download`（MediaStore） | App 沙盒 `Documents/`，开 `UIFileSharingEnabled` + `LSSupportsOpeningDocumentsInPlace` 就能在"文件"里看到 | 录制路径文案要改成 iOS 的路径 |
| **权限** | 清单 + 运行时申请 | `NSCameraUsageDescription` / `NSMicrophoneUsageDescription` + `requestAccess` | 文案要写进 Info.plist |
| **前台服务/唤醒锁** | 需要 | ❌ 不需要（也做不到） | iOS 没有对应物 |
| **FFmpeg** | 预编译 `.so` + JNI | 需要为 iOS 编一套 FFmpeg（静态库），用 Objective-C++ 桥接 | **C++ 核心可以 100% 复用**，见第 3 节 |

---

## 2. 架构对应关系（建议目录）

```
ios/pusher/
├── pusherApp.swift / AppDelegate.swift        ← 对应 PusherApplication（装崩溃处理）
├── UI/
│   ├── MainViewController.swift               ← 对应 MainActivity（面板/卡片/动画/状态机/编排）
│   ├── PanelView.swift                        ← 对应 panel_modules（8 个按钮 + 箭头网格 + 320pt 固定宽）
│   ├── ModuleView.swift                       ← 对应 9 个 frame_* 模块卡片（用同一个容器 + 内容注入）
│   ├── PreviewLogView.swift                   ← 对应 ui/PreviewLogView.kt（十六进制/文本日志）
│   ├── AudioWaveformView.swift                ← 对应 ui/AudioWaveformView.kt
│   └── AudioWaveformAggregator.swift          ← 对应 ui/AudioWaveformAggregator.kt（1s/200 点）
├── Capture/
│   ├── CameraHelper.swift                     ← 对应 camera/CameraHelper.kt
│   └── AudioCapture.swift                     ← 对应 audio/AudioCapture.kt
├── Encode/
│   ├── VideoEncoder.swift                     ← 对应 encoder/VideoEncoder.kt（VTCompressionSession）
│   └── AudioEncoder.swift                     ← 对应 encoder/AudioEncoder.kt（AudioConverter）
├── Push/
│   ├── PusherController.swift                 ← 对应 push/PusherController.kt（会话编排、A/V 同步时钟）
│   ├── PusherCore.h / PusherCore.mm           ← ObjC++ 桥（对应 push/JniWrapper.kt + JNI 层）
│   ├── LocalRecorder.swift                    ← 对应 push/LocalRecorder.kt
│   └── RecordPath.swift                       ← 对应 utils/RecordPath.kt
├── Utils/
│   ├── AppLog.swift                           ← 对应 utils/AppLog.kt
│   └── CrashHandler.swift                     ← 对应 CrashHandler.kt
└── Core/                                      ← ★ 与安卓共享的 C++（建议做成静态库）
    ├── ffmpeg_utils.cpp                       ← 直接复用（只有平台无关逻辑）
    └── pusher_core.h                          ← 平台无关的纯 C 接口（见第 3 节）
```

---

## 3. 复用安卓的 C++ 核心（强烈推荐）

安卓的 `cpp/ffmpeg_utils.cpp` 里 **99% 是平台无关的 FFmpeg 逻辑**：建流、写包、CSD（SPS/PPS、`avcC`/`hvcC`）、AAC ASC（`build_aac_asc`）、生命周期/写者保护、录制落盘、字幕样本。**不要重写**。

做法：
1. 抽出 **`pusher_core.h`**（纯 C 接口，不带 JNI）：
   ```c
   int  pc_init(const char* url, const char* protocol, const char* format,
                int vw, int vh, int sample_rate, int channels,
                int fps, int vbitrate, int abitrate, int is_hevc, int enable_subtitle);
   int  pc_write_video(const uint8_t* data, int size, int64_t pts_ms, int is_key, int is_csd);
   int  pc_write_audio(const uint8_t* data, int size, int64_t pts_ms);
   int  pc_close(void);
   void pc_start_record_fd(int fd);
   long long pc_stop_record_fd(void);
   void pc_set_subtitle_text(const char* text);
   const char* pc_last_error(void);
   // 数据/错误回调（由各平台注册）
   void pc_set_callbacks(pc_send_cb, pc_mux_cb, pc_error_cb, void* user);
   ```
2. 安卓侧：`pusher_jni.cpp` 只做 JNI ↔ C 的搬运（现有代码几乎不动）；
3. iOS 侧：`PusherCore.mm` 做 Swift/ObjC ↔ C 的搬运（回调用 block/函数指针）。

FFmpeg 为 iOS 交叉编译：`./configure --target-os=darwin --arch=arm64 --enable-cross-compile --cc="xcrun -sdk iphoneos clang" --enable-static --disable-shared`，**保持和安卓一样的组件集合**（协议 `rtmp,rtmpt,tcp,file`、封装 `flv,mp4,mpegts`、编码 `h264,aac`、`--enable-videotoolbox`），这样两端行为一致。

---

## 4. 采集与编码

### 相机（`CameraHelper.swift`）
```swift
let session = AVCaptureSession()
session.sessionPreset = .inputPriority           // 我们要自己选 1920x1080，别用 .high
// 1) 设备：默认/后置/前置（下拉前两项映射 builtInWideAngleCamera back，第三项 front）
let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position)
// 2) 输出：AVCaptureVideoDataOutput（给 VideoToolbox 用）
//    videoSettings = [kCVPixelBufferPixelFormatTypeKey: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange]
// 3) 预览：AVCaptureVideoPreviewLayer（挂在模块页的预览容器上）
// 4) 分辨率：从 device.activeFormat 里挑 16:9（1920x1080/1280x720/…），与安卓下拉一致
```
- **方向与镜像（关键，见第 5 节）**：对**预览连接**和**数据输出连接**都设
  `connection.videoRotationAngle = <当前界面方向对应的角度>`（iOS 17+；低版本用 `videoOrientation`）
  和 `connection.isVideoMirrored = false`。
- 设备切换/分辨率切换要在 `session.beginConfiguration()/commitConfiguration()` 里做。

### 视频编码（`VideoEncoder.swift`）
- `VTCompressionSessionCreate(...)`：`kVTCompressionPropertyKey_RealTime = true`、`ProfileLevel = H264HighAutoLevel`（或 HEVC）、`AverageBitRate`、`MaxKeyFrameIntervalDuration`（≈2s，和安卓一致）；
- 输入 `CVPixelBuffer`（来自 `AVCaptureVideoDataOutput`）；
- 输出 `CMSampleBuffer`：关键帧标志、PTS（用 `CMSampleBufferGetPresentationTimeStamp` → ms）；
- **CSD**：从第一帧的 `CMVideoFormatDescription` 取（H.264：`CMVideoFormatDescriptionGetH264ParameterSetAtIndex`；HEVC：`…HEVCParameterSetAtIndex`），拼成 `avcC`/`hvcC` 后作为 `is_csd=1` 交给 core（安卓就是这么做的，见 `process_csd_data`）。

### 音频（`AudioCapture.swift` + `AudioEncoder.swift`）
- 采集：`AVCaptureAudioDataOutput`（PCM `CMSampleBuffer`）或 `AVAudioEngine`；可选设备用 `AVAudioSession.availableInputs` 对应安卓的"内置/外接/默认"；
- 编码：`AudioConverterRef`（AAC-LC，采样率/声道来自模块页参数，默认 44100 / 单声道 / 128kbps）；
- **ASC**：core 里已有 `build_aac_asc()`，直接复用；
- PTS：**用累计采样数**算（`samples*1000/sampleRate`），不要用"帧序号×当前块长度"（安卓踩过漂移的坑）。

### A/V 同步（与安卓同一套逻辑）
- 会话开始记 `t0 = CACurrentMediaTime()`；
- 每路记"**首包到达时刻**"和"首包原始 PTS"，之后
  `PTS = (首包到达 − t0) + (本包PTS − 首包原始PTS)`；
- 两路共用同一个 `t0`。

---

## 5. 【关键】"预览 = 推流"在 iOS 上怎么做

安卓靠"读 buffer transform 元数据再反向补偿"，iOS **不需要**，因为它把方向交给你：

1. 监听界面方向（`viewWillTransition(to:)` 或 `UIWindowScene.interfaceOrientation`）；
2. 算出目标角度（竖屏 → 90 / 横屏左右 → 0 / 180，按你的设备自然方向）；
3. **对两个连接设同一个角度**：
   ```swift
   previewConnection.videoRotationAngle = angle          // 预览
   videoDataConnection.videoRotationAngle = angle        // 送编码器的那路
   ```
   这样相机交付给编码器的 CVPixelBuffer **本身已经是正的**，预览也是正的 → 收流端收到的就是正的、且与预览逐像素同向。
4. **前置相机**：两个连接的 `isVideoMirrored` 必须设成**同一个值**（建议都 `false`，即"不镜像"，这样和收流端一致；安卓端的结论也是"不要额外镜像"）。
5. 如果产品后续要求"预览显示原始方向（横屏数据、竖屏看着是躺的）"，那就是**两边都不设角度**（= raw）——但**两个连接必须一致**，这是本项目的核心不变量。
6. 角度变化时**不需要**重建 `AVCaptureSession`（只改连接属性，在 `beginConfiguration/commitConfiguration` 里改），所以转屏不会卡推流。

> 验收方式：竖屏/左横/右横各看一次，屏上画面与收流端（VLC/ffplay）必须同向、不拉伸。

---

## 6. 推流 / 封装 / 录制

- **协议**：能力驱动下拉（core 暴露 `avio_enum_protocols` 的结果）→ 自动显示 `RTMP / (SRT) / TCP / 关闭`；
- **协议 × 封装**的兼容提示、**"应用/流名"栏在非 RTMP 时当参数栏**（TCP 默认自动填 `?tcp_nodelay=1`）——与安卓一致；
- **协议=关闭**：URL 传空串 → core 跳过 `avio_open2`，字节只写给录制 fd（"只录文件不推流"）；
- **本地录制**（与安卓同一套机制）：
  1. `RecordPath` 在 `Documents/pusher.<ext>` 建文件（默认名字 `pusher`，扩展名按封装：flv/mp4/ts，**同名覆盖**）；
  2. 打开 `FileHandle`/`OutputStream` → 取 `fileDescriptor` → `pc_start_record_fd(fd)`；
  3. 停止推流：`pc_close()`（写 trailer）→ `pc_stop_record_fd()` 返回字节数 → 关闭文件并弹"录制已保存: …（x MB）"；
  4. 在 Info.plist 打开 `UIFileSharingEnabled` / `LSSupportsOpeningDocumentsInPlace`，用户能在"文件"App 里看到。

---

## 7. UI 精确规格（照抄即可一致）

### 7.1 面板（`PanelView`）
- 面板区域：**正方形**，边长 = `min(屏宽, 屏高)`，居中；内部内容**固定宽 320pt**；
- 8 个按钮按流水线排布（列宽等分，箭头是 `↑` 文本旋转）：

```
 Row1      [☁ 推流]                      [💾 本地录制]          ← 2 列
 Row1.5        ↖(-45°)                      ↗(+45°)
 Row2                  [📦 封装]                                ← 1 列居中
 Row2.5        ↗(+45°)         ↑          ↖(-45°)              ← 3 列
 Row3      [🎬 视频编码]       (空)        [🎵 音频编码]          ← 3 列
 Row3.5        ↑               ↑              ↑
 Row4      [📷 视频采集]     [💬 字幕]     [🎙 音频采集]          ← 3 列
```
- 按钮：`minHeight 56pt`；两列那行 `paddingHorizontal 18pt` / 字号 `16pt`；三列的行 `paddingHorizontal 6pt` / 字号 `14pt`；
  文字颜色白色；圆角与安卓一致（用同一套圆角半径，建议 4–6pt）；`margin 3pt`；
- 左下角：`📋 特殊日志`（`bottom|start`）；右下角：启停按钮（`bottom|end`，文案见状态机）。

### 7.2 展开卡片（`ModuleView` 容器）
- 尺寸：屏的 **80%**（宽高各自 80%），居中；
- 背景：白色圆角卡片（对应 `card_bg_plain`）；模块根容器加 1pt 状态边框（对应 `module_bg_state`：正常绿 / 未启用灰；失败用 2pt 红边框 `module_bg_failed`）；
- 右上角关闭按钮：**48×48pt**，`✕` 字号 **22pt 加粗**，背景 `#CC000000`，距边 8pt；
- 内容内边距 10pt；标题 16pt 加粗（带 emoji，见按钮文案减掉箭头）；
- 每行配置项：左侧标签列**固定 80pt**、字号 14pt；输入控件占剩余宽度、**`wrap_content` 高度** + `minHeight=0`（不然会裁字/塌成 0 高度，安卓踩过）；
- 预览/日志列表区域：占剩余高度，**最小 60pt**。

### 7.3 动画（与安卓同一套参数）
| 动作 | 参数 |
|---|---|
| 展开 | 从**被点按钮的矩形**形变到卡片矩形：`scale = 按钮尺寸/卡片尺寸`、`translation = 按钮位置−卡片位置`，**锚点在左上角**；时长 **380ms**，缓动 `Overshoot(0.55)` |
| 收起 | 反向：卡片矩形 → 对应按钮矩形；时长 **300ms**，`Accelerate`；先把按钮面板显示出来，让"落到按钮上"可见 |
| 遮罩 | 只在遮罩的**背景色 alpha** 上做 0→1（展开）/1→0（收起），**卡片本身不要一起淡**，否则形变看不出来；遮罩色 `#99000000` |

### 7.4 4 态配色与灰化规则
| 状态 | 颜色 | 触发 |
|---|---|---|
| 默认（未开始） | `#546E7A` | 初始/已停止 |
| 运行中 | `#43A047` | 开始推流后该路启用 |
| 故障 | `#E53935` | 该环节失败（如 RTMP 连接失败）；**要持久**，直到下一次开始/停止 |
| 未启用 | `#9E9E9E` | 摄像头/麦克风选"关闭" → 对应**采集+编码**；字幕选"关闭" → 字幕；协议选"关闭" → 推流；录制选"关闭" → 本地录制 |

### 7.5 各模块页控件（必须一一对应）

| 模块 | 控件（顺序与默认值） |
|---|---|
| 📡 推流 | 协议（能力下拉 + `关闭`）→ 服务器 → 端口（默认 1935）→ 应用/流名（非 RTMP 时标签变"参数:"，TCP 默认 `?tcp_nodelay=1`）→ 推流数据预览 |
| 💾 本地录制 | 启用（**开启**/关闭）→ 文件路径（默认 `pusher.flv`，切封装自动改后缀）→ 录制数据预览（`write: byte=<真实长度> data=<≤16 字节 HEX>`） |
| 📦 封装 | 格式（`flv（都支持）` / `fMP4（只支持 tcp）` / `mpegts（只支持 tcp）`，默认 flv，**不随协议变**）→ 封装数据预览 |
| 🎬 视频编码 | 编码器（H.264/H.265）→ 码率（默认 2500 kbps）→ 帧率（默认 30） |
| 🎵 音频编码 | 编码器（AAC）→ 码率（默认 128）→ 采样率（默认 44100，允许填 44.1）→ 声道（单声道/立体声） |
| 📷 视频采集 | 摄像头（默认设备/后置/前置/关闭）→ 分辨率（1920x1080/1280x720/854x480/640x360/480x270）→ 视频预览（预览层） |
| 🎙 音频采集 | 麦克风（默认设备/内置/外接/关闭）→ 实时波形（1 秒窗口 / 200 点 / L 绿 + R 青） |
| 💬 字幕 | 来源（固定文字/ASR/关闭，默认关闭）→ 固定文字输入框（仅"固定文字"可编辑）→ 说明文字 |
| 📋 特殊日志 | 日志列表（最多 200 条，`[mm:ss.SSS] 文本`，行字号 11pt） |

### 7.6 启停按钮状态机
```
已停止 --点--> 开启中… --相机+编码就绪--> 推流中 --点--> 停止中… --拆完--> 已停止
```
- 只有一个按钮（右下角），文案/颜色随状态变；
- 通知栏"停止推流"在 iOS 上不需要（没有前台服务），但**录制收尾**的逻辑要走同一条路径（先 `pc_close` 再关文件）。

---

## 8. 分阶段实施（每阶段都有可验收产出）

| 里程碑 | 内容 | 验收 |
|---|---|---|
| **M1** | Xcode 工程 + `PanelView` + 9 个模块卡片 + 展开/收起动画 + 4 态配色 + 状态机（**全部假数据**） | 第 0 节 UI 相关条目全勾；和安卓截图逐屏对比 |
| **M2** | `CameraHelper` + 预览 + 方向/镜像（第 5 节） | 竖屏/左横/右横：预览与收流端同向；切换分辨率/前后摄不崩 |
| **M3** | `VideoEncoder` + `AudioEncoder` + `PusherCore`（复用 C++）+ RTMP 推流 | 收流端能播，音画同步（±50ms） |
| **M4** | TCP/fMP4 推流 + 协议/封装联动 + "关闭=只录文件" | 与安卓同样的组合矩阵都能跑（RTMP+FLV、TCP+fMP4、TCP+mpegts） |
| **M5** | 本地录制（fd 方案）+ 路径/覆盖 + "录制已保存"提示 | 文件出现在"文件"App，VLC 能播，同名覆盖 |
| **M6** | 日志面板 / 数据预览 / 波形 / 灰化规则 / 崩溃落盘 | 第 0 节全部条目勾完 |
| **M7** | 与安卓逐项对照走查（含边界：只音频、只视频、摄像头关闭、麦克风关闭、协议关闭、录制关闭） | 两个端行为一致；差异要么修掉要么写进文档 |

---

## 9. 风险与注意

1. **字幕**：iOS 端同样会遇到"独立文本轨在 fMP4 分片下崩 movenc"的问题（因为是同一份 FFmpeg）→ 先按 [todo.md](todo.md) 选方案，**两个端一起定**，别各做一套。
2. **后台推流**：iOS 上相机后台不可用 → 产品预期要改（要么前台，要么只推音频）。**不要**试图用 `UIBackgroundModes: audio` 保相机，会被系统直接中断。
3. **FFmpeg 许可**：App Store 分发要注意 LGPL/GPL（本项目当前用的是 LGPL 组件，动态/静态链接方式与合规声明要确认）。
4. **H.265**：iOS 硬件编码支持良好，但收流端兼容性差；默认 H.264。
5. **热/功耗**：长时间 1080p30 推流会发热降频，两端都要看帧率与丢帧统计（可以复用"本次会话统计"这类日志）。
6. **共享 C++ 的构建**：安卓用 CMake，iOS 用 Xcode/静态库；**接口一旦抽成 `pusher_core.h`，两边都不要再往里塞平台代码**，否则一致性会慢慢跑偏。
7. **UI 一致性维护**：所有数值（颜色/字号/边距/时长）建议在两端各集中到一个常量文件，本文档第 7 节就是那个常量表；改动时同步更新本文档。
