# 安卓端：目录结构 & 平台特定事项

## 1. 目录树

```
android/
├── app/
│   ├── build.gradle.kts              # minSdk 28 / targetSdk 35 / abiFilters=arm64-v8a
│   │                                 #   jniLibs.srcDir("src/main/ffmpeg/lib") ← FFmpeg 预编译库打包入口
│   ├── proguard-rules.pro            # JNI 入口的 keep 规则
│   └── src/main/
│       ├── AndroidManifest.xml       # 权限、前台服务、configChanges（旋转不重建 Activity）
│       ├── cpp/
│       │   ├── CMakeLists.txt        # 链接预编译 FFmpeg（ffmpeg/lib/<abi>/*.so）
│       │   ├── ffmpeg_utils.cpp      # ★ FFmpeg 侧全部逻辑：建流/写包/CSD/生命周期/录制落盘
│       │   └── pusher_jni.cpp        # ★ JNI 入口：Java ↔ native 的桥；AVIO 回调也在这里
│       ├── ffmpeg/                   # 预编译 FFmpeg（include/ + lib/arm64-v8a/*.so）
│       ├── java/com/example/pusher/
│       │   ├── MainActivity.kt        # ★ 全部 UI 与业务编排（面板、模块卡片、动画、配色、推流流程）
│       │   ├── PusherApplication.kt   # Application：装 CrashHandler
│       │   ├── CrashHandler.kt        # 未捕获异常 → filesDir/last_crash.txt
│       │   ├── PushService.kt         # 前台服务：通知栏"推流中/停止推流" + CPU/WiFi 唤醒锁
│       │   ├── camera/
│       │   │   ├── CameraHelper.kt        # ★ camera2：选尺寸、开会话、预览摆放（所见即所推）
│       │   │   └── PreviewGlRenderer.kt   # GL 直通预览（保留，未启用）
│       │   ├── encoder/
│       │   │   ├── VideoEncoder.kt        # MediaCodec 视频编码（Surface 输入）
│       │   │   ├── AudioEncoder.kt        # MediaCodec AAC 编码
│       │   │   └── EncoderCallback.kt
│       │   ├── audio/AudioCapture.kt      # AudioRecord 采集（可选指定输入设备）
│       │   ├── push/
│       │   │   ├── PusherController.kt    # ★ 会话编排：initPush/teardown、A/V 同步时钟、录制生命周期
│       │   │   ├── JniWrapper.kt          # native 方法声明 + AvioDataListener 接口
│       │   │   ├── LocalRecorder.kt       # 录制：开文件 → 把 fd 交给 native → 收尾
│       │   ├── ui/
│       │   │   ├── PreviewLogView.kt          # 十六进制/文本日志列表（推流/封装/录制/特殊日志共用）
│       │   │   ├── AudioWaveformView.kt       # 波形显示（L 绿 / R 青）
│       │   │   └── AudioWaveformAggregator.kt # 1 秒窗口、200 点 min/max 包络
│       │   └── utils/
│       │       ├── AppLog.kt              # 「app 特殊日志」总线（内存历史 + 镜像 logcat + UI sink）
│       │       ├── RecordPath.kt          # 录制目标解析（MediaStore / File、固定文件名、覆盖）
│       │       ├── HexUtils.kt / TimeUtils.kt
│       └── res/
│           ├── layout/activity_main.xml   # 唯一布局：面板 + 8 个按钮 + 9 个模块卡片 + 遮罩
│           └── drawable/                  # card_bg_plain / module_bg_state / module_bg_failed
```

## 2. 数据流

```
                    ┌──────────── 预览：所见即所推 ────────────┐
 camera2 ──┬─ SurfaceTexture(TextureView) ── HWUI 显示         │
           │        （按实测 buffer transform 反向补偿）        │
           ├─ MediaCodec 输入 Surface ── H.264/H.265 ──┐        │
           └─ (同一 RepeatingRequest)                  │        │
 AudioRecord ── AAC(MediaCodec) ────────────────────────┤        │
                                                        ▼        │
                              JniWrapper.writeVideoFrame / writeAudioFrame
                                                        │
                                              ffmpeg_utils.cpp（libavformat muxer）
                                                        │
                            hooked AVIOContext（捕获 muxer 输出字节）
                                   ├─ java_on_send_callback → 16 字节 → 预览面板
                                   ├─ write(record_fd)      → 本地录制文件
                                   └─ real_avio_ctx         → 网络（RTMP/TCP/SRT，或"关闭"时没有）
```

- 预览与推流方向一致性由 `CameraHelper` 的"实测元数据摆放"保证（见 [gotcha.md](gotcha.md#1-最坑预览画面和收流端方向不一致所见非所推)）。
- A/V 同步：`PusherController` 用同一个 `sessionT0Ms` 作为两路的时间基准。
- 录制：native 直接写 Java 交进来的 fd（`nativeStartRecord/nativeStopRecord`）。

## 3. 线程模型

| 线程 | 干什么 | 注意 |
|---|---|---|
| UI 线程 | 面板/卡片/动画/状态机（`MainActivity`） | 不做耗时活；推流启动/停止都丢给线程池 |
| `cameraHandler()`（进程内共享 HandlerThread） | camera2 全部回调、会话配置 | 相机相关操作都在它上面 |
| `PusherEncode`（单线程池） | 视频帧送 muxer | — |
| `PusherAudioWrite`（单线程池） | 音频帧送 muxer | — |
| `sessionExecutor`（静态单线程） | `initPush` / `teardown` 串行化 | **停止推流必须走它**，否则会和写包线程并发 free |
| FFmpeg 内部线程 | 网络收发 | 通过 `write_mutex` + `WriterGuard` 与写包/关闭互斥 |

**关闭顺序（很重要）**：禁止新写入 → 等所有写者退出（`wait_writers_done`）→ `closePusher()`（写 trailer）→ 收尾录制（`nativeStopRecord` + 清 pending）。

## 4. Android 特定事项

### 权限（`AndroidManifest.xml`）
```xml
CAMERA / RECORD_AUDIO / INTERNET
FOREGROUND_SERVICE + FOREGROUND_SERVICE_CAMERA + FOREGROUND_SERVICE_MICROPHONE   <!-- 14+ 强制 -->
POST_NOTIFICATIONS        <!-- 13+；不给只是看不到通知，不影响推流 -->
WAKE_LOCK                 <!-- 息屏继续推 -->
WRITE_EXTERNAL_STORAGE (maxSdkVersion=29)   <!-- 仅 Android 10- 写公共目录用 -->
```
- 运行时申请分三档：相机+麦克风+网络（决定能否推流）、存储（录制用，拒绝不拦推流）、通知（只影响提示）。
- `<application android:requestLegacyExternalStorage="true">` 只对 Android 10 生效。
- `MainActivity` 声明了 `configChanges="orientation|screenSize|...`：**旋转不重建 Activity**，否则推流会被打断。

### 前台服务
- `PushService`：`startForeground(NOTIFICATION_ID, notification, TYPE_CAMERA|TYPE_MICROPHONE)`；
- `START_NOT_STICKY` + `startForeground` 异常兜底（后台被拉起时会抛）；
- 通知里带"停止推流"按钮（`ACTION_STOP` → 进程内回调 → `stopPushing()`）；停止推流时**必须 `stopService`**；
- 服务里持有 `PARTIAL_WAKE_LOCK` + `WifiLock`（`onDestroy` 释放）。Android 9+ 后台不许访问相机，锁屏继续推**只能靠前台服务**。

### 存储
- 录制目标统一走 `RecordPath`：Android 11+ 用 MediaStore Downloads（`IS_PENDING` 写入期间不可见），10- 用 `File`；
- 固定文件名 = **先删同名再插入**；输出流用 `"w"`（`"wt"` 部分机型不接受）。

### 构建/打包
- `minSdk 28 / targetSdk 35 / compileSdk 35`；只打 `arm64-v8a`；
- FFmpeg 是**预编译 .so**，通过 `sourceSets["main"].jniLibs.srcDir("src/main/ffmpeg/lib")` 打包，CMake 里 `IMPORTED` 链接；
- 构建命令：`./gradlew --offline --console=plain :app:assembleDebug`（离线缓存已就绪）；
- **换 FFmpeg 库之后必须**：`llvm-readelf -d` 看有没有引入新的 `.so` 依赖，并对比新旧导出符号集合。

### FFmpeg 预编译库现状（configure 参数）

> 编译步骤、完整参数、接收端测试命令、以及"本项目具体用了哪些组件"，见 **[ffmpeg.md](ffmpeg.md)**。
```
--enable-protocol='rtmp,rtmpt,rtsp,tcp,file'
--enable-muxer='flv,mp4,mpegts'   --enable-demuxer='flv,mov,mpegts'
--enable-encoder='h264,aac'       --enable-parser='h264,aac'
--enable-mediacodec --enable-jni
```
- 加协议/封装必须回 `~/Desktop/code/github/ffmpeg-build` 重编（`build_tcp.sh` 可直接跑）；
- configure 命令行可以直接从库里挖出来：`strings -a libavutil.so | grep -m1 enable-`。

## 5. 关键常量（改这些就能调行为）

| 位置 | 常量 | 说明 |
|---|---|---|
| `MainActivity` | `COLOR_BUTTON_DEFAULT/OK/FAILED/DISABLED` | 按钮 4 态：`#546E7A` / `#43A047` / `#E53935` / `#9E9E9E` |
| `MainActivity` | `EXPAND_MS=380` / `COLLAPSE_MS=300` | 展开/收起动画时长（+ `OvershootInterpolator(0.55f)`） |
| `MainActivity` | `CAMERA_INDEX_OFF` / `MIC_INDEX_OFF` / `SUBTITLE_INDEX_OFF` / `RECORD_INDEX_*` | 各下拉里"关闭/开启"的下标 |
| `MainActivity` | `FORMAT_INDEX_FLV/FMP4` | 封装下拉顺序（默认 flv） |
| `CameraHelper` | `HINT_90_IS_CLOCKWISE` / `MIRROR_FLIPS_ROTATION` / `PREVIEW_MIRROR_FRONT` | 预览方向标定（**改前先看 gotcha.md**） |
| `CameraHelper` | `USE_GL_PREVIEW` / `PREVIEW_USE_MEASURED_HINT` | GL 直通 / 是否用实测元数据摆放 |
| `ffmpeg_utils.cpp` | `subtitle_track_enabled` | 独立字幕轨开关（当前 false，见 todo.md） |
| `AudioWaveformAggregator` | `WINDOW_MS=1000` / `DEFAULT_POINTS=200` | 波形窗口与点数 |
| `PreviewLogView` | `ROW_TEXT_SIZE_SP=11` / `LOG_HEX_BYTES=16` | 日志行字号、十六进制显示字节数 |

## 6. 日志与排查

**「app 特殊日志」面板**（左下角 📋 按钮）是主要入口，同时镜像到 logcat，tag 列表：

```
AppLog          业务关键事件（会话、参数、状态、错误）
PusherController 推流会话编排
PusherJNI        JNI 调用（写帧/写包）
FFmpegUtils      封装/网络/CSD/录制落盘
CameraHelper     相机、预览几何、元数据
LocalRecorder    录制开文件/收尾
PreviewGl        GL 直通（未启用）
```

排查用关键日志行（照抄进 grep 即可）：
```
[编码尺寸] 相机缓冲=… 编码尺寸=…
预览元数据(第N帧): [...]
预览摆放: 黑框=… 画面盒=… 抵消旋转=…° 镜像=… (实测相机提示=…°)
相机会话就绪: 预览流=… 输出数=…
本次推流: 视频=开/关, 音频=开/关
FFmpeg 支持的输出协议: …
「应用/流名」栏(tcp) = ?tcp_nodelay=1
本地录制: 已交给 native 落盘 fd=…
本地录制已保存: …（x MB）
本次会话统计: 视频帧=… 音频帧=… 封装输出=… KB
```

崩溃排查：`adb logcat -b crash -d`（缓冲是持久的，看末尾）+ NDK 的 `llvm-addr2line`；`CrashHandler` 还会把栈写到 `filesDir/last_crash.txt`。
