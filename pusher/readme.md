# pusher

Android 直播推流 App（iOS 端见 [ios.md](ios.md)）。

链路：**相机采集 → 硬件编码 → FFmpeg 封装 → 推流 / 落盘**。
界面是一个"流水线模块面板"：默认只显示一排小按钮（对应推流链路的各个环节），点任意一个展开该环节的设置卡片。

## 功能

- **推流**：RTMP(FLV) / TCP 裸流 / SRT（需重编 FFmpeg，见 [todo.md](todo.md)）/ **关闭**（不推流，只把封装写成本地文件）
- **封装**：flv / fMP4(mp4) / mpegts（RTMP 只能配 flv，选错会提示但不拦）
- **视频**：H.264 / H.265，分辨率 1920x1080 起可调，默认 2500kbps / 30fps
- **音频**：AAC，采样率支持 kHz（44.1）或 Hz（44100）两种填法，默认 128kbps，单/立体声
  - 摄像头/麦克风下拉**第一个是"默认设备"、最后一个是"关闭"** → 可实现只推音频 / 只推视频
- **本地录制**：把推流那份字节**旁路**写成本地文件（默认 `/sdcard/Download/pusher.flv|mp4`，同名覆盖，可开关）
- **预览**：**所见即所推** —— 屏上显示的画面和接收端逐像素同向（不拉伸、不裁剪、不旋转），且与系统自动旋转开关无关
- **UI**：模块面板 + 展开/收起"矩形形变"动画 + 按钮 4 态配色（默认蓝灰 / 运行中绿 / 故障红 / 未启用灰）
- **诊断**：app 特殊日志面板、推流/封装/录制数据预览（16 字节十六进制 + 真实长度）、实时音频波形（1 秒窗口）、崩溃落盘
- **后台**：前台服务 + CPU/WiFi 唤醒锁，**锁屏/回桌面继续推**；通知栏常驻"推流中 + 停止推流"

## 构建

```bash
cd android
./gradlew --offline --console=plain :app:assembleDebug
# 产物：android/app/build/outputs/apk/debug/app-debug.apk
```

- `minSdk 28 / targetSdk 35`，目前**只打 arm64-v8a**
- FFmpeg 是**预编译库**：`android/app/src/main/ffmpeg/lib/arm64-v8a/*.so`
  （源码/构建工程在 `~/Desktop/code/github/ffmpeg-build`，configure 参数见 [android.md](android.md)）
- 离线构建依赖已缓存（`--offline` 可直接用）

## 文档

| 文件 | 内容 |
|---|---|
| [android.md](android.md) | 安卓目录结构、各模块职责、平台特定事项 |
| [ffmpeg.md](ffmpeg.md) | FFmpeg 怎么编（完整参数）、接收端测试命令、本项目用了哪些组件 |
| [gotcha.md](gotcha.md) | 过程中踩过的坑（含真机原生崩溃的定位方法） |
| [todo.md](todo.md) | 还没做完的 |
| [ios.md](ios.md) | iOS 端复刻设计（代码逻辑与 UI 与安卓完全一致） |
