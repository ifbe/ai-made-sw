# 还没做的

> 按优先级大致排序。每条都写了"现状 → 要做什么 → 注意点"。

## 1. 字幕（当前**已禁用**，功能待重做）

- **现状**：UI（来源：固定文字 / ASR / 关闭）和 native 的 tx3g 写入代码都在，但 `ffmpeg_utils.cpp` 里
  `subtitle_track_enabled = false` —— 独立文本轨在 **fMP4 分片**下必然触发 movenc 的
  `av_assert0(next_dts >= 0)`（`movenc.c:1248`）abort，真机崩过 4 次，详见 [gotcha.md](gotcha.md#6-独立字幕轨在-fmp4-下必崩movenc-断言)。
- **要做**（四选一，取决于收流端是什么播放器）：
  1. **给 FFmpeg 打补丁**：`get_cluster_duration()` 里把负的 `next_dts` 钳成 0 → 重编 `libavformat.so`。
     最省事、保留"独立字幕轨"形态；但负时长说明内部记账确实不一致，必须实测多轮。
  2. **CEA-608 塞进 H.264 SEI**（`user_data_registered_itu_t_t35` + ATSC A53 `cc_data`）：
     **不新增轨道** → 没有分片问题；VLC/mpv 能显示；**ffplay 默认不显示**。需要自己在 Annex-B 码流里插 SEI（含 emulation-prevention 处理）。
  3. **烧进画面**：采集后、编码前把文字画到帧上（需要 GL/合成一层）。任何播放器都能看，但改像素、不可开关、不可多语言。
  4. **旁路通道**：视频照旧推流，字幕走 WebSocket/HTTP，由**自己的接收端**渲染。最稳、零风险。
- **注意**：ASR 作为字幕源也还没接（见第 3 条）；`固定文字` 现在是"每帧一条"的实现，一旦走方案 1 可以直接用。

## 2. SRT 推流

- **现状**：协议下拉是**按 FFmpeg 实际能力生成**的（`nativeGetOutputProtocols()`），所以现在只显示 `RTMP / TCP / 关闭`；
  `协议 × 封装` 联动、SRT/TCP 的 host:port 校验、`应用/流名` 当参数栏，这些都已就绪。
- **要做**：编一份 arm64 的 `libsrt`，再用 `--enable-libsrt --enable-protocol=...,srt` 重编 FFmpeg。
  脚本已经写好：`~/Desktop/code/github/ffmpeg-build/build_tcp_srt.sh`（**注意**：里面的 libsrt 是 `ENABLE_ENCRYPTION=OFF`，
  不带 passphrase 加密；要加密还得先给 Android 编 OpenSSL）。
- **注意**：编完**不用改 App 代码**，协议下拉里会自动出现 SRT（能力驱动的收益）。

## 3. ASR 接入（实时语音识别）

- 字幕源里 `ASR` 目前只打日志"尚未接入"。
- 现成挂点：`PusherController` 的 `onPcmData` 回调已经在喂波形显示，直接复用同一条 PCM 流即可。
- 注意：识别结果是文本 → 走字幕（取决于第 1 条选哪个方案）；时间轴可直接用现有的 `sessionT0Ms` 公共时钟。

## 4. 本地录制与推流容器解耦

- **现状**：录制是"旁路推流那份字节"，所以**录制容器 = 推流容器**（RTMP/FLV → `pusher.flv`，TCP/fMP4 → `pusher.mp4`）。
- **要做**（如果需要"推 FLV 同时录 MP4"）：native 里再起一个独立的 muxer 实例（第二条 AVIO 输出到 fd）。

## 5. 协议 = 关闭（只写文件，不推流）

- 已实现：URL 传空 → native 跳过 `avio_open2`，hook 照样把字节写给录制 fd；`协议=关闭 且 录制=关闭` 会被拦住。
- **待做**：真机实测一遍（推流面板的预览应该仍然有数据，录制文件应该正常增长）。

## 6. 预览 GL 直通（代码保留，未启用）

- `PreviewGlRenderer.kt` + `USE_GL_PREVIEW=false`。真机实测**黑屏**，原因未定位（三个待查点已埋日志：
  会话配置失败回退、EGL/shader 初始化、HWUI 是否消费我们产出的帧）。
- 它解决的问题：相机给预览和编码器带不同 buffer transform 时，用 GL 彻底无视矩阵。
- **当前用的方案**（元数据实测驱动 + 逆旋转）已经能满足"所见即所推"，GL 这条属于备选。

## 7. 死代码 / 实验开关清理

- `ENCODE_MATCH_DISPLAY`（竖屏编码实验，默认 false，未走通）
- `USE_GL_PREVIEW`、`PREVIEW_USE_MEASURED_HINT`、`subtitle_track_enabled`
- 结论已明确的实验分支可以删掉，避免以后误开。

## 8. 只打 arm64-v8a

- `abiFilters += "arm64-v8a"`，FFmpeg 也只编了 arm64。
- 要支持 32 位 / 模拟器：为每个 ABI 编一套 FFmpeg（同一个 `build.sh` 改 `--arch`）并放进 `ffmpeg/lib/<abi>/`。

## 9. 交付/发布相关

- **release 构建与签名**还没做；`proguard-rules.pro` 里的 JNI keep 规则已加。
- **崩溃上报**：`CrashHandler` 只把栈写到 `filesDir/last_crash.txt`，没有上报/查看入口（可以在"特殊日志"面板里展示上一次崩溃）。
- 录音/推流的内存与耗时监控没有；长时间推流的稳定性（几小时）还没压测。

## 10. 其它小项

- 相机下拉目前是固定两项（默认设备=按后置处理 / 后置 / 前置），**没有枚举真实多摄**（要按 cameraId 选）。
- RTMP **断线不自动重连**（只报错并标红）。
- 音频编码器只有 AAC（OPUS 未接，native 固定 AAC），下拉里也只放 AAC。
- 录制模块只显示"开启/关闭 + 路径"，没有录制时长/大小实时显示（只有结束时 Toast）。
- 面板在不同系统字体缩放/超小屏下的观感还可以再验一轮（推流那 4 行参数已经修过一轮）。
- `initPush` 里 `avformat_write_header` 早于编码器 extradata（现在靠"带内重复 CSD"兜住）；理论上可以等 extradata 再写头，但会引入启动延迟，暂不改。
- **iOS 端**：见 [ios.md](ios.md)。
