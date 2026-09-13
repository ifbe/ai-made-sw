# 踩过的坑（按"症状 → 原因 → 解"记录）

> 这份文档是给后来人（尤其是 iOS 端）省时间的。凡是反复烧过时间的地方都写进来了，包括**被否掉的方案**。

---

## 1. 【最坑】预览画面和收流端方向不一致（所见非所推）

**症状**：收流端画面正常/躺着，App 里预览却是另一个方向；横屏时还"拉伸"。

**原因**：相机给不同输出带不同的 **buffer transform 提示**
- 给**屏幕预览**那一路带提示 → 系统显示管线（HWUI）会按 `(传感器方向 vs 屏幕方向)` 把画面**转正**；
- 给**编码器**那一路不带 → 编码器拿到什么推什么 → 收流端看到的是**没转过的原始画面**。

**关键事实**：这个提示**没有公开 API 能关掉**（`TextureView` 会自己按它转，`SurfaceView` 交给合成器转，一样）。相机的 `SCALER_ROTATE_AND_CROP_90` 能关掉显示侧旋转，但 **16:9 输出只剩 ~31.6% 视野**，等于放大 3 倍，不可用。

**我们最后的解法（元数据实测驱动）**：
1. 从 `SurfaceTexture.getTransformMatrix()` 读出**实测**旋转/镜像；
   - 注意：**前 3 帧读到的是初始单位阵**（HWUI 还没 `updateTexImage`），必须跳过；
2. `2x2 行列式 < 0` = 纯旋转（含 gralloc 固有 v 翻转）；`> 0` = 多一次镜像（前置相机）；
3. 黑框按**推流画面比例**摆；画面盒按**上屏呈现比例**（提示转了 90/270 就交换宽高）摆；整块 View **逆着转回去**抵消提示；
4. 本机标定值（写死在代码注释里）：
   | | 实测矩阵 | 行列式 | 处理 |
   |---|---|---|---|
   | 后置 | `[0,-1,-1,0]` 平移`[1,1]` | −1 | 交换宽高 + 转 270°，不镜像 |
   | 前置 | `[0,-1,1,0]` 平移`[0,1]` | +1 | 交换宽高 + 转 **90°** + `scaleX=-1` |

   相关开关：`HINT_90_IS_CLOCKWISE=false`、`MIRROR_FLIPS_ROTATION=true`、`PREVIEW_MIRROR_FRONT=true`。
5. **转屏不要重建相机会话**：既然摆放是实测驱动的，提示过期也没关系；重建会话反而会让推流卡一下。

**血泪教训**：
- 一开始用"传感器方向 − 屏幕旋转"的**公式**推算方向 → 横屏必错（提示在这台设备上**恒定不随屏幕变**），一错就拉伸；
- 中途还试过 `TextureView.setTransform()` 反向旋转 → 错，它转的是"已经铺满 View 的那层内容"，只会把画面拉歪；
- 也试过"预览走 GL 直通（彻底无视矩阵）" → 思路正确但真机黑屏（代码保留在 `PreviewGlRenderer.kt`，`USE_GL_PREVIEW=false`）。

**正确姿势**：**用实测元数据，不要用公式**；先把 `getTransformMatrix()` 打进日志再改代码。

---

## 2. 预览"没充满黑框 / 有黑边 / 被拉伸"

- 黑框形状和画面形状不一样时，**要么留黑边、要么裁画面**，不可能同时满足 → 最终选择：**黑框 = 推流画面比例**，画面正好铺满（不裁不拉伸），黑框外的区域用模块底色而不是黑色。
- 画面盒比例必须等于**上屏呈现比例**（见第 1 条），否则内容会被 HWUI 拉伸。

---

## 3. 本地录制：文件 21KB、完全放不了

**原因**（很隐蔽）：native 的 `java_on_send_callback()` 里，当年为了"推流数据预览"只显示 16 字节十六进制，写了

```c
int copy_len = buf_size > 16 ? 16 : buf_size;   // ← 每个包只拷前 16 字节给 Java
```

录制器当时是**旁路 Java 侧那份数据** → 每个包只录到 16 字节 → 整个文件 ≈ 21KB、结构全烂。

**解法**：**录制搬到 native**，在 AVIO 写回调里直接 `write(fd, buf, buf_size)`：
- Java 只负责：准备文件（MediaStore/File）→ `ParcelFileDescriptor.detachFd()` → `nativeStartRecord(fd)`；
- 预览那一路**恢复只传 16 字节**（零额外开销，不跨 JNI 拷全量）；
- 顺序安全：录制的 `write()` 和 muxer 写包共用 `write_mutex`，不会和音/视频交错。

---

## 4. 录制文件缺"文件头"，播放器打不开

**原因**：FLV/MP4 的文件头是 `initPusher()` 里 `avformat_write_header()` 写出去的，而 AVIO 回调是**在 initPusher 之后**才注册的 → 头字节根本没到 Java。

**解法**：把 `setAvioCallback` 提到 `initPusher` **之前**（代码里叫 Step 0）。顺带好处：推流数据预览也能看到头部字节了。

---

## 5. CSD（SPS/PPS）在带内重复的那一份不能丢

**症状**：丢掉"已经发过 extradata 之后的重复 CSD" → 收流端报 `non-existing PPS 0 referenced`、`no frame!`。

**原因**：编码器的 CSD 是在 `avformat_write_header` **之后**才到的，真正把 SPS/PPS 送到接收端的，恰恰是带内重复的那一份。

**解法**：`is_csd && extradata_sent` 时**照常当普通包写出去**（`ffplay` 会报一条 `missing picture in access unit with size 32`，是良性的）。

---

## 6. 独立字幕轨在 fMP4 下**必崩**（movenc 断言）

**症状**：`SIGABRT`，栈顶固定是
```
#01 libavformat.so  movenc.c:1248  get_cluster_duration   av_assert0(next_dts >= 0)
#02 libavformat.so  movenc.c:6727  mov_auto_flush_fragment
#06 av_interleaved_write_frame
#07 libpusher.so    write_subtitle_frame / write_audio_frame
```

**定位过程**（方法也值得抄）：
1. `adb logcat -b crash -d > /tmp/crash.txt`（crash 缓冲是**持久**的，开头可能是几天前的旧崩溃，看**末尾**）；
2. 帧里的 `pc` 就是**库内地址**（`(offset 0x1f78000)` 是在 APK 里的偏移，别减）；用 NDK 的
   `llvm-addr2line -f -C -e libavformat.so 0xa2910` 直接翻成源码行；
3. 结论：**只有 fMP4 分片 + 字幕轨**才崩。

**试过没用的**：把字幕样本从"每 2 秒一条（稀疏轨）"改成"**每帧一条（密集轨）**" → 一样崩。说明是 movenc 在分片边界上对文本轨的**记账缺陷**，不是样本密度问题。

**当前状态**：`ffmpeg_utils.cpp` 里 `subtitle_track_enabled = false`，**独立字幕轨停用**（UI 保留）。

**备选路线**（详见 [todo.md](todo.md)）：
① 给 `movenc.c` 的 `get_cluster_duration()` 打补丁（负时长钳成 0）后重编 —— 最省事；
② 改成"把 CEA-608 塞进 H.264 的 SEI"（**不新增轨道**，无分片问题，但 ffplay 默认不显示）；
③ 烧进画面（任何播放器都能看，但改像素、不可关）；
④ 旁路通道（WebSocket/HTTP 文本，只对自己的客户端有效）。

---

## 7. FFmpeg 预编译库的"能力边界"要先摸清

- configure 命令行**嵌在 `libavutil.so` 里**，可以直接挖出来：
  ```bash
  strings -a libavutil.so | grep -m1 "enable-"
  ```
  本工程的现状：`--enable-protocol='rtmp,rtmpt,rtsp,file'` + `--enable-muxer='flv,mp4,mpegts'`（后加过 `tcp`）。
- **FFmpeg 里 RTSP 是 muxer/demuxer，不是 protocol** → configure 里写 `rtsp` 是空转，推不出去；
- 想加 SRT/WHIP/RIST/HLS/DASH 必须**重编**（SRT 还要先编 libsrt；WHIP 要 libsrtp+openssl）；
- 预编译库**带符号**（`llvm-addr2line` 能用），`--enable-shared` 且未 strip；
- **换库后要校验**：`llvm-readelf -d libavformat.so` 看 NEEDED 没有引入新 .so；对比新旧导出符号集合（应该只多不少）。
- 库的 configure 参数改动会**整体重编**，用脚本固化（`ffmpeg-build/build_tcp.sh`）。

---

## 8. 公共下载目录（/sdcard/Download）不能直接写

- **Android 10 及以下**：`File` 直写（要 `WRITE_EXTERNAL_STORAGE`；API 29 还要 `requestLegacyExternalStorage`）；
- **Android 11+**：必须走 **MediaStore.Downloads**（`RELATIVE_PATH=Download`）→ 好处是**不需要任何权限**，也不要去申请"所有文件访问"；
- 录制期间要 `IS_PENDING=1`，写完再清 → **录制中在「下载」里看不到文件是正常的**，停止后才出现；
- `openOutputStream(uri, "wt")` 在部分机型不被 MediaProvider 接受 → 用 **`"w"`**；
- 文件名想固定（`pusher.mp4`）就必须**先删同名条目再插入**，否则系统会堆出 `pusher (1).mp4`。

---

## 9. A/V 同步

- 两路各自记"**首包到达时刻**"和"首包原始 PTS"，之后 `PTS = (首包到达 − 会话T0) + (本包PTS − 首包原始PTS)`，两路共用同一个会话时钟 `sessionT0Ms = SystemClock.elapsedRealtime()`；
- 音频**不要**用"帧序号 × 当前块样本数"算 PTS（每块 read 长度会变，必然漂移）→ 用**累计采样数**；
- native 侧不要再做 PTS 重基准（会二次偏移）。

---

## 10. 后台/锁屏继续推（Android 专属）

- 只靠 Activity 生命周期不行：**Android 9+ 后台不允许访问相机**，必须起**前台服务**，并且声明
  `foregroundServiceType="camera|microphone"` + `FOREGROUND_SERVICE_CAMERA/MICROPHONE` 权限（Android 14 起强制）；
- **前台服务不会阻止 Doze**：屏幕关掉后 CPU 会睡、WiFi 会省电 → 需要 `PARTIAL_WAKE_LOCK` + `WifiLock`（本工程在 `PushService` 里持有，销毁时释放）；
- 服务用 `START_NOT_STICKY`：进程被杀后不要被系统在后台拉起（后台起 `startForeground` 会抛异常）→ 捕获异常并 `stopSelf()`；
- 退到后台时 `TextureView` 的 Surface 会销毁 → 用"**只挂编码 Surface**"重建会话，推流不断，回前台再挂回预览。

---

## 11. 通知栏（很容易漏的两点）

- **Android 13+ 要 `POST_NOTIFICATIONS`**：不声明、不申请 → 前台服务的通知**不显示**（服务照常跑）。申请时**不要**把它并入"能否推流"的判断（否则拒了通知就不推流了）；
- 权限弹窗和首次推流几乎同时发生时，那条通知会被系统丢掉 → 用户点"允许"后要**补发一次**（`PushService.refreshNotification`）；
- **停止推流必须 `stopService`**：否则"推流中"常驻通知不消失，唤醒锁也不释放（本工程真出过这个 bug）。

---

## 12. 相机尺寸要取"两路输出的交集"

预览走 `SurfaceTexture`、编码走 `MediaCodec`，两个 `getOutputSizes()` 不一定完全一致；选尺寸时要**取交集**，否则会出现"相机不支持/编码器不支持"的启动失败。

---

## 13. 上传协议侧的坑

- **RTMP 的载荷必须是 FLV tag**：`rtmp://` + fMP4 在标准服务端上就是垃圾数据；协议下拉只影响 URL 前缀，真正决定 muxer 的是"封装"下拉 → 两者要**联动/提示**；
- **TCP 裸流是 host:port 直连**，接收端要先 `listen`，App 是主动连的一方；
- TCP 直播要 `?tcp_nodelay=1` 关 Nagle，否则小包被攒着发、多几十毫秒延迟；
- SRT 是 host:port（`mode=caller` 默认），生态默认配 MPEG-TS。

---

## 14. UI 细节（都踩过）

- **输入框固定行高会裁字**：`EditText` 自身量出来的高度受系统字体缩放影响，一旦超过父行高，`clipChildren=true` 就切掉一半；
- **"自适应高度的父容器 + `match_parent` 的子 View" 会量成 0 高度**（输入框直接消失）→ 子 View 用 `wrap_content`；
- 想减少"框虚胖"用 **`minHeight=0` + `includeFontPadding=false`**，而不是硬压行高；
- 展开/收起动画要**把"背景遮罩 alpha"和"卡片形变"分开**：整块一起淡入淡出会把矩形形变糊掉、看起来"没有动画"；
- 卡片尺寸是异步布局的（80% 屏），做形变动画要等**真正布局完成**（一次性 `OnGlobalLayoutListener`）再量矩形。

---

## 15. 排查工具箱（省时间的几个）

```bash
# 我们自己的日志（tag 列表见 android.md），只看我们 App
adb logcat -s AppLog PusherController PusherJNI FFmpegUtils CameraHelper LocalRecorder

# 原生崩溃（crash 缓冲持久，末尾是最新）
adb logcat -b crash -d > /tmp/crash.txt

# 地址翻译（预编译库带符号）
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-addr2line -f -C -e libavformat.so 0xa2910

# 挖 FFmpeg 的编译参数
strings -a libavutil.so | grep -m1 "enable-"

# 收流端（PC 先监听，TCP 模式）
ffplay -f mpegts "tcp://0.0.0.0:9000?listen=1"
ffplay -f mp4   "tcp://0.0.0.0:9000?listen=1"      # fMP4
ffplay "rtmp://127.0.0.1/live/test"                # RTMP
```

**良性的日志噪音**（别当成 bug）：`missing picture in access unit with size 32`、swscale 的 `deprecated pixel format`、`25 tbr`。
