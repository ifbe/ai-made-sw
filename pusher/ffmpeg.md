# FFmpeg：编译、接收端测试命令、本项目用了哪些

> 项目里的 FFmpeg 是**预编译库**（`android/app/src/main/ffmpeg/lib/arm64-v8a/*.so`），
> 源码与构建工程在 `~/Desktop/code/github/ffmpeg`（v**8.0.git**）和 `~/Desktop/code/github/ffmpeg-build`。
> 注意：`ffmpeg-build/src` 是指向源码目录的**符号链接**，两边是同一份代码。

---

## 1. 怎么编译，参数是什么

### 1.1 环境

| 依赖 | 说明 |
|---|---|
| NDK | `~/Library/Android/sdk/ndk/`（脚本会**自动选最新一个**：`ls -d ... \| sort -V \| tail -1`；老脚本 `build.sh` 里写死的 `30.0.14904198` 本机已经不存在了，别直接用） |
| cmake / ninja | 只有编 libsrt 时才需要（`brew install cmake ninja`） |
| 目标 | `arm64-v8a`，`android-28`（对应 `minSdk 28`） |

### 1.2 脚本一览（`~/Desktop/code/github/ffmpeg-build/`）

| 脚本 | 用途 |
|---|---|
| `build.sh` | 最原始那份（RTMP+FLV），**NDK 路径已过期**，仅作参考 |
| **`build_tcp.sh`** | ✅ **当前 App 里的库就是它编出来的**：在原始配置上加了 `tcp` 协议 |
| `build_tcp_srt.sh` | 以后要 **SRT** 时用：先编 arm64 静态 `libsrt`，再 `--enable-libsrt` 重编 FFmpeg（脚本内 `ENABLE_ENCRYPTION=OFF`，即**不带 passphrase 加密**；要加密还得先给 Android 编 OpenSSL） |
| `merge.sh` | 把多个 `.so` 合成一个（本项目**没用到**） |

跑法（脚本里已包含 configure + make + install）：

```bash
cd ~/Desktop/code/github/ffmpeg-build
bash build_tcp.sh          # 产物：android/arm64/lib/*.so
```

### 1.3 完整的 configure 参数（当前库的真实值）

```bash
NDK_ROOT=$(ls -d ~/Library/Android/sdk/ndk/* | sort -V | tail -1)
API=28
TC=$NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64
FFMPEG_SOURCE=/Users/ifbe/Desktop/code/github/ffmpeg
BUILD_DIR=/Users/ifbe/Desktop/code/github/ffmpeg-build   # 在它里面跑 configure

cd "$BUILD_DIR"
"$FFMPEG_SOURCE/configure" \
  --prefix="$BUILD_DIR/android/arm64" \
  --enable-cross-compile --target-os=android --arch=arm64 --cpu=armv8-a \
  --cc="$TC/bin/aarch64-linux-android${API}-clang" \
  --cxx="$TC/bin/aarch64-linux-android${API}-clang++" \
  --sysroot="$TC/sysroot" \
  --enable-shared --disable-static --disable-programs \
  --disable-avdevice --disable-avfilter \
  --disable-encoders --disable-decoders --disable-hwaccels \
  --disable-muxers --disable-demuxers --disable-parsers --disable-bsfs \
  --disable-protocols --disable-indevs --disable-outdevs --disable-filters \
  --enable-protocol='rtmp,rtmpt,rtsp,tcp,file' \
  --enable-muxer='flv,mp4,mpegts' \
  --enable-decoder='h264,aac' --enable-encoder='h264,aac' --enable-parser='h264,aac' \
  --enable-demuxer='flv,mov,mpegts' \
  --enable-mediacodec --enable-jni \
  --extra-cflags="-Os -fPIC -D__ANDROID_API__=$API" \
  --extra-ldflags="-lm -ldl"

make -j$(sysctl -n hw.ncpu)
make install        # → android/arm64/lib/*.so
```

参数含义（只列关键的）：

| 参数 | 为什么这么写 |
|---|---|
| `--enable-shared --disable-static` | App 直接打包 `.so`（`jniLibs.srcDir("src/main/ffmpeg/lib")`），不做静态库 |
| `--disable-programs` | 不编 `ffmpeg/ffprobe` 命令行 → **设备上没有任何 CLI 工具**，接收端测试在 PC 上做 |
| `--disable-avdevice/avfilter` | 用不到（相机/音频走 Android 原生 API，不做滤镜） |
| 先 `--disable-*` 再逐个 `--enable-*` | 白名单式构建，`.so` 体积最小、行为可预期 |
| `--enable-protocol='rtmp,rtmpt,rtsp,tcp,file'` | `rtmp/rtmpt` 推流；`tcp` 裸流；`file` 保留。**注意 `rtsp` 在 FFmpeg 里是 muxer/demuxer，不是 protocol，写在这里是空转** |
| `--enable-muxer='flv,mp4,mpegts'` | 三种封装（fMP4 就是 `mp4` muxer + `movflags=frag_keyframe+empty_moov+default_base_moof`） |
| `--enable-decoder/encoder/parser='h264,aac'` + `--enable-mediacodec --enable-jni` | **沿用原始配置，本项目其实不用 FFmpeg 的编解码器**（走 Android MediaCodec），见第 3 节 |
| `--enable-demuxer='flv,mov,mpegts'` | 只在 PC 接收端用，App 里用不到 |
| `-Os -fPIC -D__ANDROID_API__=28` | 体积优先 + 位置无关 + 与 minSdk 对齐 |

### 1.4 编完之后（**必做**）

```bash
# 1) 装进 App
cp -f ~/Desktop/code/github/ffmpeg-build/android/arm64/lib/*.so \
      android/app/src/main/ffmpeg/lib/arm64-v8a/

# 2) 检查没有引入新的 .so 依赖（出现过就会缺库崩溃）
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf -d libavformat.so | grep NEEDED

# 3) 对比新旧导出符号集合（应该只多不少；可用 diff 比对两个版本的 nm -D 输出）
# 4) 确认 configure 真的生效（这行是从库里挖出来的，权威）
strings -a libavutil.so | grep -m1 "enable-" | tr ' ' '\n' | grep -E "enable-protocol|enable-muxer"

# 5) App 启动后看「app 特殊日志」
#    FFmpeg 支持的输出协议: rtmp,rtmpt,rtsp,tcp,file      ← 能力驱动的协议下拉就是读它
```

**坑**：configure 对无效组件不报错（比如 `rtsp` 空转）；NDK 版本写死在脚本里会过期；libsrt 要静态链接 + `-lc++_static -lc++abi`（否则要多打包 `libc++_shared.so`）。

---

## 2. 接收端测试命令（PC 上，用系统 ffmpeg/ffplay）

> **顺序很重要**：TCP/SRT 是 App **主动连**过来的 → 先起接收端，再点 App 的"开始推流"。
> 常见坑：Windows 防火墙要放行；RTMP 需要一个服务端（或用下面的 `-listen` 技巧）。

### 2.1 RTMP + FLV（App：协议=RTMP，封装=flv）

```bash
# 方式 A（推荐）：先起一个 RTMP 服务端，再用 ffplay 拉
#   MediaMTX / SRS / nginx-rtmp 任选，路径 /live/test 自定
ffplay "rtmp://127.0.0.1:1935/live/test"

# 方式 B：不装服务端，让 ffplay 自己当监听端
ffplay -listen 1 "rtmp://0.0.0.0:1935/live/test"
#   App 里填：服务器=<PC 局域网 IP>  端口=1935  应用/流名=/live/test

# 只落盘不播放（用来存证）
ffmpeg -listen 1 -i "rtmp://0.0.0.0:1935/live/test" -c copy out.flv
```

### 2.2 TCP 裸流（App：协议=TCP；封装=mpegts 或 fMP4）

```bash
# MPEG-TS（默认，最省事）
ffplay -f mpegts "tcp://0.0.0.0:9000?listen=1"
# 等价写法（不依赖 ffplay 的 listen 选项）
nc -l 9000 | ffplay -f mpegts -

# fMP4（分片 mp4）
ffplay -f mp4 "tcp://0.0.0.0:9000?listen=1"
# 播放器不认就落盘再放：
ffmpeg -f mp4 -i "tcp://0.0.0.0:9000?listen=1" -c copy out.mp4 && ffplay out.mp4
#   App 里填：协议=TCP，端口=9000，地址=PC 的 IP；"应用/流名"栏此时是 URL 参数（默认已自动填 ?tcp_nodelay=1）
```

### 2.3 SRT（要先用 `build_tcp_srt.sh` 重编才有）

```bash
ffplay "srt://0.0.0.0:9000?mode=listener"
# 带参数的自测（对端要求 passphrase 时需要重编时打开加密 + OpenSSL）
# ffplay "srt://0.0.0.0:9000?mode=listener&latency=200000"
```

### 2.4 录制文件自检（App 的「本地录制」产物）

```bash
# FLV：开头必须是 46 4c 56 01（"FLV" + version 1）
xxd -l 16 pusher.flv

# 看流信息（fMP4 / FLV 都适用）
ffprobe -v error -show_entries stream=index,codec_name,codec_type,width,height,sample_rate,channels \
        -of compact pusher.mp4

# 完整解码一遍找错（没有任何输出 = 没错误）
ffmpeg -v error -i pusher.flv -f null -
```

### 2.5 一眼判断"是不是推流侧的问题"

| 现象 | 结论 |
|---|---|
| 收流端正常、本地录制也正常 | 链路 OK |
| 收流端正常、录制文件是 0 字节/很小 | 录制侧问题（历史上是"只拷了 16 字节"那个坑，见 [gotcha.md](gotcha.md#3-本地录制文件-21kb完全放不了)） |
| 收流端报 `non-existing PPS 0 referenced` | 带内 CSD 被丢了（见 [gotcha.md](gotcha.md#5-csdspspps在带内重复的那一份不能丢)） |
| 收流端画面"躺着"但 App 预览是正的 | 预览方向补偿的问题（见 [gotcha.md](gotcha.md#1-最坑预览画面和收流端方向不一致所见非所推)） |
| 日志里 `missing picture in access unit with size 32` | **良性**：那是带内重复的 CSD 包 |

---

## 3. 本项目用了 FFmpeg 的哪些部分

### 3.1 实际调用的库与符号

| 库 | 用到的符号 | 用途 |
|---|---|---|
| **libavformat** | `avformat_network_init`、`av_guess_format`、`avformat_alloc_output_context2`、`avformat_new_stream`、`avformat_write_header`、`av_write_trailer`、`av_interleaved_write_frame`、`avformat_free_context`、`avio_open2`、`avio_alloc_context`、`avio_close`、`avio_enum_protocols` | 封装（muxer）、协议（网络）、自定义 AVIO（旁路字节） |
| **libavcodec** | `av_packet_alloc`、`av_packet_free`、`av_packet_from_data` | 只有 `AVPacket` 相关（**没用 FFmpeg 编解码器**） |
| **libavutil** | `av_malloc`、`av_free`、`av_freep`、`av_gettime`、`av_strerror`、`av_dict_set`、`av_dict_free`、`av_rescale_q`、`av_assert0` | 内存/时间/时间基换算/字典（协议参数） |
| libswresample / libswscale | **没有调用** | CMake 里链接了（沿用原始配置），实际未使用 |
| 未链接 | libavdevice / libavfilter | configure 里 disable |

### 3.2 用到的封装与协议

| 类型 | 用到 | 场景 |
|---|---|---|
| muxer | `flv` | RTMP 推流（唯一合法组合）、本地录制 `.flv` |
| muxer | `mp4`（fMP4 模式） | TCP/SRT 推流、本地录制 `.mp4`；靠 `movflags=frag_keyframe+empty_moov+default_base_moof` 支持不可 seek 输出 |
| muxer | `mpegts` | TCP/SRT 推流、本地录制 `.ts` |
| protocol | `rtmp` / `rtmpt` | RTMP 推流（rtmpt=RTMP over HTTP 隧道） |
| protocol | `tcp` | TCP 裸流（`?tcp_nodelay=1` 关 Nagle） |
| protocol | `file` | 保留（当前本地录制是**自己写 fd**，不经过它） |
| protocol | `srt` | **待编**（`build_tcp_srt.sh`） |

### 3.3 这些事我们自己在 native 里做（FFmpeg 不管）

- **CSD 处理**：H.264 的 SPS/PPS → `avcC`、HEVC 的 VPS/SPS/PPS → `hvcC`（`process_csd_data` / `build_hevc_extradata`），并在带内重复发送（详见 gotcha 第 5 条）；
- **AAC ASC**：`build_aac_asc(sample_rate, channels)` 手搓 AudioSpecificConfig；
- **A/V 同步时间轴**：会话公共时钟 + 每路首包锚点（PusherController）；
- **AVIO 旁路**：`hooked AVIOContext` → 预览数据（16 字节）+ 录制落盘（fd 全量）+ 转交真实网络 ctx；
- **生命周期保护**：`write_mutex` / `WriterGuard` / `active_writers` / `pusher_closing`（写包与关闭互斥）；
- **录制落盘**：POSIX `write(fd, ...)`（不走 FFmpeg 的 file 协议）。

### 3.4 文件职责

| 文件 | 内容 |
|---|---|
| `cpp/ffmpeg_utils.cpp` | ★ 所有 FFmpeg 侧逻辑：建流/写头写包/CSD/ASC/AVIO hook/录制落盘/关闭与写者保护 |
| `cpp/pusher_jni.cpp` | JNI 薄层：Java ↔ C 的搬运 + 三个回调（onSendData / onMuxData / onRtmpError）+ 能力查询（`avio_enum_protocols`） |
| `cpp/CMakeLists.txt` | 用 `IMPORTED` 链接 `ffmpeg/lib/${ANDROID_ABI}/*.so` |

> **给 iOS 端的提示**：`ffmpeg_utils.cpp` 里 99% 是平台无关逻辑，建议抽成 `pusher_core.h` 的纯 C 接口复用（见 [ios.md](ios.md#3-复用安卓的-c-核心强烈推荐)）。
> **字幕**：独立文本轨在 fMP4 分片下会触发 movenc 断言（`movenc.c:1248`），当前 `subtitle_track_enabled=false`，方案见 [todo.md](todo.md#1-字幕当前已禁用功能待重做)。
