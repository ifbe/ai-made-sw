# 洞上应用：media（音视频）

**本文讲什么**：`ffmpeg` 这条"洞上音视频"的命令、它会拉起什么、参数是什么，以及**它现在到底能不能用**。

先说结论：**media 这条路的"设计文档"和"实际跑的脚本"是两套东西**——
[client/app/media.py](../client/app/media.py) 只有一段 docstring（讲 RTMP 收/推），**没有任何代码**；
真正被拉起的是 [client/app/ffmpeg.sh](../client/app/ffmpeg.sh)（bash + `ffmpeg`/`ffplay`，走的是 **UDP + mpegts**，不是 RTMP）。

---

## 1. 怎么起

| 方式 | 命令 / 位置 |
|---|---|
| CLI（已打通的洞上） | `ffmpeg <洞标识>`（洞标识：`fd=4` / `port=50001` / `#1` / `bob`） |
| CLI（先打洞再自动拉） | `ffmpeg <对方用户名>`（内部先 `udp <user>`，打通后自动 `_handover_hole(...)`） |
| 启动参数 | `--ffmpeg <用户名>`（可多次；启动时等价于执行 `ffmpeg <用户名>`） |
| 洞打通自动拉起 | `onholefromself` / `onholefrompeer` 取值为 `ffmpeg` |
| 图形端 | 桌面：media 页（`MediaPage`，三张卡：收流 / 推流 / 拉起应用）；Android：[`ui/MediaPage.kt`](../android/app/src/main/java/com/example/p2pnet/ui/MediaPage.kt)；iOS：[`UI/Pages/MediaPage.swift`](../ios/p2pnet/UI/Pages/MediaPage.swift) |

## 2. 拉起什么

`client.py:_launch_ffmpeg()` → `bash <脚本> <my_ip> <my_port> <peer_ip> <peer_port>`
（在"新窗口"里起，`new_window=True`）。

脚本路径由 `client.py:_ffmpeg_script_path()` 给出：`<client>/app/ffmpeg.sh`
（**已修**：原来拼的是 `<client>/ffmpeg.sh`，那个文件不存在 → `ffmpeg <洞>` 永远失败）。

脚本内部（[client/app/ffmpeg.sh](../client/app/ffmpeg.sh)）：

- `ffplay "udp://:$MY_PORT?listen=1&pkt_size=1316"` —— 本机监听，播放对端推来的流；
- `ffmpeg -f avfoundation -i "0:0" … -f mpegts "udp://$PEER_IP:$PEER_PORT?localport=$MY_PORT&pkt_size=1316"` —— 采集 + 编码 + 推给对端；
  ⚠️ **本机端口必须用查询参数 `localport=`**（**已修**，见下面"踩过的坑"）；
- `sleep <持续秒数>` 后退出。

**外部依赖**：`ffmpeg`、`ffplay`；采集后端写死 `avfoundation`（**macOS 专有**，Linux/Windows 上这条会失败）。

## 3. 参数表（从代码读）

| 参数 | 位置 | 默认 / 必填 |
|---|---|---|
| `<本机IP> <本机端口> <对方IP> <对方端口>` | `ffmpeg.sh` 位置参数 | **必填 4 个**（由 `client.py` 用洞的 `my_ip/my_port/peer_ip/peer_port` 填） |
| `<持续秒数>` | `ffmpeg.sh` 第 5 个位置参数 | 默认 `3600` |
| `--ffmpeg <用户名>` | `client.py` 启动参数 | 默认无（可多次） |
| 图形端 media 页字段 | 桌面 media 页 | 协议 `rtmp/rtsp/srt/udp`（默认 `rtmp`）、本机地址/端口、对端地址/端口（都是 `打洞后自动带出` 的占位） |

## 4. 当前状态

- **`app/media.py`：未实现**（文件里只有 docstring，没有任何可执行代码）。
- **路径：已修**。`_launch_ffmpeg()` 现在用 `_ffmpeg_script_path()` = `<client>/app/ffmpeg.sh`，
  并在脚本真的不存在时打 `[P2P] 错误: 找不到 ffmpeg.sh: …`（明确错误）。self-test 常驻断言：
  该路径存在、`_launch_ffmpeg()` 返回 True 且命令行是 `bash <真实路径> …`、日志里**不再**出现旧的"不在当前目录"。
- **发送端 URL：已修**（这是本机实测出来的坑，见下）。接收端 `udp://:<port>?listen=1&pkt_size=1316` **实测可用，未改**。
- **RTMP 收发：未实现**——`app/media.py` 里根本没有 RTMP 代码；实际链路是 mpegts over UDP。
  （`app/ffmpeg.sh` 本身能跑通：本机实测用它的 URL 模式发 2 秒 mpegts，接收端正常收到。）
- 图形端三张卡（收流 / 推流 / 拉起应用）**按钮只写日志**（Phase 1 骨架），不会真的拉起任何程序。

## 5. 已知限制

- 有坑见 [readme-gotcha.md](readme-gotcha.md)（tun/tap、平台差异等）。
- **别把 `media.py` 的 RTMP 描述当成实现**：设计说的是 RTMP，脚本做的是 UDP/mpegts，两者不是一套。
- **踩过的两个坑（都已在代码里修掉，本机 ffmpeg 9.0.2 实测）**：
  1. 脚本路径：`dirname(client.py)/ffmpeg.sh` 不存在，真实位置是 `client/app/ffmpeg.sh`；
  2. **发送端不能用 `udp://peer:port@local:localport`**：`@` 会被当成 URL 的 userinfo，
     包被发到 `@` **后面**那个地址（= 自己的端口）且**源端口是临时端口** —— 实测接收端落盘 **0 字节**；
     换成 `?localport=$MY_PORT&pkt_size=1316` 后，接收端 **43616 字节**、且**来源端口 == 洞里那个本机端口**。
     打洞全靠"从这个固定端口出去"，所以旧写法等于白打。

---

相关：[readme-cli.md](readme-cli.md)（`ffmpeg` 命令在命令表里的位置）、[readme-udp.md](readme-udp.md)（洞怎么打）、[readme-tcp.md](readme-tcp.md)、[readme-gotcha.md](readme-gotcha.md)、[readme-desktop.md](readme-desktop.md)（桌面 media 页）、[readme-wg.md](readme-wg.md)（另一条"洞上应用"）。
