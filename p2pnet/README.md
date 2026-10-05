# p2pnet

内网穿透小工具：一个 WebSocket 信令服务器 + **四种客户端**。
打洞（UDP / TCP）、地址交换与可达性探测（direct）、以及"洞打通之后跑什么"。

## 四种客户端

| 客户端 | 代码 | 文档 | 一句话 |
|---|---|---|---|
| **cli** | `client/client.py` | [readme-cli.md](doc/readme-cli.md) | 命令行客户端；命令最全，也是另外三端的**参照实现** |
| **desktop** | `client/client-gui.py` | [readme-desktop.md](doc/readme-desktop.md) | PyQt6 桌面端；**进程内**驱动 `client.py`（不起子进程） |
| **android** | `android/` | [readme-android.md](doc/readme-android.md) | Kotlin / Compose；6 个配置页 + 自由层卡片 |
| **ios** | `ios/` | [readme-ios.md](doc/readme-ios.md) | SwiftUI；与安卓同形态（协议字段 / JSON 键名 / 页面一一对齐） |

四端共用同一套服务端协议；三个图形端（desktop / android / ios）的界面刻意保持同形态。

## 快速开始

```bash
# 1. 建用户（写进 server/passwd.json）
python3 server/secret.py -f server/passwd.json add alice -p pw

# 2. 起服务器（TCP 与 UDP 同端口）
python3 -u server/server.py --port 10000 --udpport 10000

# 3. 起一个客户端（命令行；也可带 --user/--pass 自动登录）
python3 client/client.py --server 127.0.0.1 --port 10000 --user alice --pass pw
```

客户端的**权威命令清单**是它自己里的 `help`（本文档不重复）。图形端直接看各自的文档。

## 文档

### p2p

| 文件 | 内容 |
|---|---|
| [readme-direct.md](doc/readme-direct.md) | `direct`：不打洞，ICMP 可达性探测 |
| [readme-upnp.md](doc/readme-upnp.md) | `upnp`：让路由器开映射（**计划，未实现**） |
| [readme-udp.md](doc/readme-udp.md) | UDP 打洞 6 步、候选地址、`app/udptest.py` |
| [readme-tcp.md](doc/readme-tcp.md) | TCP 打洞 5 步（三个 socket、fd 继承）、`app/tcptest.py` |

### 洞上应用（洞打通之后跑什么）

| 文件 | 内容 |
|---|---|
| [readme-media.md](doc/readme-media.md) | media：洞上跑音视频（`ffmpeg.sh`，UDP/mpegts） |
| [readme-proxy.md](doc/readme-proxy.md) | proxy：把洞里的数据转发到某个地址（`app/proxy.py`） |
| [readme-wg.md](doc/readme-wg.md) | WireGuard：`wg-py`（自己实现）/ `wg-sh`（调系统 wg） |
| [readme-vpn.md](doc/readme-vpn.md) | vpn：一对一 tun/tap（`app/vpn.py`） |
| [readme-switch.md](doc/readme-switch.md) | switch：m 对 n 虚拟交换机（`app/switch.py`） |

### 程序

| 文件 | 内容 |
|---|---|
| [readme-server.md](doc/readme-server.md) | 服务端：启动、用户管理、两个端口、认证与中转、心跳 |
| [readme-cli.md](doc/readme-cli.md) | 命令行客户端：启动 / 命令 / 洞打通后自动跑什么 / 对端开关 / **心跳与自动重连** / 代码分层 |
| [readme-desktop.md](doc/readme-desktop.md) | 桌面端（`client/client-gui.py`）**唯一文档** |
| [readme-android.md](doc/readme-android.md) | 安卓端**唯一文档** |
| [readme-ios.md](doc/readme-ios.md) | iOS 端**唯一文档** |

### 其他

| 文件 | 内容 |
|---|---|
| [readme-gotcha.md](doc/readme-gotcha.md) | **已知的坑、危险行为、没验证的部分**（出问题先看这个） |
| [readme-todo.md](doc/readme-todo.md) | 设计想法 / 还没做的 |
