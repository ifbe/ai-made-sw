# p2pnet

内网穿透小工具：一个 WebSocket 信令服务器 + 命令行客户端 + **安卓 / iOS 两个图形客户端**。
打洞（UDP / TCP）、地址交换与可达性探测（direct）、以及"洞打通之后跑什么"。

- Python 客户端：`client/client.py`（下面这张表都是它的命令）
- 安卓端：[readme-android.md](doc/readme-android.md)（Compose，6 个配置页 + 自由层卡片）
- iOS 端：[readme-ios.md](doc/readme-ios.md)（SwiftUI，与安卓同形态；两端协议字段/JSON 键名/页面一一对齐）

## 能干什么

| 命令 | 作用 |
|---|---|
| `udp <user>` | 和对方打 UDP 洞（6 步） |
| `tcp <user>` | 和对方打 TCP 洞（5 步，把已建立的内核连接交给子进程） |
| `direct <user>` | 不打洞，看对方哪些地址可达（**服务端已实现 `p2pdirect` 中转**；安卓/iOS 也已实现） |
| `upnp` | 让路由器开端口映射（**还没实现**） |
| `udptest <洞>` | 洞上跑互发测试（ping/pong + RTT） |
| `proxy <洞> <host:port>` | 把洞里的数据转发到这个地址（安卓/iOS 的 proxy 页有 `-L`/`-R` 两种模式） |
| `ffmpeg <洞>` / `wg-py <洞>` / `wg-sh <洞>` | 洞上跑视频 / 自己实现的 WireGuard / 系统 wg（安卓/iOS 对应 media 页与 WireGuard 页） |

洞打通之后自动跑什么，由两个状态变量决定：
`onholefromself`（本端发起的洞）/ `onholefrompeer`（对方发起的洞），
可选 `none`（默认，只记录不拉起）/ `udptest` / `tun [设备]` / `tap [设备]` / `auto` / `switch` / `proxy <host:port>` / `ffmpeg` / `wg-py` / `wg-sh`。

别人来找我时参不参与，由四个开关决定：
`onpeerwantudp` / `onpeerwanttcp` / `onpeerwantdirect` / `onpeerwantupnp`（`auto` 默认 / `none` 静默拒绝）。

## 快速开始

```bash
# 1. 建用户（写进 passwd.json）
python3 server/secret.py -f server/passwd.json add alice -p pw

# 2. 起服务器（TCP 与 UDP 同端口）
python3 -u server/server.py --port 10000 --udpport 10000

# 3. 起客户端（也可以带 --user/--pass 自动登录）
python3 client/client.py --server 127.0.0.1 --port 10000 --user alice --pass pw
```

客户端里敲 `help` 看全部命令；最小用法：

```
udp bob              # 打洞，6 步一行一行打出来
list hole            # 看洞表（fd / 本端 / 对端 / 状态）
udptest fd=4         # 把这个洞交给互发测试
```

## 分层

```
hole/    打洞那几步（client.py 主进程里跑）
app/     打完洞之后的"使用者程序"（子进程，接管那个洞）
util/    底层设施（tun/tap 驱动、crypto、kcp）
```

## 文档

| 文件 | 内容 |
|---|---|
| [readme-udp.md](doc/readme-udp.md) | UDP 打洞 6 步、候选地址、`app/udptest.py` |
| [readme-tcp.md](doc/readme-tcp.md) | TCP 打洞 5 步（三个 socket、fd 继承）、`app/tcptest.py` |
| [readme-wg.md](doc/readme-wg.md) | 两条 WireGuard 路：`wg-py`（自己实现）/ `wg-sh`（调系统 wg） |
| [readme-direct.md](doc/readme-direct.md) | `direct`：不打洞，ICMP 可达性探测 |
| [readme-upnp.md](doc/readme-upnp.md) | `upnp`：让路由器开映射（**计划，未实现**） |
| [readme-gotcha.md](doc/readme-gotcha.md) | **已知的坑、危险行为、没验证的部分**（出问题先看这个） |
| [readme-todo.md](doc/readme-todo.md) | 设计想法 / 还没做的 |
| [readme-android.md](doc/readme-android.md) | 安卓端**唯一文档**：当前状态（目录职责 / 6 个页面 / session 与用法 / 配置持久化 / 两处外部契约）+ 协议流程 + 关键设计决策 + 历史踩过的坑 |
| [readme-desktop.md](doc/readme-desktop.md) | 桌面端（`client/client-gui.py`）：外壳 / 主页（对齐安卓）/ 引擎桥数据流 / 按钮→命令表 / 自测覆盖 / **桌面端专属的 12 个坑** |
| [readme-ios.md](doc/readme-ios.md) | iOS 端**唯一文档**：目录职责 / 6 个页面 / session 与用法 / 配置持久化 / 协议（含 `session_key` 派生）/ 两处外部契约 / 与安卓的差异 / **12 条踩过的坑** |

> 服务端协议（WebSocket 消息类型、认证）在 [readme-udp.md](doc/readme-udp.md) / [readme-tcp.md](doc/readme-tcp.md) 里；
> 全部命令和参数的权威清单是客户端里敲 `help`（或看 [client/client.py](client/client.py) 的 `print_help()`）。
