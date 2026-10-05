# 洞上应用：switch（多人多洞虚拟交换机）

**本文讲什么**：`switch` 这条路——**一堆对端**把各自打好的 UDP 洞 `plug` 进**同一个** switch 进程，
由它做 L2/L3 转发（mesh）。"一个洞 ↔ 一块 tun/tap"是另一条路，见 [readme-vpn.md](readme-vpn.md)。

---

## 1. 怎么起

**没有独立的 `switch` 命令**，只有"洞打通之后自动跑什么"这一个入口：

| 方式 | 取值 |
|---|---|
| `onholefromself switch` / `onholefrompeer switch` | 洞打通后把这条洞插上去（也可带洞标识立刻插，如 `onholefrompeer switch fd=21`） |
| 启动参数 | `--onholefromself switch` / `--onholefrompeer switch` |

`client.py` 第一次要用到 switch 时，会**后台**拉起它（`new_window=False`），并用 `stdin/stdout` 管道当控制台：

```
python3 app/switch.py --type unixsocket --socketpath <sock> --ctlpath <ctl>
```

之后每条打好的洞由 `client.py` 转成一行**文本命令**写进它的 stdin（见 `_switch_text_of()`），回复也是文本（`ok …` / `err …`）；switch 自己的控制台人也能直接敲：

```
plug localport=50001 peer=1.2.3.4:30001 [candidates=a:1,b:2]   # 插一条洞（client.py 自动做）
unplug port1                    # 拔线
status / routes                 # 看状态 / 路由表
listenstart addr=0.0.0.0 port=15991 / listenstop   # 运行时开关监听
connect [2001:db8::3]:15991     # 主动 TCP 连对方（v6 直通那种）
route add <ip> port1            # 手工加静态路由
quit
```

| 图形端 | 位置 |
|---|---|
| 桌面 | switch 页（`SwitchPage`）：配置卡首行「配置 + 状态（`未插线` / `已插 N 个`）+ 启停」→ 内嵌 DHCP 卡（默认隐藏）→ 拓扑卡（最后，画连接拓扑） |
| Android | [`ui/SwitchPage.kt`](../android/app/src/main/java/com/example/p2pnet/ui/SwitchPage.kt) |
| iOS | [`UI/Pages/SwitchPage.swift`](../ios/p2pnet/UI/Pages/SwitchPage.swift) |

## 2. 拉起什么

[`client/app/switch.py`](../client/app/switch.py)（55KB）：L2（MAC 表）/ L3（IP 表）转发、可选的 `tun`/`tap` card、
运行时动态监听、主动 `connect`、以及用 `SCM_RIGHTS` 从 `client.py` 收已建立的 TCP fd（插网线）。
日志走 stderr，控制台走 stdin/stdout。

## 3. 参数表（`app/switch.py`，从代码读）

| 参数 | 默认 | 说明 |
|---|---|---|
| `--tun-ip` | `None` | 启动时配到 tun 上的 IPv4 地址（`192.168.250.55` 或 `…/24`）；**不给就不设地址** |
| `--tun-mtu` | `1400` | card 设备 MTU（1500 的包套 UDP/IP 头会超网卡 MTU，所以默认降下来） |
| `--route-ttl` | `300.0` | 学到的路由/MAC 多久没出现就老化（秒；`0` = 不老化；手工静态路由永不老化） |
| `--switch-mode` | `None`（自动） | `l2` = MAC 表 / `l3` = IP 表 / `auto` |
| `--card` | **`none`** | `none` = 不开设备（默认）/ `tun`（加剥假 eth 头）/ `tap`（直接透传） |
| `--type` | `bindtcpsocket` | 与 `udpxxx.py` 的交互方式：TCP 127.0.0.1 端口 / `unixsocket` |
| `--base-port` | `15991` | `--type bindtcpsocket` 时的起始端口 |
| `--socketpath` / `--ctlpath` | `None` | `--type unixsocket` 的 socket 路径 / 控制通道（后者给 `SCM_RIGHTS` 传 TCP fd）；**client.py 两个都会传** |
| `--log` | `None` | 日志文件（默认 stderr） |

注意：`client.py` 启动 switch 时**只传** `--type unixsocket --socketpath … --ctlpath …`，
`--tun-ip/--tun-mtu/--route-ttl/--switch-mode/--card` 都走各自的默认值。

## 4. 当前状态

- **`app/switch.py` 代码在**（真转发代码 + 文本控制台），**但我没做过端到端组网验证** → **未验证**。
- **默认不开 card**：`--card` 默认 `none`，而 `client.py` 不传这个参数
  → 从命令行拉起的 switch **不会**建 tun/tap 设备（"本机 IP 包从 card 进出"这条要先给它 `--card tun/tap`）。
- 图形端 switch 页的「启动」按钮、`card 设备` / `交换模式` / `MTU` / `路由老化` 这些字段**都只是页面**（按了只写日志）；
  拓扑卡目前画的是**空槽位**（`未插线`），不连着真实的洞数据。

## 5. 已知限制

- 有坑见 [readme-gotcha.md](readme-gotcha.md)。
- 三种接入方式：`plug`（client.py 打好的洞，**默认通**）、`--ctlpath`（继承已建立的 TCP fd，`client.py` 启动时**一定会传**）、
  `listenstart`/`connect`（switch 自己监听/主动连，`client.py` 不碰，要人到它的控制台里敲）。

---

相关：[readme-cli.md](readme-cli.md)（`onholefromself/onholefrompeer` 取值表）、[readme-vpn.md](readme-vpn.md)（单人单 tun 那条路）、[readme-udp.md](readme-udp.md)（洞怎么打）、[readme-tcp.md](readme-tcp.md)（TCP fd 这条路）、[readme-gotcha.md](readme-gotcha.md)、[readme-desktop.md](readme-desktop.md)（桌面 switch 页）。
