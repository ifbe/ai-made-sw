# 洞上应用：vpn（单人单 tun/tap）

**本文讲什么**：`vpn` 这条路——**一个洞 ↔ 一块 `tun`/`tap` 设备**，两台机器之间拉一条三层/二层隧道。
"一堆对端插到同一台虚拟交换机"是另一条路，见 [readme-switch.md](readme-switch.md)。

---

## 1. 怎么起

**没有独立的 `vpn` 命令**（源码里 `process_input_line` 只有 `proxy`，没有 `vpn`/`tun`/`tap`）——
它只能通过"洞打通之后自动跑什么"这两个状态变量露出：

| 方式 | 取值 |
|---|---|
| `onholefromself <模式> [设备] [洞]` | 本端发起的洞打通后 |
| `onholefrompeer <模式> [设备] [洞]` | 对方发起的洞打通后 |

模式取 `tun` / `tap` / `auto`（`auto` 交给 vpn.py 自己判断），例如
`onholefrompeer tun`、`onholefrompeer tap tap0`、`onholefrompeer tun fd=21`（带洞标识 = 立刻在这条洞上拉起）。
启动参数是 `--onholefromself` / `--onholefrompeer`（CLI 参数与命令同名）。

| 图形端 | 位置 |
|---|---|
| 桌面 | vpn 页（`VpnPage`）：配置卡首行「配置 + 状态 + 启停」（`未接线` / `已接 N 条`），字段 `card 设备` / `tun 地址` / `交换模式` / `MTU` / `路由老化`，最后一行「内嵌 DHCP」开关；DHCP 卡默认隐藏 |
| Android | [`ui/VpnPage.kt`](../android/app/src/main/java/com/example/p2pnet/ui/VpnPage.kt) |
| iOS | [`UI/Pages/VpnPage.swift`](../ios/p2pnet/UI/Pages/VpnPage.swift) |

## 2. 拉起什么

`client.py:_launch_vpn()` → `python3 app/vpn.py --dev <tun|tap|auto> [--devname <设备名>]`
再由 `_launch_hole_program()` 补上 `--peeraddr/--peerport/--localport`（+ 可选 `--peercandidates` / `--remotelog`）。

vpn.py 自己做的事（见文件头 docstring）：bind 同一个本地 UDP 端口、往对端**所有候选**发包并学源地址、
洞 ↔ 设备双向透传、`KEEPALIVE_INTERVAL = 20.0` 秒发一个空数据报保 NAT；设备读写走
[`client/util/tun.py`](../client/util/tun.py) / [`client/util/tap.py`](../client/util/tap.py)。

## 3. 参数表（`app/vpn.py`，从代码读）

| 参数 | 默认 | 说明 |
|---|---|---|
| `--peeraddr` | **必填** | 对方 IP（v4/v6/域名） |
| `--peerport` | **必填**（int） | 对方端口 |
| `--localport` | **必填**（int） | 本地 UDP 端口（**沿用打洞时那个**） |
| `--localaddr` | `0.0.0.0` | 本地监听地址 |
| `--dev` | `tun` | 挂什么设备：`tun` / `tap` / `auto` |
| `--devname` | `None` | 设备名（如 `tun0` / `utun3`） |
| `--peercandidates` | `None` | 额外候选 `ip:port,ip:port` |
| `--remotelog` | `None` | 日志文件（默认 stdout） |

## 4. 当前状态

- **`app/vpn.py` 代码在**（10KB：真实 tun/tap 读写 + 双向透传 + 保活），**但我没做过端到端隧道验证** → **未验证**。
- **创建 tun/tap 需要系统允许**（macOS 上还要装驱动）；**是否需要 root 我没验证**，别当成已知条件。
- 图形端 vpn 页的「启动」按钮**只写日志**（Phase 1 骨架），页面本身不会拉起 vpn.py。
- 「内嵌 DHCP 服务器」卡**默认隐藏**，打开它也只显示卡片（内容是占位，`尚未实现`）。

## 5. 已知限制

- 有坑见 [readme-gotcha.md](readme-gotcha.md)（tun/tap 平台差异、设备名等）。

---

相关：[readme-cli.md](readme-cli.md)（`onholefromself/onholefrompeer` 取值表）、[readme-switch.md](readme-switch.md)（多人多洞那条路）、[readme-udp.md](readme-udp.md)（洞怎么打）、[readme-gotcha.md](readme-gotcha.md)、[readme-desktop.md](readme-desktop.md)（桌面 vpn 页）。
