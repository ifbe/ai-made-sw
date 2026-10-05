# 命令行客户端（`client/client.py`）

这是 **cli** 客户端，也是另外三端的**参照实现**：

- **desktop**（`client/client-gui.py`）是**进程内**驱动这个模块（`import client`，不起子进程），所以本文的命令与行为桌面端同样适用；
- **android / ios** 是原生重实现（同协议、同页面形态），差异见各自的文档。

> **全部命令与参数的权威清单是客户端里敲 `help`**（或看 `client/client.py` 的 `print_help()`）。
> 本文只讲启动方式、命令分组与几个"不看代码不知道"的行为。

服务端怎么起、用户怎么建 → [readme-server.md](readme-server.md)。

## 启动

```bash
# 交互式（自己输入用户名/密码）
python3 client/client.py --server 127.0.0.1 --port 10000

# 自动登录
python3 client/client.py --server 127.0.0.1 --port 10000 --user alice --pass pw
```

最小用法：

```
udp bob              # 打洞，6 步一行一行打出来
list hole            # 看洞表（fd / 本端 / 对端 / 状态）
udptest fd=4         # 把这个洞交给互发测试
```

## 命令

| 命令 | 作用 |
|---|---|
| `udp <user>` | 和对方打 UDP 洞（6 步） |
| `tcp <user>` | 和对方打 TCP 洞（5 步，把已建立的内核连接交给子进程） |
| `direct <user>` | 不打洞，看对方哪些地址可达（服务端中转 `p2pdirect`） |
| `upnp` | 让路由器开端口映射（**协议待定、还没实现**：命令在，`hole/upnp.py` 只打计划） |
| `udptest <洞>` | 洞上跑互发测试（ping/pong + RTT） |
| `proxy <洞> <host:port>` | 把洞里的数据转发到这个地址（图形端 proxy 页有 `-L`/`-R` 两种模式） |
| `ffmpeg <洞>` | 洞上跑 ffmpeg 视频 |
| `wg-py <洞> [pubkey=<对方公钥>]` | 洞上跑**自己实现的** WireGuard（`app/wg-python.py`，不用 root） |
| `wg-sh <洞> <我的私钥> <我的meshIP> <对方公钥> <对方meshIP> [接口名]` | 洞上调**系统 wg**（`app/wg-calltool.py` → `wghelp.sh`，需 root） |
| `ping` | 发一条**应用层** ping（见下面"心跳"一节） |
| `help` / `quit` | 帮助 / 退出（`quit` 属**主动断开**，不会触发自动重连） |

## 洞打通之后自动跑什么

由两个状态变量决定：`onholefromself`（本端发起的洞）/ `onholefrompeer`（对方发起的洞），可选值：

`none`（默认，只记录不拉起）/ `udptest` / `tun [设备]` / `tap [设备]` / `auto` / `switch` / `proxy <host:port>` / `ffmpeg` / `wg-py` / `wg-sh`。

## 别人来找我时参不参与

由四个开关决定：`onpeerwantudp` / `onpeerwanttcp` / `onpeerwantdirect` / `onpeerwantupnp`（`auto` 默认 / `none` 静默拒绝）。

## 心跳与自动重连

两层，别混：

**① 协议级心跳（保活 + 判死）**

- 连上后每 **20 秒**发一个 WebSocket `0x9` ping 帧（服务端**原样回** `0xA` pong）；
- 每次**发之前**打一行日志（`WS 心跳：发出协议级 ping（第 N 次，间隔 20s）`），**收到 pong** 再打一行（`WS 心跳：收到协议级 pong（第 N 次）`）；
- **判死**：某次 ping 发出后，**自那次 ping 起一直没收到任何字节**（不是"距上次收字节多久"）**且已过 10 秒**
  → 判定连接已死，打一行 `pong 超时：连接已断开（WS 心跳失败）`。
  （边界：`last_rx == ping_at` 同一瞬间算"收到了"，不判死。这个条件写错会变成"每个周期都稳定误判死"。）
- 心跳**在握手成功后自动启动**（`ws_handshake()` 里），所以命令行与桌面端两种模式都有；判活信号只能来自**读方**
  （谁读 socket 谁调 `note_ws_rx()`），心跳线程只发不读。

**② 自动重连（带熔断）**

- **判据只看"断开前的最后状态"**（四端统一）：

  | 断开前的最后状态 | 连接 | 自动重连 | 自动重新登录 |
  |---|---|---|---|
  | 用户主动断开（`quit` / 点"断开"） | 主动关 | ❌ | ❌ |
  | 已登录 | 被动断开 | ✅ | ✅（用内存里保存的凭据） |
  | 已连接、未登录 | 被动断开 | ✅ | ❌（只恢复连接） |

  **被服务器踢下线不单列规则**：踢只做一件事 —— 把状态从"已登录"打回"已连接未登录"
  （清 `logged_in_user`/`session_key` 并关掉各洞），日志是
  `被服务器踢下线（<服务端 message>）：登录已取消，不会自动重新登录`；
  它**不碰传输层**（不关连接、不停心跳），连接仍然可用（再发命令服务端会回 `not logged in`）。
  之后这条连接若被动断开，自然落进"已连接、未登录"那一行 → 重连但不自动重登；
  **用户被踢后手动 `login` 成功（状态回到已登录）再掉线，就又会正常自动重登** —— 状态本身就是真相。
- 重登**只试一次**：登录失败不循环重试，等用户手动。两行统一文案：
  `WS 自动重连：连接已恢复，断开前未登录，不自动重新登录` /
  `WS 自动重连：连接已恢复，但没有可用的凭据，需要手动重新登录`。
- 触发③的条件：心跳判死 / 异常断开（对端直接关连接会**立刻**识别：`recv` 返回空就是断开，
  和"非阻塞暂时没数据"分开，所以不必等心跳那 30 秒）。**不触发**：用户主动 `quit` 或手动断开、以及**首次**连接就失败；
- 退避 **1s → 2s → 4s**；**60 秒窗口内最多 3 次**，超了打一行
  `WS 自动重连已放弃：60 秒内已重连 3 次仍失败（不再自动重连，请手动连接）` 并停手；
- 过程日志（每次尝试 / 成功各一行）：
  `WS 自动重连：第 N 次（60 秒窗口内）`、`WS 自动重连成功（第 N 次）`；
- **计数清零**：手动连接、或连接**稳定存活 ≥60 秒**；
- 重连成功后，若断开前已登录（且没被踢过），会用内存里保存的凭据**自动重新登录**，日志是
  `WS 自动重连：用保存的凭据重新登录`（服务端对同名重登的处理是"踢掉旧连接、接受新连接"）；
  拿不到凭据时只恢复连接并如实打日志。
- **实现在 `client.py`**（`ws_connect_once` / `ws_reconnect_plan` / `ws_auto_reconnect` / `mark_disconnected` /
  `resume_login`），所以**单独跑 `python3 client/client.py` 就有**这套行为；桌面端只是起一条线程去调
  `ws_auto_reconnect()`，两模式日志逐字相同。

**③ 应用层 ping（`ping` 命令）**

发 `{"type":"ping","seq":N}`，服务端回 `{"type":"pong","seq":N}`（**不需要登录**）；发出的报文与收到的 pong（含 RTT）都打在日志里。这是给人**手动验证链路**用的，和上面 ① 的协议级心跳不是一回事。

## 代码分层

```
hole/    打洞那几步（client.py 主进程里跑）
app/     打完洞之后的"使用者程序"（子进程，接管那个洞）
util/    底层设施（tun/tap 驱动、crypto、kcp）
```

相关：[readme-udp.md](readme-udp.md)（UDP 6 步）、[readme-tcp.md](readme-tcp.md)（TCP 5 步）、[readme-direct.md](readme-direct.md)、[readme-wg.md](readme-wg.md)、[readme-upnp.md](readme-upnp.md)。
