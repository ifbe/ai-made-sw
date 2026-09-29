# UDP 打洞：6 步 + 候选地址 + app/udptest.py

本文讲 UDP 洞怎么打、怎么交出去：`client/hole/udp.py` 的 6 步、候选地址（peer-reflexive）、
打完洞由 `client/app/udptest.py` 接管做互发测试。

## 谁干什么

| 文件 | 在哪跑 | 干什么 |
|---|---|---|
| [client/hole/udp.py](client/hole/udp.py) | client.py 主进程（第 5/6 步一个线程） | 走第 1~6 步；**socket 也归主进程持有** |
| [client/hole/core.py](client/hole/core.py) | 同上 | 每一步打一行：`[洞 #1 bob] [3/6] 正在往服务器发 hello  （✓） ...` |
| [client/app/udptest.py](client/app/udptest.py) | 子进程 | 只做互发 ping/pong 测试，不挂 tun/tap |
| [server/server.py](server/server.py) | 服务器 | `handle_p2pudp()` + UDP 线程 `udp_server_thread()` |

**不是**收到 `thisisyourpeer_udp` 就 spawn 子进程：打洞第 5、6 步在 client.py 主进程里做完，
只有把洞交给某个用法（`udptest <洞>` / `onholefrompeer tun` …）时才拉子进程。见下面「移交」。

## 消息类型

| 方向 | type | 内容 / 说明 |
|---|---|---|
| C→S | `p2pudp` | `{"type":"p2pudp","target":"bob"}`；CLI 命令 `udp <user>` 发的就是它 |
| S→C | `send_udp_to_server` | `{"udpport":10000}`；**主动方和被动方都收到**，被动方不用敲命令 |
| C→S(UDP) | `p2pudp_hello` | `{"type":"p2pudp_hello","username":...,"signature":HMAC(session_key,"ping")}` |
| S→C | `thisisyourpeer_udp` | `name` 对端用户名 / `ip`,`port` 对端公网地址 / `my_ip`,`my_port` 本端被 NAT 看到的地址 |
| S→C | `error` | 被拒，例如 `user not found`（第 2 步直接打 ✗） |

服务端状态：`udp_addrs[username] = {"ip","port","timestamp"}`、`p2p_requests[username] = {"target","timestamp"}`。
`p2pudp` 会先清掉双方的 `udp_addrs`，保证只用本轮 burst 的地址；双方地址都到齐后立刻删掉
`p2p_requests`，后面的 burst 包不会再触发一次通知。

## 6 步

| 步 | 谁做 | 做什么 | 关键常数 |
|---|---|---|---|
| 1 | 客户端 | 发 `p2pudp` | — |
| 2 | 服务器 → 双方 | 各回一条 `send_udp_to_server` | 等不到 `STEP_RESPONSE_TIMEOUT=10s`（✗ 记在第 2 步） |
| 3 | 客户端 | 建 UDP socket 绑**随机高位端口**（50000~65000 试 20 次，失败让内核挑）→ 往服务器 UDP 端口发 `p2pudp_hello` | 15 包 burst @30ms，之后 1/s 维持 |
| 4 | 服务器 → 双方 | 两边 hello 都到 → 各发 `thisisyourpeer_udp`；客户端拿回第 3 步那个 socket | 服务器等地址 `P2P_REQUEST_TIMEOUT=30s`；客户端没等到地址 `HELLO_TIMEOUT=10s` |
| 5 | 客户端（主进程） | 往对端**所有候选地址**发 `{"type":"ping","seq":N,"ts":...}` 抢 NAT 映射 | 起始 15 包 burst @30ms，之后 1/s |
| 6 | 客户端（主进程） | 收到对方任何 `ping`/`pong` → `status='已打通'`，回填 RTT，调 `core.on_udp_ready(hole)` | `HOLE_CONFIRM_TIMEOUT=30s`（到点还没收到就失败） |

收到 `ping` **就地**往实际来源地址回 `pong` —— 所以只要有一个方向通就能救回来。

### 真实日志（一次成功的打洞）

```
[17:57:27][client] [洞 #1 bob] [1/6] 正在通知服务器  （✓） p2pudp -> bob
[17:57:27][client] [洞 #1 bob] [2/6] 正在等服务器要求发给 udp  （✓） 127.0.0.1:10095
[17:57:27][client] [打洞] 本端 UDP fd=4 端口=62497，往服务器 127.0.0.1:10095 发 hello...
[17:57:27][client] [洞 #1 bob] [3/6] 正在往服务器发 hello  （✓） UDP hello ×15（服务器已记录本端公网地址）
[17:57:27][client] [洞 #1 bob] [4/6] 正在等服务器告知双方地址  （✓） 本端 fd=4 127.0.0.1:62497 ↔ 对端 127.0.0.1:54762
[17:57:27][client] [洞 #1 bob] [5/6] 正在往对方发消息  （✓） 主进程 ping 对端
[17:57:27][client] [洞 #1 bob] [6/6] 正在等对方消息  （✓） 本端 fd=4 127.0.0.1:62497 ↔ 对端 127.0.0.1:54762
[17:57:27][client] [洞 #1] onholefromself 未设定（本端发起），不自动拉起；洞保持打通状态，用 udptest fd=4 等自己拉起
```

### 失败长什么样

```
[16:47:04][client] [洞 #1 nobody] [2/6] 正在等服务器要求发给 udp  （✗） user not found
[16:48:16][client] [洞 #3 bob] [4/6] 正在等服务器告知双方地址  （✗） 10s 没等到服务器告知地址（fd=5 端口=59293）
[..][client] [洞 #1 bob] [6/6] 正在等对方消息  （✗） 30s 没收到对方消息，打洞失败
```

前两条是真实日志；第三条是第 6 步 30s 到点时的文案（`_udp_hole_loop`）。

`[DEBUG]` 打开时第 3 步的 hello 内容会打出来：`[DEBUG] UDP hello -> <ip>:<port>: {payload}`。

## 候选地址（peer-reflexive）

`hole['candidates']` 就是"这轮往哪些地址发"。

| 规则 | 细节 |
|---|---|
| 第 0 个 | 服务器给的 srflx（`thisisyourpeer_udp` 的 `ip:port`），**永远保底留着** |
| 怎么追加 | 第 5/6 步每收到一个包，先把 `recvfrom` 的源地址记成候选（还没解析 JSON 就记） |
| 上限 | `HOLE_MAX_CANDIDATES=4`；满了 `pop(1)`（从第 1 个开始丢，服务器给的那个不动） |
| 当前对端地址 | 学到新源地址就把它设成 `peer_ip/peer_port` |
| 每轮怎么发 | 往**所有候选各发一份**：burst 期间 30ms 一轮，之后 1s 一轮（`_hole_candidates()`） |
| 为什么 | 对称 NAT 给"到不同目的地"的流量分配不同公网端口，服务器给的地址可能不是对方对我们用的那个；`recvfrom` 看到的源地址一定是对的 |

真实日志（两个候选、旧的 srflx 也还在继续发）：

```
[18:02:51][client] [洞 #1] 对端地址换成 127.0.0.1:38310（新候选，候选共 2 个）
```

同一段逻辑的 else 分支（这个源地址已经是当前对端地址、只是候选表里之前没有它）：
`[洞 #N] 记下对端候选 ip:port（候选共 N 个）`。

移交时，除了当前对端地址以外的候选会一起交给使用者程序：

```
[18:02:55][client] [P2P] 额外候选地址: 1.1.1.1:1111
```

`list hole` 里候选数 >1 会显示 `候选=N`。

## 移交：关掉自己的 socket，子进程 bind 同一个本地端口

打通用 `core.on_udp_ready(hole)` 回调 client.py，由 `_auto_handover()` 决定拉谁；
真正动手的是 `_handover_hole(hole, usage, device)`：

1. `hole['stop'].set()`；
2. 关掉主进程的 socket（`hole['sock'] = None`）；
3. `join` 那个 ping 线程（最多 2s），把本地端口让出来；
4. 拉起使用者程序；
5. `hole['handed_to'] = usage`，`status = '已交给 <usage>'`。

只传地址/端口，**不传 fd**。使用者程序自己 bind 同一个本地端口，NAT 映射才不废。

| 命令行参数 | 值 |
|---|---|
| `--peeraddr` / `--peerport` | `hole['peer_ip']` / `hole['peer_port']`（最后学到的那个对端地址） |
| `--localport` | `hole['my_port']`（打洞时那个本地端口） |
| `--peercandidates` | 除当前对端外的所有候选，`ip:port,ip:port`（有才传） |
| `--remotelog` | `--remotelog` 打开时写 `/tmp/p2pnet/<名字>-<用户>_<对端>_<时间戳>.log` |

真实命令行（当前对端 `2.2.2.2:2222`，额外候选 `1.1.1.1:1111`）：

```bash
python3 app/udptest.py --peeraddr 2.2.2.2 --peerport 2222 --localport 2222 --peercandidates 1.1.1.1:1111
```

`cwd` 是 `client/` 目录，所以是 `app/udptest.py`。

### 什么时候自动拉、什么时候等你手动

| 情况 | 行为 | 日志 |
|---|---|---|
| 设了 `onholefromself`（本端发起的洞）/ `onholefrompeer`（对方发起的洞） | 自动拉起 | `[洞 #1] onholefromself = udptest（本端发起），打洞成功，自动拉起...` |
| 两个都没设（默认） | 只记录，洞保持"已打通" | `[洞 #1] onholefrompeer 未设定（对方发起），不自动拉起；洞保持打通状态，用 udptest fd=5 等自己拉起` |
| `udp <user>` 之前敲过 `ffmpeg <user>` / `wg-py <user>` | 一次性用法优先于上面两个 | — |

自己拉的样子：

```
> list hole
[13:32:17][client] === 洞 ===
[13:32:17][client]   #1   udp  已交给 udptest    bob            fd=4      本端 127.0.0.1:61439  对端 127.0.0.1:50956  RTT=1ms

> udptest fd=4          # 洞标识: fd=<fd> / port=<本端端口> / #<编号> / <用户名>
```

还没交出去时会多一行提示：

```
[12:45:26][client]   #1   udp  已打通            bob            fd=4      本端 127.0.0.1:52195  对端 127.0.0.1:58774  RTT=1ms
[12:45:26][client]   已打通，可拉起: udptest fd=4
```

一个洞只能交一次：`[洞 #1] 已经交给 udptest，不能重复拉起`。
TCP 洞走不了这条路：`[洞 #1] 是 tcp 洞，不能这样拉起`（见 [readme-tcp.md](readme-tcp.md)）。

## app/udptest.py：洞上的互发测试

它只做三件事：bind 同一个本地端口、每秒发 ping、收 pong 算 RTT。

| 参数 | 必填 | 说明 |
|---|---|---|
| `--peeraddr` | ✔ | 对方 IP（IPv4/IPv6/域名） |
| `--peerport` | ✔ | 对方端口 |
| `--localport` | ✔ | 本地 UDP 端口（沿用打洞时那个） |
| `--peercandidates` | | `ip:port,ip:port`，打洞阶段学到的额外候选 |
| `--localaddr` | | 默认 `0.0.0.0` |
| `--remotelog` | | 日志文件，默认 stdout |

行为：

- bind 时带 `SO_REUSEADDR` + `SO_REUSEPORT`；
- 主循环每秒发 `{"type":"ping","seq":N,"ts":<time.time()>}`，**往所有候选各发一份**；
- 收到 `ping` → 回 `{"type":"pong","seq":N,"ts":<原样带回>}`，并把它当新候选（`update_peer`）；
- 收到 `pong` → 算 RTT、`streak+1`；**连续 3 个 pong**（`READY_PONGS`）打印 `✅ P2P 就绪！`；
- 5s（`PING_TIMEOUT`）没收到 pong：已就绪 → 断开退出；还没就绪 → 等到 10s 放弃；
- 收 SIGINT/SIGTERM 关 socket、清线程退出。

真实日志：

```
[17:57:30][udptest.py main]  本端: 0.0.0.0:62497 (IPv4)
[17:57:30][udptest.py main]  目标: 127.0.0.1:54762
[17:57:30][udptest.py main]  send beat: {"type": "ping", "seq": 0, "ts": 1790675850.8744147}
[17:57:30][udptest.py handle_incoming]  recv beat: {'type': 'pong', 'seq': 0}
[17:57:30][udptest.py handle_incoming]    RTT=1ms streak=1 ping=1 pong=1
[17:57:31][udptest.py handle_incoming]  recv beat: {'type': 'ping', 'seq': 17, 'ts': 1790675851.269518}
[17:57:31][udptest.py handle_incoming]  send beat: {"type": "pong", "seq": 17, "ts": 1790675851.269518}
[17:57:31][udptest.py handle_incoming]    RTT=1ms streak=2 ping=2 pong=2
[17:57:32][udptest.py handle_incoming]    RTT=1ms streak=3 ping=3 pong=3
[17:57:32][udptest.py handle_incoming]  ✅ P2P 就绪！
[17:57:34][udptest.py main]  收到信号 15，准备退出...
[17:57:34][udptest.py main]  进程退出
```

RTT=0ms 有两种可能：seq 不在发送窗口里（重复 pong），或者真的 <1ms（本机回环）。

回 [readme.md](readme.md) ｜ TCP 版见 [readme-tcp.md](readme-tcp.md) ｜ 已知的坑见 [readme-gotcha.md](readme-gotcha.md)
