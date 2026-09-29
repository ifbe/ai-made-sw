# TCP 打洞：5 步 + fd 继承 + app/tcptest.py

本文讲 TCP 洞怎么打、怎么交出去：`client/hole/tcp.py` 的 5 步（三个 socket 绑同一个本地端口、
注册也从那个端口发、谁先成留谁、两边都成挑同一条），以及为什么只能把**已建立连接的内核 socket**
继承给 `client/app/tcptest.py`。

## 谁干什么

| 文件 | 在哪跑 | 干什么 |
|---|---|---|
| [client/hole/tcp.py](client/hole/tcp.py) | client.py 主进程 | 第 1~5 步；第 5 步的 listen/connect 抢连接也在这里做 |
| [client/hole/core.py](client/hole/core.py) | 同上 | 每一步打一行：`[洞 #1 bob] [3/5] 正在向服务器注册  （✓） ...` |
| [client/app/tcptest.py](client/app/tcptest.py) | 子进程（继承 fd） | 拿着那条已连接的 socket 做互发 ping/pong |
| [server/server.py](server/server.py) | 服务器 | `handle_p2ptcp()` + 主端口上的注册处理 `handle_tcp_p2p_registration()` |

## 消息类型

| 方向 | type | 内容 / 说明 |
|---|---|---|
| C→S | `p2ptcp` | `{"type":"p2ptcp","target":"bob"}`；CLI 命令 `tcp <user>` 发的就是它 |
| S→C | `send_tcp_to_server` | `{"tcpport":10000}`；**主动方和被动方都收到** |
| C→S(TCP) | 注册 JSON | `{"username":...,"signature":HMAC(session_key,"ping")}` + `\n`，直接连**主端口** |
| S→C | `thisisyourpeer_tcp` | `name` / `ip`,`port` 对端公网地址 / `my_ip`,`my_port` 本端被 NAT 看到的地址 |
| S→C | `error` | 被拒，例如 `user not found` |

注册复用主端口（默认 `--port`，即 WebSocket 那个口）：服务器 accept 后 peek 第一个字节，
是 `{` 就当打洞注册（`_read_p2p_registration()`），否则当 HTTP/WS 收下。

服务端状态：`p2p_tcp_requests[username] = {"target","timestamp"}`、
`tcp_peer_info[username] = {"ip","port","target"}`。第二个来注册的人到齐时，服务器把
`thisisyourpeer_tcp` 交叉发给双方，然后关掉自己这端的注册连接；客户端那份**先不关**（见第 3 步）。

## 5 步

| 步 | 谁做 | 做什么 | 关键常数 |
|---|---|---|---|
| 1 | 客户端 | 发 `p2ptcp` | 等服务器要求 `STEP_RESPONSE_TIMEOUT=10s` |
| 2 | 服务器 → 双方 | 各回一条 `send_tcp_to_server` | — |
| 3 | 客户端 | **从打洞端口 P** 连服务器发注册包；这条 socket **要留着不关** | 它就是 P 上 NAT 映射的来源 |
| 4 | 服务器 → 双方 | 地址到齐 → 各发 `thisisyourpeer_tcp` | 等不到 `TCP_ADDR_TIMEOUT=30s` |
| 5 | 客户端（主进程） | 三个 socket 都在 P 上：同时 `listen(P)` + `connect(对端)`，谁先成就留谁；把那个已连接的 socket 交出去 | `PUNCH_TIMEOUT=15s`、connect 失败 0.25s 后重建重试、一边成后再等 `BOTH_WAIT=0.3s` |

### 第 3 步：注册必须从 P 发，而且 socket 留着

- 打洞端口 P 先随机挑（`_pick_local_port()`：50000~65000 试 20 次，失败就 `0` 让内核挑）；
- 注册 socket 也 `bind(0.0.0.0, P)`（`SO_REUSEADDR` + `SO_REUSEPORT`），再 `connect(服务器)`；
- **不能像 UDP 那样发完就关**：这条连接一旦关了，P 上的映射就可能被回收。等到第 5 步打完洞才关；
- 服务器靠这条连接记下你的公网 `地址:端口`，对方要连的就是这个。

真实日志：

```
[17:13:17][client] [洞 #1 bob] [3/5] 正在向服务器注册  （✓） 从本端端口 55768 注册（NAT 映射就建在这个端口上）
[17:57:11][client] [洞 #1 bob] [4/5] 正在等服务器告知双方地址  （✓） 本端 127.0.0.1:57542 ↔ 对端 127.0.0.1:50441
```

服务端那一侧（默认就打印）：

```
[TCP] alice P2P 注册来自 1.2.3.4:55768 (签名验证通过)
[P2P-TCP] alice <-> bob 地址已交换，双方可以开始打洞
```

### 第 5 步：三个 socket 都绑在 P 上

| socket | 怎么建 | 作用 |
|---|---|---|
| 注册 socket `_reg_sock` | 第 3 步留下的，绑 P | 占着 P 的 NAT 映射；洞打完后关 |
| `listen_sock` | `_bind_reusable(family, P)` + `listen(8)` | 等对方的 SYN |
| `conn_sock` | 每次重试都新建，也绑 P | `connect(对端公网地址)` |

`select` 循环（0.2s 一轮）同时等两边，直到 `PUNCH_TIMEOUT=15s`：

- `accept()` 返回 → **对方的连接进来了**；
- `connect` 完成（`SO_ERROR == 0`）→ **我们连上对方了**；
- connect 失败就关掉重建，`CONNECT_RETRY_INTERVAL=0.25s` 后再来（非阻塞 connect 的
  `EINPROGRESS` 不算失败，走 select 等）；
- 一边成之后不立刻收工，再等 `BOTH_WAIT=0.3s` 看另一边是不是也成了（两边都成必须挑同一条）。

两条都成了怎么挑（`_pick_tie_break`）：

| 情况 | 留哪条 |
|---|---|
| 只有对方连进来 | `accepted` |
| 只有我们连上 | `connected` |
| 两条都成（同时 open） | 比较两端公网 `地址:端口`：**本端小 → 留我们自己发起的那条**，否则留对方连进来的那条 |

对端算的是同一件事（它那边的 my / peer 正好相反）→ 两边结果一致。
比较的是字符串（`f"{ip}:{port}"`），IPv6 也按同一套规则。

真实日志（一条连接的两端：一边 connect 成功，另一边 accept 成功）：

```
（alice / 主动发起）
[17:13:17][client] [洞 #1 bob] [5/5] 正在同时 listen/connect 打洞，再把内核 socket 交出去
[17:13:17][client] [tcp] 同时开 listen 和 connect（都绑在端口 55768 上）...
[17:13:17][client] [tcp] listen 已就绪（0.0.0.0:55768）
[17:13:17][client] [tcp] ✅ 我们连上对方了
[17:13:18][client] [洞 #1 bob] [5/5] 正在同时 listen/connect 打洞，再把内核 socket 交出去  （✓） 本地 fd=6（127.0.0.1:57101）

（bob / 被动收到）
[17:13:17][client] [洞 #1 alice] [5/5] 正在同时 listen/connect 打洞，再把内核 socket 交出去
[17:13:17][client] [tcp] 同时开 listen 和 connect（都绑在端口 57101 上）...
[17:13:17][client] [tcp] listen 已就绪（0.0.0.0:57101）
[17:13:17][client] [tcp] ✅ 对方的连接进来了（127.0.0.1:55768）
[17:13:18][client] [洞 #1 alice] [5/5] 正在同时 listen/connect 打洞，再把内核 socket 交出去  （✓） 本地 fd=6（127.0.0.1:55768）
```

第 5 步的耗时通常跨过 1 秒，所以 `core.result` 会把整行重写一遍——日志里第 5 步会看到两行，
后一行才是带 `（✓）` 的完整行。

`[tcp] connect -> <ip>:<port>（源端口 P）` 只在 `connect()` 立即返回时才打；正常非阻塞 connect
抛 `EINPROGRESS` 走 select，不打这行。两条都成时会多一行：
`[tcp] 两条都成了（同时 open），按规则留 进来的/我们发起的 那条，关掉另一条`。

### 失败长什么样

```
[12:42:24][client] [洞 #2 bob] [4/5] 正在等服务器告知双方地址  （✗） 服务器一直没告知双方地址
[..][client] [洞 #1 bob] [5/5] 正在同时 listen/connect 打洞，再把内核 socket 交出去  （✗） 15s 内 listen/connect 都没成（对方不在或防火墙挡了）
[..][client] [洞 #1 bob] [3/5] 正在向服务器注册  （✗） 注册失败: <异常>
```

第一条是真实日志；后两条是各自超时/异常时的文案（`tcp.py`）。

## 为什么不能像 UDP 那样移交

| | UDP 洞 | TCP 洞 |
|---|---|---|
| 主进程关掉自己的 socket 之后 | NAT 映射不受影响，子进程 bind 同一个本地端口接着用 | **连接就没了**；子进程重新 `bind` + `connect` 会重新 SYN/ACK，NAT 那边对不上 |
| 所以交接的是 | 地址/端口（`--peeraddr` … `--peercandidates`） | **已建立连接的内核 socket 本身**（fd） |
| 代价 | 无 | 只能后台拉起（新终端窗口没法继承 fd），看不到窗口，只能看日志 |

## 交 fd：pass_fds → app/tcptest.py

`_launch_tcp_on_hole(hole, sock, ...)`：

1. `os.set_inheritable(fd, True)`；
2. 后台拉起 `python3 app/tcptest.py --hole-fd <fd> --peername <名字>`，`pass_fds=(fd,)`；
3. Popen 之后父进程把自己那份 `sock.close()` —— 内核里子进程那份撑着，**不是关连接**；
4. `hole['tcp_fd'] = fd`。

真实日志（紧接上面的第 5 步）：

```
[17:13:18][client] [P2P] 把已建立的连接（内核 fd=6）继承给 app/tcptest.py（对端 127.0.0.1:57101）
[17:13:18][client] [P2P] tcptest.py 已拉起（fd=6）
```

Windows 没有 `pass_fds`，`launch_in_new_terminal` 走的是
`os.set_handle_inheritable(msvcrt.get_osfhandle(fd), True)` + `close_fds=False`（**没有环境验证过**，
见 [readme-gotcha.md](readme-gotcha.md)）。

TCP 洞的去处只有两个：

| 条件 | 去哪 |
|---|---|
| `onholefromself` / `onholefrompeer` = `switch` | 常驻的 `app/switch.py`：走 Unix socket 的 `SCM_RIGHTS` 把 fd 送进去（只有 POSIX） |
| 其它任何取值 / 没设 | `app/tcptest.py`（`pass_fds` 继承 fd） |

switch 那条路的日志：

```
[17:57:11][client] [P2P] 已把 fd=9（对端 127.0.0.1:50441）送进 switch，插成 port1
```

## app/tcptest.py：接管 fd 做互发测试

```bash
python3 app/tcptest.py --hole-fd <N> [--peername <名字>] [--remotelog <文件>]
                       [--interval <秒>] [--timeout <秒>] [--ready-count <N>]
```

| 参数 | 说明 |
|---|---|
| `--hole-fd` | 必填，父进程继承过来的**已连接**socket 的 fd 号 |
| `--peername` | 只用于日志 |
| `--interval` | 心跳间隔，默认 1.0s |
| `--timeout` | 多久没收到对方任何消息算断，默认 5.0s |
| `--ready-count` | 连续几个 pong 算就绪，默认 3 |
| `--remotelog` | 日志文件，默认 stdout |

接管和收发：

- 先用 `os.fstat(fd)` 确认是 socket，再 `socket.socket(fileno=fd)` 包住它；
- **绝不 bind / listen / connect、也不关掉重建**，就当它是一条已经建好的字节流；
- 分帧：**行分隔 JSON** —— 每条消息一行 JSON + `\n`，自己按 `\n` 切缓冲区
  （单行超过 1MiB 认为对方不是本程序，丢弃该行）；
  刻意不用 `sock.makefile('rb')`，超时后它会记死状态、之后再也读不出数据；
- 每秒发 `{"type":"ping","seq":N,"ts":...}`；收到 `ping` 回 `pong`；收到 `pong` 算 RTT；
- **连续 3 个 pong** → `✅ TCP P2P 就绪！`；
- 5s 没收到对方任何消息（`--timeout`）→ 断开退出；对端关闭或 RST 也退出；
- 退出时打统计：`统计: 发送 ping=N 收到 pong=N 未就绪=否 非法行=0 平均 RTT=1.0ms`。

真实日志：

```
[17:13:18][tcptest.py main]  接管洞: fd=6 本端=127.0.0.1:55768 对端=127.0.0.1:57101
[17:13:18][tcptest.py main]  对端名字: bob
[17:13:18][tcptest.py main]  心跳间隔 1.0s，超时 5.0s，就绪需 3 个 pong
[17:13:18][tcptest.py tcp_listener]  启动
[17:13:18][tcptest.py main]  主循环开始，等待 TCP P2P 就绪...
[17:13:18][tcptest.py main]  send beat: {"type": "ping", "seq": 0, "ts": 1790673198.1219015}
[17:13:18][tcptest.py handle_line]  recv beat: {"type": "pong", "seq": 0, "ts": 1790673198.1219015}
[17:13:18][tcptest.py handle_line]    RTT=8ms streak=1 ping=1 pong=1
[17:13:20][tcptest.py handle_line]    RTT=1ms streak=3 ping=3 pong=3
[17:13:20][tcptest.py handle_line]  ✅ TCP P2P 就绪！
```

## TCP 和 UDP 的差异对照

| 项目 | UDP（[readme-udp.md](readme-udp.md)） | TCP |
|---|---|---|
| 打洞用的 socket | 1 个，主进程建、主进程持有 | 3 个（注册 / listen / connect）都绑同一个 P |
| 注册映射 | 不需要，往服务器 UDP 发 hello 就有映射 | 必须**从 P** 连服务器发注册包，socket 留着 |
| 打通判据 | 收到对方任何 `ping`/`pong` | listen/connect 任一条 ESTABLISHED |
| 候选地址 | 有，最多 4 个 peer-reflexive，每轮全发 | 没有，就服务器给的那一对 |
| 心跳 | JSON `ping`/`pong`（使用者程序里给的是明文，没有加密/混淆/KCP 参数） | JSON `ping`/`pong`，按 `\n` 分帧（面向字节流） |
| 怎么交给使用者程序 | 关掉自己的 socket → 子进程 bind 同一个本地端口 | 把已建立连接的内核 socket 用 `pass_fds` 继承 |
| 传给子进程的 | `--peeraddr/--peerport/--localport [--peercandidates]` | `--hole-fd` |
| 子进程能自己重建吗 | 能（关 socket 不影响映射） | **不能**（重新 SYN/ACK，NAT 对不上） |
| 能看到窗口吗 | 能（`--new-window`） | 只能后台（继承 fd） |
| 打通后去哪 | `udptest` / `vpn`(tun/tap) / `proxy` / `switch` / `ffmpeg` / `wg-py` / `wg-sh` | `switch` 或 `tcptest.py`，二选一 |
| 关键超时 | `HELLO_TIMEOUT=10s`、`HOLE_CONFIRM_TIMEOUT=30s` | `TCP_ADDR_TIMEOUT=30s`、`PUNCH_TIMEOUT=15s` |

回 [readme.md](readme.md) ｜ UDP 版见 [readme-udp.md](readme-udp.md) ｜ 已知的坑见 [readme-gotcha.md](readme-gotcha.md)
