# readme-gotcha —— 已知的坑 / 危险行为 / 没验证的部分

出问题先看这里。分四类：**行为反直觉**、**会出错**、**没验证**、**架构上的坑**。
每条都标了代码位置，方便对照。

---

## 一、行为反直觉

### 1. 服务端对"洞"没有任何授权
任何已登录用户都能 `p2pudp/p2ptcp/p2pdirect` 任意在线用户，服务器只检查"target 在线"。
对方没设 `onpeerwant*` 就会被打洞请求骚扰（`none` 才能静默拒绝）。

### 2. `switch.py` 的 `listenstart` 默认绑 `0.0.0.0`，且没有认证
谁连上来，谁就成为你 switch 的一个 port —— **等于能往你的 mesh 里注包**。
要暴露给外网自己注意（`listenstart addr=127.0.0.1 ...` 可只监听本机）。

### 3. `listenstop` 不会断开已接入的 port
它只停"再接新的"。已接进来的那些 port 还在表里继续转发（这是故意的，见 [readme-todo.md](readme-todo.md)）。
要断就用 `unplug <port名>`。

### 4. `direct` 只能证明"地址可达"，不能证明"端口能过"
有些机器 ping 得通但端口被防火墙过滤。所以 `direct` **不建隧道、不拉子进程**，
只记一条 `proto='direct'` 的洞并打印可达地址。别拿它当"能连"的证据。

### 5. TCP 洞的交接是"继承 fd"，所以看不到窗口
UDP 洞是"关掉主进程 socket → 子进程 bind 同一端口"；TCP 不行（连接一关就没了），
必须把**已建立连接的内核 socket** 用 `pass_fds` 继承给子进程 →
**只能后台拉起**（新终端窗口没法继承 fd），所以 `tcp` 那条路看不到窗口，只能看日志。

### 6. `switch.py` 的 `--card`（tun/tap）和 `--tun-ip` 是两件事
`--tun-ip` 是"启动时执行一次 `ip addr add`"，不是"开关"；不带它就**什么都不设**，
设备上是空的，得自己 `ip addr add`。（`--tun-mtu` 反过来：**默认就会设** 1400。）

### 7. switch 的"路由"是学出来的，不是配出来的
`routes` 只有两个写入点：从包的 `src_ip` **学**（`state.routes[src_ip] = 来的 port`）、
以及 `route add` 手工静态路由。**插洞时不带任何 IP** —— 谁在哪个洞后面全靠流量学。
冷启动/老化之后查不到 → **泛洪给所有其它 port**（能通，但会浪费带宽）。

---

## 二、会出错 / 危险

### 8. 环形拓扑下泛洪会打转
`_flood` 只排除"收到它的那个 port"，**没有 TTL、没有去重、没有防环**。
链状/星状（a—b—c）没问题；两两都插了洞形成环，泛洪的包会在环里来回转。

### 9. 目的地址是"本机"的包会被多余地泛洪
L3 转发里 `routes[本机IP]` 学成 `'card'`，而 `state.ports` 里**没有 `'card'` 这个键** →
`next_port in state.ports` 为假 → 落到 else **泛洪**。结果：这个包既正确注入了本机 tun，
又被复制给所有其它洞（多洞时流量放大）。

### 10. 中继节点如果开了内核转发，会重复投递
switch 先把包 `_inject_card` 注入本机 tun，再由自己转发。
如果中继机的 `net.ipv4.ip_forward=1` 且 `/24` 路由又指回 tun，
内核会把同一个包再写回 tun → switch 再转发一遍 → 对端收到**重复包**。
建议中继节点关掉 `ip_forward`（或者用防火墙挡）。

### 11. 路由学习没有校验
`src_ip` 完全可伪造；同一个 IP 从两个洞来会互相覆盖（后到的赢）。
（老化有，校验没有 —— 这是明确决定先不做的。）

### 12. `switch.py` 绑定地址历史遗留
`--type bindtcpsocket` 的老监听路径写死 `127.0.0.1`（[client/app/switch.py](../client/app/switch.py) 里 `tcp_port_listener`），
远程连不上。要对外监听用 console 的 `listenstart addr=0.0.0.0 port=...`。

### 13. 一台机器上的 tun 地址必须自己配，而且 `/24` 不能漏
`switch.py --tun-ip 192.168.66.2/24` 会 `ip addr add`；不带就什么都没有。
`/24` 同时决定两件事：**"我是谁"**（对方注进来的包内核才收）和
**"192.168.66.0/24 走 tun"**（你发出去的包才进 tun）。漏了前缀＝场景直接不通。

### 14. MTU：tun 上别用 1500
洞是"IP 包塞在 UDP 里"，1500 的 IP 包套上 UDP/IP 头会超网卡 MTU 而分片。
`--tun-mtu` 默认 1400 就是这个原因（0 = 不设）。

### 15. `wghelp.sh` / `wg-sh` 需要 root，且私钥会出现在命令行
`wg-calltool.py` 用 `sudo bash wghelp.sh <我的私钥> ...` 调用，
所以**私钥会出现在进程命令行里**（`ps` 可见）。不要在共享机器上用。
（`wg-calltool.py` 自己的日志里已经替成 `<my-privkey>`，但命令行替不掉。）

### 16. `wg-sh` 的 keepalive 用位置参数传
因为 `sudo` 默认 `env_reset` 会把环境变量吃掉，所以 keepalive 走第 8 个位置参数，
不能用环境变量传。

---

## 三、没验证过的（别当它能用）

| 位置 | 情况 |
|---|---|
| `client/app/wg-calltool.py` 的 Windows 分支 | 没环境，没验证 |
| `client/app/vpn.py` 的 macOS / Windows 分支 | 没环境，没验证（只验证过 Linux 的报错路径） |
| `client/hole/direct.py` 的 macOS（解析 `ifconfig`）/ Windows（解析 `ipconfig`）分支 | 没环境，没验证；只有 Linux 分支验证过 |
| `launch_in_new_terminal` 的 Windows 句柄继承分支（`set_handle_inheritable` + `close_fds=False`） | 没环境，没验证 |
| 开发机上的 tun / tap | **打不开**（没 `/dev/net/tun` 权限、非 root），所以所有 `ip addr add` / `ip link set mtu` 只验证到"命令拼装正确 + 打不开时报错正确" |
| `switch.py --card tap` | 设备选择已修（`Tap()`），但真机没验证过 |
| 安卓端 | 见 [readme-android.md](readme-android.md)（当前状态 + 协议 + 踩过的坑） |
| iOS 端 | 代码在 `ios/p2pnet/`（SwiftUI 复刻，形态与安卓一致，暂无独立文档） |
| 两端的图形客户端 | **只在编译层面验证过**（安卓 `compileDebugKotlin`、iOS `xcodebuild ... iphonesimulator`），**没有在真机/模拟器上跑过**：卡片拖动、连线落点、屏幕中线、ICMP 实测可达性、外部程序拉起都还没有运行时证据 |

---

## 四、架构上的坑 / 明确没做的

### 17. TCP 洞**没法**"先打通再移交"
这是 TCP 和 UDP 的根本差异，不是没做，是做不到：
连接一关源端口就变、NAT 映射作废，子进程重连要重新 SYN/ACK。
所以 TCP 洞必须传**内核对象**（`pass_fds` 给新进程，或 SCM_RIGHTS 给常驻进程）。

### 18. 常驻进程接 fd 只有 POSIX 做了
`switch.py` 的 `--ctlpath` 用 SCM_RIGHTS 收 fd。**Windows 没有 SCM_RIGHTS**，
要换 `DuplicateHandle` + 控制通道 —— 代码里直接报"只支持 POSIX"并返回失败（不静默）。

### 19. Python 3.6 没有 `socket.send_fds/recv_fds`
那是 **3.9+** 才有的。`switch.py` 里用底层的 `sendmsg`/`recvmsg` + `array.array('i')`
手工打包/解 `SCM_RIGHTS` 辅助数据。

### 20. `vpn.py` / `proxy.py` 接不了 TCP 洞
它们的收发路径是**数据报**（`sendto`/`recvfrom`）写的，只有 UDP 洞那套。
要接 TCP 洞得先加 `--hole-fd` 入口、把收发按**流**改写。
`switch.py` 之所以能接，是因为它的 port 抽象本来就是流的（`recv`/`sendall`/`close`）。

### 21. 服务端没实现 `thisisyourpeer_wg`
所以 WireGuard 的对方公钥 / mesh IP **只能命令行给**（`wg-py ... pubkey=`、
`wg-sh <洞> <私钥> <我的meshIP> <对方公钥> <对方meshIP>`）。
老代码里还有一段 `thisisyourpeer_wg` 的处理，现在只剩一行说明。

### 22. `upnp` 和 `onpeerwantupnp` 都是占位
`client/hole/upnp.py` 只打印"协议待定"；`onpeerwantupnp` 只是状态位、没有消费者。见 [readme-upnp.md](readme-upnp.md)。

### 23. `--appmode` 那个参数还留在子进程里
客户端的 `appmode` **命令**早就删了（换成 `onholefromself/onholefrompeer`），
但 `app/tcp.py`（已删除）时代的 `--appmode` 还留在别处；
另外 `app/wg-python.py` 里 `import subprocess` 是个**死 import**（全文件没用过）。

---

## 五、明确坏掉 / 不可用的

### 24. `wg-py`（自己实现的 WireGuard）数据面不可用
读代码就能确定，不是"没验证"：

- `send_ip()` 用了 `self._peer_index`，而**全文只有一处使用（[client/app/wg-python.py](../client/app/wg-python.py) 第 325 行）、零处赋值** → 一旦有 IP 包要从隧道发出去就 `AttributeError`。
- 代码自己写着"简化处理，实际需要 proper crypto"、"简化：Type(4) || Receiver Index(4) || Unpadded Data"。
- 没有 MAC1/MAC2、没有 cookie 这些 WireGuard 必需的防 DoS 字段。
- 本机 `cryptography` 2.1.4 太老，`RawEncoding` 缺失，启动时也直接抛异常。

**结论**：`wg-py` 现在**不要当能用**。要用 WireGuard 走 `wg-sh`（调系统 wg → `app/wghelp.sh`），或者先把 `wg-python.py` 的协议补完。见 [readme-wg.md](readme-wg.md)。

### 25. `wg-py` 还依赖 switch 先跑起来
`_launch_wg_python()` 传的是 switch 进程的 unix socket，`wg-python.py` 的 `connect_switch()` 失败就**直接 return**。
所以不先跑 `switch`（或 `onholefrom* switch`），`wg-py` 只会打一行"连接 switch 失败"然后退出。

### 26. `server.py` 的 `tcp_pending` 等待队列是死代码
`tcp_pending`（`server/server.py` 第 75 行声明）只被**读**（786-787 行 `pop(0)`），
**全文没有任何一处 append** —— 所以 `handle_tcp_p2p_registration` 里那段
"对方还没来，先排队等着"的分支永远不会命中。真正干活的是 `tcp_peer_info` 配对。
不影响功能（TCP 打洞实测能通），但读代码时容易误以为有队列机制。

---

## 改动过的、曾经坑过人的

| 曾经 | 现在 |
|---|---|
| 服务端 `handle_tcp_p2p_registration` 用 `binascii` 但没 import → 每次 TCP 注册抛 `NameError`，被裸 `except: pass` 吞掉 → `thisisyourpeer_tcp` 永不发送 | 改成内置 `bytes.fromhex` / `.hex()`，TCP 打洞才能通 |
| 步骤超时的 watchdog 盯的是"还开着的那行"，任何别的日志把它收尾后**超时 ✗ 就永远不触发** | 拆成"行是否开着"和"这步是否还没出结果"两个状态 |
| `switch.py` 不管 `--card tun` 还是 `tap` 都 `Tun()` | 按 card 选设备；tap 时 `--switch-mode` 默认 `auto` |
| `app/udp.py` 里混着"接管洞"和"挂 fake/tun/tap/switch"两件事 | 拆成 `app/udptest.py`（纯互发测试）+ `app/vpn.py`（单人单 tun）+ `app/switch.py`（多人多洞） |
| `app/udp.py --appmode fake` 那个 `fake` usage 和 `udptest` 是同一条路 | 删掉 `fake` usage |
| `hub.py` 和 `switch.py` 功能重复 | 删掉 `hub.py` |

---

回 [readme.md](../readme.md) ｜ 设计想法见 [readme-todo.md](readme-todo.md)
