# TODO / 待研究

> **本文是什么：** 设计想法 + 还没做的 + 想过的方案的合集，**不是使用说明**。
> **和 [readme.md](readme.md) 的区别：** [readme.md](readme.md) 讲"现在怎么用、怎么实现"；
> 本文讲"下一步做什么、为什么这么设计、哪些想过了还没做"。已经实现的只留一行 ✅ + 链接，不再展开。
>
> - ✅ = 已实现，指向代码或 [readme.md](readme.md) / [readme-udp.md](readme-udp.md) /
>   [readme-tcp.md](readme-tcp.md) / [readme-wg.md](readme-wg.md) /
>   [readme-direct.md](readme-direct.md) / [readme-upnp.md](readme-upnp.md)。
> - 没做的保留（这是本文的价值）；拿不准的标 `?`。
> - 已知的坑统一放 [readme-gotcha.md](readme-gotcha.md)，本文不重复。
> - 命令以 [readme.md](readme.md) 和 `client.py` 的 `help` 为准；本文里的命令多为**设想**。

---

## 0. 现状速查（2024 重构后）

打洞 / app / util 已分层：

| 位置 | 文件 | 状态 |
|---|---|---|
| hole | `client/hole/udp.py` | ✅ UDP 打洞 6 步 → [readme-udp.md](readme-udp.md) |
| hole | `client/hole/tcp.py` | ✅ TCP 打洞 5 步 → [readme-tcp.md](readme-tcp.md) |
| hole | `client/hole/direct.py` | ✅ ICMP 直连探测 → [readme-direct.md](readme-direct.md) |
| hole | `client/hole/upnp.py` | 占位，协议待定 → [readme-upnp.md](readme-upnp.md) |
| hole | `client/hole/core.py` | ✅ 公共层：client.py 注入钩子 + 打洞步骤显示（✓/✗ 一行一步） |
| app | `client/app/udptest.py` | ✅ 互发测试（**原 `app/udp.py`，已改名**） |
| app | `client/app/tcptest.py` | ✅ TCP 版，收继承来的内核 fd（**原 `app/tcp.py` 已删除**） |
| app | `client/app/vpn.py` | ✅ 单人单 tun/tap |
| app | `client/app/proxy.py` | ✅ 端口转发 |
| app | `client/app/switch.py` | ✅ 虚拟交换机，多人多洞（**取代 `app/hub.py`，hub 已删除**） |
| app | `client/app/wg-python.py` | ✅ 自己实现的 WireGuard（不用 root） |
| app | `client/app/wg-calltool.py` | ✅ 调系统 wg → `wghelp.sh`（需 root） |
| app | `client/app/ffmpeg.sh` | ✅ P2P 视频（ffmpeg + ffplay） |
| app | `client/app/audio.py` | `?` 有独立 main / 代码，但 **client.py 里没有 audio 入口**（`onholefrom*` 里也没有），没人拉起 |
| app | `client/app/media.py` / `file.py` | ❌ 只有文档字符串，未实现 |
| util | `tun.py` / `tap.py` / `tun_windows.py` / `tap_windows.py` / `crypto.py` / `kcp.py` | ✅ |

**过时的名字（文档里不能再出现）：**

| 旧 | 新 |
|---|---|
| `app/udp.py` | `app/udptest.py` |
| `app/tcp.py` | 删除；TCP 打洞重做在 `hole/tcp.py` + `app/tcptest.py` |
| `app/fake.py` | 删除；`ON_HOLE_MODES` 里已无 `fake`（但 `--onholefromself` 的 help 里还残留 `fake` 字样）`?` |
| `app/hub.py` | 删除，被 `app/switch.py` 取代 |
| client 的 `appmode …` 命令 | `onholefromself` / `onholefrompeer`（洞打通后自动跑什么） |
| `onpeermsg` | `onpeerwantudp` / `onpeerwanttcp` / `onpeerwantdirect` / `onpeerwantupnp` |
| 子进程 `--appmode …` / `--socketpath` | **已无此参数**；打洞后由 client.py 决定跑哪个 app，switch 用 console `plug` |

> `onholefrom*` 现在可设：`udptest / tun / tap / auto / switch / proxy / ffmpeg / wg-py / wg-sh`，
> 另允许设但拉起时会提示 TODO 的 `video / file`（见 `client.py` 的 `ON_HOLE_MODES`）。

---

## 1. L3 Switch 架构（Mesh VPN）

**目标（设计）：** 多节点 mesh —— 一堆对端把各自打好的洞交给同一个 switch，由它做 L2/L3 转发；
洞不通时走中继。**核心部分已实现** ✅ `client/app/switch.py`；下面是当时的思路与还没做的部分。

```
192.168.250.x 扁平虚拟局域网（所有人同一 /24 网段）

switch (192.168.250.55)        — tun/tap 设备，拥有这个网段的路由表
udp_alice (192.168.250.1)      — 一条洞，插到 switch 的端口，连 alice
udp_bob   (192.168.250.2)      — 一条洞，插到 switch 的端口，bob 洞通
udp_karl  (192.168.250.3)      — karl 洞不通，包要绕道

包到 switch：
  alice → 192.168.250.3：
    switch 查路由表：
      192.168.250.3/24 via udp_bob（Karl 不直连，走 Bob 中继）
    switch 封装包 → udp_bob 隧道
    bob 的 switch 收到 → 查表 → 到 karl
```

**类比：** Tailscale = WireGuard P2P mesh + DERP relay。我们的 switch 同时干 DERP（中继）和扁平 L3 路由表；
区别是 Tailscale 优化到每个 peer 直连，我们暂时都走 switch 中继（简化模型）。

### 术语对比

| 传统网络 | p2pnet L3 Switch |
|---------|------------------|
| 以太网交换机 | `switch.py`（L2/L3） |
| RJ45 网口 | 一条打好的洞 |
| 网线 | 洞 ↔ switch 的连接 |
| 交换机端口 | switch 维护的 port |
| Trunk 口（中继） | 洞通的链路 |
| 接入端口 | 新节点的第一条链路 |

### switch.py 接口（已实现 ✅，详见 `client/app/switch.py` 顶部注释）

```
switch.py --tun-ip 192.168.250.55[/24]   # 启动时真的 ip addr add；不带这个参数就不设地址
switch.py --tun-mtu 1400                 # card 设备 MTU，默认 1400（0 = 不改）
switch.py --route-ttl 300                # 学到的路由/MAC 多久没再出现就老化删除（0 = 不老化）
switch.py --switch-mode l3|auto|l2       # 默认 l3；--card tap 时默认 auto（tap 里是 Ethernet 帧）
switch.py --card tun|tap|none            # ✅ tap 已修：以前不管 tun/tap 都开 Tun()
switch.py --type bindtcpsocket --base-port 15991   # 老通道（TCP 洞 / WireGuard 走这个）
switch.py --type unixsocket --socketpath <path>
switch.py --ctlpath <path>               # client.py 用 SCM_RIGHTS 把已建立的 TCP 洞 fd 送进来
```

**`--type`（老通道，给"能直达"的场景）：**
- `bindtcpsocket`（默认）：switch bind `127.0.0.1:15991+`，对端按 `--socketpath` 连上来；
- `unixsocket`：switch bind 单个 Unix socket 文件（默认 `/tmp/p2pnet/switch-<pid>.sock`），
  多个连接各占一个 port。

**client.py 怎么插"网线"（新做法）：**
- UDP 洞打通后，client.py 用 console 文本命令 `plug localport=… peer=ip:port` 把洞交给 switch，
  switch 自己 bind 那个本地端口并保活；
- TCP 洞打通后，client.py 用 **ctl socket（`--ctlpath`）** 把**已建立连接的内核 fd** 经
  **SCM_RIGHTS** 送进常驻的 switch（Python 3.6 没有 `send_fds/recv_fds`，用 `sendmsg/recvmsg` + `array`）。
  这样不重新 SYN/ACK，连接直接继承。

### console 与 ctl socket（设计取舍）

| 通道 | 格式 | 用途 |
|---|---|---|
| console（stdin/stdout，pipe） | ✅ **文本命令**，一行一条，人也能敲 | `listenstart` / `listenstop` / `connect` / `plug` / `unplug` / `status` / `routes` / `route add\|del` / `quit` |
| ctl socket（`--ctlpath`，Unix socket） | ✅ **仍是 JSON**（要带 fd） | `{"cmd":"plug_fd","peer":"bob"}`（fd 在辅助数据里）/ `{"cmd":"status"}` / `{"cmd":"unplug","name":"port1"}` |

> 取舍：client.py ↔ switch 只走 pipe，不暴露额外网络 socket，避免别的进程连进来干扰；
> 只有需要传 fd 的 TCP 洞才开 ctl socket，且 ctl socket 的命令仍是 JSON。

### 路由表（已实现 ✅）

`routes: {peer_ip -> port_name}`，是 **IP → port** 的映射，不是 port → port —— peer 只关心目标 IP。

| 机制 | 状态 | 说明 |
|---|---|---|
| 动态学习 | ✅ | 从 port 收到包，`src_ip` → 该 port；从 tun 收到包按 `dst_ip` 查 |
| 静态路由 | ✅ | console `route add <ip\|网段> <port>` / `route del <ip\|网段>` |
| 老化 | ✅ | 学到的路由 `--route-ttl`（默认 300s）没再出现就删；**静态路由不老化** |
| 查不到泛洪 | ✅ | 标准 L2 交换机行为；点对点隧道不会形成广播环路，不会风暴 |
| 非直连中继 | `?` | 靠泛洪/学习到的路由自然形成中继；"可靠、成体系的中继"还没做 |

**从 tun 收到（本机发包）：** 查 `routes[dst_ip]` → 找到单播，找不到泛洪到所有 port。
**从 port 收到：** 学 `src_ip → 本 port`；所有包都 inject tun（交给 OS 路由表），同时按 `dst_ip` 单播或泛洪。

### 未实现 / 待做

| 项 | 状态 |
|---|---|
| 集中 IP 分配：server 给每个用户分固定 IP，并广播 `user_ip_map` | ❌ 设想 |
| server 把路由表分发给各 switch；新 peer 加入时通知更新 | ❌ 设想 |
| 进阶路由协议：Babel（轻量）/ OLSRv2（工业级） | ❌ 设想 |
| 非直连中继的完整行为（karl 洞不通时稳定走 bob） | `?` 部分靠泛洪 |
| Windows 下 SCM_RIGHTS 的替代（`DuplicateHandle` + 控制通道） | ❌ switch.py 里有 TODO 注释 |

---

## 2. client.py 三重角色（server 可选）

`client.py` 同时是三种管理员；**设计目标：server 完全可选**。

| 角色 | 状态 | 说明 |
|---|---|---|
| 1. WireGuard 管理员 | ✅ | 连 `app/wg-python.py` 的 admin socket 增删 peer（`add_peer` / `list_peers` / `get_pubkey`）→ [readme-wg.md](readme-wg.md) |
| 2. Switch 管理员 | ✅ | 通过 pipe 用**文本命令**管 `app/switch.py`（`plug` / `routes` / `route add` / `quit` …） |
| 3. 服务器用户 | ✅ | WebSocket 登录 → `udp` / `tcp` / `direct` → [readme.md](readme.md) |

```
client.py（server 连接，可选）  ├─ login / logout / list / del
                                ├─ udp <user> / tcp <user> / direct <user>
                                └─ 洞打通 → onholefromself / onholefrompeer 决定跑哪个 app
```

---

## 3. 纯 P2P 模式（无 Server）—— 设计目标，未实现

server 不需要，仅靠打洞 + switch 就能组成扁平内网：

```
alice:  client.py + hole + switch.py
bob:    client.py + hole + switch.py
karl:   client.py + hole + switch.py
```

### Info 交换（手动 / 发现协议）

```
peer Info:
  mesh IP = 192.168.250.1
  WireGuard 公钥 = XXXX
  公网地址 = 1.2.3.4:51820
```

交换方式：手动输入 / 扫码 / mDNS / WiFi P2P / Bluetooth / LoRa / 预设种子节点（都没实现）。

### 使用流程（无 server，设想）

```bash
# 第一次：alice 手动把 Info 告诉 bob（任意方式）
# bob 的 client.py：
bob$ wg-py <洞> pubkey=<alice公钥>     # 现在必须手动给公钥（server 不发 thisisyourpeer_wg）
  → wg-python.py 添加 peer alice，连 alice 公网地址，发 WireGuard 握手
  → 成功后 alice / bob 互通，switch 路由表自动学习
```

---

## 4. 可插拔传输层（Pluggable Transport）—— 未实现

任何网络协议都能作为 switch 的"网线"插上：

```
switch.py（tun0 = 192.168.250.55）
  ├─ socket → 洞（UDP 打洞，明文）
  ├─ socket → 洞（TCP 打洞，明文）
  ├─ socket → wg-python.py（WireGuard 加密）
  ├─ socket → wifi.py      （WiFi P2P / Ad-hoc）
  ├─ socket → ble.py       （蓝牙 LE）
  ├─ socket → lorawan.py   （LoRaWAN 远距离）
  └─ socket → bt.py        （蓝牙 Classic）
```

**每个 xxx.py 的共同接口：**
```
输入：raw IP bytes（来自 switch）  → 输出：物理层（WiFi / BLE / LoRa / UDP / TCP）
输入：物理层收到的数据            → 输出：raw IP bytes（写回 switch）
```

switch 不管物理层是什么，只负责转发。

### "频率"概念（设想）

WiFi 频道、LoRa 频段、Bluetooth Channel —— 跟 TCP/UDP 端口一样是"插口编号"，
discovery 负责扫描 / 连接这些插口。

```
alice 发现了 bob 和 karl
→ alice 的 wifi.py / ble.py / lorawan.py 各自建立到 bob/karl 的物理 tunnel
→ 都插到 alice 的 switch
→ 路由表自动学习：
    192.168.250.2 → wifi.py（bob，直连高速）
    192.168.250.3 → ble.py （karl，极近距离）
→ 同一个 /24 网段，物理路径不同，逻辑上完全透明
```

---

## 5. 大规模 Mesh（10+ peers）

**问题：**
- 全网状：N peers → 每人 N-1 条 tunnel，总数 N×(N-1)/2，不可持续；
- 不是每对 peers 都能打洞成功，需要 relay fallback；
- 共用 TUN 接口时，多个 tunnel 进程写同一个 fd 有竞争风险。

**已实现（switch 架构）✅：**
- 一条洞 = 一条"物理网线"，插到 switch 端口；
- switch 维护路由表，按 IP 查下一跳；
- 学到的路由会老化（`--route-ttl`），静态路由不老化。

**还没做：**
- 中继的稳定实现（现在靠泛洪/学习）`?`；
- 路由协议：Babel（轻量，支持有线/无线 mesh，易实现）/ OLSRv2（工业级，复杂）；
- 简化方案：中心 tracker 分发路由表（适合受控网络）。

---

## 6. 历史命令设想 → 现在的样子

旧文档里的 `appmode …` / `route_add …` **从来没实现过**，现在的对应关系：

| 旧设想 | 现状 |
|---|---|
| `appmode` / `appmode switch` / `appmode fake` | 命令删除。改用 `onholefromself` / `onholefrompeer [模式] [设备] [洞]` |
| `appmode tun [dev]` / `appmode tap [dev]` | `onholefromself tun [dev]`（单人单 tun 交给 `app/vpn.py`）；switch 交给 `app/switch.py` |
| `route` / `route_add <dest> <via>` | switch console 的 `routes` / `route add <ip\|网段> <port>` / `route del <ip\|网段>` |
| 被动方 `incoming_p2pudp` 之类 | 服务器直接给**双方**发 `send_udp_to_server`，被动方不用敲命令 |
| `onpeermsg` 一个开关 | 拆成 `onpeerwantudp` / `onpeerwanttcp` / `onpeerwantdirect` / `onpeerwantupnp` |
| 子进程 `--appmode switch` 插网线 | 参数删除；UDP 洞由 client.py `plug`，TCP 洞由 ctl socket `plug_fd`（SCM_RIGHTS） |

**还没做的命令/交互：** `onpeerwant*` 只有 `auto` / `none`，没有 `ask`（先问用户确认）。

---

## 7. 实现顺序 → 状态

| # | 原计划 | 状态 |
|---|---|---|
| 1 | `switch.py`：tun + port 监听 + 路由表 + IP 转发 | ✅ |
| 2 | 洞（udp/tcp）打通后透传 IP 包给 switch | ✅ |
| 3 | client.py 管控 switch 生命周期、插拔网线 | ✅（pipe 文本命令 + ctl SCM_RIGHTS） |
| 4 | console 协议：route / neighbors / status / route add | ✅（文本命令） |
| 5 | 非直连路由：karl 洞不通走 bob 中继 | `?` 靠泛洪/学习 |
| 6 | 路由协议：server 分发路由表 / Babel / OLSR | ❌ |

---

## 8. 安全加密层

### 登录与 session_key（已实现 ✅ [readme.md](readme.md)）

| 步骤 | 算法 | 输入 |
|------|------|------|
| Login（challenge-response） | `HMAC-SHA256(pw_hash, challenge)` | `pw_hash = SHA256(password + salt)`，`challenge` 来自服务器 |
| session_key 推导 | `HKDF(pw_hash, info=challenge)` | 同上，`pw_hash` 取自服务器存储 |

> `client/util/crypto.py` 里 HKDF / ECDH / ChaCha20-Poly1305 的零件 ✅ 都有，
> 但**隧道本身还没接上加解密**（`udp.py` / `tcp.py` 的 `handle_outgoing` 仍是 TODO）。

### Noise IK 握手（P2P Tunnel 加密）—— 未实现 ❌

```
Alice（initiator）                          Bob（responder）
  │  已知: Bob 的 static pubkey                  │
  │  互发 UDP 包打洞                             │
  │  -> e_a, {Alice 的 DH 公钥}                 │  用 Bob 的 static 公钥加密
  │              <- e_b, {Bob 的 DH 公钥}       │  用 Alice 的 static 公钥加密
  │  ECDH(a, B) = ECDH(b, A) = 共享密钥 S       │
  │  -> {cookie}  （PSK 加密，确认密钥）         │
  │  = 相同对称隧道密钥 =                        │
  │  后续所有 UDP 包: {8字节 nonce}{ChaCha20 密文}{tag} │
```

**设想的参数（还没实现）：**
```
--peerpubkey   <base64>   对方的 static 公钥（用于 ECDH）
--selfprivkey  <base64>   自己的 static 私钥（用于 ECDH + 签名认证）
```

---

## 9. ICE Peer-Reflexive 支持（无需 relay）

**问题：** 对称型 NAT 会对不同目的地分配不同端口，server 告诉的 srflx 地址不一定能用。

**UDP 已实现 ✅（见 [readme-udp.md](readme-udp.md)）：**
- 打洞阶段（client.py 主进程）维护**候选列表**：初始 = server 给的地址；
- 每轮往所有候选各发一份 ping；`recvfrom` 收到新源地址 → 追加为 peer-reflexive 候选并设为当前对端；
- pong / 数据响应到实际收到包的来源地址；
- 移交子进程时用 `--peercandidates` 把候选一并传过去，`udp.py` 隧道阶段同样维护候选列表。

**TCP：** 新方案是三个 socket 用 `SO_REUSEPORT` 绑同一本地端口、同时 listen + connect，
不靠 peer-reflexive 候选；对称 NAT 下的 TCP 穿透效果 `?` 待验证。

---

## 10. Warcraft 3 IPX 支持

**问题：** 魔兽 3 局域网对战用 IPX/SPX 协议，不是 IP。TUN 只处理 IP 包，IPX 不通。

**方案 A：找 TCP/IP 版本**
- 魔兽 3 1.28+ 原生支持 TCP/IP，盗版/民间有 IPX-over-TCP 模拟器；
- 最简单，改配置即可。

**方案 B：TAP + 网桥封装**
- TAP 收到 Ethernet 帧，按 Type 字段区分 IPv4 / IPX；
- IPX 包通过额外封装的隧道到达对端 TAP；
- 需要额外处理 IPX 广播（IPX 用广播做地址解析，NAT 穿透更复杂）。

> 注：`--card tap` 已修 ✅，TAP 基础已具备；上面的 IPX 封装还没做。

---

## 11. WireGuard P2P

### 架构（已实现 ✅）

```
wg-python.py（自己实现，不用 root）或 wg-calltool.py（调系统 wg → wghelp.sh，需 root）
  ↕ 一条打好的洞（UDP）  → 对端
  ↕ 本地端口 = 洞的本地端口
```

`switch.py` 把 WireGuard 当成一条加密"网线"插上；server 只负责打洞交换地址，
**server 端的 `p2pwg` / `thisisyourpeer_wg` 未实现** → 公钥必须命令行手动给
（`wg-py <洞> pubkey=<base64>`），详见 [readme-wg.md](readme-wg.md)。

### 与裸 UDP P2P 的区别

| | 裸 UDP | WireGuard |
|--|---------|-----------|
| 加密 | 无 | ChaCha20-Poly1305 |
| 密钥交换 | 无 | Noise IK（完美前向保密） |
| 隧道维护 | 自己实现 | 自动 keepalive + 重握手 |
| MTU 分片 | 自己处理 | WireGuard 自动处理 |
| peer 管理 | 自己实现 | 内置多 peer 表 |

**WireGuard 没有内置打洞**，本质是 UDP，所以打洞逻辑仍在 server；server 只交换公钥 + 公网地址。

### 单进程多 peer（已实现 ✅）

`wg-python.py` 单实例，通过 admin socket 管多个 peer：
```
client.py:
  wg-py <洞>            → wg-python.py 未运行 → spawn + admin socket
  再加 peer             → 已运行 → admin socket 发 add_peer
```

admin socket 命令（设想/现状 `?`，以 `wg-python.py` 为准）：
```
{"cmd": "add_peer", "name": "bob", "ip": "1.2.3.4", "port": 51820, "pubkey": "<bob公钥>"}
{"cmd": "list_peers"}
{"cmd": "remove_peer", "name": "bob"}
{"cmd": "get_pubkey"}
```

---

## 12. 最终形态

```
192.168.250.x 扁平网段
  每个人的 switch 都是这个网段的路由器
  每个人身上插着不同的"网线"：
    - WiFi P2P（近距离高速）
    - Bluetooth（极近距离）
    - LoRa（远距离低速）
    - WireGuard over UDP（互联网打洞）
  OS 路由表自动选最优路径
  app 完全不用关心走哪条物理通道
```

Tailscale = WireGuard P2P + DERP relay。
我们的 = 可插拔传输层 + switch 中继（穿透失败时）。

---

> 当前实现与用法回 [readme.md](readme.md)；
> 打洞细节见 [readme-udp.md](readme-udp.md) / [readme-tcp.md](readme-tcp.md) /
> [readme-direct.md](readme-direct.md) / [readme-upnp.md](readme-upnp.md)；
> WireGuard 见 [readme-wg.md](readme-wg.md)；已知的坑见 [readme-gotcha.md](readme-gotcha.md)。
