# WireGuard：两条路 `wg-py` / `wg-sh`

**本文讲什么**：客户端里两条 WireGuard 路——`wg-py`（拉 `app/wg-python.py`，纯用户态自己实现）
和 `wg-sh`（拉 `app/wg-calltool.py` → `app/wghelp.sh`，调系统 `wg`）——各自的命令、参数、
需要的权限，以及"**洞的本端端口必须当内核 WireGuard 的 `listen-port`**"这个关键点。

两条路都不是独立的打洞协议：**先有一条打好的 UDP 洞，再把这条洞交出去**（洞怎么打见
[readme-udp.md](readme-udp.md)）。

---

## 1. 命名对照

文件名说清做法，usage 名短，**故意不一致**：

| usage | 拉起的文件 | 做法 | root | 内核模块 | wireguard-tools |
|---|---|---|---|---|---|
| `wg-py` | [client/app/wg-python.py](client/app/wg-python.py) | 自己实现 WireGuard（Noise IK + ChaCha20-Poly1305） | 不要 | 不要 | 不要 |
| `wg-sh` | [client/app/wg-calltool.py](client/app/wg-calltool.py) → [client/app/wghelp.sh](client/app/wghelp.sh) | 调系统 `wg` / `ip`，用内核 WireGuard | **要** | **要** | **要** |

| 客户端命令 |
|---|
| `wg-py <洞标识\|对方用户名> [pubkey=<对方公钥base64>]` |
| `wg-sh <洞标识\|对方用户名> <我的私钥> <我的meshIP> <对方公钥> <对方meshIP> [接口名]` |

两种形式都支持：给**洞标识**（`fd=4` / `port=50001` / `#1` / `bob`）就在这条已打通的洞上直接拉起；
给**用户名**就先打 UDP 洞，打通后自动拉起（`_pending_usage` 记住用哪条路）。

---

## 2. `wg-py`：自己实现的 WireGuard（纯用户态）

| 项 | 值 |
|---|---|
| 文件 | [client/app/wg-python.py](client/app/wg-python.py) |
| 加密 | Noise IK 握手 + ChaCha20-Poly1305，都在文件里自己写（唯一依赖 `cryptography` 库） |
| 数据面 | **连 `app/switch.py` 的 Unix socket 当"网线"**：从 switch 收 raw IP → 发给各 peer；从 peer 收密文 → 解密后写回 switch |
| 进程模型 | 一个进程管多个 peer（单实例；client.py 全局只有一个 `WG_ADMIN_PATH`） |
| 本地监听 | 洞的本端 UDP 端口（`SO_REUSEADDR` + `bind`，就是注释里那句"不能换随机端口"） |
| 不需要 | root / 内核模块 / wireguard-tools，都不需要 |
| 前提 | 得有一个 **switch 进程在跑**（`switch` 那套会拉起它并把 socket 路径给到 `--socketpath`）；没有的话它打一行 `连接 switch 失败` 就退出 |

### 命令

```
wg-py <洞标识|对方用户名> [pubkey=<对方公钥base64>]
```

| 输入 | 行为 |
|---|---|
| `wg-py fd=4 pubkey=BDDBwN2...=` | 在已打通的洞上拉起 wg-python.py |
| `wg-py bob pubkey=BDDBwN2...=` | 先打 UDP 洞，通了自动拉起 |
| 缺 `pubkey=` | 拒绝拉起，提示 `[P2P] wg-py 需要对方的 WireGuard 公钥（服务端暂未实现 thisisyourpeer_wg，拿不到）` |

### admin socket

wg-python.py 起一个 Unix socket（跑起来时用 `--adminpath` 给；client.py 传的是
`/tmp/p2pnet/wg-admin-<client pid>.sock`），client.py 用它加/删 peer；
**第一个 peer 拉起进程，后面的 peer 直接走 admin socket 加进去**。

| `cmd` | 字段 | 作用 |
|---|---|---|
| `add_peer` | `name` / `ip` / `port` / `pubkey` / `localport` | 加一个 peer 并立刻发握手；`localport` = 洞的本端端口 |
| `remove_peer` | `name` | 移除 peer |
| `list_peers` | — | 返回本端公钥 + 每个 peer 的 `endpoint` / `active` |
| `get_pubkey` | — | 返回本端公钥（base64） |
| `exit` | — | 退出 |

### 直接跑

```
python3 app/wg-python.py --socketpath /tmp/p2pnet/switch-<pid>.sock \
                         --adminpath /tmp/p2pnet/wg-admin-<pid>.sock [--log <文件>]
```

真实 `--help`：

```
usage: wg-python.py [-h] [--appmode APPMODE] [--socketpath SOCKETPATH]
                    [--adminpath ADMINPATH] [--log LOG]
  --appmode APPMODE     连接模式（默认 switch）
  --socketpath SOCKETPATH  switch Unix socket 路径（必填）
  --adminpath ADMINPATH    admin Unix socket 路径（默认 /tmp/p2pnet/wg-admin-<pid>.sock）
  --log LOG                日志文件路径
```

### 启动参数

```
--wg-py <对方用户名>
```
（可多次指定；等价于登录成功后自动敲 `wg-py <user>`。公钥仍要命令行给，见第 3 节。）

---

## 3. 服务端没有 `thisisyourpeer_wg`

结果：**对方公钥 / 双方 mesh IP 都拿不到，只能命令行给。**

| 消息 | 状态 |
|---|---|
| `p2pwg` | 服务端 `handle_message` 里没有这个分支 |
| `thisisyourpeer_wg` | 服务端**从不发**；客户端只有一个说明分支，进来就 `return` |
| `wghelp` | 服务端转发分支已注释掉（客户端也从不发这个 type） |
| `incoming_p2pwg` | 客户端有提示分支，服务端不发 |

> 所以别等服务器给公钥：`wg-py` 要 `pubkey=`，`wg-sh` 要 4 个参数全给。

---

## 4. `wg-sh`：调系统 `wg`（内核 WireGuard）

### 链路

```
client.py
  │  洞已打通：本端端口 50001 ↔ 对端 5.6.7.8:30001
  │  先 close 自己的 socket（让子进程能 bind 同一个端口，NAT 映射不废）
  ▼
app/wg-calltool.py       只拼参数、不碰数据面和加密
  │  sudo bash app/wghelp.sh <1> <2> <3> <4> <5> [<6>] [<7>] [<8>]
  ▼
app/wghelp.sh            真正动内核
  ip link add dev wghelp0 type wireguard
  wg set wghelp0 private-key <我的私钥>
  ip addr add 192.168.250.2/24 dev wghelp0
  wg set wghelp0 listen-port 50001          ← 洞的本端端口，关键
  wg set wghelp0 peer <对方公钥> endpoint 5.6.7.8:30001 \
         persistent-keepalive 25 allowed-ips 192.168.250.3/32
  ip link set wghelp0 up
```

### 关键点：`listen-port` = 洞的本端端口

打洞打通的是**某个特定本地端口**上的 NAT 映射。内核 WireGuard 换了端口发包，
对端 NAT 上就没有这条映射 → **洞白打**。所以 `wg-calltool.py` 把洞的本端端口
当成 `--localport`，一路传到 `wghelp.sh` 的第 7 个位置参数，最后落到 `wg set ... listen-port`。

### `wghelp.sh` 的 8 个位置参数

```
wghelp.sh <我的私钥> <我的mesh IP> <对方公钥> <对方mesh IP> <对方公网地址:端口> [接口名] [监听端口] [keepalive]
```

| # | 参数 | 默认 | 说明 |
|---|---|---|---|
| 1 | 我的私钥 | 必填 | base64；`wg pubkey` 反推本端公钥 |
| 2 | 我的 mesh IP | 必填 | `ip addr add <IP>/24 dev <接口>` |
| 3 | 对方公钥 | 必填 | base64 |
| 4 | 对方 mesh IP | 必填 | 进 `allowed-ips <IP>/32` |
| 5 | 对方公网地址:端口 | 必填 | 进 `endpoint`（就是洞的对端地址） |
| 6 | 接口名 | `wghelp0` | 不存在就 `ip link add type wireguard` |
| 7 | 监听端口 | 空 | = 洞的本端端口；**空则内核自己挑一个（映射就废了）** |
| 8 | keepalive | `25` | `persistent-keepalive`，顺便维持 NAT 映射 |

**为什么用位置参数而不是环境变量**：`sudo` 默认 `env_reset`，环境变量会被吃掉。

真实用法提示（非 root、无参数时）：

```
用法: app/wghelp.sh <我的私钥> <我的mesh IP> <对方公钥> <对方mesh IP> <对方公网地址:端口> [接口名] [监听端口] [keepalive]
示例: app/wghelp.sh YGzbJJ8... 192.168.250.2 BDDBwN2... 192.168.250.3 5.6.7.8:51820 wghelp0 50001 25
```

其余限制：需要 root（`wg set` / `ip link`）、需要 `wireguard-tools`（`wg` 命令）、
Linux 专用（**macOS 要用 wg-quick**）。

### `wg-calltool.py` 的参数与行为

```
python3 app/wg-calltool.py --localport <洞本端端口> \
      --peeraddr <对端公网IP> --peerport <对端端口> \
      --my-privkey <base64> --my-ip <我的meshIP> \
      --peer-pubkey <base64> --peer-ip <对方meshIP> \
      [--iface wghelp0] [--keepalive 25] [--check-interval 30] [--dry-run] [--remotelog <文件>]
```

| 参数 | 来源 | 说明 |
|---|---|---|
| `--localport` | 洞（client.py 传） | → `wghelp.sh` 第 7 个参数（`listen-port`） |
| `--peeraddr` / `--peerport` | 洞 | 拼成 `endpoint` |
| `--peercandidates` | 洞（可选） | 内核 WG 只认一个 endpoint，**这里只写日志** |
| `--localaddr` | 洞（可选） | 仅日志参考 |
| `--my-privkey` / `--my-ip` / `--peer-pubkey` / `--peer-ip` | 命令行 | 服务端拿不到（第 3 节） |
| `--iface` | 命令行，默认 `wghelp0` | 接口名 |
| `--keepalive` | 默认 `25` | → 第 8 个位置参数 |
| `--dry-run` | — | 只打印要执行的命令，不真的跑 |
| `--check-interval` | 默认 `30` | 守护循环多久 `ip link show` 一次 |

### `--dry-run`：无 root 也能检查参数

（下面是在 Linux 开发机上跑的真实输出，密钥和绝对路径已缩略。）

```
$ python3 app/wg-calltool.py --localport 50001 --peeraddr 5.6.7.8 --peerport 30001 \
    --my-privkey 'YGzbJJ8<...>=' --my-ip 192.168.250.2 \
    --peer-pubkey 'BDDBwN2<...>=' --peer-ip 192.168.250.3 --iface wghelp0 --keepalive 25 --dry-run

[18:02:48][wg-calltool.py main]  洞: 本端端口 50001（内核 WG 会 listen 它）↔ 对端 5.6.7.8:30001
[18:02:48][wg-calltool.py main]  mesh: 本端 192.168.250.2 ↔ 对端 192.168.250.3，接口 wghelp0
[18:02:48][wg-calltool.py main]  将执行: sudo bash .../app/wghelp.sh <my-privkey> 192.168.250.2 BDDBwN2<...>= 192.168.250.3 5.6.7.8:30001 wghelp0 50001 25
[18:02:48][wg-calltool.py main]  （--dry-run，不真的执行）
```

日志里**私钥会被替换成 `<my-privkey>`**（`build_wghelp_cmd` 出来后逐项比对替换）。

### 跑完守着接口

`wghelp.sh` 成功后 `wg-calltool.py` 不退出，每 `--check-interval`（默认 30s）跑一次
`ip link show <接口>`：

| 情况 | 行为 |
|---|---|
| 接口还在 | 打一行 `接口 wghelp0 还在（listen-port 50001）` |
| 接口不见了 | 打 `⚠️ 接口 wghelp0 不见了（wg-quick down？），退出` 然后退出（洞也就没了） |
| `wghelp.sh` 退出码 1 / 127 | 提示"八成是没 root / 没装 wireguard-tools / 没内核模块" |
| `wghelp.sh` 超过 60s | 超时退出 |

退出时提示：`退出（接口/peer 没动，要清理请: sudo wg-quick down wghelp0 或 sudo ip link del wghelp0）`

### 启动参数

```
--wg-sh "user privkey=<私钥> myip=<我的meshIP> pubkey=<对方公钥> peerip=<对方meshIP> [iface=<接口名>]"
```

| 键 | 对应命令行参数 |
|---|---|
| `privkey` | `<我的私钥>` |
| `myip` | `<我的meshIP>` |
| `pubkey` | `<对方公钥>` |
| `peerip` | `<对方meshIP>` |
| `iface` | `[接口名]`（缺省 `wghelp0`） |

命令行例（client.py 自己敲 `wg-sh`）：

```
wg-sh bob YGzbJJ8... 192.168.250.2 BDDBwN2... 192.168.250.3 wghelp0
```

> `wg-sh` 的 4 个 WireGuard 参数没给全时，client.py **不会**关掉洞的 socket，
> 直接提示后返回（`[P2P] wg-sh 需要: 我的私钥 / 我的 mesh IP / 对方公钥 / 对方 mesh IP`），
> 洞保持打通状态。

---

## 5. 两条路对比

| 对比项 | `wg-py` | `wg-sh` |
|---|---|---|
| 加密在哪 | 自己写的用户态代码 | 内核 WireGuard 模块 |
| root | 不要 | 要（`sudo`） |
| 额外安装 | `cryptography` | `wireguard-tools` + 内核模块 |
| 数据面出口 | switch 的 Unix socket（raw IP） | 内核接口 `wghelp0` |
| 多 peer | 一个进程 admin socket 加多个 | 一个接口上 `wg set peer` |
| 自己的 mesh IP | 不需要（不建接口、不配 IP） | 需要（`ip addr add`） |
| 平台 | 跟 client.py 一致 | Linux（macOS 得换 wg-quick） |
| 洞的本端端口 | `bind(localport)` | `listen-port <localport>` |

---

## 6. 验证状态

| 项 | 状态 |
|---|---|
| `wg-calltool.py --dry-run` 的参数拼接、私钥脱敏 | 已在开发机（Linux）验证，输出见上文 |
| `wghelp.sh` 的用法/root/wireguard-tools 检查 | 已在开发机验证 |
| `wghelp.sh` 真正建接口（`ip link add` / `wg set`） | 未验证（需要 root + 内核模块 + wireguard-tools） |
| `wg-python.py` 与真实 WireGuard 端到端互通 | 未验证（只跑过 `--help`，没有跑过实际隧道） |

更细的踩坑记录见 [readme-gotcha.md](readme-gotcha.md)。

---

## 7. 代码位置

| 文件 | 角色 |
|---|---|
| [client/app/wg-python.py](client/app/wg-python.py) | 纯用户态 WireGuard + admin socket |
| [client/app/wg-calltool.py](client/app/wg-calltool.py) | 拼 `wghelp.sh` 命令、守护接口 |
| [client/app/wghelp.sh](client/app/wghelp.sh) | 真正执行 `ip` / `wg` |
| [client/client.py](client/client.py) | `_launch_wg_python()` / `_launch_wg_calltool()` / `_wg_admin_add_peer()` / `wg-py` / `wg-sh` 命令 |

---

回到总览：[readme.md](readme.md)
