# `direct`：不打洞，ICMP 可达性探测

**本文讲什么**：`direct <user>` 这三步——枚举本机地址 → 和服务器交换地址 → 并发 ICMP ping——
以及它的定位：**只报告"对方哪些地址可达"，不建隧道、不拉子进程**。打洞见
[readme-udp.md](readme-udp.md) / [readme-tcp.md](readme-tcp.md)。

---

## 1. 命令

| 命令 | 作用 |
|---|---|
| `direct <对方用户名>` | 走 3 步，最后记一条 `proto='direct'` 的洞 |
| `onpeerwantdirect [auto\|none]` | 别人 `direct` 来要我的地址时，回不回 |

| `onpeerwantdirect` 取值 | 收到 `p2pdirect`（对方来要地址）时 |
|---|---|
| `auto`（默认） | 枚举自己的地址，回一份 `p2pdirect_reply`，然后 ping 对方 |
| `none` | **完全不理**：不回地址、也不 ping，本地留一行 `[onpeerwantdirect=none] 已忽略 bob 的 direct 请求（不回地址、不 ping）` |

> `none` 只挡"别人来要"，不挡自己敲 `direct <user>`。

---

## 2. 三步流程

`client/hole/direct.py` 定义 `DIRECT_STEPS = 3`，步骤描述在 `hole/core.py` 的 `DIRECT_STEP_DESC`：

| 步 | 打印的描述 | 干什么 |
|---|---|---|
| 1/3 | 正在枚举本机地址 | 枚举所有网卡的 v4/v6，过滤后**全部打印**（发之前先让人看见发了什么） |
| 2/3 | 正在和服务器交换地址 | 发 `p2pdirect`，等对方回 —— 超时 `10.0s`（`STEP_RESPONSE_TIMEOUT`） |
| 3/3 | 正在 ping 对方地址 | 对地址表**并发** ICMP ping，收集可达的 |

每步一行，行尾接结果（下面按实际打印格式写的**示意**，地址是编的）：

```
[12:00:01][client] [洞 #3 bob] [1/3] 正在枚举本机地址  （✓） 本机 2 个 v4 / 5 个 v6
[direct] 本机 v4（2）: 10.0.2.15, 192.168.56.101
[direct] 本机 v6（5）: fd17:625c:f037:2:8d1b:c0ba:f309:1cf6, ...
[12:00:01][client] [洞 #3 bob] [2/3] 正在和服务器交换地址  （✓） 收到对方 3 个地址
[direct] 已把上面的地址发给服务器，等 bob 回地址...
[12:00:02][client] [洞 #3 bob] [3/3] 正在 ping 对方地址  （✓） 2/3 个地址可达
[direct] bob 可达地址: 192.168.56.1, 10.0.2.2
```

第 2 步迟迟没回 → 行尾 `（✗） 对方一直没回地址`，洞记成 `打洞失败`。

---

## 3. 第 1 步：枚举本机地址

三个平台各一套，纯 stdlib、无第三方依赖；拿不到就 `getaddrinfo` 兜底（`_addrs_getaddrinfo()`）。

| 平台 | v4 | v6 | 验证状态 |
|---|---|---|---|
| Linux | `socket.if_nameindex()` + `SIOCGIFADDR` ioctl | 读 `/proc/net/if_inet6` | **已验证**（开发机 Linux） |
| macOS | 解析 `ifconfig -a` 的 `inet` 行 | 解析 `inet6` 行，去掉 `fe80::1%en0` 的 `%en0` | 未验证 |
| Windows | 解析 `ipconfig`（按 gbk 解码）的 IPv4 行 | 解析 IPv6 行 | 未验证 |
| 兜底 | `getaddrinfo(gethostname(), AF_UNSPEC)` | 同左（可能拿不全，也没有接口信息） | — |

真实枚举输出（Linux 开发机）：

```
linux addrs -> (['10.0.2.15', '192.168.56.101'],
                ['fd17:625c:f037:2:8d1b:c0ba:f309:1cf6', 'fd17:625c:f037:2:149a:d672:5e81:c293', ...])
```

### 过滤规则（客户端和服务端各做一遍）

去掉：loopback / link-local（`169.254.x.x`、`fe80::`）/ 多播 / 未指定 / 保留。
**保留**：RFC1918 私网（`10/8`、`172.16/12`、`192.168/16`）和 ULA（`fc00::/7`，实际就是 `fd..`）——
同局域网直连要用的正是这些。

真实过滤结果（`_dedup_usable`）：

```
输入: 127.0.0.1  169.254.1.1  192.168.1.5  10.0.0.7  224.0.0.1
      fe80::1  fd00::2  0.0.0.0  8.8.8.8  192.168.1.5（重复）
输出: 192.168.1.5  10.0.0.7  fd00::2  8.8.8.8
```

---

## 4. 第 2 步：和服务器交换地址

### 消息

| 方向 | type | 字段 |
|---|---|---|
| C→S | `p2pdirect` | `target`, `ipv4[]`, `ipv6[]` —— 请求：要对方的地址 |
| S→C | `p2pdirect` | `from`（服务器填）, `ipv4[]`, `ipv6[]` —— 转发给 target |
| C→S | `p2pdirect_reply` | `target`, `ipv4[]`, `ipv6[]` —— 应答：回自己的地址 |
| S→C | `p2pdirect_reply` | `from`（服务器填）, `ipv4[]`, `ipv6[]` —— 转发给 target |

**请求和应答是两个 `type`，不是 `reply` 字段**：这样收到消息一眼就知道"该不该回"，
不会两边"收到就回"无限来回。

### 服务器做什么（`handle_p2pdirect`）

| 检查 / 动作 | 细节 |
|---|---|
| 登录校验 | 没登录 → `not logged in` |
| target | 必填；不在线 → `user not found`；是自己 → `cannot connect to yourself` |
| 清洗地址 | 每族单独 `_clean_addr_list()`：挡掉 loopback / link-local / 多播 / 未指定 / 保留 / 非法 / 重复 |
| 数量上限 | 每族最多 **32** 条（`MAX_DIRECT_ADDRS`），超了直接截断 |
| 全空 | 清洗后一个不剩 → `no addresses` |
| `from` | **服务器自己填用户名的**，不信客户端传的 |
| 转发 | `type` **原样保留**（请求转成请求、应答转成应答），只换 `from` |
| 记录 | 不记录这些地址——它们是瞬时的 |

服务器日志：

```
[P2P-DIRECT] alice -> bob，转发 2 个 v4 + 1 个 v6（请求）
[P2P-DIRECT] bob -> alice，转发 2 个 v4 + 1 个 v6（应答）
```

`server.py` 的 dispatch 里两个 type 走同一个函数：

```python
elif msg_type == 'p2pdirect':
    handle_p2pdirect(ws, msg)
elif msg_type == 'p2pdirect_reply':
    handle_p2pdirect(ws, msg)     # 应答走同一个中转，只是 type 不同
```

### 客户端收到之后（`direct.on_peer`）

| 情况 | 行为 |
|---|---|
| 是 `p2pdirect`（对方来要地址） | `onpeerwantdirect=none` → 忽略；否则枚举自己的地址，回 `p2pdirect_reply` |
| 是 `p2pdirect_reply` | 只 ping，**不再回** |
| 自己也敲过 `direct` | 不重复回第二份，打一行"对方也在找我（地址已发过）" |
| 对方地址全被过滤光 | 打一行"没给可用地址，跳过" |
| 这条洞已经 ping 过 | 直接 return（两边同时敲 `direct` 会多收一条） |

### 起始消息

```json
{"type":"p2pdirect","target":"bob","ipv4":["10.0.2.15","192.168.56.101"],"ipv6":["fd17:...:1cf6"]}
{"type":"p2pdirect_reply","target":"alice","ipv4":["10.0.2.2"],"ipv6":[]}
```

---

## 5. 第 3 步：并发 ICMP ping

调**系统 `ping`**，普通用户即可，不需要 root。

| 平台 | 命令 | 超时单位 |
|---|---|---|
| Linux（iputils） | `ping -4\|-6 -c 1 -n -W 1 <ip>` | `-W` **秒**；`-n` 不做反向 DNS |
| macOS（BSD） | `ping` / `ping6 -c 1 -W 1000 <ip>` | `-W` **毫秒**；IPv6 用 `ping6` |
| Windows | `ping -4\|-6 -n 1 -w 1000 <ip>` | `-w` **毫秒**；`-n` 是 count，不是"不做 DNS" |

真实拼出来的命令：

```
192.168.1.5 -> ['ping', '-4', '-c', '1', '-n', '-W', '1', '192.168.1.5']
fd00::1     -> ['ping', '-6', '-c', '1', '-n', '-W', '1', 'fd00::1']
```

| 参数 | 值 |
|---|---|
| 判定方式 | stdout（转小写）里出现 `ttl=` 就算通——**比退出码可靠**（Windows 收到路由器的 "Destination host unreachable" 也会返回 0） |
| 并发 | `ThreadPoolExecutor`，`PING_WORKERS = 16` |
| 单次超时 | Linux `1s`（`PING_TIMEOUT_S`）/ macOS、Windows `1000ms`（`PING_TIMEOUT_MS`），子进程外层再宽限 `+3s` |
| 阶段超时 | `len(地址数) * 2 + 15` 秒 |

---

## 6. 结果

| `list hole` 列 | direct 洞的值 |
|---|---|
| `proto` | `direct` |
| `fd` | `-`（没 socket，也没交出去） |
| 本端 / 对端 | `-`（没有端口） |
| 状态 | `直连可行`（有可达）/ `不可直连`（一个都不通）/ `打洞失败`（第 2 步超时） |
| 额外列 | `可达=K/M`，K = 可达数，M = 对方给出的地址数（`peer_addrs`） |
| 可达清单 | 紧跟在下面一行 `可达地址: a, b` |

```
  #3   direct 直连可行        bob            fd=-    本端 -  对端 -  可达=2/3
       可达地址: 192.168.56.1, 10.0.2.2
```

洞记录里的字段：

| 字段 | 内容 |
|---|---|
| `peer_addrs` | 对方给的、过滤后的地址表（direct 洞没有端口，只存 IP） |
| `reachable` | 真正 ping 通的那几个 |
| `local_init` | 这条洞是不是自己敲 `direct` 发起的（决定第 2 步的结果归谁） |

**direct 不建隧道、不拉子进程**——`_handover_hole()` 也拉不动它（它只认 `proto='udp'` 且 `status='已打通'` 的洞）。

---

## 7. 重要语义：ICMP 通 ≠ 端口能过

有些机器 ping 得通，但端口被防火墙过滤。所以 `direct` 只是**可达性报告**：

| 它能证明 | 它不能证明 |
|---|---|
| 对方这些 IP 地址在当前网络路径上可达 | 对方任何 **TCP/UDP 端口**能连上 |
| 直连值得一试 | 直连一定成功 |

真要传数据还得有个"能过的端口"——`upnp` 就是干这个的（**还没实现**，见 [readme-upnp.md](readme-upnp.md)）。

---

## 8. 代码位置

| 文件 | 角色 |
|---|---|
| [client/hole/direct.py](../client/hole/direct.py) | 枚举地址、ping、`run()` / `on_peer()` |
| [client/hole/core.py](../client/hole/core.py) | 3 步的显示（`DIRECT_STEPS` / `DIRECT_STEP_DESC`）、`get_onpeerwant('direct')` |
| [server/server.py](../server/server.py) | `handle_p2pdirect()` + `_clean_addr_list()` + `MAX_DIRECT_ADDRS` |
| [client/client.py](../client/client.py) | `direct` 命令 dispatch、`p2pdirect*` 消息分发、`_print_holes()` 里的 `可达=K/M` |
| [readme-android.md](readme-android.md) + `android/app/.../net/LocalAddrs.kt` / `net/IcmpPing.kt` | 安卓端实现：`getifaddrs` 枚举 + **子进程调 `/system/bin/ping`**（以输出里有没有 `ttl=` 判定）、卡片三步进度、每个地址一行日志、被动 auto 应答 |
| `ios/p2pnet/Util/LocalAddrs.swift` / `Util/IcmpPing.swift` | iOS 端实现：同样枚举与三步，但**没有 ping 命令**，用非特权 ICMP datagram socket（`SOCK_DGRAM` + `IPPROTO_ICMP` / `IPPROTO_ICMPV6`），结果分 可达/不可达/本机无法执行 三档 |

> 两端都**只发/收服务端已有的 `p2pdirect` / `p2pdirect_reply`**，字段就是上面第 4 节那套（`target` / `from` / `ipv4` / `ipv6`），没有新增 type、也没有签名（`direct` 的包不带 HMAC，和 `p2pudp_hello` 不同）。

---

回到总览：[readme.md](../readme.md)
