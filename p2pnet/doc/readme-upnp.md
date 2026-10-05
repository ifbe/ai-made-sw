# `upnp`：让路由器开端口映射（**计划，还没实现**）

**本文讲什么**：`upnp` 命令和 `onpeerwantupnp` 开关**现在是什么状态**（占位）、
**计划怎么做**（UPnP IGD：SSDP 发现 + `AddPortMapping`），以及为什么**双方都得有 UPnP**。
本文全部内容都是计划，不是可用功能。

> ⚠️ **还没实现**：`upnp` 不会碰路由器、不会开任何端口、不会发任何包。

---

## 1. 现状

| 项 | 状态 |
|---|---|
| `upnp` 命令 | 存在（`client.py` 里有 dispatch），但只**打印三行说明** |
| [client/hole/upnp.py](../client/hole/upnp.py) | 14 行占位文件：一个 `run()`，三条 `core.log()`；没有发现、没有映射、没有端口 |
| `onpeerwantupnp [auto\|none]` | 状态位 `ON_PEER_WANT['upnp']` 能读能写，但**没有任何消费者** |
| 服务端 | 没有 upnp 相关消息类型（`handle_message` 里没有分支） |
| 参数 | `upnp` 不带参数；`run()` 也不接参数（后面给什么都忽略） |
| 消息 | 没有为 UPnP 定义过任何 `type` |

`client.py` 里就是这一句：

```python
elif cmd == 'upnp':
    # 和路由器协商直接开端口映射 —— 协议待定
    hole_upnp.run()
```

> 下面三行是**真实输出**（`python3 -c "from hole import upnp; upnp.run()"`）：

```
[upnp] 协议待定，还没实现。计划：
  用 UPnP IGD（SSDP 发现 + AddPortMapping）让路由器开一个外网端口映射，
  映射成功就相当于自己有公网地址，不需要打洞
```

`onpeerwantupnp` 的真实提示：

```
> onpeerwantupnp
onpeerwantupnp = auto
  auto  - 参与（默认，当前行为）
  none  - 静默拒绝：不参与，本地留一行提示
  注意: upnp 本身还没实现，这一项目前没有消费者，只是先把状态位留着
```

> 对比：`udp` / `tcp` / `direct` 都真的会调 `core.get_onpeerwant(...)`；
> 全仓库**没有任何地方**调 `get_onpeerwant('upnp')`。

---

## 2. 计划：用 UPnP IGD 换一个"准公网地址"

思路一句话：**用 UPnP IGD 让路由器开一个外网端口映射，映射成功就相当于自己有公网地址，不用打洞。**

| 步 | 做什么 | 用到 |
|---|---|---|
| 1 发现 | 往 `239.255.255.250:1900` 发 SSDP `M-SEARCH`（`ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`），找 IGD 设备 | UDP 多播 |
| 2 拿控制地址 | 拉设备描述 XML，取 `controlURL` / `serviceType`（`WANIPConnection` 或 `WANPPPConnection`） | HTTP |
| 3 问外网 IP | `GetExternalIPAddress` | SOAP |
| 4 开映射 | `AddPortMapping`：外部端口 → 本机 `内网IP:端口`，指定 TCP/UDP、租期 | SOAP |
| 5 报告 | 把 `外网IP:外部端口` 当自己的"准公网地址"，通过 p2pnet 信令告诉对方 | 现有 WebSocket |
| 6 清理 | 退出时 `DeletePortMapping` | SOAP |

| 要定的事 | 备选 |
|---|---|
| 外部端口 | 让路由器自己挑，还是指定一个 |
| 内网端口绑给谁 | 新开一个 UDP socket / 直接给内核 WireGuard（`listen-port`）/ 给打洞流程 |
| 租期 | `0` = 永久，还是定时续 |
| 拿不到 IGD 时 | 明确报错，还是静默退回打洞 |

---

## 3. 为什么双方都要 UPnP

**双方的路由不确定谁的 UPnP 通，所以双方都需要 UPnP。**

只映射一边没用：映射成功那一边是"准公网地址"，另一边还在 NAT 后面，**外部主动进来的包照样被丢**，
而且对面也没有可写进 `endpoint` / 可连的地址。

| Alice 的 UPnP | Bob 的 UPnP | 结果 |
|---|---|---|
| ✓ | ✓ | 两边都有公网可达地址，**可以直接互通**，不用打洞 |
| ✓ | ✗ | 只有 Alice 有洞可进；Bob 仍要主动发出去建立映射 → 又回到"打洞 + 保活"那套 |
| ✗ | ✗ | UPnP 这条路没有意义 → 打洞（[readme-udp.md](readme-udp.md) / [readme-tcp.md](readme-tcp.md)） |

---

## 4. 和 `direct` / 打洞的关系

| 手段 | 解决的问题 | 需要对方配合 | 现状 |
|---|---|---|---|
| [direct](readme-direct.md) | 对方**地址**可不可达（ICMP） | 对方回地址 | 已实现 |
| [udp](readme-udp.md) / [tcp](readme-tcp.md) 打洞 | 在 NAT 上**凿一个洞** | 双方同时发 | 已实现 |
| `upnp` | 直接拿到一个**外网端口**，不用凿洞 | 双方都要开映射（第 3 节） | **未实现** |

`direct` 说"这个地址 ping 得通"，`upnp` 想解决的正是 direct 证明不了的那半截——
**端口能不能过**。

---

## 5. 明确标注

| 别指望 | 说明 |
|---|---|
| `upnp` 能开端口 | 现在只打印三行字 |
| 改 `onpeerwantupnp` 有用 | 没有任何代码读它 |
| 服务端会配合 | 没有定义过任何 upnp 消息类型 |
| 有部分实现可以接着写 | `hole/upnp.py` 里没有任何可复用的逻辑，要从零写 |

---

## 6. 代码位置

| 文件 | 角色 |
|---|---|
| [client/hole/upnp.py](../client/hole/upnp.py) | 14 行占位（`run()` 三条日志） |
| [client/client.py](../client/client.py) | `upnp` 命令 dispatch（第 1777 行）、`ON_PEER_WANT['upnp']`、`onpeerwantupnp` 的设置与提示 |
| [client/hole/core.py](../client/hole/core.py) | `get_onpeerwant` 钩子（注释里列了 `upnp`，但没人调） |

---

回到总览：[readme.md](../readme.md)
