# TODO / 待研究

---

## 大规模 Mesh（10+ peers）

**当前状态：** p2pnet 只做 pair-wise 直连，不含路由层。

**问题：**
- 全网状拓扑：N peers → 每人有 N-1 条 tunnel，总连接数 N×(N-1)/2，不可持续
- 不是每对 peers 都能打洞成功，需要 relay fallback
- 共用 TUN 接口时，多个 tunnel 进程写同一个 fd 有竞争风险

**方向：两层 Overlay**

```
第一层（现在做的）：打洞 + 裸 tunnel，P2P 直连或 relay
第二层（待加）：client.py 作为 central switch，多个子 tunnel 进程汇入
```

**已实现 / 进行中（clientsocket 架构）：**
- `local fake`（默认）→ 子进程用 `--nettype fake`
- `local tun <dev>` / `local tap <dev>` → 子进程用 `--nettype clientsocket --socketpath`
- `local auto` → 子进程用 `--nettype auto`
- client.py 监听 Unix socket `/tmp/p2p/{user}-{peer}.sock`
- 每个 udp.py / tcp.py 用 `--nettype clientsocket --socketpath PATH` 连入
- client.py select 监听 tun fd + 各 child socket
- tun 收包按路由表发往对应 child；child 数据汇总写 tun
- 子进程断连 → client.py 从表里删除 + log

**待实现：**
- client.py 侧 Unix socket server + select 多路复用
- 路由表：目的 IP → child socket（静态映射，peer IP 已知）

**路由协议可选：**
- Babel（轻量，支持有线/无线 mesh，易实现）
- OLSRv2（工业级，更复杂）
- 简化方案：中心 tracker 分发路由表（适合受控网络）

**IP 分配方案（/30 问题）：**
- 每对用一个 /30 → /30 数量 = N-1，不可持续
- 方案：所有人用同一 /24 网段，每人一个 IP，启动时协商分配

---

## Warcraft 3 IPX 支持

**问题：** 魔兽 3 局域网对战用 IPX/SPX 协议，不是 IP。TUN 只处理 IP 包，IPX 不通。

**协议栈对比：**
```
TUN (IP 层)     → 只认识 IP 协议族
TAP (Ethernet)  → 可以收发 Ethernet 帧，但帧内 Type 字段区分 IPv4/IPX 等
```

**方案 A：找 TCP/IP 版本**
- 魔兽 3 1.28+ 原生支持 TCP/IP，盗版/民间有 IPX-over-TCP 模拟器
- 最简单，改配置即可

**方案 B：TAP + 网桥封装**
- TAP 收到 Ethernet 帧，根据 Type 字段区分 IPv4 / IPX
- IPX 包通过额外封装的隧道到达对端 TAP
- 需要额外处理 IPX 广播（IPX 用广播做地址解析，NAT 穿透更复杂）

**结论：** 方案 A 最实际，除非有特殊需求必须用 IPX。
