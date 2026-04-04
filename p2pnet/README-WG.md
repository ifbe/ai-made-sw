# WireGuard NAT 穿透 — 特殊用法

## 核心发现

WireGuard 固定 `ListenPort` + UDP 打洞 = **无需 p2pnet 套一层**，原生 WireGuard 直接穿透 NAT 对等连接。

---

## 为什么通常 WireGuard 很难穿透 NAT

WireGuard 使用固定格式的 UDP 包：

```
WireGuard packet: 
  Sender index (4B) + Encrypted contents (16B header + payload)
```

但关键在于 **WireGuard 不知道对方在哪**——它需要一个 `Endpoint = ip:port` 显式配置。

通常 NAT 穿透失败的原因是：

```
Bob 在 NAT 后面，WireGuard 用随机临时端口 40000 发包
→ NAT 为这个会话建立了 5.6.7.8:40000 → Bob:40000 的映射
→ 但 Alice 不知道 Bob 的公网映射端口，她只能往 5.6.7.8:51820 发
→ NAT 收到 5.6.7.8:51820 的包，但映射是 40000 的，拒绝！
```

---

## 关键：固定 ListenPort

```ini
# Bob 的 WireGuard 配置
[Interface]
PrivateKey = <bob_private>
ListenPort = 51820    # ← 关键：收发都用 51820

[Peer]
PublicKey = <alice_public>
Endpoint = 1.2.3.4:51820   # Alice 的公网地址（需要打洞得知）
PersistentKeepalive = 25   # 维持 NAT 映射
```

```
Bob 的 NAT 建立映射：
  5.6.7.8:51820 → Bob:51820

Bob 发出的 WireGuard 包：
  src = 5.6.7.8:51820（跟 NAT 映射一致）
  dst = 1.2.3.4:51820

Alice 发出的 WireGuard 包：
  src = 1.2.3.4:51820
  dst = 5.6.7.8:51820（正好匹配 Bob 的 NAT 映射）
```

**只要洞打成功，WireGuard 的固定端口机制天然匹配 NAT 映射**，直接互通。

---

## 完整流程

### 第一步：打洞（我们的 signaling 服务器）

```
1. Alice → Server:  发 UDP 包（NAT 建立 1.2.3.4:51820 → Alice:51820）
2. Bob → Server:     发 UDP 包（NAT 建立 5.6.7.8:51820 → Bob:51820）
3. Server → Alice:  通知 Bob 的公网地址 5.6.7.8:51820
4. Server → Bob:    通知 Alice 的公网地址 1.2.3.4:51820
5. Alice 和 Bob 同时往对方公网地址发 UDP 包 → 洞穿透
```

### 第二步：WireGuard 启动

```
两端的 wg-quick up 配置文件里，Endpoint 已经配好对方的公网地址。
由于 PersistentKeepalive = 25 每 25 秒自动发 UDP 空包：
  → NAT 映射一直保持活跃
  → 洞永远不会过期
```

### 第三步：WireGuard 自动维持

```
WireGuard 的 handshake 本身也会发包（约每 2 分钟一次），
这些包本身就充当了 NAT 保活的作用。
PersistentKeepalive 只是更频繁地发空包，确保 NAT 映射不失效。
```

---

## 为什么不需要 p2pnet

| 传统方案 | 本方案 |
|---------|--------|
| p2pnet（我们写的 tunnel 软件） | 原生 WireGuard |
| L3 Switch（自定义路由） | WireGuard 的内置路由表 |
| 我们维护的 UDP 隧道 | WireGuard 的加密隧道 |
| 复杂的 hole punching + relay | 只需一次打洞 + WireGuard 自动保活 |

**我们只做一件事**：通过 signaling 服务器完成 UDP 打洞，通知对方公网地址。之后完全由原生 WireGuard 处理。

---

## 限制

1. **需要 signaling 服务器**：两端的公网地址谁来告诉对方？需要一个轻量服务器跑打洞协议
2. **对称 NAT 问题**：如果双方都在对称 NAT 后面，打洞可能失败（中继仍需要）
3. **固定端口必须双方都设**：ListenPort = 51820 两端都要设
4. **Endpoint 地址可能变化**：如果 NAT 重启，公网 IP/端口会变，需要重新打洞

---

## signaling 服务器要做什么

```python
# 极简 signaling（伪代码）
on_receive_udp_from_alice(addr, port):
    # Alice 的公网地址
    store alice.public_addr = (addr, port)
    notify alice about bob.public_addr  # 如果 bob 已上线

on_receive_udp_from_bob(addr, port):
    # Bob 的公网地址
    store bob.public_addr = (addr, port)
    notify bob about alice.public_addr  # 如果 alice 已上线
```

服务器只负责**通知地址**，不转发任何 WireGuard 流量。

---

## 文件

- `signaling.py` — 打洞 signaling 服务器（TODO）
- `client/wghelp.sh` — 原生 WireGuard 配置脚本
- `client/ffmpeg.sh` — P2P 视频流发送/接收脚本（ffmpeg 发送 + ffplay 接收）
- `client.py wghelp` — client 内置命令，自动拉起 wghelp.sh
- `client.py ffmpeg` — client 内置命令，自动拉起 ffmpeg.sh 做 P2P 视频通话

---

## 结论

WireGuard 的固定 `ListenPort` 机制与 UDP 打洞天然契合：
- 打洞建立 NAT 映射（src port = dst port = ListenPort）
- WireGuard 的 PersistentKeepalive 维持映射不过期
- 原生 WireGuard 处理所有隧道逻辑

**我们只需要一个轻量 signaling 服务器通知对方公网地址。**

---

## client.py wghelp 命令

```
用法: wghelp <对方用户名> <我的私钥> <我的mesh IP>
例: wghelp bob YGzbJJ8... 192.168.250.2
```

前半段逻辑同 `wg`（p2pwg 握手），后半段自动拉起 `wghelp.sh` 配置原生 WireGuard。

私钥不会经过服务器，只传给 wghelp.sh（当前机器 sudo 运行）。

**流程：**
```
1. 输入: wghelp bob <私钥> 192.168.250.2
2. client.py 发 p2pwg 给 server
3. server 返回 bob 的公钥 + mesh IP + 公网地址（如果支持 hole punch）
4. wghelp.sh 启动（需要 sudo）
5. wg set 动态配置 peer endpoint
6. ping 192.168.250.x 测试
```
