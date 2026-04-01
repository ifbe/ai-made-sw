# P2P UDP 打洞流程

## 消息类型

| 方向 | type | 说明 |
|------|------|------|
| C→S | `p2pudp` | 发起 P2P UDP 连接请求 |
| S→C | `send_udp_to_server` | 服务器通知客户端往服务器 UDP 端口发包 |
| S→C | `thisisyourpeer_udp` | 服务器告知对端公网(IP, 端口) |
| S→C | `incoming_p2pudp` | 通知有人想和你建立 P2P |

---

## 完整流程

```
alice 和 bob 都已登录，服务器已知双方 TCP 地址

alice:  > p2pudp bob
bob:    > p2pudp alice

alice:  服务器 → {"type": "send_udp_to_server", "udpport": 9999}
bob:    服务器 → {"type": "send_udp_to_server", "udpport": 9999}

alice:  往服务器 9999/UDP 发 UDP 包（p2pudp_hello）
bob:    往服务器 9999/UDP 发 UDP 包（p2pudp_hello）
        服务器从包头拿到双方公网地址：

        alice: (1.2.3.4, 40001)
        bob:   (5.6.7.8, 30001)

        服务器发现 alice 和 bob 都请求了对方（双向请求）

alice:  服务器 → {"type": "thisisyourpeer_udp", "name":"bob",   "ip":"5.6.7.8", "port":30001}
bob:    服务器 → {"type": "thisisyourpeer_udp", "name":"alice","ip":"1.2.3.4", "port":40001}

alice:  收到后启动 udptunnel.py 5.6.7.8 30001 <hello_port>
bob:    收到后启动 udptunnel.py 1.2.3.4 40001 <hello_port>

双方:   互发 UDP 包打洞
        ping/pong 确认双向可达
        收到 3 个连续 pong 后 tunnel 就绪
        失败则告知走中继
```

---

## 服务器状态字段

- `udp_addrs[username]` = `{"ip": "x.x.x.x", "port": yyyy, "timestamp": ...}`
- `p2p_requests[username]` = `{"target": "bob", "timestamp": ...}`

---

## udptunnel.py 参数

```
python3 udp.py <peer_ip> <peer_port> <local_port> [--nettype tun|tap|auto]
```

收到 `thisisyourpeer_udp` 后由 client.py 自动 spawn。

`--nettype` 说明：
- `auto`（默认）：按平台自动选择：Linux → `tun → tap → fake`，macOS → `tun → fake`
- `tun`：强制 TUN（IP 层），macOS 用 utun，Linux 用 /dev/net/tun
- `tap`：强制 TAP（Ethernet 层，Linux 专用）
- `fake`：假接口，用于测试

## udptunnel.py 架构

```
三个线程：
  主线程（唯一）：select 监听 socket，收 UDP 包
    - 收到 ping  → 回复 pong
    - 收到 pong  → 统计，够 3 个连续后启动 tunnel 线程
    - 收到其他数据 → 进队列（tunnel 未就绪则丢弃）

  heartbeat_sender 线程：每秒发一个 ping

  tunnel_worker 线程：等 ready 后启动
    - 从 tun 读数据 → 发 UDP
    - 从队列取数据 → 写 tun
```

心跳机制：
- ping 间隔：1 秒
- ready 条件：收到 3 个连续 pong（RTT 相近）
- 超时：confirmed 后 5s 无 pong 断开；未 confirmed 时 10s 放弃
