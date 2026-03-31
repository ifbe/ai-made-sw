# P2P UDP 打洞流程

## 消息类型

| 方向 | type | 说明 |
|------|------|------|
| C→S | `p2pudp` | 发起 P2P UDP 连接请求 |
| S→C | `send_udp_to_server` | 服务器通知客户端往服务器发 UDP 包 |
| S→C | `thisisyourpeer_udp` | 服务器告知对端 UDP 地址 |
| S→C | `incoming_p2pudp` | 通知有人想和你建立 P2P |

---

## 完整流程

```
alice 和 bob 都已登录，服务器已知双方 TCP 地址

alice:  > p2pudp bob
bob:    > p2pudp alice

alice:  服务器 → {"type": "send_udp_to_server", "udpport": 9999}
bob:    服务器 → {"type": "send_udp_to_server", "udpport": 9999}

alice:  往服务器 9999/UDP 发一个 UDP 包
bob:    往服务器 9999/UDP 发一个 UDP 包
        服务器从包头拿到双方 (公网IP, NAT端口)

        alice: (1.2.3.4, 40001)
        bob:   (5.6.7.8, 30001)

        服务器发现 alice 和 bob 都请求了对方（双向请求）

alice:  服务器 → {"type": "thisisyourpeer_udp", "name":"bob",   "ip":"5.6.7.8", "port":30001}
bob:    服务器 → {"type": "thisisyourpeer_udp", "name":"alice","ip":"1.2.3.4", "port":40001}

alice:  收到后启动 p2pudp.py 5.6.7.8 30001
bob:    收到后启动 p2pudp.py 1.2.3.4 40001

双方:   p2pudp.py 同时往对方地址发 UDP 包打洞
        ping/pong 确认双向可达
        成功则 P2P 隧道建立
        失败则告知走中继
```

---

## 服务器字段

- `udp_addrs[username]` = `{"ip": "x.x.x.x", "port": yyyy, "local_port": zzzz}`
- `p2p_requests[username]` = `{"target": "bob", "timestamp": ...}`

---

## p2pudp.py 参数

```
python3 p2pudp.py <peer_ip> <peer_port>
```

收到 `thisisyourpeer_udp` 后由 client.py 自动 spawn。

---

## 服务器 --udpport 参数

```
python3 server.py --udpport 9999
```

指定服务器 UDP 监听端口（用于接收客户端的 UDP 包以获取公网地址）。
