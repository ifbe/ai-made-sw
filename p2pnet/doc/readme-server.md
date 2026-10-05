# 服务端（`server/server.py`）

## 启动

```bash
# 1. 建用户（写进 passwd.json）
python3 server/secret.py -f server/passwd.json add alice -p pw

# 2. 起服务器（TCP 与 UDP 同端口）
python3 -u server/server.py --port 10000 --udpport 10000

# 3. 调试：打印所有 WebSocket 消息
python3 -u server/server.py --port 10000 --udpport 10000 --debug
```

参数：`--host`（默认 `0.0.0.0`）/ `--port`（TCP）/ `--udpport`（默认同 `--port`）/ `--debug`。
用户管理：`python3 server/secret.py {list,add,del,mod,verify} -f server/passwd.json …`。

## 两个端口

| 端口 | 用途 |
|---|---|
| TCP `--port` | WebSocket 信令。`/` 走 WS 握手；其它路径当静态文件（`server/static/`） |
| UDP `--udpport` | 收客户端的 UDP 注册/打洞包，记录其**公网地址**（打洞靠它交换地址） |

## 认证

```
客户端 → login {username}                                   ← 第一次，不带 response
服务端 → challenge {challenge}                              ← 有效期 300s
客户端 → login {username, response}                         ← response = HMAC-SHA256(hexDecode(pw_hash), hexDecode(challenge))
服务端 → login_ok                                          ← 通过；否则 error("auth failed")
```

- **`session_key` 从不在网络上传输**：两端各自算 `HKDF-SHA256(ikm=pw_hash, salt=pw_hash, info=hexDecode(challenge))`；
- **`p2pudp_hello` 必须带签名** `HMAC(session_key, "ping")`，否则服务端直接丢弃（见 `verify_session_signature`）；
- **同名重复登录**：把旧连接**踢掉**（给旧连接发 `kicked`）后接受新连接 —— 所以客户端重连后可以自动重登。

## 中转的消息类型

`p2pudp` / `p2pdirect` / `p2pdirect_reply` / `p2ptcp`：按 `target` 用户名找到对端连接并转发（服务端是**信令 + 地址中转**，数据走客户端之间的洞）。

地址相关注意：

- **每族地址上限 `MAX_DIRECT_ADDRS = 32`**，并且会**挡掉** loopback / link-local / 多播 / 保留地址（否则对端 ping 自己的 loopback 会假报"直连可行"）；
- ⚠️ **服务端不发 `server_ip`**：`send_udp_to_server` 只给 `udpport`，客户端**必须自己**把登录用的主机名解析成 IP —— 这里踩过一次坑（域名喂 `sendto` 直接失败），见 [readme-gotcha.md](readme-gotcha.md)。

## 心跳

| 层 | 客户端发 | 服务端回 |
|---|---|---|
| WS 协议级 | `0x9` ping 帧（客户端帧按 RFC 6455 掩码） | **原样**回 `0xA` pong（payload 一致） |
| 应用层 | `{"type":"ping","seq":N}` | `{"type":"pong","seq":N}`（**不需要登录**） |

两者都在；客户端的用法见 [readme-cli.md](readme-cli.md)。

相关：[readme-udp.md](readme-udp.md) / [readme-tcp.md](readme-tcp.md)（协议流程）、[readme-gotcha.md](readme-gotcha.md)（已知的坑）。
