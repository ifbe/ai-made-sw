# 洞上应用：proxy（端口转发）

**本文讲什么**：把一条打好的 **UDP 洞**当成裸通道，和指定目标 `host:port` 双向转发（远程桌面 / SSH / 任意端口转发）。
这条洞怎么打的见 [readme-udp.md](readme-udp.md)。

---

## 1. 怎么起

| 方式 | 命令 / 位置 |
|---|---|
| CLI（已打通的洞上） | `proxy <洞标识> <host:port>`（例：`proxy fd=4 127.0.0.1:3389`、`proxy bob 127.0.0.1:22`） |
| 洞打通自动拉起 | `onholefromself` / `onholefrompeer` 取值 `proxy <host:port>` |
| 图形端 | 桌面：proxy 页（`ProxyPage`，配置卡 + 代理卡）；Android：[`ui/ProxyPage.kt`](../android/app/src/main/java/com/example/p2pnet/ui/ProxyPage.kt)；iOS：[`UI/Pages/ProxyPage.swift`](../ios/p2pnet/UI/Pages/ProxyPage.swift) |

洞标识：`fd=<fd>` / `port=<本端端口>` / `#<编号>` / `<用户名>`。

## 2. 拉起什么

`client.py:_launch_proxy()` → `python3 app/proxy.py --target <host:port>`
再由 `_launch_hole_program()` 补上洞的信息：

```
--peeraddr <对方IP> --peerport <对方端口> --localport <本端UDP端口>
[--peercandidates <ip:port,ip:port>]       # 打洞时学到的额外候选（peer-reflexive）
[--remotelog /tmp/p2pnet/proxy-<user>_<peer>_<ts>.log]   # 仅 --remotelog 时
```

**为什么必须沿用同一个本地端口**：proxy.py 自己 `bind` 打洞时那个 UDP 端口，NAT 映射才不会废。

## 3. 参数表（`app/proxy.py`，从代码读）

| 参数 | 默认 | 说明 |
|---|---|---|
| `--peeraddr` | **必填** | 对方 IP（v4/v6/域名） |
| `--peerport` | **必填**（int） | 对方端口 |
| `--localport` | **必填**（int） | 本地 UDP 端口，**必须和洞的端口一致** |
| `--peercandidates` | `None` | 额外候选，`ip:port,ip:port` |
| `--localaddr` | `0.0.0.0` | 本地监听地址 |
| `--target` | `None` | 转发目标 `host:port`（**CLI 路径一定会给**，不给会直接打用法提示） |
| `--proto` | `tcp` | 目标侧协议：`tcp` / `udp` |
| `--remotelog` | `None` | 日志文件（默认 stdout） |

内部结构：`udp_listener`（洞 → 目标，顺带学源地址）、`target_reader`（目标 → 全部候选）、
`keepalive`（`KEEPALIVE_INTERVAL = 20.0` 秒往候选各发一个**空 UDP 数据报**，保 NAT 映射）。

## 4. 当前状态

- **`app/proxy.py` 代码在**（18KB：三条线程 + TCP 连接或已 connect 的 UDP socket 两种目标），
  但**我没做过端到端转发验证** → **未验证**。
- **`-L` / `-R` 两种模式在代码里不存在**：桌面 proxy 页上那两个选项（`正向 -L` / `反向 -R`）只是页面上的选择项，
  按下去只写日志；`app/proxy.py` 也没有对应参数 → **这两种模式目前都不可用**。
- **`--proto udp` 从 CLI 走不到**：`client.py` 只传 `--target`，`--proto` 用默认 `tcp`
  → 实际只能转发到 **TCP** 目标。
- 图形端 proxy 页的「启动」按钮**只写日志**（Phase 1 骨架）。

## 5. 已知限制

- 有坑见 [readme-gotcha.md](readme-gotcha.md)。
- 目标侧若只想通 UDP 服务（如自建 UDP 服务），现在的 CLI 通路做不到（见上）。

---

相关：[readme-cli.md](readme-cli.md)（`proxy` 命令）、[readme-udp.md](readme-udp.md)（洞怎么打）、[readme-tcp.md](readme-tcp.md)（TCP 洞是另一条路：第 5 步把内核 socket 继承给子进程，proxy 用的是 UDP 洞）、[readme-gotcha.md](readme-gotcha.md)、[readme-desktop.md](readme-desktop.md)（桌面 proxy 页）。
