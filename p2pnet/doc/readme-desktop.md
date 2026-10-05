# 桌面端：`client/client-gui.py`（PyQt6 图形客户端）

**本文讲什么**：桌面端怎么跑、内部怎么分层、主页（自由层）和六个页面长什么样、
它怎么驱动 `client.py`（**进程内导入调函数，不开子进程**）、哪些是真实现哪些是壳、
以及桌面端专属踩过的坑。

**和别的文档的分工**：
[readme-udp.md](readme-udp.md) / [readme-tcp.md](readme-tcp.md) / [readme-direct.md](readme-direct.md) /
[readme-wg.md](readme-wg.md) 讲**协议本身**；[readme-android.md](readme-android.md) 讲安卓端；
桌面端的界面形态**对齐安卓**（`android/app/src/main/java/com/example/p2pnet/ui/login/MainPage.kt`），
所以本文只讲"桌面这一侧怎么做的、和安卓哪里不一样"。

> **源码只有一个文件**：`client/client-gui.py`（约 3400 行）。
> 桌面端**不改 `client.py`**，也不新增任何资源文件（状态点图标是代码画的）。

---

## 1. 快速开始

```bash
# 正常跑（会弹真窗口）
python3 client/client-gui.py

# 无人值守自检：构建完整界面、不显示窗口、不进事件循环、断言一大串东西后退出
QT_QPA_PLATFORM=offscreen python3 client/client-gui.py --self-test

# 只查语法
python3 -m py_compile client/client-gui.py
```

| 项 | 值 |
|---|---|
| 依赖 | **PyQt6**（开发机 6.11.0 / Qt 6.11.0）+ Python 标准库，**不装任何别的东西** |
| Python | 开发机 3.14.8（代码用了 `X | None` 注解 + `from __future__ import annotations`） |
| 许可 | 本机 PyQt6 是 **GPL-3.0**。代码只用 **PyQt6 / PySide6 都有**的 API，枚举一律 fully-scoped；将来要发闭源二进制就换 LGPL 的 PySide6 —— **只需改两处**：所有 `from PyQt6.*` → `from PySide6.*`，`pyqtSignal` → `Signal` |
| 需要 server 吗 | 启动不需要；不连服务器时窗口照常开，只是点「未连接，点我连接」会连失败 |
| 默认连哪 | 服务器卡默认 `127.0.0.1:10000`、协议 `ws` |

---

## 2. 四个必须先知道的设计决定

1. **不开 `client.py` 子进程，而是 `import client` 调它的函数**（用户明确要求"两者不要耦合、但可以调它的函数"）。
   导入点：`EngineBridge.load()`（第 2136 行那块）。`client.py` 末尾有 `if __name__ == '__main__'` 守卫，导入无副作用；
   `client._hole_configure()` 必须调一次（把日志/WS/建洞记录/回调注入 `hole/`，都是惰性闭包，未连接也安全）。
2. **所有 `client.py` 调用串行化到一条"引擎线程"**。`client.py` 原本是单线程 select 循环写的，
   `ws_send` / `process_input_line` 都不是线程安全的 —— 所以 GUI 只往 `queue.Queue` 投命令，
   由引擎线程取出后调 `client.process_input_line(...)`（= REPL 等价物），**GUI 从不直接调 `client.py`**。
3. **日志靠重定向 `sys.stdout`（tee）**。`client.log()` 内部就是 `print(...)`，所以把 stdout 换成
   `_StreamRelay` 之后，client.py 的日志、`hole/` 的打洞步骤行、所有 `print` 全都汇进 App 内日志；
   终端照旧有输出。**没有 monkeypatch `client.log`** —— 它内部还有 `hole_core.finish_open()` 的副作用，
   覆盖它会破坏步骤行的收尾。
4. **主题是 Fusion + 自设深色 QPalette**，不是跟着系统主题走。窗口和卡片**都是黑的**，层次靠
   **1px 高亮描边**（`#4a9eff`）区分。这条是修 bug 修出来的经验，见第 12 节。
5. **WS 心跳和应用层 ping 都实现在 `client.py` 里，GUI 不自己实现**（第 7.1/7.2 节）。
   原因：GUI 是 in-process 驱动、**自己跑收循环**，如果心跳写在 GUI 里，命令行模式就没有；
   反过来写在 `main()` 的 select 循环里，GUI 模式又没有。放 `client.py` 才能两种模式都自动生效。

---

## 3. 文件结构（10 块，行号供跳转）

| 块 | 起 | 内容 |
|---|---|---|
| 1 | 114 | 常量与配色：6 个 tab、三态状态色、暗色配色常量（`C_WINDOW/C_CARD/BORDER_CARD/…`）、`apply_dark_theme()`、`make_font()` |
| 2 | 271 | 小工具：`make_state_icon()`（**代码画**状态点，无 png）、`card()/field_row()/choice_buttons()/section_note()` |
| 3 | 385 | 标题栏：`WindowButton` / `TitleBar`（6 tab + 三个窗口按钮 + 拖动 + 双击最大化 + 平台分叉） |
| 4 | 526 | `Page` 基类（带滚动区，配置页用） |
| 4a | 564 | **主页**：对齐安卓 `MainPage.kt` —— 常量 + 纯几何函数 + `CompactField/DragLabel/ServerCard/MeCard/PeerCard/SocketCard/FreeLayer/HomePage` |
| 5 | 1820 | 日志浮层 `LogOverlay`（右下角胶囊 + 90% 面板 + 动画） |
| 6 | 2014 | 系统托盘 `Tray`（`QSystemTrayIcon`，不可用时优雅降级） |
| 7 | 2097 | **引擎桥**：`_StreamRelay` + `EngineBridge`（导入 client.py、引擎线程、命令队列、数据信号） |
| 8 | 2439 | `ContentArea`（页面栈 + 浮层宿主）+ `MainWindow`（无边框、边缘缩放、✕ 语义） |
| 9 | 2813 | 单实例（`QLocalServer`/`QLocalSocket`） |
| 10 | 2854 | `main()` + `run_self_test()` |

---

## 4. 窗口外壳

- **无边框**（`Qt.WindowType.FramelessWindowHint`）+ 自绘标题栏：左侧 6 个 tab、右侧三个窗口按钮，高 38px。
- **拖动**：标题栏空白处按下 → `windowHandle().startSystemMove()`（交给系统，手感/贴边/跨屏才对）；
  点在 tab 或窗口按钮上**不会**触发拖动。
- **双击标题栏空白** = 最大化 / 还原；最大化状态变化会同步 `▢/❐` 字形。
- **边缘缩放**：根布局留 5px 边（`RESIZE_MARGIN`），鼠标移进去换光标，按下时 `startSystemResize(edges)`；
  最大化时禁用。
- **平台分叉**（`IS_MAC`）：
  - Windows / Linux：自绘 `— ▢ ✕` 放**右侧**（和 Chrome 一致）；
  - macOS：仍然 Frameless + 自绘，但按 macOS 习惯把三颗**圆形**按钮放**左侧**（红黄绿），tab 紧随其后。
    为什么不做"保留原生红黄绿 + 把 tab 画进原生标题栏"：那需要
    `NSWindow.titlebarAppearsTransparent` / `fullSizeContentView`，只有 pyobjc 能设，
    而这个项目**不装额外依赖**；Qt 自己没暴露这两项。`IS_MAC` 一个开关控制，将来想换回去只改这一处。
- **顶部不放 `QMenuBar`**：macOS 会把菜单栏提升到屏幕顶部，Phase 1 不需要，避免多一行。

---

## 5. 主页（对齐安卓 `MainPage.kt`）

```
┌─ 自由层（**填满整个内容区**，卡片随意摆放）──────────────────────┐
│      ┌─ 服务器卡（自由层里的元素，顶部对齐、不可拖）──────┐        │ ← 横屏：**居中占一半宽**
│      │ 协议       服务器            端口                │        │   竖屏：**满宽**（左右各 4px）
│      │ [ws]  [ 127.0.0.1   ]  [ 10000 ]                │        │   宽度随窗口比例实时变
│      │ [          未连接，点我连接          ]           │        │
│      └────────────────────────────────────────────────┘        │
│   alice(10.0.0.2:50001)      bob(…)                              │  ← 随机落上半屏，标题行是拖动把手
│   [direct][upnp][udp][tcp]   [direct][upnp][udp][tcp]            │
│   ─────────────── 屏幕几何中线 ───────────────                    │
│                    ┌ UDP socket ──────────── ✕ ┐                  │  ← socket 卡挂在对应 peer 卡下方
│                    │ 本机绑定 192.168.1.5:40001 │                  │
│   我(5.6.7.8:40001)│ ✓ 发给服务器              │                  │
│   用户名 [alice]    │ ✓ 收到服务器回复           │                  │
│   密码   [****]     │   公网 5.6.7.8:40001       │                  │
│  [登录][ping][list] │ ✓ 发给对端 / ✓ 收到对端回复 │                  │
│        ↑ 默认居中   │ [udptest][tun][switch]…   │                  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.1 服务器卡（`ServerCard`）—— **三行**

| 行 | 内容 |
|---|---|
| 第一行 | **小字标签** `协议` / `服务器` / `端口`，只起提示作用（`QLabel#colLabel`）；**左边缘与下面三个控件逐一（±1px）对齐** |
| 第二行 | **一个**协议按钮（文字就是当前协议，默认 `ws`，点一下 ⇄ `wss`）+ 地址框 + 端口框，行尾 `addStretch` |
| 第三行 | **一个**全宽按钮，`未连接，点我连接` / `已连接，点我断开`（由 `isConnected` 决定） |

- **标签怎么对齐**（`_sync_label_widths()`）：不能照抄常量宽度 —— `f_host` 是"最小 200 / 自然 / 最大 300"，
  实测 200；写死 300 会让 `端口` 对不齐。所以布局量完之后，把每个标签的固定宽度设成**对应控件的实际宽度**
  （`ctl.width()`），构造后用 `QTimer.singleShot(0, …)` 触发一次，`resizeEvent` 里再对齐一次
  （宽度为 0 时跳过，等下次）。
- 第二行的地址框/端口框**框内不再有前缀标签**（`CompactField(..., inline_label=False)`）——
  标签只在第一行出现，避免两处重复。self-test 断言"第二行的 QLabel 列表为空"守着这条。
- 常量：`SCHEME_BTN_W=62`、`HOST_FIELD_MIN_W=200`、`HOST_FIELD_MAX_W=300`、`PORT_FIELD_W=118`
  （端口框要能完整显示 `10000`：self-test 用 `QFontMetrics` 实测 `'10000'` 的宽度做断言）。
- ⚠️ **用户名/密码和 登录/退出/list 都不在这里**，它们在自由层的「我」卡片上（安卓也是）。
- ⚠️ 选 `wss` 时日志会说明："`client.py` 目前只有明文 ws —— 这次按 ws 连"（`ws_handshake` 没有 TLS 分支）。

### 5.2 自由层（`FreeLayer`）

**自由层填满整个内容区**，服务器卡片是它里面的一个元素（所以"自由层正中" = 整个内容区的正中）。

四类东西 + 三种连线：

| 东西 | 规则 |
|---|---|
| **服务器卡片** | 自由层内的元素：**顶部对齐、不可拖动**；宽度随窗口比例**实时**变 —— **竖屏（高>宽）满宽、横屏（宽>高）居中占一半**（`SERVER_CARD_MARGIN_X=4` / `SERVER_CARD_MARGIN_TOP=8`）；其它卡片的限位按它的**实际矩形 + `SERVER_CARD_GAP`(12)** 算（它左右两侧的空白带纵向可到顶，其余列要从它下面开始） |
| **「我」卡片** | 宽度按内容自适应（输入框最小 140）；**默认竖直居中**（`ME_CARD_MARGIN = 0`，这个 margin 同时是拖动时与自由层上下边的留白）；**若居中会压住服务器卡片则以限位为准**（横屏窗口很矮时会被推到服务器卡下方）；标题 `我(ip:port)` 是拖动把手；拖动被 clamp 在自由层内；按钮行是 `[登录/退出] [ping] [list]`（`ping` 发应用层 ping，见第 7.1 节；只有在连上时才可点） |
| **其他人卡片** | 高度**固定 58**、宽度按内容自适应；标题 `名字(ip:port)`（`nodeLabel`）是拖动把手；一行四个按钮 `direct / upnp / udp / tcp`（每个宽 44） |
| **socket 卡片** | 挂在对应 peer 卡**正下方**、**至少在下半屏**（`y ≥ 区域高/2`）、x 与 peer 卡水平中心对齐；基准位置**算一次就冻结**，之后 peer 移动不带着它走；右上角 `✕` |
| **中线** | **窗口**几何中心（不是内容区中心）：`win.height()/2 - mapTo(win).y()`；1px、`C_TEXT_DIM` 35% 透明、贯通左右 |
| **服务器 ↔ 我** | 起点 = **服务器卡片底边**（它进了自由层，不再是自由层顶边）；x = 我卡中心 x；**未登录 = 白色虚线**，**已登录 = 绿色实线**（`#4CAF50`、线宽 2） |
| **服务器 ↔ peer** | 绿色实线；起点 = 服务器卡片底边，终点 y = peer 卡顶 + 10（标题行中心） |
| **peer ↔ 它的 socket 卡** | **白色虚线**；peer 卡底边中点 → socket 卡顶边中点 |
| 绘制顺序 | 我卡 → 其他人卡 → **socket 卡最后 raise**（保证压最上层、`✕` 始终可点） |

**随机摆放**（`random_peer_positions`）：相对坐标 `x∈[0,1]`、`y∈[0, 0.5]`（只落上半屏）；
与已放置的若 `|Δx|<0.3 且 |Δy|<0.2` 就重摇，**最多 12 次**。
与安卓的差别：**只给新出现的 peer 摇位置**，已有的保持不动（安卓是 peers/尺寸一变整批重摇），
这样别人上下线时屏幕不会"跳"。

**线段的计算是纯函数**（`link_segments`，第 681 行）：输入尺寸/位置/状态，输出 `Segment` 列表，
`paintEvent` 只负责画。这样做是为了**能用断言测**（条数/颜色/端点/虚线 pattern），不靠截图比对。

### 5.3 socket 卡片的三种形态（`SocketCard`，第 979 行）

| 形态 | 标题 | 内容 |
|---|---|---|
| `udp` | `UDP socket` | `本机绑定 …` → 四步打勾（`✓`/`○`：发给服务器 / 收到服务器回复 / 发给对端 / 收到对端回复，第 2 步打勾才显示 `公网 …`、`对方 …`）→ **第 5 行 6 个用法按钮** `udptest / tun / switch / wg / proxy / media`，**第 4 步打勾后才可点**，已选中的那颗描边/文字变绿 |
| `direct` | `direct 直连探测 · bob` | 三步（枚举本机地址 / 和服务器交换地址 / 并发 ping 可达性）+ `可达地址: …`（以"可达"开头就画绿）+ `（direct 只证明地址可达，不建隧道）` |
| `tcp` / `upnp` | `tcp 流程预览` | 计划步骤 + 尾注 |

> 与安卓的两处文字差异（**源码为准**，已在报告里指出）：
> ① 安卓第 2 步打勾后显示的是 `对方 …`（不是 `对端`）；
> ② 安卓没有"交给用法"这一行文字 —— 第 5 行就是**用法按钮那一行**，`handed_to` 非空表现为那颗按钮变绿。
> ③ tcp 的尾注安卓写"尚未实现真实握手"，但 **Python 端 tcp 打洞是真实现**（`hole/tcp.py`），
> 所以桌面端据实写成 `（仅流程预览；Python 端 tcp 打洞已实现，Phase 3 接真实进度）`；upnp 保持安卓原文。

---

## 6. 六个 tab

顺序固定、**都不可关闭**：`主页 / media / proxy / wireguard / vpn / switch`（与安卓/iOS 一致）。

| tab | 现在有什么 | 真假 |
|---|---|---|
| **主页** | 见第 5 节 | ✅ 真实现（服务器卡按钮、我卡登录/退出/list、peer 四按钮都真的驱动 client.py；卡片随数据实时更新） |
| media | 收流卡（协议 + **只读**本机地址/端口）/ 推流卡（协议 + 对端地址/端口 + 采集）/ 拉起应用卡 | 🟡 仅界面骨架（Phase 3 接 media.py/ffmpeg） |
| proxy | 配置卡（**首行 = 「配置」+ 状态（`未接线` / `已接 N 条`）+ 弹簧 + 启停**，字段：模式/协议/保活/洞地址/洞端口）+ 代理卡 | 🟡 仅界面骨架 |
| wireguard | 实现三档（自己实现/官方库/调系统程序）+ My Interface + Peer 1 | 🟡 仅界面骨架 |
| vpn | 配置卡（**首行 = 「配置」+ 状态（`未接线`）+ 弹簧 + 启停**，字段若干，**最后一行「内嵌 DHCP」开关**）→ 嵌入 DHCP 服务器（默认隐藏） | 🟡 仅界面骨架 |
| switch | 版式：**配置卡（首行为「配置」+ 状态（`未插线` / `已插 N 个`）+ 弹簧 + 启停；**最后一行**是「内嵌 DHCP」开关）→ 嵌入 DHCP 服务器（默认隐藏）→ 拓扑卡（最后）**；拓扑卡画连接拓扑（一行网口格子，0 个时一个虚线空位，点格子 = 拔线） | 🟡 仅界面骨架 |

**配置页是"卡片骨架"**：字段用 disabled 的输入框/下拉示意、按钮只写日志，**不做存盘、不做逻辑**
（安卓/iOS 那套 `*_config` JSON 持久化是 Phase 3 的事）。

---

## 7. 引擎桥：数据怎么流

```
 GUI（主线程）                    引擎线程（1 条）                  client.py（被导入的模块）
 ─────────────                    ─────────────────                 ────────────────────────
 服务器卡/我卡/peer卡/用法按钮
        │ command("udp bob")            │ queue.get() → dispatch()          │ process_input_line("udp bob")
        └────────────► queue ──────────►└──────────────────────────────────►└── hole_udp.start("bob")
                                        │ select(sock, 0.05) → recv         │
                                        │ cli.recv_buf += data              │
                                        │ while cli.ws_recv():              │
                                        │     _observe(obj)  ← 先看一眼 type │
                                        │     cli.handle_server_message(obj)│
                                        ▼                                   ▼
     界面更新 ◄── Qt 信号（跨线程自动排队）── peers_changed / holes_changed / me_changed / state_changed
```

| 信号 | 何时发 | 接到哪 |
|---|---|---|
| `line(str)` | client.py 每输出一行（tee） | 日志浮层 |
| `state_changed(str)` | 连接中 / 登录成功 / 登出 / 断开 | 托盘图标 + 服务器卡按钮文字 + 我卡登录按钮 |
| `peers_changed(list)` | `list_result`（**已过滤掉自己**）、登出、断开、掉线 | 自由层的其他人卡片 |
| `holes_changed(list)` | `cli.holes` 变化时（按签名去重，不是每 50ms 都发） | socket 卡片 |
| `me_changed(ip, port)` | `list_result` 里自己那条、`thisisyourpeer_udp`、（登出/断开时清空） | 「我」卡片标题 |
| `engine_stopped(str)` | 引擎线程结束（含失败原因） | 日志 |

**`list_result` 的解析照安卓 `tryParseListResult`**：用户名等于自己的那条 → 更新「我」卡片的 ip:port；
**其余才生成其他人卡片**（`entries.filter(username != me)`）。`me` 取 `cli.logged_in_user`，
为空时退回输入过的用户名（对应安卓的 `ifBlank { username }`）。
**登出 / 断开 / 掉线**都会清空别人卡片、把「我」卡标题退回 `我`（对应安卓 `onLogout` / `onDisconnect` 里的
`peers = emptyList()`、`myIp = ""`、`myPort = 0`）。

**打洞步骤怎么打勾**（两条腿，结构化优先）：
1. **结构化**：`hole['status']`（`打洞中 / 已打通 / 打洞失败`）、`hole['handed_to']`、`hole['my_port']`、`hole['peer_ip']`；
2. **步骤行**：被中继的 stdout 里有固定格式
   `[洞 #1 bob] [2/6] 正在等服务器要求发给 udp  （✓）…`，用 `_STEP_LINE_RE` 解析成
   `hole_steps[洞号][步序] = 是否完成`（**进程内文本**，不是解析子进程输出，所以可以接受）。

### 7.1 WS 协议级心跳（实现在 `client.py`，GUI 只做一行通知）

服务端支持 RFC 6455 的 ping/pong：客户端发 `0x9` ping 帧 → 服务器**原样回 `0xA` pong**（payload 一致）。

**为什么放在 `client.py`**：GUI 是 in-process 驱动、自己跑收循环；`main()` 也有自己的 select 循环。
心跳写在哪一边都只能覆盖一半用户。所以做成"**连接建立后自动启动**"的东西：

| 位置（`client.py`） | 干什么 |
|---|---|
| `ws_ping_frame()` | 构**掩码** ping 帧（`0x89` / `0x80\|len` / 4 字节 mask / 掩码 payload，payload 固定 `b'p2pnet'`）。不能用 `ws_encode()` —— 那只发 `0x1` 文本帧 |
| `start_ws_heartbeat()` / `stop_ws_heartbeat()` | 起停心跳线程（`name='ws-heartbeat'`，daemon）。`stop` 可从线程内部调，不会自 join |
| `note_ws_rx()` | **读方**每收到任何字节喊一声（pong 帧也算）。GUI 的引擎循环和 `main()` 的 select 循环各调一次 |
| `_ws_heartbeat_loop()` / `_ws_heartbeat_tick(now)` | 每 0.5s 一轮；距上次发送 ≥ **20s** → 发一个 ping（**发之前先打一行日志**，见下）；**判死条件见下面那条**（写错会稳定误判，已经踩过一次）。一轮的逻辑抽在 `_ws_heartbeat_tick()` 里，**self-test 不用起真线程就能测** |
| `ws_heartbeat_log_text(n)` / `ws_heartbeat_pong_log_text(n)` | 一对日志的正文（三端逐字一致）：发出 `WS 心跳：发出协议级 ping（第 N 次，间隔 20s）`、收到 `WS 心跳：收到协议级 pong（第 N 次）`。`N` 从 1 起、**随连接重置**（`start_ws_heartbeat()` 里清零） |
| `ws_heartbeat_payload(n)` / `ws_heartbeat_seq_from_payload()` | 心跳 payload **带序号**（`p2pnet#N`）。服务端**原样回** payload，所以收到 pong 时能解出"这是第几次 ping 的回包" —— **精确对应**，不是靠"数收到过几次"猜 |

- **自动启动点**：`ws_handshake()` 成功后就 `start_ws_heartbeat()` —— 这是 `main()` 和 GUI **唯一共用的**连接建立路径，
  所以两种模式都自动有，不需要各调用方记着起。
- **判活信号只能来自读方**：心跳线程**只发不读**，绝不和读方抢 socket。
  ⚠️ 不能靠 `ws_recv()` 的返回值判活 —— 它对 pong 帧返回 `None`（只处理 `0x1`/`0x8`），
  所以"收到任何字节"才是判据（GUI 那一行 `cli.note_ws_rx()`）。
- **判死条件（必须逐字是这样，写错会稳定误判）**：

  ```python
  if ping_at and last_rx < ping_at and (now - ping_at) >= WS_HEARTBEAT_TIMEOUT:
  ```
  也就是说：**"发出那次 ping 之后一直没收到任何字节"（`last_rx < ping_at`）** *并且* **距那次 ping 已 ≥10s**。
  时间基准是 **ping 时刻**，不是 `last_rx`。
  ⚠️ 只写 `now - last_rx >= TIMEOUT` 是**错的**：那问的是"距上次收字节多久"，
  只要 ping 发出满 10s 就必然为真 —— 哪怕这期间 pong 早就到了、`last_rx` 刚被刷新，
  **每个心跳周期都会在 ping+10s 稳定判死**（用户实机撞到过，见第 12 节第 11 条）。
  边界：`last_rx == ping_at`（同一瞬间）算"收到了"，**不**判死。
- **第二道防线**：`ws_recv()` 的 `0xA` 分支里，一旦确认是**我们自己的**心跳 payload（序号解得出来），
  就调 `_hb_clear_pending()` 把 `_hb_ping_sent_at` 清 0 —— 语义就是"应答到了，不再等应答"。
  这样即便将来判死条件又被改坏，也不会拿旧的等待状态去判死。
- **判死之后**：`log()` 打**一行** `pong 超时：连接已断开（WS 心跳失败）`，把 `connected` 置 `False`，
  停掉心跳。**不主动关 socket**：socket 归读方所有，由读方收尾（GUI 的引擎循环发现 `cli.connected == False`
  就 `break` → `_teardown`；`main()` 的循环同理 `break` → 收尾）。
  这样避免"心跳线程把正在读的 fd 关掉"这种竞态。
- **一对日志**：
  - **每次真的发帧之前**打 `WS 心跳：发出协议级 ping（第 N 次，间隔 20s）`
    —— 只有"真的发了帧"那一轮打；只是检查、没到时机（或没 socket）那一轮**不打**；
  - **真的读到 `0xA` pong 时**打 `WS 心跳：收到协议级 pong（第 N 次）`，`N` 从 payload 里的序号解出。
    位置在 `ws_recv()` 的 `0xA` 分支（**返回契约不变，仍是 `None`**），所以
    **命令行和 GUI 两种模式都自动有**（两边都走 `ws_recv()`）。
    非本协议的心跳 pong（payload 不带 `p2pnet#`）**不会**误报。
  - 判死那行照旧只留一行（`pong 超时：连接已断开（WS 心跳失败）`）。
- `ws_recv()` 顺手做了规范该做的事：遇到服务端发来的 `0x9` 就回一个 `0xA` pong，遇到 `0x8` 就停心跳，
  遇到 `0xA` 就按上面的规则打"收到"日志 —— **返回契约不变**（仍然只在 `0x1` 时返回文本，其它一律 `None`）。
- **GUI 侧只允许一行通知**：引擎循环里 `cli.note_ws_rx()`。self-test 会用源码自检断言
  "`client-gui.py` 里 0 处 `ws_ping_frame`/`heartbeat_action`/`HEARTBEAT_INTERVAL`"。

### 7.2 应用层 ping（`ping` 命令 + 「我」卡片的 `ping` 按钮）

服务端：`{"type":"ping","seq":N}` → 回 `{"type":"pong","seq":N}`（**不需要登录**，seq 原样带回）。

- 实现在 `client.py`：新增 **`ping` 命令**（`process_input_line("ping")` → `send_app_ping()`），
  `help` 输出里紧跟 `help` 之后；`seq` 计数器也在 `client.py`（从 1 开始每次 +1）。
- 行为：**先 `log()` 打出报文** `发出应用层 ping：{"type": "ping", "seq": N}`（App 内日志面板能看到），
  再 `ws_send(ws_sock, ...)`；收到 pong 时 `handle_server_message` 的 `pong` 分支打
  `收到应用层 pong：{...}（RTT x.xms）`（`seq → 发出时刻` 算 RTT）。
- **GUI 侧**：`ping` 按钮就是**投一条 `ping` 命令**给引擎队列（和别的命令同一条路），
  自己不再拼 `{"type":"ping","seq":N}`。
- ⚠️ 别和这两处混淆：`hole/udp.py` 的 **UDP** ping/pong（洞打通后在洞上互发），
  以及 `sign_with_session_key(b'ping')`（`p2pudp_hello` 的签名用的字面量）。

### 7.3 WS 自动重连（带熔断）

**触发**：连接**已建立之后**，因 WS 协议级心跳判死、或**异常断开**（对端关闭 / 收发报错）。
**不触发**：用户在界面手动点「断开」；首次连接就失败（保持原样）。

| 规则 | 值 |
|---|---|
| 退避 | **1s → 2s → 4s**（`WS_RECONNECT_BACKOFF`） |
| 熔断 | **60 秒滑窗内最多 3 次**（`WS_RECONNECT_WINDOW=60` / `WS_RECONNECT_MAX=3`），到顶仍失败 → 放弃 |
| 计数重置 | ① 用户手动连接；② 连接**稳定存活 ≥60 秒** |

日志（**三端逐字一致**，前缀由 `log()` 加）：

```
WS 自动重连：第 N 次（60 秒窗口内）
WS 自动重连成功（第 N 次）
WS 自动重连已放弃：60 秒内已重连 3 次仍失败（不再自动重连，请手动连接）
```

- **策略是纯函数**（`client.py`）：`ws_reconnect_delay()`（退避表，越界返回 `None` = 熔断）、
  `ws_reconnect_prune()`（丢掉滑窗外的时刻）、`ws_reconnect_allowed()`（窗口内还有名额吗），
  加三个文案 helper —— **三端都拿这几个函数**，行为与文字不会漂。
- **实现全在 `client.py`**（这样 `python3 client.py --server … --port …` 单独跑也有同样的行为）：
  `ws_connect_once()`（建 socket + 握手，握手成功自动起心跳）、`ws_reconnect_reset()`（计数清零）、
  `ws_reconnect_plan()`（纯决策：`(第 N 次, 等待秒数)` 或 `None`）、`ws_reconnect_note_attempt()`、
  `ws_reconnect_sleep()`（可打断的退避等待）、`ws_auto_reconnect(host, port, *, on_connected, should_stop)`
  （**重连循环的唯一实现**：退避 1s→2s→4s、60 秒滑窗内最多 3 次、熔断打那行放弃日志）、
  `mark_disconnected()`（会话收尾：记"断开前是否已登录"、稳定 ≥60s 清计数、清会话态、关旧 socket）、
  `start_login()` / `resume_login()`（重连后用保存的凭据跑**现有登录流程**）。
- **命令行模式**（`main()`）：首次连接（失败就退出，不重连）→ `_run_session()`（一次会话的读循环）
  → `mark_disconnected()` → `ws_auto_reconnect()` → `resume_login()` → 再进 `_run_session()`，循环。
  用户输入 `quit` 会置 `_user_quit` → 不重连。
  ⚠️ 会话循环里 `recv` 返回空 = **对端真的关了 → 立刻 break**（和"只是暂时没数据 EWOULDBLOCK"分开），
  所以对端一断就立刻重连，不用等心跳 30 秒判死 —— 这个 EOF/EWOULDBLOCK 的区分是这次一并修的。
- **GUI 模式**（`EngineBridge`）：断开收尾统一走 `_serve_until_disconnect() → _teardown() → _maybe_reconnect()`，
  其中 `_maybe_reconnect()` 只做"起一条重连线程"，线程里调 `cli.ws_auto_reconnect(..., should_stop=…)`；
  成功后 `cli.resume_login()` + 接着跑读循环。**GUI 不再自己实现重连计数/退避/熔断**（重复状态已删），
  两模式的日志因此逐字一致。
- **凭据**：`challenge` 阶段把上次登录用的用户名/密码留在内存（`_saved_login_user/_saved_login_pass`），
  `logout_ok` 时清掉（主动登出后不会被自动重连偷偷登回去）。
- **恢复登录**：断开前若为**已登录**，用保存的凭据（`login()` 时存下、`logout()` 时清掉）走现有登录流程重新登录
  （服务端对同名重登是"踢旧连新"，所以旧连接收到 `kicked` 属正常）。拿不到凭据 → **只恢复连接**并明确打一行
  `WS 自动重连：没有可用的凭据，需要手动重新登录（当前未登录）`，**不假装已登录**。
- **状态显示**：重连期间按"未连接"（沿用现有断线态），重连 + 登录恢复后再回到"已连接 / 已登录"。
- **命令行与 GUI 行为一致**：都自动重连、都恢复登录、日志逐字相同（都走 `client.py`）。

### 7.4 卡片首行：统一容器 + 内嵌 DHCP 显隐（vpn / switch）

- **行不许纵向长高**（用户实机报的"每一行间隔特别大"）：行容器都是裸 QWidget，默认纵向策略 Preferred，
  父布局（卡片 body）**没有尾部弹簧**时 Qt 会把卡片多余高度**平均摊给每一行** ——
  实测 1080×720 每行被拉到 **107px**、1080×1400 时 **243px**，视觉上就是"行间空一大截"。三条修法（全局生效）：
  ① 行容器统一走 `row_fixed()` → `setSizePolicy(Preferred, Fixed)`，行高永远 = `sizeHint().height()`；
  ② 每张卡的 `body` 末尾 + 页面 `body` 末尾各补 `addStretch(1)`（`ConfigPage.finish_layout()`，
     由 `MainWindow` 建页时调一次）→ 余量落到"底部空白"，卡片贴合内容高度、**内容顶对齐**；
  ③ `card()` 的 `body.setSpacing(6)` → **2**（行几乎贴住；标题与 body 间距 8 → 6）。
- **vpn / switch / proxy 三页的配置卡首行都走同一个构造入口**（proxy 原来还是"字段 + 独立启动按钮"的老结构，
  已补齐）：`card_head_row(parent, 文字, state_widget, control)`：
  `setContentsMargins(0,0,0,0)` + 左文字 + **弹簧** + 状态 + 控件，右侧一律顶到同一个右边界。
  配置卡与 DHCP 卡**都**用它，而且两张卡都用 `add_card(..., render_title=False)`
  （不画标题行，标题文字由首行承担）—— 这样"两张卡的首行"是**同一种东西**，
  容器与内边距不可能跑偏。`card()` 的 `outer` 仍是 `(12,10,12,12)`，卡片 `border: 1px`
  → 实测两行的左边界都是 **x=25**（12 + 1 边框 + 12），右边界都是 **1045**（1070-25）。
- **内嵌 DHCP 是"字段行版式"，不是"右侧控件版式"**：
  ```python
  row, _, _ = field_row(self, "内嵌 DHCP", sw)   # 标签在标签列（label_w=84）→ 开关紧跟其后
  row.layout().addStretch(1)                     # 右边留空（开关不许被顶到卡片最右）
  ```
  实测开关 `x=115` = 同卡片「路由老化」输入框的 `x=115`（同一列），行高 `28` = 字段行高 `28`，
  开关右边界 `153` 距卡片内容右边界 `1045` 还有 **892px** 空白。**不要**用 `card_head_row(..., control=sw)`
  的右侧控件位（那会把控件顶到最右，用户明确不要）。
  ⚠️ **必须显式写 `enabled=True`**：`field_row()` 的 `enabled` 默认是 `False`（Phase 1 占位控件默认禁用），
  忘了传就会把开关禁用 → 用户点了没反应、DHCP 卡永远出不来（**实机 bug，见第 12 节第 19 条**）。
- **开关控件 `ToggleSwitch`**：`QAbstractButton` 子类，纯 PyQt6 绘制（QSS 外）：38 宽、**控件高 28**
  （= `field_row` 里 `QLineEdit.setFixedHeight(28)`，这样行高与字段行一致），轨道只画 20px、垂直居中；
  开 = `C_ACCENT` 蓝轨道 + 钮在右，关 = `C_BORDER` 暗轨道 + 钮在左。
  用 `QCheckBox` 的话在深色卡片上只是个小方块，看不出开/关。
  标签由 `field_row` 给 `fieldLabel` 样式：**和「路由老化」一致（次要灰、字重 400）**，不是 `cardTitle`（加粗白 600）。
- **内嵌 DHCP 开关**在**配置卡最后一行**（视觉上"这行开启下面那张卡"），由
  `ConfigPage.add_dhcp_toggle(body, dhcp_card)` 生成：`dhcpEnabled` **默认 false**，
  勾选 → DHCP **整卡** `setVisible(True)`，取消 → 整卡隐藏（不是 `setEnabled`）。
- **首行高度也必须相等**（用户报过"嵌入 dhcp 服务器那一行高度特别高"）：`card_head_row()` 里
  `row.setFixedHeight(CARD_HEAD_H)`（= 26，与启停按钮同高）。两个原因缺一不可：
  ① 不固定高度，**父布局会把卡片多余的高度摊给这一行** —— DHCP 卡内容少、被纵向拉伸时首行涨到 38/69px；
  ② **不能用 `sizeHint()` 现算** —— 构造那一刻 QSS/字体还没生效（offscreen 下是 fallback 字体），
  带按钮的那行算出 27、只有文字的那行算出 26，两行又不等高。DHCP 卡 `body` 末尾另加 `addStretch(1)`，
  让余量落到弹簧而不是各行。
- **状态用词口径（三端统一，别被"统一成一套词"）**：**vpn / proxy 看通道数** → `未接线` / `已接 N 条`
  （`channels_state_text()`）；**switch 看网口数** → `未插线` / `已插 N 个`（`ports_state_text()`，与同页「拓扑」卡同词）。
- **空态不单独占一行**：空态已由首行状态（`未接线` / `未插线`）表达，`通道：还没有` 这类行是重复 → 三端一致删掉；
  判据是"首行状态已表达的空态文案 = 删；含动态信息（列表/数量明细）= 留"。
  ⚠️ proxy 页首行目前**没有**状态标签（还没做首行统一），删掉那行后该页不再有"无通道"提示 —— 见第 11 节。
- 首行左侧文字固定是 **「配置」**（三端一致；vpn 原来那句"一对一：一个洞 ↔ 一块 tun/tap"属"界面不写说明"，已移进类 docstring）。
- self-test **真量像素**回归（第 10 节那张表里也有一条）：先切页 + `win.grab()` + `processEvents()`，
  再量两行在页面坐标里的 x/宽度/**高度**并断言三者都相等，另断言固定高度没把文字裁掉。

**洞 → 卡片字段**：`hole['my_ip'/'my_port']` = 本机绑定；`hole['peer_ip'/'peer_port']` = 对端；
`hole['proto']` 决定卡片形态（`udp` / `direct` / `tcp` / `upnp`）；`handed_to` 决定哪颗用法按钮变绿。

---

## 8. 按钮 → `client.py` 命令（全部核实过命令名）

| 界面 | 命令 | 备注 |
|---|---|---|
| 服务器卡那一个按钮 | `EngineBridge.connect(host, port)` / `.disconnect()` | 走 `socket.create_connection` + `cli.ws_handshake`；**不是** REPL 命令 |
| 我卡 `登录` / `退出` | `login <用户名>` / `logout` | 登录前**必须**预置 `cli.ARGS_USER/ARGS_PASS`，否则 `challenge` 到达时 client.py 会 `input("密码: ")` 在引擎线程里**阻塞等键盘** |
| 我卡 `ping` | **`ping`**（`client.py` 的 `process_input_line("ping")` → `send_app_ping()`） | seq 在 `client.py` 里从 1 开始 +1；发出/收到的报文都进日志，收到时带 RTT |
| 我卡 `list` | `list` | |
| （自动）WS 心跳 | **不走 REPL、也不在 GUI 里**：`client.py` 的心跳线程在 `ws_handshake()` 后自动起 | 每 20s 发 `0x89` 掩码帧 + **发前一行日志**；判活看"有没有字节"；判死后 `connected=False`（见 7.1） |
| peer 卡 `direct` / `upnp` / `udp` / `tcp` | `direct <用户名>` / `upnp`（无参数） / `udp <用户名>` / `tcp <用户名>` | |
| socket 卡 `udptest` | `udptest #<洞号>` | |
| socket 卡 `media` | `ffmpeg #<洞号>` | |
| socket 卡 `wg` | `wg-py <对方用户名>` | |
| socket 卡 `tun` / `switch` | `onholefromself tun #<洞号>` / `onholefromself switch #<洞号>` | client.py 里 tun/switch **不是独立命令**，而是"角色+模式"设定，带洞标识即可立刻拉起 |
| socket 卡 `proxy` | （暂不发命令，只记日志） | 需要目标 `host:port`，Phase 3 从 proxy 页取 |
| socket 卡 `✕` | `del hole=#<洞号>` | 同时把卡片从界面移除 |

---

## 9. 日志浮层 / 托盘 / 单实例

- **日志浮层**（`LogOverlay`，应用级，浮在**所有页面**之上，不属于主页）：
  右下角 `日志` 胶囊（76×32，黑底 + 高亮描边）→ 点开是内容区 **90%** 的居中面板
  （标题 `App 内日志` + `清空` / `📋复制` / `✕`），**从胶囊的位置长出来**（`QVariantAnimation` 插值几何 +
  `QGraphicsOpacityEffect` 淡入，260ms，和手机端同参数）。
  折叠时**整层 `hide()`** —— 这样内容区里只剩胶囊一个可点控件，页面点击完全不受影响
  （**不能**用 `WA_TransparentForMouseEvents`，见第 12 节）。
- **系统托盘**（`Tray`，`QSystemTrayIcon`，0 额外安装）：
  图标是**代码画的状态点**（灰=未连接 / 黄=连接中 / 绿=已登录），tooltip `p2pnet · 未连接`；
  右键菜单 `显示主窗口 / 连接 / 断开 / 退出登录 / 查看日志 / 退出`；左键单击 = 唤回窗口。
  `isSystemTrayAvailable() == False`（例如 headless/offscreen）时**不建图标**，并把 ✕ 的语义降级成"真退出"。
- **✕ 的语义**：托盘可用 → **收进托盘**（不退出），**第一次**弹一句系统通知说明；
  托盘不可用 → 真退出（否则窗口一没、进程还占着端口，用户找不回来）。
- **单实例**：`QLocalServer`/`QLocalSocket`，socket 名 `p2pnet-desktop-gui`；
  第二次启动会发一行 `show` 后退出，已有实例把窗口唤到前台；启动前 `removeServer()` 清掉上次异常退出留下的 socket 文件。
- 退出时 `EngineBridge.shutdown()`：`hole_udp.stop_all_hellos()` + `close_all_holes("退出")` + 关 socket +
  join 引擎线程 + **把 `sys.stdout/stderr` 还回去**。

---

## 10. `--self-test` 覆盖了什么

无人值守、不弹窗、不联网、不起 server、不起子进程，`SELF-TEST OK` 且退出码 0。段落列表：

| 段 | 断言/证据 |
|---|---|
| 布局摘要 | 平台、无边框标志、标题栏（含平台分叉）、6 tab 名字、6 页面与各自的卡片骨架、托盘可用性、浮层参数、✕ 语义、引擎桥状态 |
| 日志浮层动画 | 手喂 `progress 0/0.5/1.0` 打印面板几何/透明度的插值；折叠时整层 `hidden`；胶囊父节点必须是 `ContentArea`（兄弟节点） |
| 架构 | `import client` 的模块 `__name__ == "client"` 且与引擎桥持有同一对象；**源文件里 `subprocess`/`Popen` 各 0 次**（断言自己扫源文件） |
| 桩 socket | 塞一个假 socket 给 `cli.ws_sock`，`process_input_line('list')` → 发出去 `{'type':'list'}`；`('udp bob')` → `{'type':'p2pudp','target':'bob'}`（用 client.py 自己的 `ws_recv()` 解码回来验） |
| 日志汇流 | `cli.log("…")` 之后那行必须出现在 App 内日志里，且 `sys.stdout` 是中继 |
| 暗色主题接线 | `style=='fusion'`、palette `Window/Base/WindowText` 的值、9 个 QSS 关键片段、胶囊/面板样式串 |
| 背景不透明 | **`win.grab()` 真渲染一遍数非不透明像素**（0 个）+ 标题栏像素颜色 + 五类容器的 `WA_StyledBackground` |
| 服务器卡片宽度规则（**真量像素**） | 800×1000 竖屏 → 卡宽 **782** ≈ 自由层宽 790（99%）；1200×800 横屏 → 卡宽 **591** ≈ 一半，且 x=299 = (1190−591)/2 **居中**；**切回竖屏又变 782**（证明随 resize 实时变）；很矮横屏 1200×340 → 我卡被限位推到 top=130（居中会是 98）；默认位置与拖到上下极限都不许与服务器卡片矩形相交 |
| 主页布局 | 3 个假 peer：数量、y 全在上半区、高度=58；我卡**默认竖直居中**（竖屏 800×1000 实测：中心 y 475.5 vs 自由层中心 476.0；me_y=403 me_h=145 area_h=952）；socket 卡在下半屏且在 peer 下方、与 peer 中心对齐差 0.0px；中线 = 窗口中心换算值 |
| 连线 | `link_segments` 的条数/颜色/端点/虚线 pattern：未登录白虚线、已登录绿实线、peer 绿实线、peer↔socket 白虚线、中线 alpha/贯通 |
| 拖动 | 程序化拖动 + **真 Qt 鼠标事件**两条路径：`grabMouse` 生效、位移 1:1、边界 clamp、松开释放 |
| 数据 | `list_result` → peer 卡；`thisisyourpeer_udp` → 我卡标题；`status='已打通'` → 前四步打勾 + 6 个用法按钮可点；`handed_to='udptest'` → 第五步（用法行）打勾且按钮变绿；`✕` → 卡片移除 + 命令 `del hole=#1`；peer 四按钮命令名 |
| ping 按钮（3b） | 按钮行顺序 `[登录, ping, list]`；未连接时不可点、连上后可点；点 3 次 → 投给引擎的**命令**是 `ping`（不是自己拼报文） |
| WS 心跳（间隔/文案/成对日志，不起真线程） | `WS_HEARTBEAT_INTERVAL == 20.0`、`WS_HEARTBEAT_TIMEOUT == 10.0`；`ws_heartbeat_log_text(1/3)` 与 `ws_heartbeat_pong_log_text(5)` 文案逐字一致；驱动 `_ws_heartbeat_tick()`：+5s→`idle`（计数 0、无字节、不打日志）／+20.5s→`sent`（计数 1、socket 收到 `6+len(payload)` 字节、`byte0=0x89`、payload=`p2pnet#1` 且是掩码后的、日志正好一行）／+21s→`idle`（计数仍 1、**心跳日志仍 1 行 = 没发就不打**）／+41s→`sent`（第 2 次）；**判死条件三个回归用例**：① pong 已到达（`last_rx=ping+0.1s`）在 ping+10.5s → **不许 dead**／② 真没回（`last_rx=ping-0.1s`）→ dead + 那行日志／③ 边界 `last_rx == ping_at` → 不许 dead／④ 未到超时（ping+9.5s）→ 不许 dead；**真喂 `0xA` 帧进 `ws_recv()`**：返回 `None`（契约）+ 多一行 `收到协议级 pong（第 1 次）`，payload 为 `p2pnet#7` 时打出 `第 7 次`（序号精确对应），喂非心跳 payload **不多行**；喂自己的心跳 pong 后 `_hb_ping_sent_at` 被清 0（第二道防线） |
| 单独跑 `client.py` 的端到端（E2E 脚本常驻） | **单次启动只连一次**：服务端 `[连接]` == **1** 条、客户端 `已连接至` == **1** 条、`自动登录` == **1** 次、`登录成功` == **1** 次；场景 A（kill → 重连 1/2/3 次 → 已放弃 → 之后不再尝试）；场景 B（kill → 窗口内重启 → 重连成功 + 用保存凭据恢复登录） |
| 自动重连策略（**实现在 client.py**） | 退避 `[1.0, 2.0, 4.0, None]`；滑窗 60s / 上限 3；窗口内 3 次 → 第 4 次不许；-61s/-70s 被丢；时间滑过 61s → 又允许；计数清零 → 允许；三条日志文案逐字断言；`ws_reconnect_plan()`（GUI 的 `_reconnect_plan` 只是委托它）四步（空→(1,1.0)、1 次→(2,2.0)、2 次→(3,4.0)、3 次→None）；真跑 `ws_auto_reconnect()` 的放弃路径：窗口已满 → 立即返回 False + 打 1 行放弃日志（**不联网**） |
| 界面文案净化 | `ast` 抽出全部字符串字面量（排除 docstring）扫"python 端 / 第 5 行点 / 参数一一对应 / xxx.py / client/app/ / 通道：还没有"等禁字样 → 0 处命中；并用**白名单**断言界面说明行只剩 2 条（字段语义 + 网口操作提示），新增说明行会直接红 |
| 行高 / 行间隙（**720 与 1400 两种窗口高度**） | 每个配置页（media/proxy/wireguard/vpn/switch）的每张卡、每个直接子行：断言 `行高 <= max(sizeHint, minimumHeight, 子控件需要的高度) + 2`（行不许被纵向拉伸），并断言相邻行**间隙 ≤ 4px**；两种窗口高度下的 `行高 = [...]` / `间隙 = [...]` 都打印 —— 改后**逐项相同**（间隙恒 2px），证明与窗口高度无关 |
| 内嵌 DHCP 行（字段行版式 + 开关 + 真点击 + 标签样式） | **开关左边界 x == 同卡片「路由老化」输入框的 x**（同一列，实测都是 115）；**该行高度 == 相邻字段行高度**（实测都 28）；**开关右边界距卡片内容右边界 > 300px**（不许贴最右，实测留空 892px）；`ToggleSwitch` 38×28 在配置卡最后一行；标签 `objectName == "fieldLabel"`、**字重 == 「路由老化」（400）且 < 卡片标题（600）**；新页面默认 `checked=False` + DHCP 卡隐藏；**`sw.isEnabled() is True`**（防 `field_row` 默认禁用它）；**真鼠标事件**（press+release）点击开关 → 打开且 DHCP 卡**真有几何**（实测 `QRect(12,248,1046,140)`）、再点 → 关；**切换后页面其它按钮仍须有反应**（点「启动」要打日志）；自绘开关的**禁用态像素**检查：启用时高亮蓝像素 428 → 禁用时 0 |
| 卡片首行（**真量像素**） | **vpn / switch / proxy 三页**：`dhcpEnabled` 默认 False、DHCP 卡默认 `isHidden()==True`；先 `setChecked(True)` 让卡片可见（隐藏控件量不出真实几何），再 `win.grab()` 后量两行 → 断言 `x`/`w`/**`h`** 三者完全相等（实测两页都是 x=25 / w=1020 / **h=26**，右边界 1045；页面宽 1070）；首行左标签必须是「配置」；固定高度不许裁掉文字；开关开→显示、关→隐藏；配置卡**最后一行**含该 QCheckBox |
| switch 页版式 | 卡片顺序 = `配置 / 嵌入 DHCP 服务器 / 拓扑`；启停按钮在配置卡首行（该行 = 状态 QLabel + 弹簧 + 按钮）；拓扑卡里 0 个按钮 |
| 下沉自检 | **源码扫描**：`client-gui.py` 里 0 处 `ws_ping_frame`/`heartbeat_action`/`_send_ws_ping`/`HEARTBEAT_INTERVAL`；同一批关键词在 `client.py` 里都存在 |
| `ping` 命令 | 桩 socket 下调 `process_input_line("ping")` ×3 → 发出去 `{"type":"ping","seq":1/2/3}`（用 `client.py` 自己的解码器解回来核对），日志里出现 `发出应用层 ping` 行；喂一条 pong → 日志里出现 `收到应用层 pong` 且带 `RTT` |
| 服务器卡 | **三行结构**：三个标签与对应控件的 `x()` 差 ≤1px、标签宽度=控件实际宽度、标签在控件上方；`协议↔btn_scheme` / `服务器↔f_host` / `端口↔f_port` 逐对断言；第二行 QLabel 列表为空；`ws → wss → ws` 切换 + `values()` 跟随；端口框用 `QFontMetrics` 实测能放下 `'10000'`；地址框在上下限之间 |
| 卡片描边 | 我卡 / peer 卡 / socket 卡 都有 `border: 1px solid #4a9eff` |
| list 过滤自己 | `users=[自己, dave]` → peer 卡只有 `dave`，我卡标题被更新 |
| 登出/断开清卡 | 喂 `logout_ok` / 调 `disconnect()` → 别人卡片清空、我卡标题退回 `我` |

---

## 11. 已知限制与 TODO

- **5 个配置页只是界面骨架**：没有存盘、没有逻辑，也没接各自的 Python 用法。
- **没有"UDP 测试页"**：安卓有一个专门的 `UdpTestPage`（地址块 + 消息历史），桌面端**没做** ——
  点 socket 卡的 `udptest` 会把洞交给 `client.py` 的 `udptest`，它的收发日志走 stdout 汇进 App 内日志，
  暂时没有独立页面（要做的话就是再加一个 tab + 一条 `udpSockMessages` 过滤）。
- **`proxy` 用法按钮不发命令**（需要目标 `host:port`，等 proxy 页接线）。
- **`wss` 是假的**：`client.py` 的 `ws_handshake` 只有明文 ws，选 wss 会按 ws 连（日志里会说明）。
- **媒体/proxy 的"拉起外部程序"契约还没做**（安卓是 Intent、iOS 是 URL scheme，桌面该用 `QDesktopServices`/`subprocess`，
  Phase 3 定）。
- **proxy 页首行已统一**（vpn / switch / proxy 三页现在都是「配置 + 状态 + 弹簧 + 启停」）：
  proxy 的状态文案走同一个 `channels_state_text()`（空 = `未接线`，非空 = `已接 N 条`），
  启停按钮高度也统一到 `CARD_HEAD_H`。
- **proxy 第二张卡的标题已收干净**：`代理（-R：本机连出去；-L：本机 listen）` → **`代理`**（括号那句挪进注释；
  安卓/iOS 本来就只有「代理」）。media 的 `收流（对端 → 本机）` / `推流（本机 → 对端）` 是**短方向限定词**
  （用来区分收/推），保留。
- **心跳的 pong 只用来"配对日志"**：我们从 payload 解出序号打 `第 N 次`，但不校验别的
  （比如"收到的 pong 次数 == 发出的 ping 次数"）；判活的定义仍然是"有没有字节进来"（`note_ws_rx()`）。
- **心跳线程异常会留一行日志但不会自动重启**：如果线程因为意外异常退出，连接会失去保活
  （`WS 心跳线程异常退出：…` 这行会出现在日志里，便于发现）。
- **拖动手感的进一步优化**：现在每帧重画整个自由层（含连线）。卡片多起来之后可以考虑
  只更新受影响区域、或给连线做缓存。
- **macOS 的"纯菜单栏常驻"**（`LSUIElement`、不占 Dock）没做，要打包阶段再定。
- **没有真机/真窗口的运行时验证**：开发过程只跑 `--self-test`（offscreen）。第一次真跑建议
  `python3 client/client-gui.py`，注意点「未连接，点我连接」是**真连**。

---

## 12. 踩过的坑（桌面端专属，按"现象 → 原因 → 解法"记）

1. **标题栏透明，透出后面别的程序**。
   两个原因叠加：① **QSS 的 `background` 对 `QWidget` 子类默认不生效**（要 `Qt.WA_StyledBackground`，
   `QFrame` 才天然会画）；② 全局写了 `QWidget { background: transparent; }`，而**顶层窗口自己也是 QWidget**，
   把自己的背景也关了，于是没有兜底。
   解法：删掉全局透明、给主窗口/标题栏/内容区/页面/自由层都设 `WA_StyledBackground` + 显式黑底。
   现在 self-test 用 `win.grab()` 数非不透明像素守着这条。
2. **`WA_TransparentForMouseEvents` 会连子控件一起禁用**（Qt 文档原话：*the widget **and its children***）。
   用它做"折叠时点击穿透"会导致「日志」胶囊自己点不动。
   解法：折叠时**整层 `hide()`**，胶囊改成浮层的**兄弟**节点（挂 `ContentArea`）。
3. **不在布局里的浮层永远是 100×30**。日志浮层要能浮起来、要能动画，所以不能进布局；
   而**隐藏状态下 `setGeometry` 不会给子控件发 resize 事件**（Qt 要到 show 才发）。
   解法：`ContentArea.resizeEvent` 里 `setGeometry` **之后**再补一次 `relayout()`，不依赖事件顺序。
4. **拖动"卡卡的、不跟鼠标"**。拖动把手只有二十来像素高，光标一快就滑出标签 → 收不到 move；
   加上 `_relayout()` 每帧 `adjustSize()` 掉帧。
   解法：按下 `grabMouse()`、传**全局坐标**、按"按下点 → 卡片左上角"的固定偏移 1:1 反算位置、`_relayout()` 不再重量尺寸。
5. **`pyqtSignal` 不能当函数调用**（`self.drag_requested("begin", gp)` → `TypeError: native Qt signal is not callable`），
   必须 `.emit(...)`。这个 bug **程序化拖动测不出来**（程序化调用绕过了那段接线），
   是补了"真 Qt 鼠标事件"的断言才暴露的 —— 所以那条断言留在 self-test 里了。
6. **`import client` 会在 `client/hole/` 里撒 `__pycache__/*.pyc`**（等于往仓库多写文件）。
   解法：导入前置 `sys.dont_write_bytecode = True`。
7. **`@dataclass` + `importlib.util.spec_from_file_location`**：不把模块注册进 `sys.modules` 就 `exec_module`，
   Python 3.14 的 dataclass 会报 `'NoneType' object has no attribute '__dict__'`。
   这只影响**探针/测试脚本**，正常跑脚本没问题；修法是先 `sys.modules["cg"] = m`。
8. **字体别名扫描白白花 200ms**：把本机没装的字体名交给 Qt，它会去找别名。
   解法：`make_font()` 用 `QFontDatabase.families()` 先过滤；样式表里不要写不存在的 family。
9. **`offscreen` 平台插件的默认字体就叫 `Sans Serif`**，会打一条无关的字体警告；
   那是平台产物，不是代码问题（真跑 cocoa 不会有）。
10. **`QLocalServer`/`QLocalSocket` 在 `PyQt6.QtNetwork`**，不在 `QtCore`。
11. **心跳"稳定误判死"（用户实机撞到）**：判死条件原来写成 `now - last_rx >= TIMEOUT`，
    只问"距上次收字节多久"，**没比较 `last_rx` 与 `ping_at`**。于是 ping 发出满 10s 就必然为真 ——
    哪怕 pong 刚到、`last_rx` 刚刷新，**每个周期都会在 ping+10s 判死**（现象：`发出 ping（第 1 次）` →
    `收到 pong（第 1 次）` → 10s 后 `pong 超时：连接已断开`）。
    修法：条件补成 `last_rx < ping_at and (now - ping_at) >= TIMEOUT`，再加 `_hb_clear_pending()` 作第二道防线。
    **教训**：self-test 当时只驱动了"一个字节都没收到"那条路径，**从没驱动"pong 已到达之后不许判死"** ——
    现在这条已经是常驻断言（第 10 节那张表里的四个用例）。
12. **PyQt6：子线程 `emit` 到普通 Python callable 是"队列投递"**，必须有事件循环（或 `processEvents()`）
    才会真的被调用。写测试脚手架时如果只 `time.sleep()`，会看到"线程明明发了信号、列表里却什么都没有"，
    很容易误判成产品 bug（我第一次跑自动重连 E2E 就栽在这上面）。真 app 里 `app.exec()` 一直在跑，不受影响。
13. **量像素前必须让布局真跑起来**：`win.resize()` + `page.layout().activate()` **不够** —— 控件仍是
    100×30 的默认尺寸（父 agent 也踩过）。有效做法是切到该页后调一次 `win.grab()`
    （强制 polish/布局/渲染）+ `processEvents()`，量出来的才是真实几何。
14. **隐藏的控件没有真实几何**：`setVisible(False)` 的卡片，其子控件量出来是未布局的 sizeHint
    （实测 `x=13 w=74 h=0`，会让你以为"宽度不一致"）。量之前必须先把它显示出来，量完再复位。
15. **构造期 `sizeHint()` 是"未上样式"的尺寸**：`card_head_row()` 里如果按 `max(26, 按钮.sizeHint().height())`
    定高，offscreen 的 fallback 字体会让带按钮那行算成 **27**、只有文字那行算成 **26** → 两行不等高。
    固定高度要用**常量**（`CARD_HEAD_H`），并另加一条"文字塞得下"的断言防大字号裁切。
16. **"行间距特别大"其实是"行被纵向拉伸"**（用户实机报的）：行容器是裸 QWidget（默认纵向 Preferred），
    卡片 body 没有尾部弹簧时父布局把多余高度**平均摊给每一行** → 1080×720 每行 107px、1400 时 243px。
    修法＝行 `setSizePolicy(Preferred, Fixed)` + 每张卡/每个页面 body 末尾 `addStretch(1)` + 行间距 6→2。
    **断言必须在高窗口下量**；上界要算 `max(sizeHint, minimumHeight, 子控件需要的高度)`，
    否则"故意固定 26px 的首行"和"30px 按钮的行"都会误报。
17. **PyQt6 `drawRoundedRect` 没有 `(int, float, int, int, float, float)` 重载**：自绘控件里
    `y0 = (h - th) / 2` 是 float，传进去会抛 `TypeError`；而异常从 `paintEvent` 里逃出来会让进程
    **直接 abort（退出码 134）**，很难看出是画的问题。用 `//` 取整即可。
18. **"设置行"要用字段行版式，不要用"右侧控件"版式**：`card_head_row(..., control=…)` 会把控件顶到卡片最右；
    像「内嵌 DHCP」这种要跟字段对齐的行，应该走 `field_row(self, "内嵌 DHCP", sw)` + 行尾 `addStretch(1)`
    （标签列 84 → 控件紧跟 → 右边留空）。
19. **"点了开关没反应、DHCP 卡不出来"（实机 bug）**：`field_row()` 的 `enabled` 默认是 `False`
    （Phase 1 占位控件默认禁用），「内嵌 DHCP」这行忘了传 `enabled=True` → 开关被 `setEnabled(False)`；
    而我自绘的 `ToggleSwitch` 当时**不区分禁用态**（照旧画成蓝色可见开关）→ 用户看到的是"好好的开关，
    点了没反应"。两处都补了：`enabled=True`；`paintEvent` 按 `isEnabled()` 画禁用色（灰轨道 + 灰钮）。
    **教训**：self-test 里只调 `setChecked()` 是**测不到**这类 bug 的 —— 现在这条断言走**真鼠标事件**
    （press + release），并额外断言"切换后页面其它控件仍要响应"（用户还报了"点其他东西也没反应"）。
20. **`card_head_row()` 的左侧标签默认是"卡片标题"样式**（`cardTitle`：加粗 + 主白色）；
    当它被当作**设置行**（如「内嵌 DHCP」）用时，必须传 `label_object="fieldLabel"`，
    才能和同卡片里的字段标签（「路由老化」等：次要灰、字重 400）一致 —— 用户报过"这一行不要特殊加粗白色"。
    另外：**"开关"别用 `QCheckBox`**（深色卡片上只有一个小方块，看不出开/关），用自绘 `ToggleSwitch`。
21. **`recv()` 的"空"有两种意思，别混**：非阻塞 socket 的 `EWOULDBLOCK`（只是暂时没数据）与
    **返回 `b''`（对端真的关了）**。原来命令行循环把两者都当成"没数据"继续转 → 对端关闭后只能干等
    心跳 20+10 秒才判死才重连。分开之后（`None` = 没数据继续转，`b''` = 立刻 break）对端一断就立刻重连。
22. **重构时"旧路径没删干净"→ 每次启动连两次**（真 bug）：把 `main()` 的连接部分抽成 `ws_connect_once()`
    之后，那段旧的 `getaddrinfo + connect + ws_handshake + log("已连接至…") + start_login + Windows 输入线程`
    **没删**，于是每次启动连两条连接：第一个 socket 被全局 `ws_sock` 覆盖后**泄漏**（FD 泄漏 +
    服务端多挂一条永不登录的连接），`--user/--pass` 时第一条连接的 challenge 还被丢弃 → 登录对不上。
    修法＝删掉旧块，`ws_connect_once()` 成为**唯一**连接入口（现在全文件只有一处 `socket.socket(...)` 建 WS）。
    **教训**：E2E 必须**数"连了几次"**（服务端 `[连接]` 1 条 + 客户端「已连接至」1 条 + `自动登录`/`登录成功`
    各 1 次）。两个计数坑：① 起服务端时的"端口就绪探针"也会被服务端记一条 `[连接]`；② 那行是**异步**打印的
    （connect 成功 ≠ 服务端已打完），所以要先等它落盘再取日志偏移量。
23. **别在断言里写"待禁字面量"本身**：源码扫描型断言（不许出现 `subprocess`、不许出现 `xxx.py`）会把
    **断言自己的字符串**也扫进去 → 自伤。修法是拼接构造（`"sub" + "process"`）或锚定上下文（`"\n名字 = "`）。
    这一轮被绊了三次。

---

## 13. 改这个文件时的注意事项

- **不要动 `client.py`**、不要动 `server/`：桌面端只做"调它的函数"。
- **不要给 `QWidget` 子类设透明背景**，容器要背景就 `setAttribute(WA_StyledBackground)` + 显式颜色
  （第 12 节第 1 条）。
- **新增"会变的界面数据"时**：在 `EngineBridge` 加一条信号 → `_observe()`/`_emit_holes()` 里发出去 →
  `MainWindow` 接到页面上；**不要在界面上轮询 `cli.*`**。
- **所有 `client.py` 调用都投队列**（`engine.command(...)`），别从 GUI 线程直接调。
- **界面不写解释性文案**：提到 python 端文件路径、"到主页怎么点"、实现现状/架构的整行说明**一律不放屏幕**
  （信息写进代码注释/docstring）。已删掉的有：media 两条（RTMP 输入/输出说明）、media 拉起应用的架构说明、
  proxy 的 -L/-R 用法说明、wg 的"三档都要用本地端口"、主页服务器卡那行 Phase 说明、tcp 卡片的实现现状尾注；
  proxy/vpn 的"通道：还没有（在主页 … 点 X）"先只留状态，后来**空态整行也删了**（空态已由首行状态表达，
  再挂一行是重复；三端一致。将来有真实通道时按 `if channels:` 渲染动态列表）。保留的是：字段语义
  （"对方路由器公网地址:端口…"）、状态文本、以及最短操作提示（"点网口 = 拔线"）。
  self-test 用 `ast` 抽出所有**字符串字面量**（排除 docstring）扫禁字样，命中就红。
- **不要在 `client-gui.py` 里重新实现 ping / 心跳**：它们在 `client.py`（`ws_ping_frame` / `start_ws_heartbeat` /
  `send_app_ping`）。GUI 只负责在读循环里 `cli.note_ws_rx()` 通知一声，以及 `ping` 按钮投一条 `ping` 命令。
  self-test 有源码自检守着这条。
- **改完必须** `python3 -m py_compile client/client-gui.py` +
  `QT_QPA_PLATFORM=offscreen python3 client/client-gui.py --self-test`（后者会验上面第 10 节那一大串，
  包括像素级的不透明回归）；**不要**为了看效果在开发机上弹窗跑（除非用户要求）。
- 给界面加数据时，顺手在 `--self-test` 里加一条断言（第 10 节的段落就是模板：
  纯函数算几何 → 断言；界面状态 → 造数据 → 断言）。
