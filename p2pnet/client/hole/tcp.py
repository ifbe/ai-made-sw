# -*- coding: utf-8 -*-
"""TCP 打洞 5 步（client.py 主进程做前 4 步 + 打洞本身，第 5 步把内核 socket 交出去）。

  1. 通知服务器（发 p2ptcp）
  2. 服务器要求连 TCP（send_tcp_to_server）
  3. 向服务器注册（**从打洞那个本地端口 P 发出去**，NAT 映射才建在 P 上）
  4. 服务器告知双方地址（thisisyourpeer_tcp）
  5. 三个 socket 都在 P 上：同时 **listen** 和 **connect 对方**，谁先成就留谁，
     把那个**已经建立连接的内核 socket** 用 fd 继承交给使用者程序（app/tcptest.py 等）

为什么要这么绕（和 UDP 完全不同）：
  * UDP 洞可以"主进程先打通、关掉 socket、子进程 bind 同一个本地端口"接着用 ——
    因为 UDP 关掉 socket 不影响 NAT 映射。
  * TCP 不行：连接一关就没了，子进程重新 bind+connect 会**重新 SYN/ACK**，
    NAT 那边对不上。所以 TCP 洞的"交接"必须是**传递那个已建立的内核对象（fd）**，
    不能让子进程自己重建。

三个 socket 都 bind 同一个本地端口 P 靠 SO_REUSEPORT（见 _bind_reusable）；
注册用的那个也要从 P 发出，否则服务器看到的是另一个公网端口，对方连不上。

双方可能**互相连成功**（同时 open 出两条不同的 TCP 连接）。这时必须挑同一条，
否则一边用 X 一边用 Y，互相收不到。挑法用量化的规则（见 _pick_tie_break），
两边算出来的一致；这是 TCP 同时打开的标准做法。
"""

import sys
import json
import time
import errno
import socket
import select

from hole import core

TCP_ADDR_TIMEOUT = 30.0        # 第 4 步等服务器告知地址多久算失败
STEP_RESPONSE_TIMEOUT = 10.0   # 第 2 步等服务器要求多久算失败
PUNCH_TIMEOUT = 15.0           # 第 5 步 listen/connect 同时试多久算失败
CONNECT_RETRY_INTERVAL = 0.25  # 主动 connect 的重试间隔（失败要重建 socket 才能再连）
BOTH_WAIT = 0.3                # 一边成了之后再等一会儿，看另一边是不是也成了（要挑一致的）

# 当前正在走第 1~4 步的那个洞（被动方为 None，第 2 步才建）
_current_hole = None
# 注册用的那个 socket：它绑在打洞端口 P 上，留着不关（关掉映射就没了，等打到洞再关）
_reg_sock = None


# ====== 第 1 步：通知服务器 ======

def start(target):
    """tcp <user>：发 p2ptcp，建洞记录，走第 1、2 步"""
    global _current_hole
    hole = core.record_hole('tcp', target, '', 0, '', 0, status='打洞中')
    hole['local_init'] = True
    _current_hole = hole
    core.ws_send({"type": "p2ptcp", "target": target})
    core.once(hole, 1, core.TCP_STEPS, True, f'p2ptcp -> {target}')
    core.begin(hole, 2, core.TCP_STEPS, timeout=STEP_RESPONSE_TIMEOUT)
    return hole


# ====== socket 工具 ======

def _bind_reusable(family, local_port):
    """建一个 TCP socket 并 bind 到打洞端口 P（多个 socket 共用 P 靠 SO_REUSEPORT）

    Linux/macOS 有 SO_REUSEPORT，多个 socket 能同时 bind 同一个 P；
    Windows 没有这个选项（SO_REUSEADDR 语义不同、还会被"抢端口"），
    所以 Windows 上这套三 socket 打法需要另想办法 —— 见下面 _pick_tie_break 的 TODO。
    """
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(('0.0.0.0', int(local_port)))
    return s


def _register(server_ip, tcpport, local_port, family):
    """第 3 步：**从打洞端口 P** 连服务器发注册包，然后把 socket 留着

    留着的原因：这条连接就是 P 上的 NAT 映射的来源。UDP 那边敢关是因为映射不受影响，
    TCP 一关映射就可能被回收（而且对方要连的就是 P 的公网映射）。
    """
    info = socket.getaddrinfo(server_ip, tcpport, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family2, socktype, proto, _, sockaddr = info[0]
    sock = _bind_reusable(family2, local_port)
    sock.connect(sockaddr)
    payload = {'username': core.get_username()}
    sig = core.sign_session() if core.sign_session else None
    if sig:
        payload['signature'] = sig
    if core.get_debug():
        print(f"[DEBUG] TCP registration -> {server_ip}:{tcpport} "
              f"（源端口 {sock.getsockname()[1]}）: {payload}")
    sock.sendall((json.dumps(payload) + '\n').encode())
    return sock


# ====== 第 2、3、4 步 ======

def on_send_tcp_to_server(tcpport):
    """收到 {"type":"send_tcp_to_server"}（主动方和被动方都会收到）"""
    global _current_hole, _reg_sock
    server_ip = core.get_server()[0]

    hole = _current_hole
    peer_init = hole is None or hole['status'] != '打洞中' or hole.get('registered')
    if peer_init and core.get_onpeerwant('tcp') == 'none':
        core.log("[onpeerwanttcp=none] 已忽略对方的 TCP 打洞请求（不参与、不注册，对方会自己超时）")
        return
    if peer_init:
        # 被动方（对方发起）没有第 1 步，这里新建记录
        hole = core.record_hole('tcp', '', '', 0, '', 0, status='打洞中')
    _current_hole = hole

    # 打洞端口 P：被动方还不知道服务器会看到哪个端口，所以先随机挑一个（和 UDP 一样的做法）
    local_port = hole.get('my_port') or _pick_local_port()
    hole['my_port'] = local_port
    core.result(hole, 2, core.TCP_STEPS, True, f'{server_ip}:{tcpport}')

    try:
        _reg_sock = _register(server_ip, tcpport, local_port, socket.AF_INET)
    except Exception as e:
        hole['status'] = '打洞失败'
        core.result(hole, 3, core.TCP_STEPS, False, f'注册失败: {e}')
        _current_hole = None
        return

    hole['local_port'] = local_port
    hole['registered'] = True
    core.once(hole, 3, core.TCP_STEPS, True,
              f'从本端端口 {local_port} 注册（NAT 映射就建在这个端口上）')
    core.begin(hole, 4, core.TCP_STEPS, timeout=TCP_ADDR_TIMEOUT,
               timeout_msg='服务器一直没告知双方地址')


def _pick_local_port():
    """随机挑一个高位端口当打洞端口 P（和 UDP 那边一个思路）"""
    import random
    for _ in range(20):
        p = random.randint(50000, 65000)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            s.bind(('0.0.0.0', p))
            s.close()
            return p
        except OSError:
            s.close()
            continue
    return 0        # 0 = 让内核挑（bind_reusable 里 bind(('0.0.0.0', 0))）


# ====== 第 4、5 步：服务器告知地址 → 同时 listen/connect → 交 fd ======

def on_thisisyourpeer(msg):
    """收到 {"type":"thisisyourpeer_tcp"}"""
    global _current_hole, _reg_sock
    peer_name = msg.get('name', '')
    peer_ip = msg.get('ip', '')
    peer_port = msg.get('port', 0)
    my_ip = msg.get('my_ip', '')
    my_port = msg.get('my_port', 0)

    hole = _current_hole
    if hole is None or hole['status'] != '打洞中':
        hole = core.record_hole('tcp', peer_name, peer_ip, peer_port,
                                my_ip, my_port, fd=None, sock=None,
                                status='打洞中')
    local_port = hole.get('my_port') or my_port
    hole['peer'] = peer_name
    hole['peer_ip'] = peer_ip
    hole['peer_port'] = peer_port
    hole['my_ip'] = my_ip
    hole['my_port'] = local_port
    hole['status'] = '打洞中'
    _current_hole = None

    core.result(hole, 4, core.TCP_STEPS, True,
                f'本端 {my_ip}:{local_port} ↔ 对端 {peer_ip}:{peer_port}')
    core.begin(hole, 5, core.TCP_STEPS, timeout=PUNCH_TIMEOUT,
               timeout_msg=f'{PUNCH_TIMEOUT:.0f}s 内 listen/connect 都没成')

    core.log(f"[tcp] 同时开 listen 和 connect（都绑在端口 {local_port} 上）...")
    ok, sock, err = _punch(hole, local_port, peer_ip, peer_port, my_ip, my_port)

    # 注册那条用完就关（洞已打到，映射由新连接占着）
    if _reg_sock is not None:
        try:
            _reg_sock.close()
        except OSError:
            pass
        _reg_sock = None

    if not ok:
        hole['status'] = '打洞失败'
        core.result(hole, 5, core.TCP_STEPS, False, err)
        return
    hole['status'] = '已打通'
    core.result(hole, 5, core.TCP_STEPS, True,
                f'本地 fd={sock.fileno()}（{sock.getpeername()[0]}:{sock.getpeername()[1]}）')
    # 把**这个已经建立连接的内核 socket** 交给使用者程序（不 close、不重做握手）
    core.launch_tcp(hole, sock, peer_name, peer_ip, peer_port, my_ip, my_port)


def _punch(hole, local_port, peer_ip, peer_port, my_ip, my_port):
    """listen + connect 同时试，谁先成就留谁；两边都成的话按规则挑同一条

    返回 (ok, sock, err)
    """
    family = socket.AF_INET6 if ':' in str(my_ip) or ':' in str(peer_ip) else socket.AF_INET
    listen_sock = None
    conn_sock = None
    accepted = None
    connected = None
    try:
        listen_sock = _bind_reusable(family, local_port)
        listen_sock.listen(8)
        listen_sock.setblocking(False)
        core.log(f"[tcp] listen 已就绪（0.0.0.0:{local_port}）")
    except Exception as e:
        if listen_sock:
            listen_sock.close()
        return False, None, f'listen 失败: {e}'

    deadline = time.time() + PUNCH_TIMEOUT
    next_connect = 0.0
    both_until = None          # 一边成了之后的"再等等另一边"的截止时间

    while time.time() < deadline:
        # ---- 主动 connect（失败要重建 socket 才能再连，所以每次都新建）----
        if conn_sock is None and time.time() >= next_connect:
            try:
                conn_sock = _bind_reusable(family, local_port)
                conn_sock.setblocking(False)
                conn_sock.connect((peer_ip, int(peer_port)))
                core.log(f"[tcp] connect -> {peer_ip}:{peer_port}（源端口 {local_port}）")
            except BlockingIOError:
                pass                       # EINPROGRESS，正常，等 select
            except OSError as e:
                # 已经连上（EISCONN）也算成功，其余情况重建重试
                if e.errno == errno.EISCONN:
                    connected = conn_sock
                else:
                    try:
                        conn_sock.close()
                    except OSError:
                        pass
                    conn_sock = None
                    next_connect = time.time() + CONNECT_RETRY_INTERVAL

        # ---- 等：listen 上有新连接 或 我们的 connect 完成 ----
        rlist = [listen_sock]
        wlist = [conn_sock] if conn_sock is not None else []
        try:
            r, w, _ = select.select(rlist, wlist, [], 0.2)
        except OSError:
            r, w = [], []

        if listen_sock in r and accepted is None:
            try:
                s, addr = listen_sock.accept()
                accepted = s
                core.log(f"[tcp] ✅ 对方的连接进来了（{addr[0]}:{addr[1]}）")
            except OSError:
                pass

        if conn_sock is not None and conn_sock in w and connected is None:
            err = conn_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                connected = conn_sock
                # 置空是为了不再把它放进 select 的可写集合 —— 否则同一个 socket
                # 一直"可写"，日志会被刷屏（连上了就是连上了）
                conn_sock = None
                core.log("[tcp] ✅ 我们连上对方了")
            else:
                try:
                    conn_sock.close()
                except OSError:
                    pass
                conn_sock = None
                next_connect = time.time() + CONNECT_RETRY_INTERVAL

        # ---- 一边成了：再等一小会儿看另一边是不是也成了（两边都成要挑一致的）----
        if accepted is not None or connected is not None:
            if both_until is None:
                both_until = time.time() + BOTH_WAIT
            if accepted is not None and connected is not None:
                break
            if time.time() >= both_until:
                break

    # ---- 挑一条 ----
    keep = None
    drop = None
    if accepted is not None and connected is not None:
        keep, drop = _pick_tie_break(accepted, connected, my_ip, my_port, peer_ip, peer_port)
        core.log(f"[tcp] 两条都成了（同时 open），按规则留 "
                 f"{'进来的' if keep is accepted else '我们发起的'}那条，关掉另一条")
    elif accepted is not None:
        keep = accepted
    elif connected is not None:
        keep = connected

    for s in (listen_sock, conn_sock, drop):
        if s is None or s is keep:
            continue
        try:
            s.close()
        except OSError:
            pass
    if keep is None:
        return False, None, f'{PUNCH_TIMEOUT:.0f}s 内 listen/connect 都没成（对方不在或防火墙挡了）'
    keep.setblocking(True)
    return True, keep, ''


def _pick_tie_break(accepted, connected, my_ip, my_port, peer_ip, peer_port):
    """两条连接都成了，挑哪条？—— 两边必须挑**同一条**，否则各说各话

    两条连接是：
      X = 我们发起的（connected）：本端 my_addr → 对端 peer_addr
      Y = 对方发起的（accepted） ：对端 peer_addr → 本端 my_addr
    规则：比较两端的公网 地址:端口，**公网地址小的那一端发起的连接**获胜。
      本端算：my_addr < peer_addr ? 留 connected(X) : 留 accepted(Y)
      对端算同一件事（它那边的 my/peer 正好相反）→ 结果一致 ✓
    """
    my_addr = f"{my_ip}:{my_port}"
    peer_addr = f"{peer_ip}:{peer_port}"
    if my_addr < peer_addr:
        return connected, accepted
    return accepted, connected


# ====== 服务器拒绝 ======

def on_error(msg):
    """服务器回 error 时调用；返回 True 表示这一步的问题已经被标掉了"""
    global _current_hole
    hole = _current_hole
    _current_hole = None
    if hole is None or hole['status'] != '打洞中':
        return False
    hole['status'] = '打洞失败'
    core.result(hole, 2, core.TCP_STEPS, False, msg)
    return True
