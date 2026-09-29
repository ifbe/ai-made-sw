# -*- coding: utf-8 -*-
"""UDP 打洞 6 步（client.py 主进程内跑）。

  1. 通知服务器（发 p2pudp）
  2. 服务器要求发给 udp（send_udp_to_server）
  3. 往服务器 UDP 端口发 hello（15 包 burst @30ms，之后 1/s 维持）
  4. 服务器告知双方地址（thisisyourpeer_udp）
  5. 往对方发消息（同一个 socket 直接发 ping：起始 15 包 burst 抢 NAT 映射，之后 1/s）
  6. 收到对方消息 → 洞打通

第 5/6 步由主进程自己做，socket 也由主进程持有；只有把洞交给某个协议
（udptest / onholefrompeer tun …）时，client.py 才会关掉它、让子进程 bind 同一端口。
"""

import json
import time
import socket
import random
import threading

from hole import core

PING_INTERVAL = 1.0
HOLE_BURST_COUNT = 15          # 第 5 步起始 burst 包数（和 hello burst 一样，抢 NAT 映射）
HOLE_BURST_INTERVAL = 0.03     # burst 包间隔
HOLE_MAX_CANDIDATES = 4        # 一条洞最多记几个对端候选地址（第 0 个是服务器给的，保底）
HELLO_TIMEOUT = 10.0           # 建了 socket 但一直没等到对端地址 → 放弃
HOLE_CONFIRM_TIMEOUT = 30.0    # 拿到对端地址后多少秒还没收到对方消息 → 打洞失败
STEP_RESPONSE_TIMEOUT = 10.0   # 等服务器回应的步骤（第 2 步）多久没动静算失败

# 已建 socket、正在往服务器发 hello、还没拿到对端地址的洞
_pending_hellos = []
# 本次 udp/ffmpeg/wg <user> 的目标（下次 send_udp_to_server 时绑定到待打洞 socket）
_pending_target = None
# 当前正在走第 1~4 步的那个洞（被动方为 None，第 2 步才建）
_current_hole = None


# ====== 第 1 步：通知服务器 ======

def start(target):
    """udp / ffmpeg / wg / wghelp <user> 的共同入口：发 p2pudp，建洞记录，走第 1、2 步"""
    global _pending_target, _current_hole
    _pending_target = target
    hole = core.record_hole('udp', target, '', 0, '', 0, status='打洞中')
    hole['local_init'] = True
    _current_hole = hole
    core.ws_send({"type": "p2pudp", "target": target})
    core.once(hole, 1, core.UDP_STEPS, True, f'p2pudp -> {target}')
    core.begin(hole, 2, core.UDP_STEPS, timeout=STEP_RESPONSE_TIMEOUT)
    return hole


# ====== 第 2、3 步：服务器要求发给 udp → 建 socket 发 hello ======

def on_send_udp_to_server(udpport):
    """收到 {"type":"send_udp_to_server"}（主动方和被动方都会收到）"""
    global _pending_target, _current_hole
    target = _pending_target
    _pending_target = None

    hole = _current_hole
    peer_init = hole is None or hole['status'] != '打洞中' or hole.get('sock') is not None
    if peer_init and core.get_onpeerwant('udp') == 'none':
        core.log("[onpeerwantudp=none] 已忽略对方的 UDP 打洞请求（不参与、不发 hello，对方会自己超时）")
        return
    if peer_init:
        # 被动方（对方发起）没有第 1 步，这里新建记录，对端名字等第 4 步才知道
        hole = core.record_hole('udp', target or '', '', 0, '', 0, status='打洞中')
    _current_hole = hole

    core.result(hole, 2, core.UDP_STEPS, True, f'{core.get_server()[0]}:{udpport}')
    _start_hello(hole, udpport, target)
    core.once(hole, 3, core.UDP_STEPS, True, 'UDP hello ×15（服务器已记录本端公网地址）')
    core.begin(hole, 4, core.UDP_STEPS)


# onpeermsg 由 client 判断（它才有那个状态变量），这里通过 core.get_onpeermsg() 取


def _start_hello(hole, server_udp_port, target):
    """建一个 UDP socket，往服务器 UDP 端口发 hello（等 thisisyourpeer_udp）"""
    server_ip = core.get_server()[0]
    username = core.get_username()
    # 保持 IPv4（服务器是 IPv4 0.0.0.0），避免 IPv6 socket 发到 IPv4 服务器失败
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_port = None
    for _ in range(20):
        p = random.randint(50000, 65000)
        try:
            sock.bind(('0.0.0.0', p))
            local_port = p
            break
        except OSError:
            continue
    if local_port is None:
        sock.bind(('0.0.0.0', 0))
        local_port = sock.getsockname()[1]

    stop_ev = threading.Event()
    ph = {'sock': sock, 'fd': sock.fileno(), 'local_port': local_port,
          'target': target, 'stop': stop_ev, 'thread': None, 'hole': hole}
    with core.holes_lock:
        _pending_hellos.append(ph)
    t = threading.Thread(target=_hello_loop, args=(ph, server_ip, server_udp_port, username),
                         daemon=True, name=f'hello-{local_port}')
    ph['thread'] = t
    t.start()
    core.log(f"[打洞] 本端 UDP fd={ph['fd']} 端口={local_port}，"
            f"往服务器 {server_ip}:{server_udp_port} 发 hello...")
    return ph


def _hello_loop(ph, server_ip, server_udp_port, username):
    """往服务器 UDP 端口发 hello（15 个 burst + 之后每秒 1 个维持映射）。

    socket 归洞所有，这里只有"超时没人接手"时才关它：
    被 _take_pending_hello 取走 → 直接退出（socket 留给洞用）。
    """
    sock = ph['sock']
    stop_ev = ph['stop']

    def _send():
        sig = core.sign_session() if core.sign_session else None
        payload = {'type': 'p2pudp_hello', 'username': username}
        if sig:
            payload['signature'] = sig
        if core.get_debug():
            print(f"[DEBUG] UDP hello -> {server_ip}:{server_udp_port}: {payload}")
        try:
            sock.sendto(json.dumps(payload).encode(), (server_ip, server_udp_port))
        except OSError:
            pass

    for _ in range(15):
        if stop_ev.is_set():
            return
        _send()
        time.sleep(0.03)

    deadline = time.time() + HELLO_TIMEOUT
    while not stop_ev.is_set():
        if time.time() > deadline:
            with core.holes_lock:
                if ph not in _pending_hellos:
                    return  # 刚被取走 → 交给洞，不关 socket
                _pending_hellos.remove(ph)
            ph['stop'].set()
            try:
                sock.close()
            except OSError:
                pass
            hole = ph.get('hole')
            if hole is not None:
                with core.holes_lock:
                    if hole['status'] == '打洞中':
                        hole['status'] = '打洞失败'
                core.result(hole, 4, core.UDP_STEPS, False,
                             f'{HELLO_TIMEOUT:.0f}s 没等到服务器告知地址'
                             f'（fd={ph["fd"]} 端口={ph["local_port"]}）')
            else:
                core.log(f"[打洞] {HELLO_TIMEOUT:.0f}s 没等到对端地址，放弃"
                        f"（fd={ph['fd']} 端口={ph['local_port']}）")
            return
        time.sleep(1.0)
        if stop_ev.is_set():
            break
        _send()


def _take_pending_hello(peer):
    """取出一个待打洞的 hello socket（优先 target == peer，否则取最早的一个）"""
    with core.holes_lock:
        pick = None
        for ph in _pending_hellos:
            if ph.get('target') == peer:
                pick = ph
                break
        if pick is None and _pending_hellos:
            pick = _pending_hellos[0]
        if pick is not None:
            _pending_hellos.remove(pick)
    if pick:
        pick['stop'].set()  # 停止往服务器发 hello，同一个 socket 改去 ping 对端
    return pick


def stop_all_hellos():
    """停止所有还在发 hello 的 socket（被踢下线 / 登出 / 改用 TCP 时）"""
    with core.holes_lock:
        pend = list(_pending_hellos)
        _pending_hellos.clear()
    for ph in pend:
        ph['stop'].set()
        try:
            ph['sock'].close()
        except OSError:
            pass
    return pend


# ====== 第 4、5、6 步：服务器告知地址 → 互发 → 收到就算通 ======

def on_thisisyourpeer(msg):
    """收到 {"type":"thisisyourpeer_udp"}"""
    global _current_hole
    peer_name = msg.get('name', '')
    peer_ip = msg.get('ip', '')
    peer_port = msg.get('port', 0)
    my_ip = msg.get('my_ip', '')

    # 把刚才发 hello 的 socket 拿过来（不再交给子进程，主进程自己走第 5/6 步）
    ph = _take_pending_hello(peer_name)
    hole = ph.get('hole') if ph else None
    if ph is None:
        core.log(f"[打洞] 收到 {peer_name} 的地址，但没有待打洞 socket，临时建一个...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
        ph = {'sock': sock, 'fd': sock.fileno(), 'local_port': sock.getsockname()[1],
              'target': peer_name, 'stop': threading.Event(), 'thread': None}
    if hole is None:
        hole = core.record_hole('udp', peer_name, peer_ip, peer_port,
                               my_ip, ph['local_port'], fd=ph['fd'], sock=ph['sock'],
                               status='打洞中')

    # 第 4 步：地址拿到，补齐这条洞（服务器给的这个地址是第一个候选）
    hole['peer'] = peer_name
    hole['fd'] = ph['fd']
    hole['sock'] = ph['sock']
    hole['my_ip'] = my_ip
    hole['my_port'] = ph['local_port']
    hole['peer_ip'] = peer_ip
    hole['peer_port'] = peer_port
    hole['candidates'] = [{'ip': peer_ip, 'port': peer_port}]
    _current_hole = None
    core.result(hole, 4, core.UDP_STEPS, True,
                 f'本端 fd={hole["fd"]} {my_ip}:{hole["my_port"]} ↔ 对端 {peer_ip}:{peer_port}')
    core.once(hole, 5, core.UDP_STEPS, True, '主进程 ping 对端')
    core.begin(hole, 6, core.UDP_STEPS)

    t = threading.Thread(target=_udp_hole_loop, args=(hole,),
                         daemon=True, name=f"hole-{hole['id']}")
    hole['thread'] = t
    t.start()


def _add_candidate(hole, addr):
    """把收到包的源地址记成候选（peer-reflexive），并设为当前对端地址。

    对称型 NAT 会给"到不同目的地"的流量分配不同公网端口，服务器告诉我们的
    对端地址可能不是对方对我们实际使用的那个；从 recvfrom 看到的源地址一定是对的，
    所以两个都留着、每轮都发。
    """
    ip, port = addr[0], addr[1]
    msg = None
    with core.holes_lock:
        cands = hole.setdefault('candidates', [])
        known = any(c['ip'] == ip and c['port'] == port for c in cands)
        if not known:
            cands.append({'ip': ip, 'port': port})
            # 别被灌爆：第 0 个是服务器给的，保底留着
            while len(cands) > HOLE_MAX_CANDIDATES:
                cands.pop(1)
        moved = (hole['peer_ip'], hole['peer_port']) != (ip, port)
        if moved:
            hole['peer_ip'], hole['peer_port'] = ip, port
        if moved:
            msg = (f"[洞 #{hole['id']}] 对端地址换成 {ip}:{port}"
                   f"（{'新候选' if not known else '已有候选'}，候选共 {len(cands)} 个）")
        elif not known:
            msg = f"[洞 #{hole['id']}] 记下对端候选 {ip}:{port}（候选共 {len(cands)} 个）"
    if msg:
        core.log(msg)


def _hole_candidates(hole):
    """这一轮要往哪些地址发（至少包含当前对端地址）"""
    with core.holes_lock:
        cands = [dict(c) for c in (hole.get('candidates') or [])]
    cur = (hole['peer_ip'], hole['peer_port'])
    if not any(c['ip'] == cur[0] and c['port'] == cur[1] for c in cands):
        cands.append({'ip': cur[0], 'port': cur[1]})
    return cands


def _udp_hole_loop(hole):
    """第 5/6 步：给对端发 ping、收 ping/pong。

    先 burst（HOLE_BURST_COUNT 包 @HOLE_BURST_INTERVAL）抢 NAT 映射，
    然后回落到 1/s 重试；收到对方的任何心跳 = 第 6 步成功。
    成功之后继续 1/s 维持 NAT 映射，等用户/自动规则把洞交给某个协议。
    """
    sock = hole.get('sock')
    if sock is None:
        return

    seq = 0
    sent_at = {}                      # seq -> 发送时刻（算 RTT）
    burst_left = HOLE_BURST_COUNT
    next_send = time.time()           # 立刻发第一个
    give_up_at = time.time() + HOLE_CONFIRM_TIMEOUT

    while not hole['stop'].is_set():
        now = time.time()

        # ---- 还没打通、超过总时限 → 打洞失败 ----
        if hole['status'] == '打洞中' and now > give_up_at:
            with core.holes_lock:
                if hole['status'] == '打洞中':
                    hole['status'] = '打洞失败'
            hole['stop'].set()
            try:
                sock.close()
            except OSError:
                pass
            hole['sock'] = None
            core.result(hole, 6, core.UDP_STEPS, False,
                         f'{HOLE_CONFIRM_TIMEOUT:.0f}s 没收到对方消息，打洞失败')
            return

        # ---- 到点发 ping（往所有候选各发一份；burst 阶段 30ms 一轮，之后 1s 一轮）----
        if now >= next_send:
            payload = json.dumps({'type': 'ping', 'seq': seq, 'ts': now}).encode()
            for c in _hole_candidates(hole):
                try:
                    sock.sendto(payload, (c['ip'], c['port']))
                except OSError:
                    # 单个候选不可达（ICMP）不该影响其它候选
                    if hole['stop'].is_set():
                        return
            sent_at[seq] = now
            if len(sent_at) > 64:
                for k in sorted(sent_at)[:-64]:
                    del sent_at[k]
            seq += 1
            if burst_left > 1:
                burst_left -= 1
                next_send = now + HOLE_BURST_INTERVAL
            else:
                burst_left = 0
                next_send = now + PING_INTERVAL
            continue

        # ---- 收包（超时按"离下一次发包还有多久"来定，burst 期间也及时收）----
        try:
            sock.settimeout(max(0.01, min(0.25, next_send - now)))
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            if hole['stop'].is_set():
                return
            time.sleep(0.05)          # 某个候选不可达，别整个退出
            continue

        # 收到包就记住这个源地址（对称 NAT 下这才是对方真正对我们用的地址）
        _add_candidate(hole, addr)
        try:
            msg = json.loads(data.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            continue
        t = msg.get('type')
        if t == 'ping':
            # 对方在找我 → 立刻回 pong（关键：只要有一个方向通就能救回来）
            try:
                sock.sendto(json.dumps({'type': 'pong', 'seq': msg.get('seq')}).encode(), addr)
            except OSError:
                pass
            _mark_hole_confirmed(hole)
        elif t == 'pong':
            st = sent_at.pop(msg.get('seq'), None)
            if st is not None:
                hole['rtt'] = (time.time() - st) * 1000
            _mark_hole_confirmed(hole)


def _mark_hole_confirmed(hole):
    """收到对方 UDP 消息 → 第 6 步成功，交给 client 决定接下来拉起什么"""
    with core.holes_lock:
        if hole['status'] != '打洞中':
            return
        hole['status'] = '已打通'
    core.result(hole, 6, core.UDP_STEPS, True,
                 f'本端 fd={hole["fd"]} {hole["my_ip"]}:{hole["my_port"]}'
                 f' ↔ 对端 {hole["peer_ip"]}:{hole["peer_port"]}')
    core.on_udp_ready(hole)


# ====== 服务器拒绝（比如目标不存在）======

def on_error(msg):
    """服务器回 error 时调用；返回 True 表示这一步的问题已经被标掉了"""
    global _current_hole
    hole = _current_hole
    _current_hole = None
    if hole is None or hole['status'] != '打洞中':
        return False
    hole['status'] = '打洞失败'
    core.result(hole, 2, core.UDP_STEPS, False, msg)
    return True
