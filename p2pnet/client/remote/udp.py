#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet P2P UDP 隧道
用法: python3 udp.py <peer_ip> <peer_port> <local_port> [--appmode tun|tap|clientsocket|auto]

架构:
  主线程:    select 监听 socket，收 UDP，ping/pong 自己处理，非 ping/pong 推进队列
  发送线程:  每 1s 发一个 ping
  隧道线程:  等就绪后，从队列取数据写 tun，从 tun 读数据发 UDP
"""

import os
import sys
import json
import time
import socket
import argparse
import select
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _auto_tun(nettype, name=None):
    """
    根据 nettype 和平台自动选择 tun 实现。
    nettype: 'tun' | 'tap' | 'fake' | 'auto'
    name: 指定设备名（如 utun3、tap0）；tun/tap 模式下为 socketpath 参数；clientsocket 模式下为 socket 路径
    返回一个 TUN-like 实例（send/recv/close 接口）。
    """
    if nettype == 'fake':
        from app.fake import FakeTun
        return FakeTun()

    import platform
    sysname = platform.system()

    if nettype == 'tun' or nettype == 'auto':
        # 试 Tun
        try:
            if sysname == 'Windows':
                from app.tun_windows import TunWintun
                return TunWintun()
            else:
                from app.tun import Tun
                return Tun(name=name)
        except Exception as e:
            if nettype == 'tun':
                raise RuntimeError(f"TUN 不可用: {e}")

    if nettype == 'tap' or nettype == 'auto':
        # 试 Tap
        try:
            if sysname == 'Windows':
                from app.tap_windows import TapWindows
                return TapWindows()
            else:
                from app.tap import Tap
                return Tap(name=name)
        except Exception as e:
            if nettype == 'tap':
                raise RuntimeError(f"TAP 不可用: {e}")

    if nettype == 'clientsocket':
        path = name
        if not path:
            raise RuntimeError("--socketpath 未设置（clientsocket 模式由 client.py 启动）")
        from app.clientsocket import ClientSocket
        log(f"clientsocket 连接 {path}")
        return ClientSocket(path)

    if nettype == 'auto':
        # 最后 fallback fake
        from app.fake import FakeTun
        t = FakeTun()
        log(f"警告: Tun/Tap 均不可用，使用 FakeTun")
        return t

    raise ValueError(f"未知的 nettype: {nettype}")


PING_INTERVAL = 1.0
PING_TIMEOUT = 5.0
READY_PONGS = 3


def ts():
    return time.strftime("%H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description='p2pnet P2P UDP')
    parser.add_argument('--peeraddr', required=True, help='对方 IP（IPv4/IPv6/域名，自动识别）')
    parser.add_argument('--peerport', type=int, required=True, help='对方端口')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地监听地址（默认 0.0.0.0）')
    parser.add_argument('--localport', type=int, required=True, help='本地 UDP 端口')
    parser.add_argument('--appmode', default='fake',
                        help='appmode 模式（fake/tun/tap/clientsocket/auto）')
    parser.add_argument('--socketpath', default=None,
                        help='clientsocket 模式：Unix socket 路径（client.py 传入）')
    parser.add_argument('--cipher', choices=['none', 'chacha20-poly1305'],
                        default='none', help='加密方式：none=不加密（默认），chacha20-poly1305=ChaCha20-Poly1305 AEAD')
    parser.add_argument('--obfs', choices=['none', 'xor', 'tls'],
                        default='none', help='混淆方式：none=不混淆（默认），xor=XOR 流混淆，tls=TLS 指纹混淆（伪装 HTTPS ClientHello）')
    parser.add_argument('--transport', choices=['none', 'kcp'],
                        default='none', help='可靠传输方式：none=不封装（默认），kcp=KCP 可靠传输')
    parser.add_argument('--key', default=None,
                        help='对称密钥（base64），与 --cipher 配合使用，client.py 登录后派生')
    parser.add_argument('--remotelog', default=None,
                        help='日志文件路径（默认 stdout）')
    args = parser.parse_args()

    peer_ip = args.peeraddr
    peer_port = args.peerport
    local_addr = args.localaddr
    local_port = args.localport
    nettype = args.appmode
    sock_path = args.socketpath or ''
    _log_file = args.remotelog

    # 日志：_log_file 有值则写文件，否则写 stdout
    _log_fp = None
    if _log_file:
        _log_fp = open(_log_file, 'a', encoding='utf-8')

    def log(*a, **kw):
        msg = ' '.join(str(x) for x in a)
        ts_str = time.strftime("%H:%M:%S")
        line = f"[{ts_str}][udptunnel]  {msg}"
        if _log_fp:
            _log_fp.write(line + '\n')
            _log_fp.flush()
        else:
            print(line)

    # 自动判断 IPv4/IPv6
    local_res = socket.getaddrinfo(local_addr, local_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    family, socktype, proto, _, sockaddr = local_res[0]
    sock = socket.socket(family, socktype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(sockaddr)
    sock.setblocking(False)
    actual_port = sock.getsockname()[1]
    local_family = 'IPv6' if family == socket.AF_INET6 else 'IPv4'
    # 启动参数打印
    appmode = args.appmode
    log(f"本端: {local_addr}:{actual_port} ({local_family})")
    log(f"目标: {peer_ip}:{peer_port}")
    log(f"appmode={appmode}  socketpath={sock_path}")
    log(f"cipher={args.cipher}  obfs={args.obfs}  transport={args.transport}")
    log(f"key={args.key or ''}")
    log(f"remotelog={_log_file or ''}")

    # 状态
    stop_event = threading.Event()
    data_queue = []
    queue_lock = threading.Lock()
    queue_not_empty = threading.Condition(queue_lock)
    tunnel_ready = threading.Event()
    tunnel_thread = None

    # 心跳统计
    pong_streak = 0
    confirmed = False
    last_pong_time = time.time()
    seq = 0
    sent_pings = {}

    # 可变的目标地址（发现 peer-reflexive 后更新）
    active_peer = {'ip': peer_ip, 'port': peer_port}
    # 所有已知候选（server 提供的 + 动态发现的）
    candidates = [{'ip': peer_ip, 'port': peer_port}]

    def update_peer(addr_tuple):
        """收到来自新地址的包时，更新 active_peer 和 candidates"""
        ip, port = addr_tuple
        if ip == active_peer['ip'] and port == active_peer['port']:
            return  # 没变
        # 检查是否已在 candidates 里
        for c in candidates:
            if c['ip'] == ip and c['port'] == port:
                active_peer['ip'] = ip
                active_peer['port'] = port
                log(f"🔄 active_peer 切换到已知候选 {ip}:{port}")
                return
        # 新候选，加入并切换
        candidates.append({'ip': ip, 'port': port})
        old_ip, old_port = active_peer['ip'], active_peer['port']
        active_peer['ip'] = ip
        active_peer['port'] = port
        log(f"🆕 发现 peer-reflexive 地址 {ip}:{port}（原 {old_ip}:{old_port} 已加入候选）")

    # ==================== 发送线程：每秒发一个 ping，探测所有候选 ====================
    def heartbeat_sender():
        nonlocal seq
        while not stop_event.is_set():
            now = time.time()
            msg = json.dumps({'type': 'ping', 'seq': seq, 'ts': now})
            for c in candidates:
                log(f"send {msg} -> {c['ip']}:{c['port']}")
                try:
                    sock.sendto(msg.encode(), (c['ip'], c['port']))
                except Exception as e:
                    log(f"发送失败 {c['ip']}:{c['port']}: {e}")
            sent_pings[seq] = now
            seq += 1
            time.sleep(PING_INTERVAL)

    # ==================== 隧道线程 ====================
    def tunnel_worker():
        tun = _auto_tun(nettype, args.socketpath)
        log(f"tunnel 启动（{tun}）")
        while not stop_event.is_set():
            # 从 tun 读 -> 发 UDP（发到 active_peer）
            try:
                data = tun.recv(4096)
                if data:
                    sock.sendto(data, (active_peer['ip'], active_peer['port']))
                    log(f"UDP-> {len(data)}B hex:{data[:16].hex()} -> {active_peer['ip']}:{active_peer['port']}")
            except BlockingIOError:
                pass

            # 从队列取数据 -> 写 tun（非 ping/pong 的隧道数据）
            with queue_not_empty:
                while not data_queue and not stop_event.is_set():
                    queue_not_empty.wait(timeout=0.5)
                if stop_event.is_set():
                    break
                if data_queue:
                    item = data_queue.pop(0)
                    # 兼容旧格式（data）或新格式（data, addr）
                    if isinstance(item, tuple):
                        data, _ = item
                    else:
                        data = item
            tun.send(data)
            log(f"tun<- {len(data)}B hex:{data[:16].hex()}")

        tun.close()
        log(f"tunnel 结束")

    # ==================== 心跳发送线程启动 ====================
    log(f"主循环开始，等待 P2P 就绪...")
    t_sender = threading.Thread(target=heartbeat_sender, daemon=True)
    t_sender.start()

    # ==================== 主循环：收 UDP 包 ====================
    while not stop_event.is_set():
        r, _, _ = select.select([sock], [], [], 0.5)
        if not r:
            elapsed = time.time() - last_pong_time
            if confirmed and elapsed > PING_TIMEOUT:
                log(f"⚠️  {elapsed:.1f}s 无 pong，断开")
                break
            if not confirmed and elapsed > PING_TIMEOUT * 2:
                log(f"⚠️  {PING_TIMEOUT*2:.1f}s 未就绪，放弃")
                break
            continue

        data, addr = sock.recvfrom(4096)

        # 尝试解析 JSON
        is_json = False
        try:
            msg = json.loads(data.decode('utf-8'))
            is_json = True
        except Exception:
            msg = None

        if is_json:
            t = msg.get('type', '')
            s = msg.get('seq', -1)
            log(f"recv {msg}")

            if t == 'ping':
                # 发现 peer-reflexive：ping 来自新地址
                update_peer(addr)
                pong = json.dumps({'type': 'pong', 'seq': s, 'ts': msg.get('ts')})
                log(f"send {pong} -> {addr}")
                sock.sendto(pong.encode(), addr)

            elif t == 'pong':
                rtt = (time.time() - sent_pings.get(s, time.time())) * 1000
                last_pong_time = time.time()
                # pong 来自新地址 → 发现 peer-reflexive
                update_peer(addr)
                log(f"  pong #{s} RTT={rtt:.0f}ms  streak={pong_streak+1}  from {addr}")
                if s == seq - 1:
                    pong_streak += 1
                else:
                    pong_streak = 1
                if not confirmed and pong_streak >= READY_PONGS:
                    confirmed = True
                    log(f"✅ P2P 就绪！启动 tunnel")
                    tunnel_ready.set()
                    tunnel_thread = threading.Thread(target=tunnel_worker, daemon=True)
                    tunnel_thread.start()
        else:
            # 非 JSON：隧道数据
            hex16 = data[:16].hex()
            # 隧道数据来自新地址 → 发现 peer-reflexive
            update_peer(addr)
            log(f"recv {len(data)}B hex:{hex16} from {addr}")
            if tunnel_ready.is_set():
                with queue_not_empty:
                    data_queue.append((data, addr))
                    queue_not_empty.notify()
            else:
                log(f"  tunnel 未就绪，丢弃")

    stop_event.set()
    with queue_not_empty:
        queue_not_empty.notify()
    if tunnel_thread:
        tunnel_thread.join(timeout=2)
    sock.close()
    log(f"结束")


if __name__ == '__main__':
    main()
