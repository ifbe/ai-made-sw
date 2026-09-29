#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p2pnet 打完洞之后的互发测试（udptest）

洞由 client.py 的 hole/udp.py 打好后转交过来。本程序**只做互发测试**：
  * bind 同一个本地 UDP 端口（NAT 映射才不废）
  * 每秒往对端**所有候选地址**发一个 ping
  * 收到 pong 算 RTT，连续 READY_PONGS 个 pong → 打印「✅ P2P 就绪！」
  * 一段时间收不到 pong → 认为断了，退出

**不挂任何本地设备/端点**：要挂 tun/tap 用 `app/vpn.py`，要转发端口用
`app/proxy.py`，要接虚拟交换机用 `app/switch.py`。每个程序自己解析参数、
自己实现"接管洞"那套（不共用公共模块）。

用法:
  python3 udptest.py --peeraddr <ip> --peerport <port> --localport <port>
                     [--peercandidates ip:port,ip:port] [--localaddr 0.0.0.0]
                     [--remotelog <文件>]
"""

import os
import sys
import json
import time
import socket
import signal
import select
import argparse
import threading

_TAG = os.path.basename(__file__)   # 'udptest.py'（日志标签，别写死）
_log_fp = None                      # 日志文件句柄（main() 里赋值）


def ts():
    return time.strftime("%H:%M:%S")


def log(func_name, *a):
    msg = ' '.join(str(x) for x in a)
    line = f"[{ts()}][{_TAG} {func_name}]  {msg}"
    if _log_fp:
        _log_fp.write(line + '\n')
        _log_fp.flush()
    else:
        print(line)


PING_INTERVAL = 1.0     # 每秒一个 ping
PING_TIMEOUT = 5.0      # 就绪后多久没 pong 算断开；未就绪时用它的 2 倍
READY_PONGS = 3         # 连续多少个 pong 算"就绪"


def parse_candidates(peer_ip, peer_port, raw):
    """候选地址表：第一个是 client.py 给的 peeraddr:peerport，后面是打洞学到的"""
    cands = [{'ip': peer_ip, 'port': peer_port}]
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        ip, _sep, port = item.rpartition(':')
        try:
            port = int(port)
        except ValueError:
            continue
        if not ip or not (0 < port < 65536):
            continue
        if not any(c['ip'] == ip and c['port'] == port for c in cands):
            cands.append({'ip': ip, 'port': port})
    return cands


def open_hole_socket(local_addr, local_port):
    """bind client.py 移交过来的那个本地端口（NAT 映射就指着它）"""
    res = socket.getaddrinfo(local_addr, local_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    family, socktype, proto, _, sockaddr = res[0]
    sock = socket.socket(family, socktype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.settimeout(0.5)
    sock.bind(sockaddr)
    return sock, family


def main():
    parser = argparse.ArgumentParser(description='p2pnet 打完洞之后的互发测试（udptest）')
    parser.add_argument('--peeraddr', required=True, help='对方 IP（IPv4/IPv6/域名）')
    parser.add_argument('--peerport', type=int, required=True, help='对方端口')
    parser.add_argument('--localport', type=int, required=True, help='本地 UDP 端口（沿用打洞时那个）')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地监听地址（默认 0.0.0.0）')
    parser.add_argument('--peercandidates', default=None,
                        help='额外对端候选 ip:port,ip:port（打洞阶段学到的 peer-reflexive）')
    parser.add_argument('--remotelog', default=None, help='日志文件路径（默认 stdout）')
    args = parser.parse_args()

    global _log_fp
    if args.remotelog:
        _log_fp = open(args.remotelog, 'a', encoding='utf-8')

    sock, family = open_hole_socket(args.localaddr, args.localport)
    actual_port = sock.getsockname()[1]
    log("main", f"本端: {args.localaddr}:{actual_port} ({'IPv6' if family == socket.AF_INET6 else 'IPv4'})")
    log("main", f"目标: {args.peeraddr}:{args.peerport}")

    peer_lock = threading.Lock()
    active_peer = {'ip': args.peeraddr, 'port': args.peerport}
    candidates = parse_candidates(args.peeraddr, args.peerport, args.peercandidates)
    if len(candidates) > 1:
        log("main", "对端候选: " + ', '.join(f"{c['ip']}:{c['port']}" for c in candidates))

    stop_event = threading.Event()
    pong_streak = 0
    confirmed = False
    last_pong_time = time.time()
    seq = 0
    sent_pings = {}          # seq -> 发送时刻
    sent_pings_order = []    # 发送顺序，用来清理旧条目
    pingsent = 0
    pongrecv = 0

    def update_peer(addr_tuple):
        ip, port = addr_tuple
        with peer_lock:
            if ip == active_peer['ip'] and port == active_peer['port']:
                return
            for c in candidates:
                if c['ip'] == ip and c['port'] == port:
                    active_peer['ip'] = ip
                    active_peer['port'] = port
                    log("update_peer", f"🔄 active_peer → {ip}:{port}")
                    return
            candidates.append({'ip': ip, 'port': port})
            old = f"{active_peer['ip']}:{active_peer['port']}"
            active_peer['ip'] = ip
            active_peer['port'] = port
            log("update_peer", f"🆕 peer-reflexive {ip}:{port}（原 {old} 加入候选）")

    def get_candidates():
        with peer_lock:
            return list(candidates)

    def handle_incoming(data, addr):
        nonlocal pong_streak, confirmed, last_pong_time, pongrecv
        # 只认 JSON 心跳；别的（比如别人发的数据）在"互发测试"里没有意义，丢掉
        try:
            msg = json.loads(data.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            log("handle_incoming", f"recv {len(data)}B（不是心跳，忽略）from {addr}")
            return
        t = msg.get('type', '')
        s = msg.get('seq', -1)
        if t == 'ping':
            update_peer(addr)
            pong = json.dumps({'type': 'pong', 'seq': s, 'ts': msg.get('ts')})
            log("handle_incoming", f"recv beat: {msg}")
            log("handle_incoming", f"send beat: {pong}")
            try:
                sock.sendto(pong.encode(), addr)
            except OSError as e:
                log("handle_incoming", f"回 pong 失败: {e}")
        elif t == 'pong':
            last_pong_time = time.time()
            update_peer(addr)
            if s in sent_pings:
                rtt = (time.time() - sent_pings[s]) * 1000
                pong_streak += 1
                pongrecv += 1
                del sent_pings[s]
            else:
                rtt = 0.0     # 已经收到过或不在窗口内
            log("handle_incoming", f"recv beat: {msg}")
            log("handle_incoming",
                f"  RTT={rtt:.0f}ms streak={pong_streak} ping={pingsent} pong={pongrecv}")
            if not confirmed and pong_streak >= READY_PONGS:
                confirmed = True
                log("handle_incoming", "✅ P2P 就绪！")

    def udp_listener():
        nonlocal confirmed
        log("udp_listener", "启动")
        while not stop_event.is_set():
            r, _, _ = select.select([sock], [], [], 0.5)
            if not r:
                elapsed = time.time() - last_pong_time
                if confirmed and elapsed > PING_TIMEOUT:
                    log("udp_listener", f"⚠️  {elapsed:.1f}s 没收到 pong，断开")
                    break
                if not confirmed and elapsed > PING_TIMEOUT * 2:
                    log("udp_listener", f"⚠️  {PING_TIMEOUT * 2:.1f}s 还没就绪，放弃")
                    break
                continue
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            handle_incoming(data, addr)
        stop_event.set()
        log("udp_listener", "结束")

    def _signal_handler(signum, frame):
        log("main", f"收到信号 {signum}，准备退出...")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    t_udp = threading.Thread(target=udp_listener, daemon=True, name='udp_listener')
    t_udp.start()

    # ========== 主线程：每秒往所有候选发 ping ==========
    log("main", "主循环开始，等待 P2P 就绪...")
    while not stop_event.is_set():
        now = time.time()
        msg = json.dumps({'type': 'ping', 'seq': seq, 'ts': now})
        log("main", f"send beat: {msg}")
        for c in get_candidates():
            try:
                sock.sendto(msg.encode(), (c['ip'], c['port']))
            except OSError as e:
                log("main", f"发送失败 {c['ip']}:{c['port']}: {e}")
        sent_pings[seq] = now
        sent_pings_order.append(seq)
        pingsent += 1
        while len(sent_pings_order) > 100:
            sent_pings.pop(sent_pings_order.pop(0), None)
        seq += 1
        time.sleep(PING_INTERVAL)

    log("main", "开始清理...")
    stop_event.set()
    t_udp.join(timeout=2.0)
    sock.close()
    if _log_fp:
        _log_fp.close()
    log("main", "进程退出")


if __name__ == '__main__':
    main()
