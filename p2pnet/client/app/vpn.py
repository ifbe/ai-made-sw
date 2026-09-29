#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p2pnet 单人单 tun 的 VPN（一个洞 ↔ 一个 tun/tap 设备）

和 `app/switch.py` 的分工：
  * `vpn.py`   ：**单人单 tun**。一个洞 ↔ 一个 tun/tap 设备，对端就是一个固定 peer，
                 适合"两台机器之间拉一条三层/二层隧道"。
  * `switch.py`：**多人多洞**。一堆对端（都在 192.168.x.0/24 这种网段里）把洞交给
                 同一个 switch 进程，由它做 L2/L3 转发（mesh）。

洞由 client.py 的 hole/udp.py 打好后转交过来。本程序自己：
  * bind 同一个本地 UDP 端口（NAT 映射才不废）
  * 往对端**所有候选地址**发包；收到包就学源地址（peer-reflexive）
  * 洞 → 设备 / 设备 → 洞 双向透传
  * 保活：每 KEEPALIVE_INTERVAL 秒发一个**空数据报**（收方忽略），空闲时 NAT 映射不过期

用法:
  python3 vpn.py --peeraddr <ip> --peerport <port> --localport <port>
                 --dev tun|tap|auto [--devname <设备名>]
                 [--peercandidates ip:port,ip:port] [--localaddr 0.0.0.0]
                 [--remotelog <文件>]
"""

import os
import sys
import time
import socket
import signal
import select
import platform
import argparse
import threading

_TAG = os.path.basename(__file__)   # 'vpn.py'
_log_fp = None

# 让 `util.tun` / `util.tap` 能被 import（本文件在 client/app/ 下，包在 client/ 下）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

KEEPALIVE_INTERVAL = 20.0   # 空闲时每 20s 发一个空数据报，保 NAT 映射
SOCK_TIMEOUT = 0.5


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


def parse_candidates(peer_ip, peer_port, raw):
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
    res = socket.getaddrinfo(local_addr, local_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    family, socktype, proto, _, sockaddr = res[0]
    sock = socket.socket(family, socktype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.settimeout(SOCK_TIMEOUT)
    sock.bind(sockaddr)
    return sock, family


def open_device(dev, devname):
    """挂一个 tun 或 tap（auto = 先试 tun 再试 tap）"""
    sysname = platform.system()

    def _tun():
        if sysname == 'Windows':
            from util.tun_windows import TunWintun
            return TunWintun()
        from util.tun import Tun
        return Tun(name=devname)

    def _tap():
        if sysname == 'Windows':
            from util.tap_windows import TapWindows
            return TapWindows()
        from util.tap import Tap
        return Tap(name=devname)

    if dev == 'tun':
        return _tun()
    if dev == 'tap':
        return _tap()
    if dev == 'auto':
        try:
            return _tun()
        except Exception as e:
            log("open_device", f"tun 不可用（{e}），改试 tap")
        return _tap()
    raise RuntimeError(f"未知的 --dev: {dev}（可用 tun / tap / auto）")


def main():
    parser = argparse.ArgumentParser(description='p2pnet 单人单 tun 的 VPN（一个洞 ↔ 一个设备）')
    parser.add_argument('--peeraddr', required=True, help='对方 IP（IPv4/IPv6/域名）')
    parser.add_argument('--peerport', type=int, required=True, help='对方端口')
    parser.add_argument('--localport', type=int, required=True, help='本地 UDP 端口（沿用打洞时那个）')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地监听地址（默认 0.0.0.0）')
    parser.add_argument('--dev', default='tun', help='挂什么设备：tun / tap / auto')
    parser.add_argument('--devname', default=None, help='设备名（如 tun0 / utun3 / fd=21 这种）')
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

    try:
        dev = open_device(args.dev, args.devname)
    except Exception as e:
        log("main", f"❌ 挂设备失败（--dev {args.dev}）：{e}")
        sock.close()
        return 1
    log("main", f"设备已就绪（{dev}），保活间隔 {KEEPALIVE_INTERVAL:.0f}s")

    peer_lock = threading.Lock()
    active_peer = {'ip': args.peeraddr, 'port': args.peerport}
    candidates = parse_candidates(args.peeraddr, args.peerport, args.peercandidates)
    if len(candidates) > 1:
        log("main", "对端候选: " + ', '.join(f"{c['ip']}:{c['port']}" for c in candidates))

    stop_event = threading.Event()
    stats = {'to_net': 0, 'to_dev': 0}

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

    def to_peer(data):
        """往所有候选各发一份"""
        for c in get_candidates():
            try:
                sock.sendto(data, (c['ip'], c['port']))
            except OSError as e:
                log("to_peer", f"发送失败 {c['ip']}:{c['port']}: {e}")

    # ---------- 洞 → 设备 ----------
    def hole_listener():
        while not stop_event.is_set():
            r, _, _ = select.select([sock], [], [], SOCK_TIMEOUT)
            if not r:
                continue
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if stop_event.is_set():
                    break
                log("hole_listener", f"recvfrom 出错: {e}")
                continue
            if not data:
                continue                     # 空数据报 = 保活，忽略
            update_peer(addr)
            try:
                dev.send(data)
                stats['to_dev'] += 1
                if stats['to_dev'] <= 5 or stats['to_dev'] % 100 == 0:
                    log("hole_listener", f"洞 → 设备 {len(data)}B（第 {stats['to_dev']} 个）")
            except OSError as e:
                log("hole_listener", f"写设备失败: {e}")
        log("hole_listener", "结束")

    # ---------- 设备 → 洞 ----------
    def dev_listener():
        while not stop_event.is_set():
            r, _, _ = select.select([dev], [], [], SOCK_TIMEOUT)
            if not r:
                continue
            try:
                data = dev.recv(65535)
            except BlockingIOError:
                continue
            except OSError as e:
                if stop_event.is_set():
                    break
                log("dev_listener", f"读设备出错: {e}")
                continue
            if not data:
                continue
            to_peer(data)
            stats['to_net'] += 1
            if stats['to_net'] <= 5 or stats['to_net'] % 100 == 0:
                log("dev_listener", f"设备 → 洞 {len(data)}B（第 {stats['to_net']} 个）")
        log("dev_listener", "结束")

    # ---------- 保活：空闲也把 NAT 映射顶住 ----------
    def keepalive():
        while not stop_event.is_set():
            if stop_event.wait(KEEPALIVE_INTERVAL):
                break
            to_peer(b'')
            log("keepalive", "发空数据报保活")
        log("keepalive", "结束")

    def _signal_handler(signum, frame):
        log("main", f"收到信号 {signum}，准备退出...")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    threads = [
        threading.Thread(target=hole_listener, daemon=True, name='hole_listener'),
        threading.Thread(target=dev_listener, daemon=True, name='dev_listener'),
        threading.Thread(target=keepalive, daemon=True, name='keepalive'),
    ]
    for t in threads:
        t.start()
    log("main", "主循环开始（洞 ↔ 设备 双向透传）...")

    for t in threads:
        t.join()
    stop_event.set()

    log("main", f"统计: 洞→设备 {stats['to_dev']} 个，设备→洞 {stats['to_net']} 个")
    try:
        dev.close()
    except Exception:
        pass
    sock.close()
    if _log_fp:
        _log_fp.close()
    log("main", "进程退出")
    return 0


if __name__ == '__main__':
    sys.exit(main())
