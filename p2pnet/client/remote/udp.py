#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet P2P UDP 隧道
用法: python3 udp.py <peer_ip> <peer_port> <local_port> [--nettype tun|tap|clientsocket|auto]

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
        from local.fake import FakeTun
        return FakeTun()

    import platform
    sysname = platform.system()

    if nettype == 'tun' or nettype == 'auto':
        # 试 Tun
        try:
            if sysname == 'Windows':
                from local.tun_windows import TunWintun
                return TunWintun()
            else:
                from local.tun import Tun
                return Tun(name=name)
        except Exception as e:
            if nettype == 'tun':
                raise RuntimeError(f"TUN 不可用: {e}")

    if nettype == 'tap' or nettype == 'auto':
        # 试 Tap
        try:
            if sysname == 'Windows':
                from local.tap_windows import TapWindows
                return TapWindows()
            else:
                from local.tap import Tap
                return Tap(name=name)
        except Exception as e:
            if nettype == 'tap':
                raise RuntimeError(f"TAP 不可用: {e}")

    if nettype == 'clientsocket':
        path = name
        if not path:
            raise RuntimeError("--socketpath 未设置（clientsocket 模式由 client.py 启动）")
        from local.clientsocket import ClientSocket
        print(f"[{ts()}][udptunnel]  clientsocket 连接 {path}")
        return ClientSocket(path)

    if nettype == 'auto':
        # 最后 fallback fake
        from local.fake import FakeTun
        t = FakeTun()
        print(f"[{ts()}][udptunnel]  警告: Tun/Tap 均不可用，使用 FakeTun")
        return t

    raise ValueError(f"未知的 nettype: {nettype}")


PING_INTERVAL = 1.0
PING_TIMEOUT = 5.0
READY_PONGS = 3


def ts():
    return time.strftime("%H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description='p2pnet P2P UDP')
    parser.add_argument('--peeraddr', required=True, help='对方 IP')
    parser.add_argument('--peerport', type=int, required=True, help='对方端口')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地监听地址（默认 0.0.0.0）')
    parser.add_argument('--localport', type=int, required=True, help='本地 UDP 端口')
    parser.add_argument('--nettype', choices=['auto', 'tun', 'tap', 'fake', 'clientsocket'],
                        default='auto', help='网络接口类型（auto: tun→tap→fake）')
    parser.add_argument('--socketpath', default=None,
                        help='tun/tap 模式：指定设备名（如 utun3）；clientsocket 模式：Unix socket 路径（client.py 传入）')
    args = parser.parse_args()

    peer_ip = args.peeraddr
    peer_port = args.peerport
    local_addr = args.localaddr
    local_port = args.localport
    nettype = args.nettype or 'auto'
    sock_path = args.socketpath or ''

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind((local_addr, local_port))
    sock.setblocking(False)
    actual_port = sock.getsockname()[1]
    print(f"[{ts()}][udptunnel]  本端: {local_addr}:{actual_port}")
    print(f"[{ts()}][udptunnel]  目标: {peer_ip}:{peer_port}")
    print(f"[{ts()}][udptunnel]  nettype={nettype}" + (f" socketpath={sock_path}" if sock_path else ""))

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

    # ==================== 发送线程：每秒发一个 ping ====================
    def heartbeat_sender():
        nonlocal seq
        while not stop_event.is_set():
            now = time.time()
            msg = json.dumps({'type': 'ping', 'seq': seq, 'ts': now})
            print(f"[{ts()}][udptunnel]  send {msg}")
            try:
                sock.sendto(msg.encode(), (peer_ip, peer_port))
                sent_pings[seq] = now
                seq += 1
            except Exception as e:
                print(f"[{ts()}][udptunnel]  发送失败: {e}")
            time.sleep(PING_INTERVAL)

    # ==================== 隧道线程 ====================
    def tunnel_worker():
        tun = _auto_tun(args.nettype, args.socketpath)
        print(f"[{ts()}][udptunnel]  tunnel 启动（{tun}）")
        while not stop_event.is_set():
            # 从 tun 读 -> 发 UDP
            try:
                data = tun.recv(4096)
                if data:
                    sock.sendto(data, (peer_ip, peer_port))
                    print(f"[{ts()}][udptunnel]  UDP-> {len(data)}B hex:{data[:16].hex()}")
            except BlockingIOError:
                pass

            # 从队列取数据 -> 写 tun（非 ping/pong 的隧道数据）
            with queue_not_empty:
                while not data_queue and not stop_event.is_set():
                    queue_not_empty.wait(timeout=0.5)
                if stop_event.is_set():
                    break
                if data_queue:
                    data = data_queue.pop(0)
            tun.send(data)
            print(f"[{ts()}][udptunnel]  tun<- {len(data)}B hex:{data[:16].hex()}")

        tun.close()
        print(f"[{ts()}][udptunnel]  tunnel 结束")

    # ==================== 心跳发送线程启动 ====================
    print(f"[{ts()}][udptunnel]  主循环开始，等待 P2P 就绪...")
    t_sender = threading.Thread(target=heartbeat_sender, daemon=True)
    t_sender.start()

    # ==================== 主循环：收 UDP 包 ====================
    while not stop_event.is_set():
        r, _, _ = select.select([sock], [], [], 0.5)
        if not r:
            elapsed = time.time() - last_pong_time
            if confirmed and elapsed > PING_TIMEOUT:
                print(f"[{ts()}][udptunnel]  ⚠️  {elapsed:.1f}s 无 pong，断开")
                break
            if not confirmed and elapsed > PING_TIMEOUT * 2:
                print(f"[{ts()}][udptunnel]  ⚠️  {PING_TIMEOUT*2:.1f}s 未就绪，放弃")
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
            print(f"[{ts()}][udptunnel]  recv {msg}")

            if t == 'ping':
                pong = json.dumps({'type': 'pong', 'seq': s, 'ts': msg.get('ts')})
                print(f"[{ts()}][udptunnel]  send {pong}")
                sock.sendto(pong.encode(), addr)

            elif t == 'pong':
                rtt = (time.time() - sent_pings.get(s, time.time())) * 1000
                last_pong_time = time.time()
                print(f"[{ts()}][udptunnel]    pong #{s} RTT={rtt:.0f}ms  streak={pong_streak+1}")
                if s == seq - 1:
                    pong_streak += 1
                else:
                    pong_streak = 1
                if not confirmed and pong_streak >= READY_PONGS:
                    confirmed = True
                    print(f"[{ts()}][udptunnel]  ✅ P2P 就绪！启动 tunnel")
                    tunnel_ready.set()
                    tunnel_thread = threading.Thread(target=tunnel_worker, daemon=True)
                    tunnel_thread.start()
        else:
            # 非 JSON：隧道数据
            hex16 = data[:16].hex()
            print(f"[{ts()}][udptunnel]  recv {len(data)}B hex:{hex16}")
            if tunnel_ready.is_set():
                with queue_not_empty:
                    data_queue.append(data)
                    queue_not_empty.notify()
            else:
                print(f"[{ts()}][udptunnel]    tunnel 未就绪，丢弃")

    stop_event.set()
    with queue_not_empty:
        queue_not_empty.notify()
    if tunnel_thread:
        tunnel_thread.join(timeout=2)
    sock.close()
    print(f"[{ts()}][udptunnel]  结束")


if __name__ == '__main__':
    main()
