#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet P2P UDP 隧道
用法: python3 udp.py <peer_ip> <peer_port> <local_port> [--appmode tun|tap|tun|auto]

架构:
  app_listener:   select([app]) → recv → handle_outgoing() → 网络发出
  udp_listener:   select([sock]) → recv → handle_incoming() → app.send() 直接写入
"""

import os
import sys
import json
import time
import socket
import argparse
import select
import threading
import signal

# ---- Inline ClientSocket（连接 switch Unix socket，自动加/剥 eth 头）----
FAKE_SRC_MAC = b'\x00\x00\x00\x00\x00\x00'
FAKE_BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'
ETH_TYPE_IP = b'\x08\x00'

def _make_eth_header():
    return FAKE_BROADCAST_MAC + FAKE_SRC_MAC + ETH_TYPE_IP


# ---- 全局变量 ----
_log_fp = None  # 日志文件句柄（main() 里赋值）
datasent = 0  # 发送的非心跳数据次数
datarecv = 0  # 收到的非心跳数据次数

class ClientSocket:
    def __init__(self, path):
        self._path = path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(path)
        self._recv_buf = b''

    def send(self, data):
        frame = _make_eth_header() + data
        self._sock.sendall(frame)

    def recv(self, bufsize=4096):
        while len(self._recv_buf) < 14:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b''
            self._recv_buf += chunk
        self._recv_buf = self._recv_buf[14:]
        while len(self._recv_buf) < 1500:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            self._recv_buf += chunk
        payload = self._recv_buf
        self._recv_buf = b''
        return payload

    def setsockopt(self, *args):
        self._sock.setsockopt(*args)

    def setblocking(self, flag):
        self._sock.setblocking(flag)

    def fileno(self):
        return self._sock.fileno()

    def close(self):
        self._sock.close()

    @property
    def path(self):
        return self._path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _auto_app(nettype, name=None):
    if nettype == 'fake':
        from app.fake import FakeTun
        return FakeTun()

    import platform
    sysname = platform.system()

    if nettype == 'tun' or nettype == 'auto':
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

    if nettype == 'tun':
        path = name
        if not path:
            raise RuntimeError("--socketpath 未设置（tun 模式由 client.py 启动）")
        print(f"[{ts()}][udptunnel]  tun 连接 {path}")
        return ClientSocket(path)

    if nettype == 'auto':
        from app.fake import FakeTun
        t = FakeTun()
        print(f"[{ts()}][udptunnel]  警告: Tun/Tap 均不可用，使用 FakeTun")
        return t

    raise ValueError(f"未知的 nettype: {nettype}")


def _log_prefix(func_name):
    return f"[{ts()}][udp.py {func_name}]"

def ts():
    return time.strftime("%H:%M:%S")


def log(func_name, *a, **kw):
    """模块级 log，main() 里会覆盖 _log_fp 来重定向日志"""
    msg = ' '.join(str(x) for x in a)
    ts_str = time.strftime("%H:%M:%S")
    line = f"[{ts_str}][udp.py {func_name}]  {msg}"
    if _log_fp:
        _log_fp.write(line + '\n')
        _log_fp.flush()
    else:
        print(line)


def handle_outgoing(data, args, sock, active_peer):
    """
    处理 app 发来的数据。
    TODO: 加密 → 混淆 → sock.sendto() 发出
    """
    global datasent
    ip, port = active_peer['ip'], active_peer['port']
    hex_str = ' '.join(f'{b:02x}' for b in data[:32])
    datasent += 1
    log("handle_outgoing", f"send data: len={len(data)}, hex={hex_str}")
    sock.sendto(data, (ip, port))


PING_INTERVAL = 1.0
PING_TIMEOUT = 5.0
READY_PONGS = 3


def main():
    global pong_streak, confirmed, last_pong_time, seq, sent_pings, sock, _log_fp, datasent, datarecv

    parser = argparse.ArgumentParser(description='p2pnet P2P UDP')
    parser.add_argument('--peeraddr', required=True, help='对方 IP（IPv4/IPv6/域名，自动识别）')
    parser.add_argument('--peerport', type=int, required=True, help='对方端口')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地监听地址（默认 0.0.0.0）')
    parser.add_argument('--localport', type=int, required=True, help='本地 UDP 端口')
    parser.add_argument('--appmode', default='fake',
                        help='appmode 模式（fake/tun/tap/tun/auto）')
    parser.add_argument('--socketpath', default=None,
                        help='tun 模式：Unix socket 路径（client.py 传入）')
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
    _log_file = args.remotelog

    _log_fp = None
    if _log_file:
        _log_fp = open(_log_file, 'a', encoding='utf-8')

    def log(func_name, *a, **kw):
        msg = ' '.join(str(x) for x in a)
        ts_str = time.strftime("%H:%M:%S")
        line = f"[{ts_str}][udp.py {func_name}]  {msg}"
        if _log_fp:
            _log_fp.write(line + '\n')
            _log_fp.flush()
        else:
            print(line)

    # UDP socket
    local_res = socket.getaddrinfo(local_addr, local_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    family, socktype, proto, _, sockaddr = local_res[0]
    sock = socket.socket(family, socktype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.settimeout(0.5)  # 设置超时以便优雅退出
    sock.bind(sockaddr)
    actual_port = sock.getsockname()[1]
    local_family = 'IPv6' if family == socket.AF_INET6 else 'IPv4'
    log("main", f"本端: {local_addr}:{actual_port} ({local_family})")
    log("main", f"目标: {peer_ip}:{peer_port}")
    log("main", f"appmode={nettype}  socketpath={args.socketpath or ''}")
    log("main", f"cipher={args.cipher}  obfs={args.obfs}  transport={args.transport}")
    log("main", f"key={args.key or ''}")
    log("main", f"remotelog={_log_file or ''}")

    # ========== 共享状态 ==========
    stop_event = threading.Event()
    pong_streak = 0
    confirmed = False
    last_pong_time = time.time()
    seq = 0
    sent_pings = {}
    sent_pings_order = []  # 有序记录发送顺序，用于清理旧条目
    pingsent = 0  # 发送的 ping 总数
    pongrecv = 0  # 收到的有效 pong 总数
    datasent = 0  # 发送的非心跳数据次数（模块级）
    datarecv = 0  # 收到的非心跳数据次数

    peer_lock = threading.Lock()
    active_peer = {'ip': peer_ip, 'port': peer_port}
    candidates = [{'ip': peer_ip, 'port': peer_port}]

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
            old_ip, old_port = active_peer['ip'], active_peer['port']
            active_peer['ip'] = ip
            active_peer['port'] = port
            log("update_peer", f"🆕 peer-reflexive {ip}:{port}（原 {old_ip}:{old_port} 加入候选）")

    def get_active():
        with peer_lock:
            return {'ip': active_peer['ip'], 'port': active_peer['port']}

    def get_candidates():
        with peer_lock:
            return list(candidates)

    # ========== handle_incoming: 处理收到的 UDP 包（嵌套函数，访问闭包变量）==========
    def handle_incoming(data, addr, args, app):
        global pong_streak, confirmed, last_pong_time, seq, sent_pings
        global datarecv
        nonlocal pingsent, pongrecv
        # 尝试解析 JSON 心跳
        try:
            msg = json.loads(data.decode('utf-8'))
            t = msg.get('type', '')
            s = msg.get('seq', -1)
            if t == 'ping':
                update_peer(addr)
                pong = json.dumps({'type': 'pong', 'seq': s, 'ts': msg.get('ts')})
                log("handle_incoming", f"recv beat: {pong}")
                log("handle_incoming", f"send beat: {pong}")
                sock.sendto(pong.encode(), addr)
                return
            elif t == 'pong':
                last_pong_time = time.time()
                update_peer(addr)

                # 有效 pong：是我们发出去的且还没收到过 pong 的
                if s in sent_pings:
                    rtt = (time.time() - sent_pings[s]) * 1000
                    pong_streak += 1
                    pongrecv += 1
                    del sent_pings[s]  # 标记已收到 pong
                else:
                    rtt = 0  # 已收到过或不在窗口内

                log("handle_incoming", f"recv beat: {data.decode('utf-8')}")
                log("handle_incoming", f"  RTT={rtt:.0f}ms streak={pong_streak} ping={pingsent} pong={pongrecv} datasent={datasent} datarecv={datarecv}")
                if not confirmed and pong_streak >= READY_PONGS:
                    confirmed = True
                    log("handle_incoming", f"✅ P2P 就绪！")
                return
        except (ValueError, UnicodeDecodeError):
            pass
        if not confirmed:
            log("handle_incoming", f"recv {len(data)}B（tunnel not ready，丢弃）")
            return
        hex_str = ' '.join(f'{b:02x}' for b in data[:32])
        datarecv += 1
        log("handle_incoming", f"recv data: len={len(data)}, hex={hex_str} from {addr}")
        app.send(data)

    # ========== 初始化 app ==========
    app = _auto_app(nettype, args.socketpath)
    log("main", f"app 启动（{app}）")

    # ========== app_listener: 监听 app，收到数据发出 ==========
    def app_listener():
        log("app_listener", "启动")
        while not stop_event.is_set():
            r, _, _ = select.select([app], [], [], 0.5)
            if not r:
                continue
            try:
                data = app.recv(4096)
            except BlockingIOError:
                continue
            if not data:
                continue
            handle_outgoing(data, args, sock, get_active())
        log("app_listener", "结束")

    # ========== udp_listener: 监听 UDP，收包处理 ==========
    def udp_listener():
        log("udp_listener", "启动")
        while not stop_event.is_set():
            r, _, _ = select.select([sock], [], [], 0.5)
            if not r:
                elapsed = time.time() - last_pong_time
                if confirmed and elapsed > PING_TIMEOUT:
                    log("udp_listener", f"⚠️  {elapsed:.1f}s 无 pong，断开")
                    break
                if not confirmed and elapsed > PING_TIMEOUT * 2:
                    log("udp_listener", f"⚠️  {PING_TIMEOUT*2:.1f}s 未就绪，放弃")
                    break
                continue

            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            handle_incoming(data, addr, args, app)

        stop_event.set()
        log("udp_listener", "结束")

    t_app = threading.Thread(target=app_listener, daemon=True, name='app_listener')
    t_udp = threading.Thread(target=udp_listener, daemon=True, name='udp_listener')
    t_app.start()
    t_udp.start()

    # ========== 信号处理：优雅退出 ==========
    def _signal_handler(signum, frame):
        log("main", f"收到信号 {signum}，准备退出...")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ========== main thread: 心跳发送 ==========
    log("main", f"主循环开始，等待 P2P 就绪...")
    while not stop_event.is_set():
        now = time.time()
        msg = json.dumps({'type': 'ping', 'seq': seq, 'ts': now})
        log("main", f"send beat: {msg}")
        for c in get_candidates():
            try:
                sock.sendto(msg.encode(), (c['ip'], c['port']))
            except Exception as e:
                log("main", f"发送失败 {c['ip']}:{c['port']}: {e}")
        sent_pings[seq] = now
        sent_pings_order.append(seq)
        pingsent += 1

        # 限制 sent_pings 大小，超时的直接删（计数器不动）
        while len(sent_pings_order) > 100:
            old_seq = sent_pings_order.pop(0)
            sent_pings.pop(old_seq, None)

        seq += 1
        time.sleep(PING_INTERVAL)

    # ========== 清理 ==========
    log("main", "开始清理...")
    stop_event.set()

    # 等待子线程结束（非 daemon 方式）
    for t in [t_app, t_udp]:
        t.join(timeout=2.0)

    app.close()
    sock.close()
    log("main", f"app 结束，进程退出")


if __name__ == '__main__':
    main()
