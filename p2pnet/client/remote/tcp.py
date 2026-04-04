#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remote/tcp.py - P2P TCP 隧道（直接打洞，无 relay）
用法: python3 tcp.py [--peeraddr IP] [--peerport PORT] [--localport PORT] \
    [--appmode tun|tap|tun|auto]

打洞原理：
  1. bind(local_port) + listen() — 让 NAT 记住这个端口的映射
  2. 同时 connect(peer_ip, peer_port) — 在 NAT 上产生外向映射
  3. select(A1=listen, A2=connect) 竞速：accept 或 connect 哪个先完成用哪个
  4. 直接 P2P 失败则退出（不 relay）

架构（隧道建立后）：
  app_listener:   select([app]) → recv → handle_outgoing() → tunnel 发出
  tcp_listener:   select([tunnel]) → recv → handle_incoming() → app.send() 直接写入
"""

import os
import sys
import time
import socket
import argparse
import select
import threading

# ---- Inline ClientSocket（连接 switch Unix socket，自动加/剥 eth 头）----
FAKE_SRC_MAC = b'\x00\x00\x00\x00\x00\x00'
FAKE_BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'
ETH_TYPE_IP = b'\x08\x00'

def _make_eth_header():
    return FAKE_BROADCAST_MAC + FAKE_SRC_MAC + ETH_TYPE_IP

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
        print(f"[{ts()}][tcp]  tun 连接 {path}")
        return ClientSocket(path)

    if nettype == 'auto':
        from app.fake import FakeTun
        t = FakeTun()
        print(f"[{ts()}][tcp]  警告: Tun/Tap 均不可用，使用 FakeTun")
        return t

    raise ValueError(f"未知的 nettype: {nettype}")


CONNECT_TIMEOUT = 8.0


def ts():
    return time.strftime("%H:%M:%S")


def log(*a, **kw):
    """模块级 log，main() 里会覆盖 _log_fp 来重定向日志"""
    msg = ' '.join(str(x) for x in a)
    ts_str = time.strftime("%H:%M:%S")
    print(f"[{ts_str}][tcp]  {msg}")


def handle_incoming(data, args, app):
    """
    处理从 tunnel 收到的数据。
    TODO: 解密 → 解混淆 → 解帧 → app.send() 写入 app
    """
    if not data:
        return
    hex_str = ' '.join(f'{b:02x}' for b in data[:32])
    log(f"recv {len(data)}B hex: {hex_str}")
    app.send(data)


def handle_outgoing(data, args, tunnel_sock):
    """
    处理 app 发来的数据。
    TODO: 加密 → 混淆 → 组帧 → tunnel 发出
    """
    hex_str = ' '.join(f'{b:02x}' for b in data[:32])
    log(f"app->tcp {len(data)}B hex: {hex_str}")
    tunnel_sock.sendall(data)


def main():
    parser = argparse.ArgumentParser(description='p2pnet P2P TCP 直接打洞')
    parser.add_argument('--peeraddr', help='对方公网 IP（IPv4/IPv6/域名，自动识别）')
    parser.add_argument('--peerport', type=int, help='对方公网端口')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地绑定地址（默认 0.0.0.0）')
    parser.add_argument('--localport', type=int, help='本地绑定端口（与 TCP 中继注册时相同）')
    parser.add_argument('--peername', default=None, help='对方用户名（仅用于日志）')
    parser.add_argument('--appmode', default='fake',
                        help='appmode 模式（fake/tun/tap/tun/auto）')
    parser.add_argument('--socketpath', default=None,
                        help='tun 模式：Unix socket 路径（client.py 传入）')
    parser.add_argument('--cipher', choices=['none', 'chacha20-poly1305'],
                        default='none', help='加密方式：none=不加密（默认），chacha20-poly1305=ChaCha20-Poly1305 AEAD')
    parser.add_argument('--transport', choices=['none', 'framed'],
                        default='none', help='分帧方式：none=心跳 JSON 文本行+原始数据（默认），framed=TLV 分帧（type=0 心跳明文 / type=1 数据密文）')
    parser.add_argument('--obfs', choices=['none', 'xor', 'tls'],
                        default='none', help='混淆方式：none=不混淆（默认），xor=XOR 流混淆，tls=TLS 指纹混淆（伪装 HTTPS ClientHello）')
    parser.add_argument('--key', default=None,
                        help='对称密钥（base64），与 --cipher 配合使用，client.py 登录后派生')
    parser.add_argument('--remotelog', default=None,
                        help='日志文件路径（默认 stdout）')
    args = parser.parse_args()

    peer_ip = args.peeraddr
    peer_port = args.peerport
    local_addr = args.localaddr
    local_port = args.localport
    _log_file = args.remotelog

    _log_fp = None
    if _log_file:
        _log_fp = open(_log_file, 'a', encoding='utf-8')

    def log(*a, **kw):
        msg = ' '.join(str(x) for x in a)
        ts_str = time.strftime("%H:%M:%S")
        line = f"[{ts_str}][tcp]  {msg}"
        if _log_fp:
            _log_fp.write(line + '\n')
            _log_fp.flush()
        else:
            print(line)

    log(f"本端: {local_addr}:{local_port}")
    log(f"目标: {peer_ip}:{peer_port}")
    log(f"appmode={args.appmode}  socketpath={args.socketpath or ''}")
    log(f"cipher={args.cipher}  obfs={args.obfs}  transport={args.transport}")
    log(f"key={args.key or ''}")
    log(f"remotelog={_log_file or ''}")

    # ==================== 打洞阶段：listen + connect 竞速 ====================
    listen_res = socket.getaddrinfo('::', local_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = listen_res[0]
    listen_sock = socket.socket(family, socktype, proto)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        listen_sock.bind(sockaddr)
    except OSError as e:
        log(f"bind({local_port}) 失败: {e}，尝试随机端口")
        listen_sock.bind(('::', 0))
    listen_sock.listen(5)
    listen_sock.settimeout(1.0)
    actual_port = listen_sock.getsockname()[1]
    local_family = 'IPv6' if family == socket.AF_INET6 else 'IPv4'
    log(f"listen {actual_port} ({local_family})，等待对端 SYN...")

    peer_res = socket.getaddrinfo(peer_ip, peer_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    peer_family, _, _, _, _ = peer_res[0]
    connect_sock = socket.socket(peer_family, socket.SOCK_STREAM)
    connect_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    connect_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    connect_sock.setblocking(False)

    connect_pending = True
    try:
        connect_sock.connect((peer_ip, peer_port))
    except BlockingIOError:
        log(f"connect -> {peer_ip}:{peer_port}，SYN 已发送（等待 NAT 映射）")
    except Exception as e:
        log(f"connect 异常: {e}，继续等待 accept")
        connect_pending = False

    tunnel_sock = None
    deadline = time.time() + CONNECT_TIMEOUT

    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        r, w, e = select.select([listen_sock, connect_sock], [connect_sock], [connect_sock], remaining)

        if connect_pending and (connect_sock in w or (not connect_pending and connect_sock in r)):
            try:
                connect_sock.setblocking(False)
                try:
                    connect_sock.connect((peer_ip, peer_port))
                except OSError:
                    pass
                tunnel_sock = connect_sock
                log(f"✅ connect 完成！用 connect socket 建立隧道")
                break
            except Exception as e:
                log(f"connect 最终确认失败: {e}")
                connect_pending = False

        if listen_sock in r:
            try:
                accepted, addr = listen_sock.accept()
                tunnel_sock = accepted
                log(f"✅ accept 成功！来自 {addr}，用 accept socket 建立隧道")
                break
            except socket.timeout:
                pass

    if tunnel_sock is not connect_sock:
        try:
            connect_sock.close()
        except:
            pass
    if tunnel_sock is not listen_sock:
        try:
            listen_sock.close()
        except:
            pass

    if tunnel_sock is None:
        log(f"⚠️  {CONNECT_TIMEOUT}s 内直接 P2P 未建立，退出（不 relay）")
        return

    tunnel_sock.setblocking(False)
    log(f"P2P TCP 隧道建立成功，开始 tunnel！")

    # ==================== 隧道建立后的多线程模式 ====================
    app = _auto_app(args.appmode, args.socketpath)
    log(f"app 启动（{app}）")

    stop_event = threading.Event()

    # app_listener: select([app]) → recv → handle_outgoing() → tunnel 发出
    def app_listener():
        log(f"app_listener 启动")
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
            handle_outgoing(data, args, tunnel_sock)
        log(f"app_listener 结束")

    # tcp_listener: select([tunnel]) → recv → handle_incoming() → app.send() 直接写入
    def tcp_listener():
        log(f"tcp_listener 启动")
        while not stop_event.is_set():
            r, _, _ = select.select([tunnel_sock], [], [], 0.5)
            if not r:
                continue
            try:
                data = tunnel_sock.recv(4096)
            except BlockingIOError:
                continue
            if not data:
                log(f"对端关闭连接，tunnel 结束")
                stop_event.set()
                break
            handle_incoming(data, args, app)
        stop_event.set()
        log(f"tcp_listener 结束")

    t_app = threading.Thread(target=app_listener, daemon=True, name='app_listener')
    t_tcp = threading.Thread(target=tcp_listener, daemon=True, name='tcp_listener')
    t_app.start()
    t_tcp.start()

    t_app.join()
    t_tcp.join()

    tunnel_sock.close()
    app.close()
    log(f"结束")


if __name__ == '__main__':
    main()
