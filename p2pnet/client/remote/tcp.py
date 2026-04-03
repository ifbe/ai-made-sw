#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remote/tcp.py - P2P TCP 隧道（直接打洞，无 relay）
用法: python3 tcp.py [--peeraddr IP] [--peerport PORT] [--localport PORT] \
    [--nettype tun|tap|clientsocket|auto]

打洞原理：
  1. bind(local_port) + listen() — 让 NAT 记住这个端口的映射
  2. 同时 connect(peer_ip, peer_port) — 在 NAT 上产生外向映射
  3. select(A1=listen, A2=connect) 竞速：accept 或 connect 哪个先完成用哪个
  4. 直接 P2P 失败则退出（不 relay）

Tunnel：tunnel socket <-> tun interface
"""

import os
import sys
import time
import socket
import argparse
import select
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _auto_tun(nettype, name=None):
    """根据 nettype 和平台自动选择 tun 实现。name 指定设备名（tun/tap）或 socket 路径（clientsocket）。"""
    if nettype == 'fake':
        from local.fake import FakeTun
        return FakeTun()

    import platform
    sysname = platform.system()

    if nettype == 'tun' or nettype == 'auto':
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
        print(f"[tcp]  clientsocket 连接 {path}")
        return ClientSocket(path)

    if nettype == 'auto':
        from local.fake import FakeTun
        print(f"[tcp]  警告: Tun/Tap 均不可用，使用 FakeTun")
        return FakeTun()

    raise ValueError(f"未知的 nettype: {nettype}")


CONNECT_TIMEOUT = 8.0
ACCEPT_TIMEOUT = 8.0


def ts():
    return time.strftime("%H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description='p2pnet P2P TCP 直接打洞')
    parser.add_argument('--peeraddr', help='对方公网 IP（IPv4/IPv6/域名，自动识别）')
    parser.add_argument('--peerport', type=int, help='对方公网端口')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地绑定地址（默认 0.0.0.0）')
    parser.add_argument('--localport', type=int, help='本地绑定端口（与 TCP 中继注册时相同）')
    parser.add_argument('--nettype', choices=['auto', 'tun', 'tap', 'fake', 'clientsocket'],
                        default='auto', help='网络接口类型（auto: tun→tap→fake）')
    parser.add_argument('--socketpath', default=None,
                        help='tun/tap 模式：指定设备名（如 utun3）；clientsocket 模式：Unix socket 路径（client.py 传入）')
    parser.add_argument('--cipher', choices=['none', 'chacha20-poly1305'],
                        default='none', help='加密方式：none=不加密（默认），chacha20-poly1305=ChaCha20-Poly1305 AEAD')
    parser.add_argument('--transport', choices=['none', 'framed'],
                        default='none', help='分帧方式：none=心跳 JSON 文本行+原始数据（默认），framed=TLV 分帧（type=0 心跳明文 / type=1 数据密文）')
    parser.add_argument('--obfs', choices=['none', 'xor', 'tls'],
                        default='none', help='混淆方式：none=不混淆（默认），xor=XOR 流混淆，tls=TLS 指纹混淆（伪装 HTTPS ClientHello）')
    parser.add_argument('--key', default=None,
                        help='对称密钥（base64），与 --cipher 配合使用，client.py 登录后派生')
    args = parser.parse_args()

    peer_ip = args.peeraddr
    peer_port = args.peerport
    local_addr = args.localaddr
    local_port = args.localport
    print(f"[{ts()}][tcp]  本端: {local_addr}:{local_port}")
    print(f"[{ts()}][tcp]  目标: {peer_ip}:{peer_port}")
    print(f"[{ts()}][tcp]  nettype={args.nettype}" + (f" socketpath={args.socketpath}" if args.socketpath else ""))

    tun = _auto_tun(args.nettype, args.socketpath)

    # ==================== listen socket：让 NAT 记住 7777 -> 外部端口 的映射 ====================
    # 自动判断 IPv4/IPv6（listen 端）
    listen_res = socket.getaddrinfo('::', local_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = listen_res[0]
    listen_sock = socket.socket(family, socktype, proto)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        listen_sock.bind(sockaddr)
    except OSError as e:
        print(f"[{ts()}][tcp]  bind({local_port}) 失败: {e}，尝试随机端口")
        listen_sock.bind(('::', 0))
    listen_sock.listen(5)
    listen_sock.settimeout(ACCEPT_TIMEOUT)
    actual_port = listen_sock.getsockname()[1]
    local_family = 'IPv6' if family == socket.AF_INET6 else 'IPv4'
    print(f"[{ts()}][tcp]  listen {actual_port} ({local_family})，等待对端 SYN...")

    # ==================== connect socket：发出 SYN 到对端 ====================
    # 自动判断 IPv4/IPv6（connect 端）
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
        # 非阻塞 connect 发出 SYN，等待完成
        print(f"[{ts()}][tcp]  connect -> {peer_ip}:{peer_port}，SYN 已发送（等待 NAT 映射）")
    except Exception as e:
        print(f"[{ts()}][tcp]  connect 异常: {e}，继续等待 accept")
        connect_pending = False

    # ==================== select 竞速：accept 或 connect 哪个先完成用哪个 ====================
    tunnel_sock = None
    use_accept = False
    deadline = time.time() + CONNECT_TIMEOUT

    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        r, w, e = select.select([listen_sock, connect_sock], [connect_sock], [connect_sock], remaining)

        # --- connect 完成 ---
        if connect_pending and (connect_sock in w or (not connect_pending and connect_sock in r)):
            try:
                # 再调一次 connect 让 socket 状态更新
                connect_sock.setblocking(False)
                try:
                    connect_sock.connect((peer_ip, peer_port))
                except OSError:
                    pass
                tunnel_sock = connect_sock
                use_accept = False
                print(f"[{ts()}][tcp]  ✅ connect 完成！用 connect socket 建立隧道")
                break
            except Exception as e:
                print(f"[{ts()}][tcp]  connect 最终确认失败: {e}")
                connect_pending = False

        # --- accept 到来（对方 SYN 穿过 NAT 到达）---
        if listen_sock in r:
            try:
                accepted, addr = listen_sock.accept()
                tunnel_sock = accepted
                use_accept = True
                print(f"[{ts()}][tcp]  ✅ accept 成功！来自 {addr}，用 accept socket 建立隧道")
                break
            except socket.timeout:
                pass

    # ==================== 清理没用上的 socket ====================
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
        print(f"[{ts()}][tcp]  ⚠️  {CONNECT_TIMEOUT}s 内直接 P2P 未建立，退出（不 relay）")
        tun.close()
        return

    tunnel_sock.setblocking(False)
    print(f"[{ts()}][tcp]  P2P TCP 隧道建立成功，开始 tunnel！")

    # ==================== Tunnel 循环：tunnel socket <-> tun ====================
    while True:
        r, _, _ = select.select([tunnel_sock, tun], [], [], 1.0)

        # tun -> tunnel socket
        if tun in r:
            try:
                data = tun.recv(4096)
                if data:
                    tunnel_sock.sendall(data)
                    print(f"[{ts()}][tcp]  tun->tcp {len(data)}B hex:{data[:16].hex()}")
            except BlockingIOError:
                pass

        # tunnel socket -> tun
        if tunnel_sock in r:
            try:
                data = tunnel_sock.recv(4096)
                if not data:
                    print(f"[{ts()}][tcp]  对端关闭连接，tunnel 结束")
                    break
                tun.send(data)
                print(f"[{ts()}][tcp]  tcp->tun {len(data)}B hex:{data[:16].hex()}")
            except BlockingIOError:
                pass
            except Exception as e:
                print(f"[{ts()}][tcp]  tunnel recv 错误: {e}")
                break

    tunnel_sock.close()
    tun.close()
    print(f"[{ts()}][tcp]  结束")


if __name__ == '__main__':
    main()
