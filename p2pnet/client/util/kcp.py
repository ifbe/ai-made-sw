#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet KCP 可靠传输封装

依赖：pip install pykcp（kcp C 库的 Python binding）
      或自行实现 ikcp_xxx 系列函数绑定到原始 KCP C 代码

接口：
  KCPChannel(sock, peer_ip, peer_port)
    .send(plaintext_bytes)    # 加密后（app 层）写入 KCP，KCP 加 seg header
    .recv() → bytes           # KCP 排序去重后交付（app 层再解密）
    .input(encrypted_bytes)    # 收到加密包后喂给 KCP
    .update(now_ms)           # 定时调用，触发重传/心跳

内部：
  每个 UDP 包 = KCP seg header（明文）+ encrypted payload
  KCP seg header 结构（ikcp.c）：
    4 bytes: conv（连接号）
    4 bytes: sn（序号）
    4 bytes: frg（分片序号）
    2 bytes: wnd（窗口）
    4 bytes: cmd（IKCP_CMD_PUSH / IKCP_CMD_ACK）
    4 bytes: ts（时间戳）
    4 bytes: sn（对方确认收到的最大序号）
    ...
    数据：encrypted payload

注意：KCP header 是明文，接收方可以读 seq 做排序。
      加密 payload 不影响 KCP 操作，KCP 把密文当 opaque bytes 处理。
"""

import os
import sys
import time
import asyncio
import errno

# ---- KCP C 库绑定（需要 pip install pykcp 或自行绑定） ----

try:
    import pykcp as ikcp
    HAS_IKCP = True
except ImportError:
    HAS_IKCP = False
    ikcp = None

# KCP 命令
IKCP_CMD_PUSH = 81   # 数据
IKCP_CMD_ACK  = 82   # ACK
IKCP_CMD_WASK = 83   # 窗口探询
IKCP_CMD_WINS  = 84   # 窗口大小


class KCPChannel:
    """
    异步 KCP 通道，挂在已有 UDP socket 上。

    参数：
      sock：已绑定的 UDP socket
      conv：连接号（4字节），双方需一致
      peer_ip / peer_port：对方地址（用于 sendto）
    """

    def __init__(self, sock, conv: int, peer_ip: str, peer_port: int):
        self.sock = sock
        self.conv = conv
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.ikcp = None

        if HAS_IKCP:
            self.ikcp = ikcp.ikcp_create(conv, id(peer_ip))  # peer context placeholder
            ikcp.ikcp_setoutput(self.ikcp, self._kcp_output)
            # 参数调优
            ikcp.ikcp_nodelay(self.ikcp, 1, 10, 1, 1)  # nodelay, interval, resend, nc
            ikcp.ikcp_wndsize(self.ikcp, 1024, 1024)
        else:
            raise RuntimeError("pykcp 未安装，请运行：pip install pykcp")

    def _kcp_output(self, data, size, user):
        """KCP 调用此函数输出段（发送）"""
        self.sock.sendto(data, (self.peer_ip, self.peer_port))

    def send(self, plaintext: bytes):
        """发送明文（KCP 内部会加 seg header，分片等）"""
        if not HAS_IKCP:
            raise RuntimeError("pykcp 未安装")
        ikcp.ikcp_send(self.ikcp, plaintext)

    def input(self, encrypted_segment: bytes):
        """收到 UDP 包后调用，把数据喂给 KCP"""
        if not HAS_IKCP:
            raise RuntimeError("pykcp 未安装")
        ikcp.ikcp_input(self.ikcp, encrypted_segment)

    def recv(self) -> bytes:
        """接收一个完整分段（已排序去重），返回明文"""
        if not HAS_IKCP:
            raise RuntimeError("pykcp 未安装")
        # peek size
        size = ikcp.ikcp_peeksize(self.ikcp)
        if size < 0:
            return None
        buf = bytearray(size)
        n = ikcp.ikcp_recv(self.ikcp, buf, size)
        if n > 0:
            return bytes(buf[:n])
        return None

    def update(self, now_ms: int = None):
        """定时调用，驱动 KCP 内部定时器（重传、ACK 等）"""
        if not HAS_IKCP:
            raise RuntimeError("pykcp 未安装")
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        ikcp.ikcp_update(self.ikcp, now_ms)

    def check(self, now_ms: int = None) -> int:
        """返回下次需要调用 update 的时间（ms）"""
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        if not HAS_IKCP:
            return 1000
        return ikcp.ikcp_check(self.ikcp, now_ms)


# ---- 简化异步版本（不依赖 pykcp，纯 Python 模拟） ----

class KCPChannelSim:
    """
    纯 Python 模拟的 KCP 接口（测试用）。
    不实现真正的 KCP 可靠性，只做分片/重组。
    正式使用请安装 pykcp。
    """

    def __init__(self, sock, conv, peer_ip, peer_port):
        self.sock = sock
        self.conv = conv
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.send_seq = 0
        self.recv_buf = {}

    def send(self, plaintext: bytes, mtu=1400):
        """把 plaintext 按 MTU 分片发送，每片 = seq[4] + frg[1] + data"""
        fragments = [plaintext[i:i+mtu] for i in range(0, len(plaintext), mtu)]
        total = len(fragments)
        for i, frag in enumerate(fragments):
            seg = struct.pack('<IBB', self.send_seq, i, total) + frag
            self.sock.sendto(seg, (self.peer_ip, self.peer_port))
        self.send_seq += 1

    def input(self, segment: bytes):
        """收到 UDP 段存入 recv_buf，按 seq 重组"""
        if len(segment) < 6:
            return
        seq, frg, total = struct.unpack('<IBB', segment[:6])
        data = segment[6:]
        if seq not in self.recv_buf:
            self.recv_buf[seq] = {}
        self.recv_buf[seq][frg] = data

    def recv(self) -> bytes:
        """返回最早一个完整的包（所有分片都收到）"""
        for seq in sorted(self.recv_buf):
            parts = self.recv_buf[seq]
            if len(parts) == max(p.keys()) + 1:
                result = b''.join(parts[i] for i in sorted(parts))
                del self.recv_buf[seq]
                return result
        return None

    def update(self, now_ms=None):
        pass  # 模拟版本不需要定时器


# ---- 工厂函数 ----

def create_kcp_channel(sock, conv, peer_ip, peer_port, simulate=False):
    if simulate or not HAS_IKCP:
        return KCPChannelSim(sock, conv, peer_ip, peer_port)
    return KCPChannel(sock, conv, peer_ip, peer_port)
