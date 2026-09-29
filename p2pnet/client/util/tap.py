#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
local/tap.py - TAP 设备封装（Linux 专用）
macOS 不支持 TAP，导入时会立即报错。

用法：
  tap = Tap()          # auto，找下一个空闲 tap
  tap = Tap(name='tap0')  # 指定设备
  tap.send(data)       # 发 Ethernet 帧（bytes）
  data = tap.recv()    # 收 Ethernet 帧（bytes）
  tap.close()
"""

import os
import sys
import struct
import fcntl
import platform

if platform.system() != 'Linux':
    raise ImportError("TAP 仅支持 Linux（macOS 不支持 TAP）")

TUNDEV = '/dev/net/tun'
# struct ifreq: ifr_name[16] + ifr_flags[2]
TUNSETIFF = 0x400454ca
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000  # 不带 4 字节包头


class Tap:
    def __init__(self, name=None):
        self._fd = None
        self._name = None

        if not os.path.exists(TUNDEV):
            raise RuntimeError(f"{TUNDEV} 不存在（需要 tun 模块: sudo modprobe tun）")

        self._fd = os.open(TUNDEV, os.O_RDWR)

        if name:
            tun_name = name.encode() if isinstance(name, str) else name
        else:
            tun_name = b'tap%d'

        # 设 TAP 模式
        ifr = struct.pack('16sH', tun_name, IFF_TAP | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)

        self._name = ifr[:16].rstrip(b'\x00').decode()

        # 设非阻塞
        flags = fcntl.fcntl(self._fd, fcntl.F_GETFL)
        fcntl.fcntl(self._fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def send(self, data: bytes) -> int:
        """发 Ethernet 帧"""
        if self._fd is None:
            raise RuntimeError("TAP 已关闭")
        return os.write(self._fd, data)

    def recv(self, size=4096) -> bytes:
        """收 Ethernet 帧"""
        if self._fd is None:
            raise RuntimeError("TAP 已关闭")
        while True:
            try:
                d = os.read(self._fd, size)
                if d:
                    return d
            except OSError as e:
                if e.errno == 11:
                    import time; time.sleep(0.01)
                    continue
                raise

    def fileno(self) -> int:
        return self._fd

    @property
    def name(self) -> str:
        return self._name

    def close(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except:
                pass
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return f"<Tap {self._name} fd={self._fd}>"
