#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
local/tun.py - TUN 设备封装（Linux / macOS）
支持：
  - Linux: /dev/net/tun + ioctl
  - macOS: /dev/utunN（需一次性 ifconfig create 创建）

用法：
  tun = Tun()          # auto，找下一个空闲 utun（N）/dev/net/tun
  tun = Tun(name='utun3')  # 指定设备
  tun.send(data)       # 发 IP 包（bytes）
  data = tun.recv()    # 收 IP 包（bytes）
  tun.close()
"""

import os
import sys
import socket
import struct
import fcntl
import subprocess
import platform

# Linux TUN ioctl 常量
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000   # 不带包信息（Linux 上 tun 默认带 4 字节头，macOS 不带）


def _tun_set_pi(sock_fd, enabled):
    """Linux：设置 TUN 是否带 PI（包信息）"""
    from fcntl import ioctl
    import array
    # IFF_NO_PI 标志控制是否带 4 字节头
    pass  # IFF_NO_PI 在打开时通过 flags 设置，之后不可改；这里通过重新创建设置


class Tun:
    _sysname = platform.system()

    def __init__(self, name=None):
        self._fd = None
        self._name = None
        self._created_name = None  # 如果我们创建了设备，记录下来

        if self._sysname == 'Linux':
            self._init_linux(name)
        elif self._sysname == 'Darwin':
            self._init_macos(name)
        else:
            raise NotImplementedError(f"TUN 不支持 {self._sysname}")

    # ── Linux ────────────────────────────────────────────────────────────────

    def _init_linux(self, name=None):
        """Linux: open /dev/net/tun，设 IFF_TUN | IFF_NO_PI"""
        TUNDEV = '/dev/net/tun'
        if not os.path.exists(TUNDEV):
            raise RuntimeError(f"{TUNDEV} 不存在（需要 tun 模块: sudo modprobe tun）")

        self._fd = os.open(TUNDEV, os.O_RDWR)

        if name:
            # 指定名称
            tun_name = name.encode() if isinstance(name, str) else name
        else:
            tun_name = b'tun%d'  # 内核分配

        # struct ifreq: ifr_name[16] + ifr_flags[2]
        ifr = struct.pack('16sH', tun_name, IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)

        # 读取实际设备名（内核可能改了）
        tun_name_out = ifr[:16].rstrip(b'\x00').decode()
        self._name = tun_name_out

        # 设非阻塞
        flags = fcntl.fcntl(self._fd, fcntl.F_GETFL)
        fcntl.fcntl(self._fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    # ── macOS ───────────────────────────────────────────────────────────────

    def _init_macos(self, name=None):
        """macOS: 打开 /dev/utunN，不存在则用 ifconfig create 创建"""
        if name:
            candidates = [name]
        else:
            # 找下一个空闲 utun
            for i in range(10):
                candidates.append(f'utun{i}')
            candidates.extend([f'utun{i}' for i in range(10, 20)])

        last_err = None
        for dev_name in candidates:
            dev_path = f'/dev/{dev_name}'
            try:
                self._fd = os.open(dev_path, os.O_RDWR)
                self._name = dev_name
                # 设非阻塞
                flags = fcntl.fcntl(self._fd, fcntl.F_GETFL)
                fcntl.fcntl(self._fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                return
            except (OSError, IOError) as e:
                last_err = e
                continue

        # 都不存在，尝试创建（需要 root；创建后其他人可打开）
        if name:
            try:
                subprocess.run(
                    ['sudo', 'ifconfig', name, 'create'],
                    check=True,
                    capture_output=True,
                )
                self._fd = os.open(f'/dev/{name}', os.O_RDWR)
                self._name = name
                flags = fcntl.fcntl(self._fd, fcntl.F_GETFL)
                fcntl.fcntl(self._fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                return
            except subprocess.CalledProcessError:
                pass

        raise RuntimeError(f"无法打开或创建 TUN 设备: {last_err}")

    # ── 通用接口 ─────────────────────────────────────────────────────────────

    def send(self, data: bytes) -> int:
        """发 IP 包"""
        if self._fd is None:
            raise RuntimeError("TUN 已关闭")
        return os.write(self._fd, data)

    def recv(self, size=4096) -> bytes:
        """收 IP 包（阻塞直到有数据）"""
        if self._fd is None:
            raise RuntimeError("TUN 已关闭")
        # macOS 上 read 可以直接读
        while True:
            try:
                d = os.read(self._fd, size)
                if d:
                    return d
            except OSError as e:
                if e.errno == 11:  # EAGAIN
                    import time; time.sleep(0.01)
                    continue
                raise

    def fileno(self) -> int:
        """返回 fd，供 select 使用"""
        return self._fd

    @property
    def name(self) -> str:
        """设备名，如 'tun0'、'utun3'"""
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
        return f"<Tun {self._name} fd={self._fd}>"
