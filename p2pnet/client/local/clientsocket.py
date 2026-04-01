#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
local/clientsocket.py - 连接 client.py 提供的 Unix socket
用于 tunnel 子进程（udp.py / tcp.py）和 client.py 之间的 IPC。

接口（与 FakeTun / Tun / Tap 对称）：
  sock = ClientSocket('/tmp/p2pnet-alice-bob.sock')
  sock.send(data)    # 发 IP 包给 client.py
  data = sock.recv() # 从 client.py 收 IP 包
  sock.close()

使用 Unix domain SOCK_STREAM（类似 TCP）。
"""

import os
import socket


class ClientSocket:
    def __init__(self, path: str):
        self._path = path
        self._sock = None
        self._connect()

    def _connect(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self._path)

    def send(self, data: bytes) -> int:
        """发 IP 包给 client.py"""
        if self._sock is None:
            raise RuntimeError("socket 已关闭")
        return self._sock.send(data)

    def recv(self, size=4096) -> bytes:
        """从 client.py 收 IP 包（阻塞）"""
        if self._sock is None:
            raise RuntimeError("socket 已关闭")
        while True:
            d = self._sock.recv(size)
            if d:
                return d

    def fileno(self) -> int:
        """返回 fd，供 select 使用"""
        return self._sock.fileno()

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except:
                pass
            self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return f"<ClientSocket {self._path}>"
