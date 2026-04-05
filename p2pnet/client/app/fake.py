#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app/fake.py - 假 tun/tap 接口（用于测试 / fake 模式）
send() 永远返回成功
recv() 非阻塞，没包抛 BlockingIOError
后台线程每 3 秒发一个 32bit 时间戳
"""

import os
import time
import errno
import struct
import random
import threading


def _log_prefix(func_name):
    return f"[{ts()}][fake.py {func_name}]"

def ts():
    return time.strftime("%H:%M:%S")


class FakeTun:
    def __init__(self):
        import os
        self._rfd, self._wfd = os.pipe()
        self._closed = False
        self._lock = threading.Lock()
        print(f"[{ts()}][fake.py __init__]  启动 (pipe r={self._rfd} w={self._wfd})")

        # 后台线程：每 3 秒发一个 32bit 时间戳到 pipe
        def _sender():
            while not self._closed:
                ts_bytes = struct.pack('>I', int(time.time()))  # big-endian 32bit timestamp
                pad_bytes = os.urandom(random.randint(0, 12))  # 随机 0~12 字节填充
                try:
                    os.write(self._wfd, ts_bytes + pad_bytes)
                except (OSError, IOError):
                    break
                time.sleep(3)
        self._thread = threading.Thread(target=_sender, daemon=True)
        self._thread.start()

    def fileno(self):
        """返回只读端的 fd，select 需要"""
        return self._rfd

    def send(self, data):
        """发送数据包，永远成功（直接丢弃，不写 pipe）"""
        hex_str = ' '.join(f'{b:02x}' for b in data[:32])
        print(f"[{ts()}][fake.py send]  len={len(data)} hex={hex_str}")
        return len(data)

    def recv(self, size=4096):
        """接收数据包，非阻塞，没包抛 BlockingIOError"""
        import errno
        try:
            d = os.read(self._rfd, size)
        except (OSError, IOError) as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise BlockingIOError(errno.EAGAIN, "no data")
            raise
        if d:
            hex_str = ' '.join(f'{b:02x}' for b in d[:32])
            print(f"[{ts()}][fake.py recv]  len={len(d)} hex={hex_str}")
        return d

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            os.close(self._rfd)
            os.close(self._wfd)
        except OSError:
            pass
        print(f"[{ts()}][fake.py close]  销毁")
