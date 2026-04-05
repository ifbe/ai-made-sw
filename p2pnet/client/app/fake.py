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
                packet = ts_bytes + pad_bytes
                hex_str = ' '.join(f'{b:02x}' for b in packet[:32])
                print(f"[{ts()}][fake.py send]  len={len(packet)} hex={hex_str}")
                try:
                    os.write(self._wfd, packet)
                except (OSError, IOError):
                    break
                time.sleep(3)
        self._thread = threading.Thread(target=_sender, daemon=True)
        self._thread.start()

    def fileno(self):
        """返回只读端的 fd，select 需要"""
        return self._rfd

    def on_write(self, data):
        """收到来自 udp.py 的数据（网络发来的）"""
        hex_str = ' '.join(f'{b:02x}' for b in data[:32])
        print(f"[{ts()}][fake.py recv]  len={len(data)} hex={hex_str}")
        return len(data)

    def on_read(self, size=4096):
        """返回 fake 主动发的数据，供 udp.py 拿走"""
        import errno
        try:
            d = os.read(self._rfd, size)
        except (OSError, IOError) as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise BlockingIOError(errno.EAGAIN, "no data")
            raise
        return d

    # 兼容旧调用
    send = on_write
    recv = on_read

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
