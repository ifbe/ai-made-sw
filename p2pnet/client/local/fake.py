#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
local/fake.py - 假 tun/tap 接口（用于测试）
send() 永远返回成功
recv() 永远抛出 BlockingIOError（不阻塞）
"""


class FakeTun:
    def send(self, data):
        """发送数据包，永远成功"""
        return len(data)

    def recv(self, size=4096):
        """接收数据包，非阻塞，没包就抛 BlockingIOError"""
        import errno
        raise BlockingIOError(errno.EAGAIN, "no data")

    def close(self):
        pass
