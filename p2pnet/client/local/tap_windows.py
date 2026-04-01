#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
local/tap_windows.py - TAP 设备封装（Windows 专用）

tap-windows 是 OpenVPN 的 TAP 驱动，封装 Ethernet 帧。
与 Linux TAP 不同，Windows 上走文件句柄 ReadFile/WriteFile。

设备路径: \\.\TAP-<adapter_name> 或 \\.\tap0802

用法：
  tap = TapWindows()          # auto，找第一个 TAP 适配器
  tap = TapWindows(name='TAP001')  # 指定适配器名
  tap.send(ethernet_frame)     # 发 Ethernet 帧（bytes）
  data = tap.recv()            # 收 Ethernet 帧（bytes）
  tap.close()
"""

import ctypes
import ctypes.wintypes as wt
import os
import time
import platform
import subprocess
import uuid

if platform.system() != 'Windows':
    raise ImportError("tap_windows 仅支持 Windows")

# ==================== Windows API ====================

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
                         wt.DWORD, wt.DWORD, wt.HANDLE]
CreateFileW.restype = wt.HANDLE

ReadFile = kernel32.ReadFile
ReadFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD,
                      ctypes.POINTER(wt.DWORD), wt.LPVOID]
ReadFile.restype = wt.BOOL

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD,
                      ctypes.POINTER(wt.DWORD), wt.LPVOID]
WriteFile.restype = wt.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

# TAP-Windows ioctl
TAP_IOCTL_GET_MAC = 1         # 用 DeviceIoControl 获取 MAC 地址
TAP_IOCTL_GET_VERSION = 2
TAP_IOCTL_GET_MTU = 3
TAP_IOCTL_GET_INFO = 4
TAP_IOCTL_SET_MEDIA_STATUS = 5

# TAP control codes ( CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS) )
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

def _ctl_code(dev, func, meth, access):
    return (dev << 16) | (access << 14) | (func << 2) | meth

TAP_CONTROL_CODE = lambda func, meth: _ctl_code(FILE_DEVICE_UNKNOWN, func, meth, FILE_ANY_ACCESS)

# TAP ioctl codes
TAP_IOCTL_GET_MAC = TAP_CONTROL_CODE(1, METHOD_BUFFERED)    # 0x0010a218
TAP_IOCTL_SET_MEDIA_STATUS = TAP_CONTROL_CODE(6, METHOD_BUFFERED)

# DeviceIoControl
DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD,
                              wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
DeviceIoControl.restype = wt.BOOL

# ==================== 辅助函数 ====================

def _get_last_error():
    err = ctypes.get_last_error()
    raise RuntimeError(f"Windows error {err}")


def _bool_ok(ret):
    if not ret:
        _get_last_error()


# ==================== TapWindows 类 ====================

class TapWindows:
    """
    Windows TAP（tap-windows / OpenVPN driver）封装。
    通过文件句柄 ReadFile/WriteFile 收发 Ethernet 帧。
    """

    # TAP 适配器注册表路径
    ADAPTER_REG_KEY = r"SYSTEM\CurrentControlSet\Services\Tap0802\Parameters\NetworkInterface"

    def __init__(self, name: str = None):
        self._handle = None
        self._name = name or None
        self._closing = False

        if not self._name:
            self._name = self._find_first_adapter()

        self._handle = self._open_adapter(self._name)
        # 激活适配器（通知驱动媒体状态为已连接）
        self._set_media_status(True)

    def _find_first_adapter(self) -> str:
        """遍历注册表，找第一个 TAP 适配器名称"""
        import winreg
        candidates = []

        # 尝试多个可能的注册表路径
        keys_to_try = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tap0802\Parameters\NetworkInterface"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WintunUserspaceDirectory"),
        ]

        for hkey, path in keys_to_try:
            try:
                key = winreg.OpenKey(hkey, path)
                try:
                    i = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(key, i)
                            candidates.append(guid)
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except:
                pass

        if not candidates:
            raise RuntimeError("未找到 TAP 适配器，请安装 OpenVPN 或 TAP-Windows 驱动")

        # TAP 用 GUID 作为名称
        return candidates[0]

    def _open_adapter(self, name: str):
        """打开 TAP 适配器设备"""
        # 尝试两种路径格式
        for path_prefix in [f'\\\\.\\{name}', f'\\\\.\\TAP-{name}']:
            h = CreateFileW(
                path_prefix,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if h and h != INVALID_HANDLE_VALUE:
                return h

        # 直接用 GUID 路径（tap0802 用 NetworkInterface 下的 key 名作为设备名）
        h = CreateFileW(
            f'\\\\.\\{name}',
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        if h == INVALID_HANDLE_VALUE:
            _get_last_error()
        return h

    def _set_media_status(self, connected: bool):
        """通知驱动媒体状态（必须调用，适配器才会真正激活）"""
        # struct { DWORD status; } status=1 表示连接，0 表示断开
        import struct as st
        status = st.pack('I', 1 if connected else 0)
        buf = ctypes.create_string_buffer(64)
        n = wt.DWORD()
        ok = DeviceIoControl(
            self._handle,
            TAP_IOCTL_SET_MEDIA_STATUS,
            status, len(status),
            buf, 64,
            ctypes.byref(n), None
        )
        if not ok:
            _get_last_error()

    def send(self, data: bytes) -> int:
        """发 Ethernet 帧"""
        if not self._handle or self._handle == INVALID_HANDLE_VALUE:
            raise RuntimeError("TAP 已关闭")
        n = wt.DWORD()
        ok = WriteFile(self._handle, data, len(data), ctypes.byref(n), None)
        if not ok:
            _get_last_error()
        return n.value

    def recv(self, size=4096, timeout_ms=1000) -> bytes:
        """收 Ethernet 帧（阻塞直到有数据或超时）"""
        if not self._handle or self._handle == INVALID_HANDLE_VALUE:
            raise RuntimeError("TAP 已关闭")

        buf = ctypes.create_string_buffer(size)
        n = wt.DWORD()
        start = time.monotonic()

        while not self._closing:
            ok = ReadFile(self._handle, buf, size, ctypes.byref(n), None)
            if ok and n.value > 0:
                return buf.raw[:n.value]

            elapsed = (time.monotonic() - start) * 1000
            if timeout_ms and elapsed >= timeout_ms:
                raise BlockingIOError("超时无数据")

            time.sleep(0.01)

        raise BlockingIOError("TAP 已关闭")

    def fileno(self):
        """Windows 上没有 fd 概念"""
        raise NotImplementedError("TapWindows 不支持 fileno()")

    @property
    def name(self) -> str:
        return self._name

    def close(self):
        self._closing = True
        if self._handle and self._handle != INVALID_HANDLE_VALUE:
            CloseHandle(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return f"<TapWindows {self._name}>"


# ==================== 便捷入口 ====================

def Tap(*args, **kwargs):
    return TapWindows(*args, **kwargs)
