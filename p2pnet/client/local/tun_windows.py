#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
local/tun_windows.py - Wintun TUN 封装（Windows 专用）

Wintun 是 WireGuard 官方轻量 TUN 驱动（Windows）。
DLL: %SystemRoot%\System32\wintun.dll

使用 Wintun 环冲区 API：
  1. WintunOpenAdapter / WintunCreateAdapter 拿到 adapter
  2. WintunStartSession 创建 session（管理 RX/TX 环）
  3. WintunReceiveIPPacket 从 RX 环读 IP 包
  4. WintunSendPacket 发 IP 包到 TX 环
  5. 关闭 session 和 adapter

用法：
  tun = TunWintun(adapter_name='Wintun')  # 默认找第一个 Wintun 适配器
  tun.send(ip_packet_bytes)
  data = tun.recv()        # 返回原始 IP 包 bytes
  tun.close()
"""

import ctypes
import ctypes.wintypes as wt
import os
import time
import platform
import uuid
import subprocess
import sys

if platform.system() != 'Windows':
    raise ImportError("tun_windows 仅支持 Windows")

# ==================== 加载 wintun.dll ====================

def _load_wintun():
    dll_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'),
                             'System32', 'wintun.dll')
    if not os.path.exists(dll_path):
        raise RuntimeError(f"wintun.dll 未找到，请安装 WireGuard 或 Wintun：{dll_path}")
    return ctypes.CDLL(dll_path)

_wintun = _load_wintun()

# ==================== 常量 ====================

WINTUN_MAX_PACKET_SIZE = 0xFFFF
WINTUN_RING_CAPACITY = 0x100000  # 1 MB 环，建议值

# ==================== ctypes 定义 ====================

class GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', wt.DWORD),
        ('Data2', wt.WORD),
        ('Data3', wt.WORD),
        ('Data4', wt.BYTE * 8),
    ]

# WINTUN_CREATE_ADAPTER_WOW64213 = ...
# 我们用 ANSI 版本
_wintun.WintunCreateAdapter.argtypes = [
    wt.LPCWSTR,  # name
    wt.LPCWSTR,  # tunnel_type (description)
    GUID,         # requested_guid (optional, can be zeroed)
]
_wintun.WintunCreateAdapter.restype = wt.HANDLE  # WINTUN_ADAPTER_HANDLE (actually a pointer)

_wintun.WintunOpenAdapter.argtypes = [wt.LPCWSTR]
_wintun.WintunOpenAdapter.restype = wt.HANDLE

_wintun.WintunCloseAdapter.argtypes = [wt.HANDLE]
_wintun.WintunCloseAdapter.restype = None

_wintun.WintunStartSession.argtypes = [wt.HANDLE, wt.DWORD]  # adapter, capacity
_wintun.WintunStartSession.restype = wt.HANDLE  # WINTUN_SESSION_HANDLE

_wintun.WintunEndSession.argtypes = [wt.HANDLE]
_wintun.WintunEndSession.restype = None

_wintun.WintunReceivePacket.argtypes = [wt.HANDLE]  # session
_wintun.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ulong)  # returns pointer to packet info

_wintun.WintunReceivePacketData.argtypes = [wt.HANDLE]  # session
_wintun.WintunReceivePacketData.restype = ctypes.c_void_p  # data pointer

_wintun.WintunReleasePacket.argtypes = [wt.HANDLE, ctypes.c_void_p]
_wintun.WintunReleasePacket.restype = None

_wintun.WintunSendPacket.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD]
_wintun.WintunSendPacket.restype = wt.DWORD  # WIN32_ERROR

_wintun.WintunSendPacketData.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD]
_wintun.WintunSendPacketData.restype = wt.DWORD

# wintun.h 的结构：
# WINTUN_PACKET_HEADER { DWORD length; } + data
# 实际上 ReceivePacket 返回 PVOID data，直接可用

# ==================== 辅助函数 ====================

def _check_err(err):
    if err != 0:
        raise RuntimeError(f"Wintun API error: {err}")


# ==================== TunWintun 类 ====================

class TunWintun:
    """
    Wintun TUN 封装。
    adapter_name: 要打开的适配器名称，None 则找注册表中第一个
    """

    # 注册表路径（WireGuard/Wintun 适配器信息）
    ADAPTER_KEY = r"SYSTEM\CurrentControlSet\Services\WintunUserspaceDirectory"

    def __init__(self, adapter_name: str = None):
        self._handle = None   # adapter handle
        self._session = None   # session handle
        self._name = adapter_name
        self._closing = False

        # 找或打开适配器
        self._adapter_name, self._handle = self._find_or_open_adapter(adapter_name)

        # 启动 session
        self._session = _wintun.WintunStartSession(self._handle, WINTUN_RING_CAPACITY)
        if not self._session:
            raise RuntimeError("WintunStartSession 失败")

    def _find_or_open_adapter(self, name) -> tuple:
        """找（注册表）或打开指定名称的 Wintun 适配器"""
        import winreg

        # 先试着直接打开
        if name:
            h = _wintun.WintunOpenAdapter(name)
            if h and h != -1:
                return name, h

        # 遍历注册表找适配器
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.ADAPTER_KEY)
            try:
                i = 0
                while True:
                    subkey_name = winreg.EnumKey(key, i)
                    # 读适配器名称
                    try:
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            friendly_name, _ = winreg.QueryValueEx(subkey, 'Name')
                            h = _wintun.WintunOpenAdapter(friendly_name)
                            if h and h != -1:
                                return friendly_name, h
                        finally:
                            winreg.CloseKey(subkey)
                    except:
                        pass
                    i += 1
            except OSError:
                pass
            finally:
                winreg.CloseKey(key)
        except:
            pass

        raise RuntimeError("未找到 Wintun 适配器，请先安装 WireGuard 并添加接口")

    def send(self, data: bytes) -> int:
        """发 IP 包（data 必须是完整 IP 包）"""
        if not self._session:
            raise RuntimeError("session 已关闭")
        if len(data) > WINTUN_MAX_PACKET_SIZE:
            raise ValueError(f"包太大: {len(data)}")
        err = _wintun.WintunSendPacketData(self._session, data, len(data))
        if err != 0:
            raise RuntimeError(f"WintunSendPacketData 失败: {err}")
        return len(data)

    def recv(self, timeout_ms=1000) -> bytes:
        """收 IP 包（阻塞直到有数据或超时）"""
        if not self._session:
            raise RuntimeError("session 已关闭")
        start = time.monotonic()
        while not self._closing:
            # WintunReceivePacketData 返回 (data_ptr, data_len) 元组
            pkt = _wintun.WintunReceivePacketData(self._session)
            if pkt:
                ptr, size = pkt
                if ptr and size > 0:
                    _wintun.WintunReleasePacket(self._session, ptr)
                    return ctypes.string_at(ptr, size)

            elapsed = (time.monotonic() - start) * 1000
            if timeout_ms and elapsed >= timeout_ms:
                raise BlockingIOError("超时无数据")
            time.sleep(0.005)

        raise BlockingIOError("TUN 已关闭")

    def fileno(self):
        """Windows 上没有 fd 概念，抛出异常"""
        raise NotImplementedError("Wintun 不支持 select.fileno()，用 recv 超时")

    @property
    def name(self) -> str:
        return self._name or self._adapter_name

    def close(self):
        self._closing = True
        if self._session:
            try:
                _wintun.WintunEndSession(self._session)
            except:
                pass
            self._session = None
        if self._handle:
            try:
                _wintun.WintunCloseAdapter(self._handle)
            except:
                pass
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return f"<TunWintun {self._adapter_name}>"


# ==================== 便捷入口 ====================

def Tun(*args, **kwargs):
    """统一入口：Windows 用 Wintun"""
    return TunWintun(*args, **kwargs)
