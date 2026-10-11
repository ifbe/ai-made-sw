#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 设备层：把"按偏移读写的一块空间"抽象出来

卷只要求载体提供四件事：``size`` / ``read_at`` / ``write_at`` / ``flush``（外加 ``close``）。
本模块提供这些实现：

===========================  ==========================================================
``FileDevice``               整个文件就是一个区域
``RegionDevice``             ``[offset, offset+length)`` 这一段（文件内位置、分区）
``MemDevice``                一块内存（演示/测试用，掉电即失）
``VhdDevice``                ``.vhd`` 虚拟磁盘（fixed / dynamic），呈现为"虚拟磁盘"
===========================  ==========================================================

配套工具：

* :func:`open_container`  按**文件内容**识别 raw / vhd-fixed / vhd-dynamic / vhdx
* :func:`read_partitions` 解析 MBR / GPT 分区表
* :func:`open_device`     把命令行参数变成 ``(Device, 描述)``
* :func:`add_device_args` 给 argparse 加上 ``--file/--vdisk/--mem/--part/--offset/--length/--vhd``
* :func:`create_vhd`      新建一个 ``.vhd``（dynamic 或 fixed）

只依赖标准库；兼容 Python 3.6+。**本模块不依赖 easyfs.py**（方向是 easyfs.py 依赖它）。
"""

from easyfs_config import *      # noqa: F401,F403

import os
import re
import stat
import sys
import struct
import zlib

VHD_BLOCK = 2 << 20                     # 动态 VHD 的块大小（2 MiB，与常见实现一致）


class EasyFSDeviceError(Exception):
    pass


def _align_up(x, a):
    return -(-x // a) * a


# ================================================================ 基类

class Device(object):
    """设备接口。子类必须提供 ``size`` 与 ``read_at`` / ``write_at``。"""

    size = 0
    read_only = False

    def check(self, off, n):
        if off < 0 or n < 0 or off + n > self.size:
            raise EasyFSDeviceError("越界: off=%d n=%d size=%d"
                                    % (off, n, self.size))

    def read_at(self, off, n):
        raise NotImplementedError

    def write_at(self, off, data):
        raise NotImplementedError

    def flush(self):
        pass

    def close(self):
        pass


class FileDevice(Device):
    """把一个文件当作区域（整文件）。``size`` 给定时创建/截断到这个长度。"""

    def __init__(self, path, size=None, read_only=False):
        self.path = path
        self.read_only = read_only
        self.is_block = is_block_device(path) if os.path.exists(path) else False
        if self.is_block:
            # 块设备：容量问内核；**绝不能 truncate**（那是毁盘）
            if size is not None:
                raise EasyFSDeviceError(
                    "块设备不能按容器尺寸截断（%s）；卷在盘里的哪一段请用 --offs/--size" % path)
            self.size = block_device_size(path)
        elif size is not None:
            with open(path, "wb") as f:
                f.truncate(size)
            self.size = size
        else:
            if not os.path.exists(path):
                raise EasyFSDeviceError("文件不存在: " + path)
            self.size = os.path.getsize(path)
        try:
            self.f = open(path, "rb" if read_only else "r+b")
        except PermissionError:
            raise EasyFSDeviceError(
                "打不开 %s：权限不足%s。块设备通常要 root / sudo，或把用户加进 `disk` 组"
                % (path, "" if read_only else "（写方式）"))
        except OSError as e:
            raise EasyFSDeviceError("打不开 %s：%s" % (path, e))

    def read_at(self, off, n):
        self.check(off, n)
        self.f.seek(off)
        data = self.f.read(n)
        if len(data) != n:
            raise EasyFSDeviceError("短读: off=%d 想要 %d 实际 %d"
                                    % (off, n, len(data)))
        return data

    def write_at(self, off, data):
        if self.read_only:
            raise EasyFSDeviceError("只读设备")
        self.check(off, len(data))
        self.f.seek(off)
        self.f.write(data)

    def flush(self):
        self.f.flush()
        os.fsync(self.f.fileno())

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass

    def __repr__(self):
        return "<FileDevice %s %d B>" % (self.path, self.size)


class RegionDevice(Device):
    """某个设备里的一段窗口 —— 文件内位置、磁盘镜像里的分区，都靠它。"""

    def __init__(self, dev, offset, length, name=None):
        if offset < 0 or length <= 0 or offset + length > dev.size:
            raise EasyFSDeviceError("区域越界: [%d, %d) 超出 %d"
                                    % (offset, offset + length, dev.size))
        self.dev = dev
        self.offset = offset
        self.size = length
        self.name = name
        self.read_only = getattr(dev, "read_only", False)

    def read_at(self, off, n):
        self.check(off, n)
        return self.dev.read_at(self.offset + off, n)

    def write_at(self, off, data):
        self.check(off, len(data))
        self.dev.write_at(self.offset + off, data)

    def flush(self):
        self.dev.flush()

    def close(self):
        self.dev.close()

    def __repr__(self):
        return "<RegionDevice %s @%d %d B>" % (self.name or "", self.offset,
                                               self.size)


class MemDevice(Device):
    """一块内存。用来在没有文件/权限时试玩（掉电即失）。"""

    def __init__(self, size):
        self.buf = bytearray(size)
        self.size = size

    def read_at(self, off, n):
        self.check(off, n)
        return bytes(self.buf[off:off + n])

    def write_at(self, off, data):
        self.check(off, len(data))
        self.buf[off:off + len(data)] = data

    def __repr__(self):
        return "<MemDevice %d B>" % self.size


# ================================================================ VHD

def _be(data, off, fmt):
    return struct.unpack_from(">" + fmt, data, off)


def _vhd_checksum(block):
    """VHD 的校验和：把校验和字段当 0，各字节求和后取反（ones' complement）。"""
    lo, hi = (36, 40) if len(block) == 1024 else (64, 68)
    total = 0
    for i, b in enumerate(block):
        if lo <= i < hi:
            continue
        total += b
    return (~total) & 0xFFFFFFFF


def _chs_capacity(size):
    """VHD 的几何是按 CHS 记的，容量必须 ≥ 当前大小（qemu 等工具会按 CHS 算）。"""
    heads, sectors = 16, 63
    total = _align_up(size, SECTOR) // SECTOR
    cyls = min(-(-total // (heads * sectors)), 0xFFFF)
    return cyls * heads * sectors * SECTOR


def _make_footer(current_size, disk_type, data_offset):
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">I", f, 8, 0x00000002)            # features
    struct.pack_into(">I", f, 12, 0x00010000)           # version
    struct.pack_into(">Q", f, 16, data_offset)          # data offset
    struct.pack_into(">I", f, 24, 0)                    # timestamp
    f[28:32] = b"easy"
    struct.pack_into(">I", f, 32, 0x00010000)           # creator version
    f[36:40] = b"Wi2k"
    struct.pack_into(">Q", f, 40, current_size)         # original size
    struct.pack_into(">Q", f, 48, current_size)         # current size
    total_sectors = _align_up(current_size, SECTOR) // SECTOR
    cyls = min(-(-total_sectors // (16 * 63)), 0xFFFF)
    f[56] = (cyls >> 8) & 0xFF
    f[57] = cyls & 0xFF
    f[58] = 16
    f[59] = 63
    struct.pack_into(">I", f, 60, disk_type)            # 2=fixed 3=dynamic
    f[68:84] = os.urandom(16)                           # unique id
    struct.pack_into(">I", f, 64, _vhd_checksum(f))
    return bytes(f)


def _make_dynamic_header(table_offset, max_entries, block_size):
    h = bytearray(1024)
    h[0:8] = b"cxsparse"
    struct.pack_into(">Q", h, 8, 0xFFFFFFFFFFFFFFFF)    # data offset（未用）
    struct.pack_into(">Q", h, 16, table_offset)
    struct.pack_into(">I", h, 24, 0x00010000)           # version
    struct.pack_into(">I", h, 28, max_entries)
    struct.pack_into(">I", h, 32, block_size)
    struct.pack_into(">I", h, 36, _vhd_checksum(h))
    return bytes(h)


def create_vhd(path, size, dynamic=True):
    """新建一个 ``.vhd``：``dynamic=True`` 为动态盘（稀疏），否则为固定盘。

    尺寸会向上取到 CHS 几何容量 —— VHD 的容量是按 CHS 记的，qemu 等工具按几何算，
    取整可以让"当前大小"和别的工具看到的容量完全一致。
    """
    size = _chs_capacity(size)
    if not dynamic:
        with open(path, "wb") as f:
            f.truncate(size)
            f.seek(size)                                 # 页脚必须在末尾
            f.write(_make_footer(size, 2, 0xFFFFFFFFFFFFFFFF))
        return size
    max_entries = _align_up(size, VHD_BLOCK) // VHD_BLOCK
    table_offset = 512 + 1024                           # footer 副本 + 动态头
    bat_bytes = _align_up(max_entries * 4, SECTOR)
    bat = b"\xff\xff\xff\xff" * max_entries
    bat += b"\x00" * (bat_bytes - len(bat))
    footer = _make_footer(size, 3, 512)
    with open(path, "wb") as f:
        f.write(footer)                                 # 0：页脚副本
        f.write(_make_dynamic_header(table_offset, max_entries, VHD_BLOCK))
        f.write(bat)
        f.write(footer)                                 # 末尾：真正的页脚
    return size


class VhdDevice(Device):
    """``.vhd`` 虚拟磁盘（fixed / dynamic），对外就是一个普通设备。

    只读打开时不会分配块；可写打开时按需分配 2 MiB 的块并维护 BAT 与位图。
    differencing（差异盘）与 ``.vhdx`` 不支持。
    """

    def __init__(self, path, read_only=False):
        self.path = path
        self.read_only = read_only
        self.f = open(path, "rb" if read_only else "r+b")
        self.file_size = os.path.getsize(path)
        if self.file_size < SECTOR:
            raise EasyFSDeviceError("不是 VHD：文件太短")
        self.f.seek(self.file_size - SECTOR)
        self.footer = self.f.read(SECTOR)
        if self.footer[0:8] != b"conectix":
            raise EasyFSDeviceError("不是 VHD：末尾没有 conectix 页脚（.vhdx 不支持）")
        want = _be(self.footer, 64, "I")[0]
        got = _vhd_checksum(self.footer)
        if want != got:
            raise EasyFSDeviceError("VHD 页脚校验和不对: 0x%08x vs 0x%08x"
                                    % (want, got))
        self.disk_type = _be(self.footer, 60, "I")[0]
        self.size = _be(self.footer, 48, "Q")[0]        # 虚拟磁盘大小
        self.kind = "vhd-fixed" if self.disk_type == 2 else "vhd-dynamic"
        self.bitmap_size = 0
        self.block_size = 0
        self.table_offset = 0
        self.bat = []
        if self.disk_type == 2:
            if self.file_size < self.size:
                raise EasyFSDeviceError("固定 VHD 文件比虚拟磁盘小")
        elif self.disk_type == 3:
            self.f.seek(512)
            h = self.f.read(1024)
            if h[0:8] != b"cxsparse":
                raise EasyFSDeviceError("动态 VHD 头缺失（cxsparse）")
            if _be(h, 36, "I")[0] != _vhd_checksum(h):
                raise EasyFSDeviceError("动态 VHD 头校验和不对")
            self.table_offset = _be(h, 16, "Q")[0]
            self.max_entries = _be(h, 28, "I")[0]
            self.block_size = _be(h, 32, "I")[0]
            self.bitmap_size = _align_up(-(-self.block_size // SECTOR) // 8,
                                         SECTOR)
            raw = bytearray()
            self.f.seek(self.table_offset)
            left = self.max_entries * 4
            while left > 0:
                chunk = self.f.read(min(left, 1 << 20))
                if not chunk:
                    break
                raw += chunk
                left -= len(chunk)
            self.bat = list(struct.unpack(">%dI" % self.max_entries,
                                          bytes(raw[:self.max_entries * 4])))
        else:
            raise EasyFSDeviceError("不支持的 VHD 类型 %d（差异盘）" % self.disk_type)

    # ---- 动态盘的块操作

    def _block_index(self, off):
        return off // self.block_size

    def _ensure_block(self, idx):
        """确保第 idx 块已分配，返回它在文件里的字节偏移。"""
        if idx >= len(self.bat):
            raise EasyFSDeviceError("块号越界: %d" % idx)
        sec = self.bat[idx]
        if sec != 0xFFFFFFFF:
            return sec * SECTOR
        if self.read_only:
            raise EasyFSDeviceError("只读 VHD，不能分配块")
        start = self.file_size - SECTOR                  # 覆盖掉末尾的页脚
        self.f.seek(start)
        self.f.write(b"\x00" * (self.bitmap_size + self.block_size))
        self.f.write(self.footer)                        # 页脚挪到新末尾
        self.f.flush()
        self.file_size = start + self.bitmap_size + self.block_size + SECTOR
        self.bat[idx] = start // SECTOR
        self.f.seek(self.table_offset + idx * 4)
        self.f.write(struct.pack(">I", self.bat[idx]))
        return start

    def _read_block(self, idx, block_off, want_off, n):
        """从动态盘读，未分配或位图未置位的部分补 0。"""
        sec = self.bat[idx]
        if sec == 0xFFFFFFFF:
            return b"\x00" * n
        start = sec * SECTOR
        bmp_off = start
        data_off = start + self.bitmap_size
        out = bytearray()
        pos = want_off
        end = want_off + n
        while pos < end:
            s = pos // SECTOR                            # 块内扇区号
            upto = min(end, (s + 1) * SECTOR)
            self.f.seek(bmp_off + (s >> 3))
            b = self.f.read(1)
            present = bool(b and (b[0] >> (s & 7)) & 1)
            if present:
                self.f.seek(data_off + pos)
                out += self.f.read(upto - pos)
            else:
                out += b"\x00" * (upto - pos)
            pos = upto
        return bytes(out)

    def _write_block(self, idx, block_off, want_off, data):
        start = self._ensure_block(idx)
        bmp_off = start
        data_off = start + self.bitmap_size
        pos, i = want_off, 0
        while i < len(data):
            s = pos // SECTOR
            upto = min(pos + (len(data) - i), (s + 1) * SECTOR)
            take = upto - pos
            self.f.seek(data_off + pos)
            self.f.write(data[i:i + take])
            # 置位图里对应的 bit（LSB first）
            self.f.seek(bmp_off + (s >> 3))
            b = self.f.read(1)
            val = (b[0] if b else 0) | (1 << (s & 7))
            self.f.seek(bmp_off + (s >> 3))
            self.f.write(bytes((val,)))
            pos += take
            i += take

    # ---- Device 接口

    def read_at(self, off, n):
        self.check(off, n)
        if self.disk_type == 2:
            self.f.seek(off)
            return self.f.read(n)
        out = bytearray()
        pos, end = off, off + n
        while pos < end:
            idx = self._block_index(pos)
            block_off = idx * self.block_size
            upto = min(end, block_off + self.block_size)
            out += self._read_block(idx, block_off, pos - block_off, upto - pos)
            pos = upto
        return bytes(out)

    def write_at(self, off, data):
        if self.read_only:
            raise EasyFSDeviceError("只读设备")
        self.check(off, len(data))
        if self.disk_type == 2:
            self.f.seek(off)
            self.f.write(data)
            return
        pos, i = off, 0
        while i < len(data):
            idx = self._block_index(pos)
            block_off = idx * self.block_size
            take = min(len(data) - i, block_off + self.block_size - pos)
            self._write_block(idx, block_off, pos - block_off, data[i:i + take])
            pos += take
            i += take

    def flush(self):
        self.f.flush()
        os.fsync(self.f.fileno())

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass

    def __repr__(self):
        return "<VhdDevice %s %s %d B>" % (self.kind, self.path, self.size)


# ================================================================ 容器识别

# --------------------------------------------------------------------------
# VMDK（monolithicSparse：单文件、稀疏、不压缩）—— 只建"全零空盘"
# 布局：512 B 稀疏头 | 描述符（文本）| 颗粒目录 GD | 颗粒表 GT | 颗粒（按需）
# 全零的颗粒不分配 ⇒ 新建的盘里只有元数据（几十 KiB）
# --------------------------------------------------------------------------
VMDK_MAGIC = 0x564D444B                # 'KDMV'（小端存 ⇒ 字节是 4B 44 4D 56）
VMDK_GRAIN_SECTORS = 128               # 颗粒 = 128 扇区 = 64 KiB（常见实现）
VMDK_GTES_PER_GT = 512


def _vmdk_descriptor(path, capacity_sectors):
    heads, sectors = 16, 63
    cyl = max(1, (capacity_sectors + heads * sectors - 1) // (heads * sectors))
    return ('# Disk DescriptorFile\n'
            'version=1\n'
            'encoding="UTF-8"\n'
            'CID=fffffffe\n'
            'parentCID=ffffffff\n'
            'createType="monolithicSparse"\n'
            '\n'
            '# Extent description\n'
            'RW %d SPARSE "%s"\n'
            '\n'
            '# The Disk Data Base\n'
            '#DDB\n'
            '\n'
            'ddb.virtualHWVersion = "4"\n'
            'ddb.geometry.cylinders = "%d"\n'
            'ddb.geometry.heads = "%d"\n'
            'ddb.geometry.sectors = "%d"\n'
            'ddb.adapterType = "ide"\n'
            % (capacity_sectors, os.path.basename(path), cyl, heads, sectors))


def create_vmdk(path, size):
    """新建一个 `.vmdk`（monolithicSparse，单文件稀疏）。返回实际容量。"""
    size = (size + SECTOR - 1) // SECTOR * SECTOR          # 512 对齐
    if size < SECTOR or size > (1 << 44):
        raise EasyFSDeviceError("VMDK 容量不合理: %d" % size)
    cap = size // SECTOR
    desc = _vmdk_descriptor(path, cap).encode("utf-8")
    desc_sectors = (len(desc) + SECTOR - 1) // SECTOR
    gd_offset = 1 + desc_sectors                           # 头占 1 扇区
    n_gt = (cap + VMDK_GRAIN_SECTORS * VMDK_GTES_PER_GT - 1) // (VMDK_GRAIN_SECTORS * VMDK_GTES_PER_GT)
    gd_sectors = (n_gt * 4 + SECTOR - 1) // SECTOR
    gt_offset = gd_offset + gd_sectors
    gt_sectors = (n_gt * VMDK_GTES_PER_GT * 4 + SECTOR - 1) // SECTOR
    over = gt_offset + gt_sectors                          # 元数据总扇区数
    hdr = bytearray(SECTOR)
    struct.pack_into("<I", hdr, 0, VMDK_MAGIC)
    struct.pack_into("<I", hdr, 4, 1)                      # version
    struct.pack_into("<I", hdr, 8, 1)                      # flags: 只置"有效换行检测"
    struct.pack_into("<Q", hdr, 12, cap)                   # capacity（扇区）
    struct.pack_into("<Q", hdr, 20, VMDK_GRAIN_SECTORS)    # grainSize（扇区）
    struct.pack_into("<Q", hdr, 28, 1)                     # descriptorOffset（扇区）
    struct.pack_into("<Q", hdr, 36, desc_sectors)          # descriptorSize（扇区）
    struct.pack_into("<I", hdr, 44, VMDK_GTES_PER_GT)      # numGTEsPerGT
    struct.pack_into("<Q", hdr, 48, 0)                     # rgdOffset（无冗余 GD）
    struct.pack_into("<Q", hdr, 56, gd_offset)             # gdOffset
    struct.pack_into("<Q", hdr, 64, over)                  # overHead
    hdr[72] = 0                                            # uncleanShutdown
    hdr[73] = 0x0A                                         # singleEndLineChar
    hdr[74] = 0x20                                         # nonEndLineChar
    hdr[75] = 0x0D                                         # doubleEndLineChar1
    hdr[76] = 0x0A                                         # doubleEndLineChar2
    struct.pack_into("<H", hdr, 77, 0)                     # compressAlgorithm = 无
    # 颗粒目录：每张颗粒表都先指好位置（表本身全零 ⇒ 一个颗粒都没分配）
    gt_step = VMDK_GTES_PER_GT * 4 // SECTOR               # 一张表占几扇区
    gd = struct.pack("<%dI" % n_gt,
                     *[gt_offset + i * gt_step for i in range(n_gt)])
    with open(path, "wb") as f:
        f.write(bytes(hdr))
        f.write(desc + b"\x00" * (desc_sectors * SECTOR - len(desc)))
        f.write(gd + b"\x00" * (gd_sectors * SECTOR - len(gd)))
        f.truncate(over * SECTOR)                          # GT 区（全零）
    return size


def vmdk_info(path):
    """把 VMDK 头解出来（不认的格式返回 None）。"""
    n = os.path.getsize(path)
    if n < SECTOR:
        return None
    with open(path, "rb") as f:
        h = f.read(SECTOR)
    if struct.unpack_from("<I", h, 0)[0] != VMDK_MAGIC:
        return None
    return {
        "version": struct.unpack_from("<I", h, 4)[0],
        "flags": struct.unpack_from("<I", h, 8)[0],
        "capacity_bytes": struct.unpack_from("<Q", h, 12)[0] * SECTOR,
        "grain_sectors": struct.unpack_from("<Q", h, 20)[0],
        "descriptor_offset": struct.unpack_from("<Q", h, 28)[0] * SECTOR,
        "descriptor_size": struct.unpack_from("<Q", h, 36)[0] * SECTOR,
        "gtes_per_gt": struct.unpack_from("<I", h, 44)[0],
        "gd_offset": struct.unpack_from("<Q", h, 56)[0] * SECTOR,
        "overhead_sectors": struct.unpack_from("<Q", h, 64)[0],
        "compress": struct.unpack_from("<H", h, 77)[0],
        "file_bytes": n,
    }


# --------------------------------------------------------------------------
# DMG（UDIF，未压缩 = "UDRO"）：[原始数据][XML plist][koly 尾块 512 B]
# 字段一律**大端**（Apple 的 UDIF 约定）。只建"全零空盘"，不压缩。
# --------------------------------------------------------------------------
DMG_KOLY_SIZE = 512


def _crc32_range(path, off, length, chunk=1 << 20):
    """算文件里一段的 CRC32（分块，不整段读进内存）。"""
    c = 0
    with open(path, "rb") as f:
        f.seek(off)
        left = length
        while left > 0:
            b = f.read(min(chunk, left))
            if not b:
                break
            c = zlib.crc32(b, c)
            left -= len(b)
    return c & 0xFFFFFFFF


def _dmg_mish(capacity_sectors, data_offset, data_length):
    """`mish`（BLKX）块：一个"未压缩"整盘条目（大端）。

    布局：头 40 B + 保留 24 B + 校验和 128 B（到 200）+ 运行条目数 4 B(200)
          + 运行条目 40 B 一个（204 起）。
    """
    b = bytearray(204)
    b[0:4] = b"mish"
    struct.pack_into(">I", b, 4, 1)                 # version
    struct.pack_into(">Q", b, 8, 0)                 # sectorNumber
    struct.pack_into(">Q", b, 16, capacity_sectors)  # sectorCount
    struct.pack_into(">Q", b, 24, data_offset)      # dataOffset
    struct.pack_into(">I", b, 32, 0x20)             # buffersNeeded
    struct.pack_into(">I", b, 36, 1)                # blockDescriptors
    struct.pack_into(">I", b, 64, 2)                # 本块校验和类型 = CRC32
    struct.pack_into(">I", b, 68, 32)               # 校验和长度
    struct.pack_into(">I", b, 200, 1)               # 运行条目数 = 1
    b += struct.pack(">IIQQQQ", 1, 0, 0, capacity_sectors, data_offset, data_length)
    return bytes(b)


def _dmg_plist(mish, name):
    import base64
    b64 = base64.b64encode(mish).decode("ascii")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n'
            '<dict>\n'
            '\t<key>resource-fork</key>\n'
            '\t<dict>\n'
            '\t\t<key>blkx</key>\n'
            '\t\t<array>\n'
            '\t\t\t<dict>\n'
            '\t\t\t\t<key>Attributes</key><string>0x0050</string>\n'
            '\t\t\t\t<key>CFName</key><string>%s</string>\n'
            '\t\t\t\t<key>Data</key><data>%s</data>\n'
            '\t\t\t\t<key>ID</key><string>-1</string>\n'
            '\t\t\t\t<key>Name</key><string>%s</string>\n'
            '\t\t\t</dict>\n'
            '\t\t</array>\n'
            '\t</dict>\n'
            '</dict>\n'
            '</plist>\n' % (name, b64, name)).encode("utf-8")


def create_dmg(path, size, name="whole disk (EasyFS)"):
    """新建一个 `.dmg`（UDIF 未压缩）。返回虚拟容量。"""
    size = (size + SECTOR - 1) // SECTOR * SECTOR
    if size < SECTOR:
        raise EasyFSDeviceError("DMG 容量太小")
    cap = size // SECTOR
    # 原始数据（全零）→ plist → koly
    with open(path, "wb") as f:
        f.truncate(size)                                     # 数据叉：全零
        xml = _dmg_plist(_dmg_mish(cap, 0, size), name)
        xml_off = size
        f.seek(size)
        f.write(xml)
        koly_off = f.tell()
        k = bytearray(DMG_KOLY_SIZE)
        k[0:4] = b"koly"
        struct.pack_into(">I", k, 4, 4)                      # version
        struct.pack_into(">I", k, 8, DMG_KOLY_SIZE)          # headerSize
        struct.pack_into(">I", k, 12, 1)                     # flags
        struct.pack_into(">Q", k, 16, 0)                     # runningDataForkOffset
        struct.pack_into(">Q", k, 24, 0)                     # dataForkOffset
        struct.pack_into(">Q", k, 32, size)                  # dataForkLength
        struct.pack_into(">Q", k, 40, 0)                     # rsrcForkOffset
        struct.pack_into(">Q", k, 48, 0)                     # rsrcForkLength
        struct.pack_into(">I", k, 56, 1)                     # segmentNumber
        struct.pack_into(">I", k, 60, 1)                     # segmentCount
        k[64:80] = bytes(bytearray(range(16)))               # segmentID（随便）
        struct.pack_into(">I", k, 80, 2)                     # dataChecksumType = CRC32
        struct.pack_into(">I", k, 84, 32)                    # dataChecksumSize
        data_crc = _crc32_range(path, 0, size)          # 数据叉的 CRC32（整段）
        struct.pack_into(">I", k, 88, data_crc)
        struct.pack_into(">Q", k, 216, xml_off)              # xmlOffset
        struct.pack_into(">Q", k, 224, len(xml))             # xmlLength
        struct.pack_into(">I", k, 352, 2)                    # checksumType = CRC32
        struct.pack_into(">I", k, 356, 32)                   # checksumSize
        struct.pack_into(">I", k, 360, zlib.crc32(xml) & 0xFFFFFFFF)   # 主校验和
        struct.pack_into(">I", k, 488, 1)                    # imageVariant
        struct.pack_into(">Q", k, 492, cap)                  # sectorCount
        f.seek(koly_off)
        f.write(bytes(k))
    return size


def dmg_info(path):
    """把 DMG 的 koly 尾块 / mish 块解出来（不是 DMG 返回 None）。"""
    n = os.path.getsize(path)
    if n < DMG_KOLY_SIZE:
        return None
    with open(path, "rb") as f:
        f.seek(n - DMG_KOLY_SIZE)
        k = f.read(DMG_KOLY_SIZE)
        if k[0:4] != b"koly":
            return None
        info = {
            "version": struct.unpack_from(">I", k, 4)[0],
            "header_size": struct.unpack_from(">I", k, 8)[0],
            "flags": struct.unpack_from(">I", k, 12)[0],
            "data_fork_offset": struct.unpack_from(">Q", k, 24)[0],
            "data_fork_length": struct.unpack_from(">Q", k, 32)[0],
            "data_crc": struct.unpack_from(">I", k, 88)[0],
            "xml_offset": struct.unpack_from(">Q", k, 216)[0],
            "xml_length": struct.unpack_from(">Q", k, 224)[0],
            "master_crc": struct.unpack_from(">I", k, 360)[0],
            "image_variant": struct.unpack_from(">I", k, 488)[0],
            "sector_count": struct.unpack_from(">Q", k, 492)[0],
            "file_bytes": n,
        }
        f.seek(info["xml_offset"])
        xml = f.read(info["xml_length"])
    info["xml_bytes"] = len(xml)
    info["master_crc_ok"] = (zlib.crc32(xml) & 0xFFFFFFFF) == info["master_crc"]
    import base64
    m = re.search(rb"<key>Data</key><data>([A-Za-z0-9+/=]+)</data>", xml)
    if m:
        try:
            mish = base64.b64decode(m.group(1))
        except Exception:
            mish = b""
        if mish[0:4] == b"mish":
            info["mish_blocks"] = struct.unpack_from(">I", mish, 36)[0]
            info["mish_entry_type"] = struct.unpack_from(">I", mish, 40)[0]
            info["mish_sectors"] = struct.unpack_from(">Q", mish, 16)[0]
            info["mish_data_offset"] = struct.unpack_from(">Q", mish, 64)[0]
            info["mish_data_length"] = struct.unpack_from(">Q", mish, 72)[0]
    return info


class VmdkDevice(Device):
    """``.vmdk``（monolithicSparse，单文件稀疏），对外就是普通设备。

    只读打开不会分配颗粒；可写时按需追加 64 KiB 颗粒并写回颗粒表。
    只支持"不压缩、无冗余颗粒表"的 monolithicSparse —— 也就是我们建出来的那种。
    """

    def __init__(self, path, read_only=False):
        self.path = path
        self.read_only = read_only
        info = vmdk_info(path)
        if info is None:
            raise EasyFSDeviceError("不是 VMDK：开头没有 KDMV 魔数")
        if info["flags"] & 0x2:
            raise EasyFSDeviceError("带冗余颗粒表（RGD）的 VMDK 不支持")
        if info["compress"]:
            raise EasyFSDeviceError("压缩的 VMDK 不支持（compressAlgorithm=%d）"
                                    % info["compress"])
        self.f = open(path, "rb" if read_only else "r+b")
        self.file_size = os.path.getsize(path)
        self.size = info["capacity_bytes"]
        self.kind = "vmdk"
        self.grain_sectors = info["grain_sectors"] or VMDK_GRAIN_SECTORS
        self.grain_bytes = self.grain_sectors * SECTOR
        self.gtes = info["gtes_per_gt"] or VMDK_GTES_PER_GT
        self.gd_offset = info["gd_offset"]
        self.overhead_bytes = info["overhead_sectors"] * SECTOR
        self.n_gt = max(1, (self.size + self.grain_bytes * self.gtes - 1)
                        // (self.grain_bytes * self.gtes))
        raw = self._read(self.gd_offset, self.n_gt * 4)
        self.gd = list(struct.unpack("<%dI" % self.n_gt, raw))
        self.gt = {}                     # gt 号 -> GTE 列表
        self.dirty_gd = False
        self.dirty_gt = set()

    def _read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def _gt_of(self, gi):
        gt_i = gi // self.gtes
        if gt_i not in self.gt:
            base = self.gd[gt_i]
            if base == 0:
                self.gt[gt_i] = [0] * self.gtes
            else:
                raw = self._read(base * SECTOR, self.gtes * 4)
                self.gt[gt_i] = list(struct.unpack("<%dI" % self.gtes, raw))
        return self.gt[gt_i]

    def _set_gte(self, gi, gte):
        gt_i, idx = divmod(gi, self.gtes)
        self._gt_of(gt_i)[idx] = gte
        self.dirty_gt.add(gt_i)
        if self.gd[gt_i] == 0:                       # 这条颗粒表还没落盘
            self.dirty_gd = True

    def _alloc_grain(self):
        """在文件末尾追加一个全零颗粒，返回它的 GTE（扇区号）。"""
        at = max(self.file_size, self.overhead_bytes)
        at = (at + SECTOR - 1) // SECTOR * SECTOR
        self.f.seek(at)
        self.f.write(b"\x00" * self.grain_bytes)
        self.file_size = at + self.grain_bytes
        return at // SECTOR

    def read_at(self, off, n):
        out = bytearray()
        while n > 0:
            gi, in_g = divmod(off, self.grain_bytes)
            take = min(n, self.grain_bytes - in_g)
            if gi >= self.n_gt * self.gtes:
                raise EasyFSDeviceError("VMDK 读越界: @%d" % off)
            gte = self._gt_of(gi)[gi % self.gtes]
            out += (b"\x00" * take if gte == 0
                    else self._read(gte * SECTOR + in_g, take))
            off += take
            n -= take
        return bytes(out)

    def write_at(self, off, data):
        if self.read_only:
            raise EasyFSDeviceError("只读设备")
        data = bytes(data)
        pos = 0
        while pos < len(data):
            gi, in_g = divmod(off, self.grain_bytes)
            take = min(len(data) - pos, self.grain_bytes - in_g)
            gte = self._gt_of(gi)[gi % self.gtes]
            if gte == 0:
                gte = self._alloc_grain()
                self._set_gte(gi, gte)
            self.f.seek(gte * SECTOR + in_g)
            self.f.write(data[pos:pos + take])
            pos += take
            off += take

    def flush(self):
        if self.read_only:
            return
        for gt_i in sorted(self.dirty_gt):           # 颗粒表 → 目录 → 文件
            if self.gd[gt_i] == 0:
                at = max(self.file_size, self.overhead_bytes)
                at = (at + SECTOR - 1) // SECTOR * SECTOR
                self.f.seek(at)
                self.f.write(b"\x00" * (self.gtes * 4))
                self.gd[gt_i] = at // SECTOR
                self.file_size = at + self.gtes * 4
            self.f.seek(self.gd[gt_i] * SECTOR)
            self.f.write(struct.pack("<%dI" % self.gtes, *self.gt[gt_i]))
        if self.dirty_gd or self.dirty_gt:
            self.f.seek(self.gd_offset)
            self.f.write(struct.pack("<%dI" % self.n_gt, *self.gd))
        self.dirty_gd = False
        self.dirty_gt = set()
        self.f.flush()

    def close(self):
        try:
            self.flush()
        finally:
            self.f.close()

    def __repr__(self):
        return "<VmdkDevice %s %d B>" % (self.path, self.size)


def open_container(path, read_only=False):
    """按内容识别并打开一个"磁盘镜像"，返回 ``(Device, 类型字符串)``。"""
    if not os.path.exists(path):
        raise EasyFSDeviceError("文件不存在: " + path)
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(8)
        f.seek(max(0, size - 512))
        tail = f.read(8)
    if head[0:8] == b"vhdxfile":
        raise EasyFSDeviceError("这是 .vhdx（VHDX），本实现只支持 .vhd / raw")
    if tail[0:8] == b"conectix":
        return VhdDevice(path, read_only=read_only), "vhd"
    if tail[0:4] == b"koly":
        raise EasyFSDeviceError(
            "这是 DMG（UDIF）：只能 `tool vdisk` 建 / 看详情，不能当卷载体"
            "（要当载体请用 .vhd / .vmdk / .img）")
    if head[0:4] == b"KDMV":                     # VMDK 稀疏头（小端 magic 0x564D444B）
        return VmdkDevice(path, read_only=read_only), "vmdk"
    return FileDevice(path, read_only=read_only), "raw"


# ================================================================ 分区表

def _guid(raw):
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10]
    d5 = raw[10:16]
    return "%08X-%04X-%04X-%s-%s" % (d1, d2, d3, d4.hex().upper(), d5.hex().upper())


def read_partitions(dev):
    """解析 MBR / GPT，返回 ``(类型, [分区 dict])``。

    分区 dict：``index``（从 1 开始）、``start``、``length``、``type``、``name``、``boot``。
    只处理主分区；扩展分区只报告不展开。
    """
    if dev.size < SECTOR:
        return "none", []
    mbr = dev.read_at(0, SECTOR)
    if mbr[510:512] != b"\x55\xaa":
        return "none", []
    gpt_hdr = None
    if dev.size >= 2 * SECTOR:
        h = dev.read_at(SECTOR, SECTOR)
        if h[0:8] == b"EFI PART":
            gpt_hdr = h
    if gpt_hdr is not None:
        return "gpt", _gpt_parts(dev, gpt_hdr)
    return "mbr", _mbr_parts(mbr)


def _mbr_parts(mbr):
    """MBR 分区项是**小端**（注意：VHD 才是大端）。"""
    parts = []
    for i in range(4):
        e = mbr[446 + i * 16:446 + (i + 1) * 16]
        ptype = e[4]
        start, count = struct.unpack_from("<II", e, 8)
        if ptype == 0 or count == 0:
            continue
        parts.append({
            "index": i + 1,
            "start": start * SECTOR,
            "length": count * SECTOR,
            "type": "0x%02X" % ptype,
            "name": "",
            "boot": e[0] == 0x80,
            "extended": ptype in (0x05, 0x0F, 0x85),
        })
    return parts


def _gpt_parts(dev, hdr):
    """GPT 头与分区项都是**小端**。"""
    entry_lba, count, esize = struct.unpack_from("<QII", hdr, 72)
    count = min(count, 128)
    esize = max(esize, 128)
    raw = dev.read_at(entry_lba * SECTOR, count * esize)
    parts = []
    for i in range(count):
        e = raw[i * esize:(i + 1) * esize]
        if e[0:16] == b"\x00" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        if last < first:
            continue
        name = e[56:128].decode("utf-16-le", "replace").rstrip("\x00")
        parts.append({
            "index": len(parts) + 1,
            "start": first * SECTOR,
            "length": (last - first + 1) * SECTOR,
            "type": _guid(e[0:16]),
            "name": name,
            "boot": False,
            "extended": False,
        })
    return parts


def describe(dev):
    """人类可读的设备描述（给 CLI/日志用）。"""
    return "%s  %s" % (repr(dev), describe_size(dev.size))


def describe_size(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return ("%d B" % n) if unit == "B" else ("%.2f %s" % (n, unit))
        n /= 1024.0
    return "%d B" % n


# ================================================================ 命令行接线

def _open_scoped(path, read_only, offs, size):
    """在容器上取 `[offs, offs+size)`（`size=None` = 到末尾）；`--disk` 用。"""
    dev = FileDevice(path, read_only=read_only)
    if offs == 0 and size is None:
        return dev
    win, _desc = _window(dev, offs, size, path)     # _window 返回 (设备, 描述)
    return win


# --------------------------------------------------------------------------
# 分区标识：MBR 一个字节 / GPT 16 字节 GUID（只改分区表，不碰数据）
#
# GPT 的 GUID 用**纯 ASCII 串**（像 BIOS boot 分区的 `Hah!IdontNeedEFI` 一样）：
# 我们的 16 字节就是 b"easyparteasypart"（正好 16 字节）。
# 注意盘上是**混合字节序**（前三段小端）⇒ 规范串长得不像 ASCII，这是正常的。
# --------------------------------------------------------------------------
MBR_TYPE_EASYFS = 0x7F

GPT_TYPE_EASYFS = b"easyparteasypart"           # 恰好 16 字节


def guid_text(raw):
    """16 字节 → 规范 GUID 串（与 `sgdisk -p` 显示的一致）。"""
    return _guid(raw)


def guid_bytes(text):
    """GUID 文本 → 16 字节：接受 16 字符 ASCII 串（如 `easyparteasypart`）或规范串。"""
    if isinstance(text, (bytes, bytearray)):
        if len(text) != 16:
            raise EasyFSDeviceError("GUID 必须是 16 字节")
        return bytes(text)
    t = str(text).strip()
    if len(t) == 16 and all(32 <= ord(c) < 127 for c in t):
        return t.encode("ascii")
    h = t.replace("-", "")
    if len(h) != 32:
        raise EasyFSDeviceError("GUID 看不懂: %r（给 16 字符 ASCII，或 8-4-4-4-12 十六进制）"
                                % text)
    try:
        raw = bytearray(bytes.fromhex(h))
    except ValueError:
        raise EasyFSDeviceError("GUID 不是十六进制: %r" % text)
    raw[0:4] = raw[0:4][::-1]                   # 规范串 → 盘上：前三段小端
    raw[4:6] = raw[4:6][::-1]
    raw[6:8] = raw[6:8][::-1]
    return bytes(raw)


# --------------------------------------------------------------------------
# 建分区表（MBR / GPT）：默认建**一个占满的分区**，类型直接写成我们的标识
# --------------------------------------------------------------------------
def _chs(lba):
    """LBA → CHS 三字节（255 头 / 63 扇区，跟常见实现一致）。"""
    c = lba // (255 * 63)
    h = (lba // 63) % 255
    s = lba % 63 + 1
    return bytes(bytearray([h & 0xFF, (s & 0x3F) | ((c >> 2) & 0xC0), c & 0xFF]))


def create_mbr(dev, part_index=1, start=None, length=None, ptype=MBR_TYPE_EASYFS,
               dry_run=False):
    """在 `dev` 上建一张 MBR 表 + 一个分区。返回分区描述。"""
    total = dev.size // SECTOR
    if total < 2048:
        raise EasyFSDeviceError("容器太小，放不下分区表（至少 1 MiB）")
    if not (1 <= part_index <= 4):
        raise EasyFSDeviceError("MBR 只有 4 个主分区项（--part 1..4）")
    if start is None:
        start = 1 << 20                                  # 默认从 1 MiB 开始（字节）
    start = (start + SECTOR - 1) // SECTOR            # 入参是**字节**，转成 LBA
    if length is None:
        length = (total - start) * SECTOR
    length = length // SECTOR * SECTOR
    cnt = length // SECTOR
    if cnt <= 0 or start + cnt > total:
        raise EasyFSDeviceError("分区放不下：start=%d 扇区 count=%d（容器 %d 扇区）"
                                % (start, cnt, total))
    if cnt > 0xFFFFFFFF:
        raise EasyFSDeviceError("MBR 单个分区不能超过 2 TiB（用 GPT）")
    mbr = bytearray(SECTOR)
    mbr[440:444] = struct.pack("<I", zlib.crc32(b"easyfs") & 0xFFFFFFFF)   # 磁盘签名
    off = 446 + (part_index - 1) * 16
    mbr[off + 0] = 0x00                                  # 不可引导
    mbr[off + 1:off + 4] = _chs(start)
    mbr[off + 4] = ptype
    mbr[off + 5:off + 8] = _chs(start + cnt - 1)
    mbr[off + 8:off + 12] = struct.pack("<I", start)
    mbr[off + 12:off + 16] = struct.pack("<I", cnt)
    mbr[510:512] = b"\x55\xaa"
    if not dry_run:
        dev.write_at(0, bytes(mbr))
        dev.flush()
    return {"table": "mbr", "index": part_index, "start": start * SECTOR,
            "length": cnt * SECTOR, "type": ptype}


def _guid_raw():
    import uuid
    return uuid.uuid4().bytes_le                          # GPT 盘上就是这种字节序


def create_gpt(dev, part_index=1, start=None, length=None,
               type_raw=GPT_TYPE_EASYFS, name="EasyFS", dry_run=False):
    """在 `dev` 上建一张 GPT（保护性 MBR + 主/备两份头 + 128 个分区项）。"""
    total = dev.size // SECTOR
    if total < 4096:
        raise EasyFSDeviceError("容器太小，放不下 GPT（至少 2 MiB）")
    n_ent, ent_size = 128, 128
    ent_sectors = n_ent * ent_size // SECTOR              # 32 扇区
    first_usable = 2 + ent_sectors                        # 34
    last_usable = total - 1 - ent_sectors - 1             # 备份头在最后 1 扇区
    if start is None:
        start = 1 << 20                              # 默认从 1 MiB 开始（字节）
    start = (start + SECTOR - 1) // SECTOR            # 入参是**字节**，转成 LBA
    if length is None:
        length = (last_usable + 1 - start) * SECTOR
    length = length // SECTOR * SECTOR
    cnt = length // SECTOR
    if not (1 <= part_index <= n_ent):
        raise EasyFSDeviceError("GPT 有 %d 个分区项（--part 1..%d）" % (n_ent, n_ent))
    if start < first_usable or cnt <= 0 or start + cnt - 1 > last_usable:
        raise EasyFSDeviceError(
            "分区放不下：start=%d count=%d（可用 [%d, %d]）"
            % (start, cnt, first_usable, last_usable))
    disk_guid = _guid_raw()
    part_guid = _guid_raw()
    # 分区项数组
    ent = bytearray(n_ent * ent_size)
    o = (part_index - 1) * ent_size
    ent[o:o + 16] = type_raw
    ent[o + 16:o + 32] = part_guid
    struct.pack_into("<Q", ent, o + 32, start)            # first LBA
    struct.pack_into("<Q", ent, o + 40, start + cnt - 1)  # last LBA
    struct.pack_into("<Q", ent, o + 48, 0)                # flags
    nm = name.encode("utf-16-le")[:72]
    ent[o + 56:o + 56 + len(nm)] = nm
    ent_crc = zlib.crc32(bytes(ent)) & 0xFFFFFFFF

    def header(my_lba, alt_lba, ent_lba, first_u, last_u):
        h = bytearray(SECTOR)
        h[0:8] = b"EFI PART"
        struct.pack_into("<I", h, 8, 0x00010000)          # revision 1.0
        struct.pack_into("<I", h, 12, 92)                 # header_size
        struct.pack_into("<Q", h, 24, my_lba)
        struct.pack_into("<Q", h, 32, alt_lba)
        struct.pack_into("<Q", h, 40, first_u)
        struct.pack_into("<Q", h, 48, last_u)
        h[56:72] = disk_guid
        struct.pack_into("<Q", h, 72, ent_lba)
        struct.pack_into("<I", h, 80, n_ent)
        struct.pack_into("<I", h, 84, ent_size)
        struct.pack_into("<I", h, 88, ent_crc)
        struct.pack_into("<I", h, 16, 0)
        struct.pack_into("<I", h, 16, _hdr_crc(h, 92))
        return bytes(h)

    # 保护性 MBR
    pm = bytearray(SECTOR)
    pm[446 + 4] = 0xEE
    pm[446 + 5:446 + 8] = _chs(min(total - 1, 0xFFFFFF))
    struct.pack_into("<I", pm, 446 + 8, 1)
    struct.pack_into("<I", pm, 446 + 12, min(total - 1, 0xFFFFFFFF))
    pm[510:512] = b"\x55\xaa"
    if not dry_run:
        dev.write_at(0, bytes(pm))
        dev.write_at(SECTOR, header(1, total - 1, 2, first_usable, last_usable))
        dev.write_at(2 * SECTOR, bytes(ent))              # 主项数组
        dev.write_at((total - 1 - ent_sectors) * SECTOR, bytes(ent))   # 备份项数组
        dev.write_at((total - 1) * SECTOR,
                     header(total - 1, 1, total - 1 - ent_sectors,
                            first_usable, last_usable))
        dev.flush()
    return {"table": "gpt", "index": part_index, "start": start * SECTOR,
            "length": cnt * SECTOR, "type": guid_text(type_raw), "name": name}


def _gpt_geometry(dev):
    """读主头，返回各项（含项数组的绝对偏移）。"""
    if dev.size < 2 * SECTOR:
        raise EasyFSDeviceError("太小，没有 GPT")
    hdr = bytearray(dev.read_at(SECTOR, SECTOR))
    if hdr[0:8] != b"EFI PART":
        raise EasyFSDeviceError("第 1 扇区不是 GPT 头（EFI PART）")
    g = {}
    g["hdr"] = hdr
    g["hdr_size"] = struct.unpack_from("<I", hdr, 12)[0]
    g["my_lba"] = struct.unpack_from("<Q", hdr, 24)[0]
    g["alt_lba"] = struct.unpack_from("<Q", hdr, 32)[0]
    g["ent_lba"] = struct.unpack_from("<Q", hdr, 72)[0]
    g["n_ent"] = struct.unpack_from("<I", hdr, 80)[0]
    g["ent_size"] = struct.unpack_from("<I", hdr, 84)[0]
    if not (128 <= g["ent_size"] <= 4096) or g["n_ent"] == 0:
        raise EasyFSDeviceError("GPT 头里的项数组参数不对（size=%d n=%d）"
                                % (g["ent_size"], g["n_ent"]))
    g["arr_off"] = g["ent_lba"] * SECTOR
    g["arr_len"] = g["n_ent"] * g["ent_size"]
    return g


def _hdr_crc(hdr, hsize):
    """头的 CRC：把 CRC 字段当 0，覆盖前 `hsize` 字节。"""
    b = bytearray(hdr[:hsize])
    struct.pack_into("<I", b, 16, 0)
    return zlib.crc32(bytes(b)) & 0xFFFFFFFF


def verify_gpt(dev):
    """检查主/备 GPT 头与项数组是否自洽；返回问题列表（空 = 没问题）。"""
    bad = []
    try:
        g = _gpt_geometry(dev)
    except EasyFSDeviceError as e:
        return ["主头读不了: %s" % e]
    arr = dev.read_at(g["arr_off"], g["arr_len"])
    if zlib.crc32(arr) & 0xFFFFFFFF != struct.unpack_from("<I", g["hdr"], 88)[0]:
        bad.append("主头里的项数组 CRC 与数组对不上")
    if _hdr_crc(g["hdr"], g["hdr_size"]) != struct.unpack_from("<I", g["hdr"], 16)[0]:
        bad.append("主头自己的 CRC 不对")
    alt = g["alt_lba"] * SECTOR
    if alt + SECTOR <= dev.size:
        bh = bytearray(dev.read_at(alt, SECTOR))
        if bh[0:8] == b"EFI PART":
            bhsize = struct.unpack_from("<I", bh, 12)[0]
            bent = struct.unpack_from("<Q", bh, 72)[0]
            blen = struct.unpack_from("<I", bh, 80)[0] * struct.unpack_from("<I", bh, 84)[0]
            barr = dev.read_at(bent * SECTOR, blen)
            if barr != arr:
                bad.append("备份项数组与主项数组不一致")
            if zlib.crc32(barr) & 0xFFFFFFFF != struct.unpack_from("<I", bh, 88)[0]:
                bad.append("备份头里的项数组 CRC 不对")
            if _hdr_crc(bh, bhsize) != struct.unpack_from("<I", bh, 16)[0]:
                bad.append("备份头自己的 CRC 不对")
        else:
            bad.append("找不到备份 GPT 头（@%d）" % alt)
    return bad


def set_partition_type(dev, index, kind, dry_run=False):
    """把**已有分区**的标识改成我们的：`kind` = "mbr"（0x7F）或 "gpt"（`easyparteasypart`）。

    只动分区表，**不碰任何数据**。GPT 会同时更新主/备两份头与两份项数组。
    """
    if index is None or index < 1:
        raise EasyFSDeviceError("要指定分区号（--part N）")
    table, parts = read_partitions(dev)
    if table == "none":
        raise EasyFSDeviceError("这个容器里没有分区表")
    if kind == "mbr":
        if table != "mbr":
            raise EasyFSDeviceError("这是 %s 分区表，不是 MBR（用 `gpt --seteasy`）" % table.upper())
        mbr = bytearray(dev.read_at(0, SECTOR))
        off = 446 + (index - 1) * 16
        old = mbr[off + 4]
        if old == 0:
            raise EasyFSDeviceError("MBR 里没有 %d 号分区" % index)
        mbr[off + 4] = MBR_TYPE_EASYFS
        if not dry_run:
            dev.write_at(0, bytes(mbr))
            dev.flush()
        return "MBR 分区 #%d：类型 0x%02X → 0x%02X（我们的标识）" % (index, old, MBR_TYPE_EASYFS)
    if kind == "gpt":
        if table != "gpt":
            raise EasyFSDeviceError("这是 %s 分区表，不是 GPT（用 `mbr --seteasy`）" % table.upper())
        g = _gpt_geometry(dev)
        if index > g["n_ent"]:
            raise EasyFSDeviceError("GPT 只有 %d 个分区项（要 #%d）" % (g["n_ent"], index))
        arr = bytearray(dev.read_at(g["arr_off"], g["arr_len"]))
        off = (index - 1) * g["ent_size"]
        old = bytes(arr[off:off + 16])
        if old == b"\x00" * 16:
            raise EasyFSDeviceError("GPT 里没有 %d 号分区（类型是全 0）" % index)
        arr[off:off + 16] = GPT_TYPE_EASYFS
        if not dry_run:
            # ① 主项数组 + 主头 CRC
            dev.write_at(g["arr_off"], bytes(arr))
            h = g["hdr"]
            struct.pack_into("<I", h, 88, zlib.crc32(bytes(arr)) & 0xFFFFFFFF)
            struct.pack_into("<I", h, 16, _hdr_crc(h, g["hdr_size"]))
            dev.write_at(g["my_lba"] * SECTOR, bytes(h))
            # ② 备份项数组 + 备份头 CRC（必须一起改，否则两份不一致）
            alt = g["alt_lba"] * SECTOR
            if alt + SECTOR <= dev.size:
                bh = bytearray(dev.read_at(alt, SECTOR))
                if bh[0:8] == b"EFI PART":
                    bent = struct.unpack_from("<Q", bh, 72)[0]
                    bhsize = struct.unpack_from("<I", bh, 12)[0]
                    dev.write_at(bent * SECTOR, bytes(arr))
                    struct.pack_into("<I", bh, 88, zlib.crc32(bytes(arr)) & 0xFFFFFFFF)
                    struct.pack_into("<I", bh, 16, _hdr_crc(bh, bhsize))
                    dev.write_at(alt, bytes(bh))
            dev.flush()
        return "GPT 分区 #%d：类型 %s → %s" % (index, guid_text(old), guid_text(GPT_TYPE_EASYFS))
    raise EasyFSDeviceError("不认识的标识类型: %r" % kind)


def add_disk_safety_args(ap, with_force=True):
    """给**会写盘**的命令自己加上 `--yes` / `--force`（`--disk` 的确认与强行越过）。

    放在这里而不是 `add_device_args` 里，是因为它们是**主命令自己的细节参数**：
    各命令自己定义、自己负责，也避免和别人的 `--force`（如 sftpcli = 覆盖文件）撞车。
    `--force` 的 dest 用 `disk_force`，就是为了不撞。
    """
    ap.add_argument("--yes", dest="yes", action="store_true",
                    help="跳过 --disk 的确认（脚本用；非交互环境必须给）")
    if with_force:                       # sftpcli/server 自己有 --force（= 覆盖文件），就不给了
        ap.add_argument("--force", dest="disk_force", action="store_true",
                        help="越过 --disk 的保护（已挂载 / 根文件系统这两条拒绝）")


def add_device_args(ap, required=True, with_create=True):
    """给 argparse 加上设备相关参数（`--file` / `--vdisk` / `--mem` 三选一）。

    区域参数 `--offs` / `--size` 描述"**卷在容器的哪一段**"，都不给 = 整个文件。
    """
    g = ap.add_mutually_exclusive_group(required=required)
    g.add_argument("--file", help="卷所在的文件（默认整个文件就是卷）")
    g.add_argument("--vdisk", help="磁盘镜像（.img / .vhd），自动识别并解析分区表")
    g.add_argument("--mem", help="用一块内存当卷，如 64M（不落盘，演示/测试用）")
    g.add_argument("--disk", help="**真实磁盘设备**（如 /dev/sda）：会先打印盘信息并要求确认；"
                                  "分区设备（/dev/sda1）直接用 --file 即可")
    ap.add_argument("--part", type=int,
                    help="分区号（从 1 开始）；与 --offs/--size 二选一")
    ap.add_argument("--offs", default="0", help="区域起始偏移，默认 0")
    ap.add_argument("--size", help="区域长度；不给 = 从 --offs 到容器末尾")
    if with_create:
        ap.add_argument("--vhd", choices=("dynamic", "fixed"), default="dynamic",
                        help="--vdisk 指向不存在的文件时，按这个类型新建（默认 dynamic）")


def _window(dev, offs, size, desc):
    """在 `dev` 上取区域 `[offs, offs+size)`；`size` 为 None 表示到末尾。"""
    if size is None:
        size = dev.size - offs
    win = RegionDevice(dev, offs, size, name=desc)
    return win, "%s [%s, +%s)" % (desc, describe_size(offs), describe_size(size))


# --------------------------------------------------------------------------
# 块设备（真实磁盘 / 分区）：容量必须问内核，**绝不能 os.path.getsize**（返回 0）
# --------------------------------------------------------------------------
BLKGETSIZE64 = 0x80081272          # linux/fs.h（x86_64 等常见架构）


def is_block_device(path):
    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def _sysfs(path, *names):
    """读 `/sys/class/block/<盘>/<...>`（只读，不需要设备权限）。"""
    real = os.path.realpath(path)
    base = os.path.basename(real)
    parent = base.rstrip("0123456789") or base     # /dev/sda1 → sda
    for who in (base, parent):
        for nm in names:
            try:
                with open("/sys/class/block/%s/%s" % (who, nm)) as f:
                    v = f.read().strip()
                if v:
                    return v
            except Exception:
                pass
    return ""


def block_device_size(path):
    """块设备的字节容量：ioctl(BLKGETSIZE64) → lseek → sysfs。"""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        n = _sysfs(path, "size")
        if n:
            return int(n) * 512
        raise EasyFSDeviceError("打不开块设备 %s：%s" % (path, e))
    try:
        try:
            import fcntl
            buf = bytearray(8)
            fcntl.ioctl(fd, BLKGETSIZE64, buf, True)
            n = struct.unpack("<Q", bytes(buf))[0]
            if n:
                return n
        except Exception:
            pass
        try:
            n = os.lseek(fd, 0, os.SEEK_END)
            if n:
                return n
        except Exception:
            pass
        n = _sysfs(path, "size")
        if n:
            return int(n) * 512
        raise EasyFSDeviceError("读不出块设备容量：%s" % path)
    finally:
        os.close(fd)


def is_partition_node(path):
    return bool(_sysfs(path, "partition"))


def _mounts():
    out = []
    try:
        with open("/proc/mounts") as f:
            for ln in f:
                a = ln.split()
                if len(a) >= 2:
                    out.append((a[0], a[1]))
    except Exception:
        pass
    return out


def disk_mounts(path):
    """这个盘（整盘 = 含它的所有分区；分区 = 它自己）上被挂载的 (设备, 挂载点)。"""
    real = os.path.realpath(path)
    base = os.path.basename(real)
    whole = not is_partition_node(path)          # 整盘 ⇒ 匹配 sda、sda1、sda2…
    hits = []
    for src, mnt in _mounts():
        r = os.path.realpath(src) if src.startswith("/") else src
        b = os.path.basename(r) if r.startswith("/") else r
        if r == real or b == base or (whole and b.startswith(base)):
            hits.append((src, mnt))
    return hits


def root_disk_mounted(path):
    """`/` 是否就在这个盘上（最危险的那种误操作）。"""
    hits = dict((m, d) for d, m in disk_mounts(path)) if False else None
    for d, m in disk_mounts(path):
        if m == "/":
            return True
    return False


def disk_info_lines(path):
    """打印前的"这个盘是什么"（只读 sysfs / /proc/mounts，不需要设备权限）。"""
    real = os.path.realpath(path)
    size = 0
    for get in (lambda: block_device_size(path), lambda: os.path.getsize(path)):
        try:
            size = get()
            if size:
                break
        except Exception:
            pass
    L = []
    L.append("  设备          %s%s" % (path, "" if real == path else "（→ %s）" % real))
    L.append("  容量          %s (%d B)" % (describe_size(size), size))
    L.append("  型号/厂商     %s / %s" % (_sysfs(path, "device/model") or "?",
                                          _sysfs(path, "device/vendor") or "?"))
    L.append("  序列          %s" % (_sysfs(path, "device/serial") or "?"))
    L.append("  可移动        %s" % ({"1": "是", "0": "否"}.get(_sysfs(path, "removable"), "?")))
    L.append("  逻辑/物理扇区 %s / %s" % (_sysfs(path, "queue/logical_block_size") or "?",
                                          _sysfs(path, "queue/physical_block_size") or "?"))
    L.append("  类型          %s" % ("分区" if is_partition_node(path) else "整盘"))
    m = disk_mounts(path)
    L.append("  挂载          %s" % (", ".join("%s → %s" % x for x in m) if m else "无"))
    if root_disk_mounted(path):
        L.append("  根文件系统    ✗✗ **就在这个盘上**（/ 挂在这里）")
    else:
        L.append("  根文件系统    否 ✓")
    return L


def confirm_ask(lines=(), assume_yes=False,
                question="继续吗？[y/N]（脚本里加 --yes 就免问） "):
    """通用确认：先把要干的事打出来 → 问一句 → `--yes` 视为用户答了 y。

    非交互（管道 / 脚本）且没给 `--yes` ⇒ **拒绝**，不替人做决定 ✓。
    """
    for ln in lines:
        print(ln)
    sys.stdout.flush()
    if assume_yes:
        print("  已确认（--yes）")
        return
    if not sys.stdin.isatty():
        raise EasyFSDeviceError(
            "非交互环境：拿不准的破坏性操作，请显式加 --yes 确认（我不替人做决定）")
    sys.stdout.write("  " + question)
    sys.stdout.flush()
    got = sys.stdin.readline().strip().lower()
    if got not in ("y", "yes"):
        raise EasyFSDeviceError("已取消（输入的是 %r；回车即取消）" % got)
    print("  已确认 ✓")

def confirm_dangerous_disk(path, lines, force=False, assume_yes=False, extra="",
                           allow_mounted=False):
    """`--disk` 的仪式：先亮出这个盘是什么 → 拒绝挂载中/系统盘 → 要求确认。"""
    print("⚠️  --disk 指向**整块真实设备**（不是镜像）：下面的操作直接写硬件。")
    for ln in lines:
        print(ln)
    if extra:
        print(extra)
    m = disk_mounts(path)
    if m and not force and not allow_mounted:
        raise EasyFSDeviceError(
            "拒绝：这个盘（或其分区）正被挂载：%s\n"
            "  先卸载（umount …）再来；确实要强行继续：--force"
            % ", ".join("%s → %s" % x for x in m))
    if m and allow_mounted:
        print("  提示          这个盘（或其分区）正被挂载：%s"
              % ", ".join("%s → %s" % x for x in m))
        print("                （只改分区类型，不碰数据；但被挂载时重新读表可能要等 umount ✓）")
    if root_disk_mounted(path) and not force:
        raise EasyFSDeviceError("拒绝：**根文件系统 `/` 就在这个盘上**，继续会毁掉正在运行的系统。"
                                "（真要继续：--force，并先备份/确认你在做什么）")
    sys.stdout.flush()
    if assume_yes:
        print("  已确认（--yes）")
        return
    print("  接下来会**销毁该盘上的全部分区表与数据**。")
    confirm_ask(assume_yes=assume_yes)


def open_device(args, create_size=None, read_only=False):
    """把上面那组参数变成一个设备，返回 ``(Device, 描述字符串)``。

    区域 = ``[--offs, --offs + --size)``；``--size`` 省略 = 到容器末尾。
    ``--part`` 与 ``--offs/--size`` 二选一。

    `create_size`：容器不存在时的默认总大小；`--size` 给了就以 `offs + size` 为准。
    """
    offs = _parse_size(args.offs) if getattr(args, "offs", None) else 0
    size = _parse_size(args.size) if getattr(args, "size", None) else None
    part = getattr(args, "part", None)
    if part is not None and (offs or size is not None):
        raise EasyFSDeviceError("--part 与 --offs/--size 二选一（都是「卷在哪」，别混用）")

    if getattr(args, "disk", None):
        # `--disk` = "容器是**真实块设备**"（危险目标）⇒ 打印盘信息 + 危险检查 + 确认。
        # "卷在哪" 用和 `--vdisk` **完全同一套规则**：不给区域时绝不悄悄吃掉分区表。
        path = args.disk
        if not os.path.exists(path):
            raise EasyFSDeviceError("设备不存在: %s" % path)
        if not is_block_device(path):
            raise EasyFSDeviceError(
                "--disk 只接**块设备**（%s 不是）；磁盘镜像请用 --vdisk，普通文件/分区设备请用 --file"
                % path)
        force = bool(getattr(args, "disk_force", False))
        yes = bool(getattr(args, "yes", False))
        base_lines = disk_info_lines(path)

        def _bail(msg, extra_lines=()):
            """拒绝时：先把盘信息（+分区表）打出来，再报错 —— 让用户知道拒的是哪个盘。"""
            print("✗✗ 已拒绝（**没有动这个盘**）")
            for ln in list(base_lines) + [x for x in extra_lines if x]:
                print(ln)
            sys.stdout.flush()
            raise EasyFSDeviceError(msg)

        # ① 危险目标检查（不需要设备权限就能判：挂载中 / 根文件系统）
        if not read_only and not force:
            m = disk_mounts(path)
            if m:
                _bail("这个盘（或其分区）**正被挂载**：%s\n"
                      "  先 umount 再来（U 盘常被桌面自动挂载）；确实要强行继续：--force"
                      % ", ".join("%s → %s" % x for x in m))
            if root_disk_mounted(path):
                _bail("**根文件系统 `/` 就在这个盘上**，继续会毁掉正在运行的系统"
                      "（真要继续：--force）")
        # ② 打开（读；块设备容量问内核，绝不 truncate）—— 打不开也先亮盘信息
        try:
            dev = FileDevice(path, read_only=True)
        except EasyFSDeviceError:
            for ln in base_lines:
                print(ln)
            sys.stdout.flush()
            raise
        extra = ""
        try:
            table, parts = read_partitions(dev)
        except Exception:
            table, parts = "none", []
        if parts:
            extra += "\n  分区表        %s（%d 个分区）" % (table.upper(), len(parts))
            for q in parts:
                extra += ("\n    #%d %-8s @%-12d %-11s %s" %
                          (q["index"], q["type"], q["start"], describe_size(q["length"]),
                           ("引导 " if q["boot"] else "") + q["name"]))
        # ③ "卷在哪"：与 --vdisk 同一套规则
        note = None
        if part is not None:
            sel = [q for q in parts if q["index"] == part]
            if not sel:
                dev.close()
                _bail("没有 %d 号分区（共 %d 个）" % (part, len(parts)), [extra])
            q = sel[0]
            dev.close()
            dev = _open_scoped(path, read_only, q["start"], q["length"])
            note = "  %s 分区 #%d @%d +%s" % (table.upper(), q["index"], q["start"],
                                              describe_size(q["length"]))
        elif offs or size is not None:
            dev.close()
            dev = _open_scoped(path, read_only, offs, None if size is None else size)
            note = "@%d +%s" % (offs, describe_size(dev.size))
        elif not parts:
            note = "整盘（这个盘没有分区表）"
        elif len(parts) == 1:
            q = parts[0]
            dev.close()
            dev = _open_scoped(path, read_only, q["start"], q["length"])
            note = ("自动选了唯一的 %s 分区 #%d @%d +%s"
                    % (table.upper(), q["index"], q["start"], describe_size(q["length"])))
        else:
            dev.close()
            _bail("这个盘有 %d 个分区，**不能替你猜**：请用 --part N 选一个"
                  "（或用 --offs/--size 指定范围；要整个盘当卷就显式写 --offs 0）"
                  % len(parts), [extra])
        desc = "块设备 %s（%s） → %s" % (path, describe_size(
            block_device_size(path) if is_block_device(path) else dev.size), note)
        lines = base_lines + ([extra] if extra else [])
        if read_only:
            for ln in lines:
                print(ln)
            print("  卷所在        %s" % note)
            sys.stdout.flush()
            return dev, desc
        # ④ 确认仪式（打印盘信息 + 分区表 + 卷在哪 → [y/N]）
        confirm_dangerous_disk(path, lines, force=force, assume_yes=yes,
                               extra="  卷所在        %s" % note)
        # ⑤ 确认之后才按**可写**方式重新打开
        dev.close()
        dev = FileDevice(path, read_only=False)
        try:
            table, parts = read_partitions(dev)
        except Exception:
            parts = []
        if part is not None:
            q = [x for x in parts if x["index"] == part][0]
            dev = RegionDevice(dev, q["start"], q["length"], name="part%d" % q["index"])
        elif offs or size is not None:
            dev = _window(dev, offs, size, "disk[%d,%s)" % (offs, size))
        elif len(parts) == 1:
            q = parts[0]
            dev = RegionDevice(dev, q["start"], q["length"], name="part%d" % q["index"])
        return dev, desc

    if getattr(args, "mem", None):
        dev = MemDevice(_parse_size(args.mem))
        return dev, "内存 %s" % describe_size(dev.size)

    if getattr(args, "vdisk", None):
        path = args.vdisk
        if not os.path.exists(path):
            total = (offs + size) if size is not None else create_size
            if not total:
                raise EasyFSDeviceError("镜像不存在: %s（给 --size 可新建）" % path)
            ext = os.path.splitext(path)[1].lower()
            if ext == ".vmdk":
                create_vmdk(path, total)
            elif ext in (".img", ".raw", ""):
                with open(path, "wb") as f:
                    f.truncate(total)
            else:                                   # .vhd（及未知名，保持老行为）
                create_vhd(path, total,
                           dynamic=(getattr(args, "vhd", "dynamic") == "dynamic"))
        dev, kind = open_container(path, read_only=read_only)
        desc = "%s（%s，虚拟 %s）" % (kind, path, describe_size(dev.size))

        if part is not None:
            table, parts = read_partitions(dev)
            sel = [p for p in parts if p["index"] == part]
            if not sel:
                raise EasyFSDeviceError("没有 %d 号分区（共 %d 个）"
                                        % (part, len(parts)))
            p = sel[0]
            dev = RegionDevice(dev, p["start"], p["length"],
                               name="part%d" % p["index"])
            return dev, ("%s → %s 分区 #%d @%d %s"
                         % (desc, table.upper(), p["index"], p["start"],
                            describe_size(p["length"])))

        if offs or size is not None:
            dev, wdesc = _window(dev, offs, size, path)
            return dev, "%s → %s" % (desc, wdesc)

        # 没给区域：盘里有分区就自动用（单个自动选，多个要求 --part），没有就整盘
        table, parts = read_partitions(dev)
        if not parts:
            return dev, desc + " → 无分区表，按整盘处理"
        if len(parts) > 1:
            raise EasyFSDeviceError(
                "%s 分区表里有 %d 个分区，请用 --part 选（或用 --offs/--size 指定区域）：%s"
                % (table.upper(), len(parts),
                   "  ".join("#%d %s %s" % (q["index"], q["type"],
                                            describe_size(q["length"]))
                             for q in parts)))
        p = parts[0]
        dev = RegionDevice(dev, p["start"], p["length"],
                           name="part%d" % p["index"])
        return dev, ("%s → %s 分区 #%d @%d %s"
                     % (desc, table.upper(), p["index"], p["start"],
                        describe_size(p["length"])))

    path = args.file
    created = not os.path.exists(path)
    if created:
        total = (offs + size) if size is not None else create_size
        if not total:
            raise EasyFSDeviceError("文件不存在: %s" % path)
        FileDevice(path, size=total, read_only=read_only).close()

    if offs or size is not None:
        base = FileDevice(path, read_only=read_only)
        if offs + (size if size is not None else 0) > base.size:
            base.close()
            raise EasyFSDeviceError(
                "区域 [%s, +%s) 超出容器（%s）；先把容器弄大，或改小 --size"
                % (describe_size(offs),
                   describe_size(size if size is not None else 0),
                   describe_size(base.size)))
        dev, wdesc = _window(base, offs, size, path)
        return dev, wdesc + ("（新建）" if created else "")

    dev = FileDevice(path, read_only=read_only)
    return dev, "%s（%s%s）" % (path, describe_size(dev.size),
                               "，新建" if created else "")


def open_container_device(args, read_only=False):
    """打开**容器本身**（不裁区域）—— `resize` 需要它，因为它要同时看到旧新两个区域。

    与 `open_device` 的区别：这里忽略 `--offs/--size/--part`，也拒绝 `--mem`
    （内存卷每次调用都是新的，resize 没有意义）。
    """
    if getattr(args, "mem", None):
        raise EasyFSDeviceError("--mem 是内存卷，每次调用都是新建的，resize 没有意义")
    # `--part N` 允许：它代替 --offs/--size 说明"**改前位置**"（= 那个分区的范围）。
    # 这里只是借用它的几何，**不写分区表**（分区表是别人管的 ✓）。
    if getattr(args, "disk", None):
        path = args.disk
        if not os.path.exists(path):
            raise EasyFSDeviceError("设备不存在: %s" % path)
        if not is_block_device(path):
            raise EasyFSDeviceError("--disk 只接块设备（%s 不是）；镜像请用 --vdisk"
                                    % path)
        if read_only:
            for _ln in disk_info_lines(path):
                print(_ln)
        else:
            # resize / optimize 会改 anchor 与位图 ⇒ 挂载中/系统盘一律拒（要 --force）
            confirm_dangerous_disk(
                path, disk_info_lines(path),
                force=bool(getattr(args, "disk_force", False)),
                assume_yes=bool(getattr(args, "yes", False)),
                extra="  （本命令会改 anchor / 位图；**不搬数据**）")
        dev = FileDevice(path, read_only=read_only)
        return dev, "块设备 %s（%s）" % (path, describe_size(dev.size))
    if getattr(args, "vdisk", None):
        dev, kind = open_container(args.vdisk, read_only=read_only)
        return dev, "%s（%s，虚拟 %s）" % (kind, args.vdisk,
                                          describe_size(dev.size))
    path = args.file
    if not os.path.exists(path):
        raise EasyFSDeviceError("文件不存在: %s" % path)
    dev = FileDevice(path, read_only=read_only)
    return dev, "%s（%s）" % (path, describe_size(dev.size))


def _parse_size(text):
    """'64M' / '4K' / '1048576' -> int（与 easyfs.parse_size 同义，此处自带一份）"""
    s = str(text).strip().lower().replace("_", "")
    mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(s, 0)
