#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 格式层（库）

这是 EasyFS 的**唯一实现层**：块头、设备、anchor、位图、分配、目录与属性解析。
外层工具（``tool-ctrl.py`` / ``tool-sftpcli.py`` / ``tool-server.py``，统一入口 ``tool.py``）
都只是它的薄壳；设备实现见 ``easyfs_device.py``。

格式规格（唯一权威）在 ``doc/``：

* ``doc/common.md``  §1 坐标（自相对 delta、逻辑坐标 L）、§2 通用 4K 块头、§4 不变量
* ``doc/layout.md``  §1 区域几何、§2 anchor 字段表、§3 挂载/发现、§4 逻辑坐标
* ``doc/1-alloc.md`` §3 位图块、§4 自举（mkfs）、§5 分配策略、§7 崩溃一致性
* ``doc/2-dir.md``   §2 TLV 属性、§3 目录块、§5 条目增删改

只依赖标准库；兼容 Python 3.6+（不用 3.7+ 的语法）。
"""

import bisect
import os
import struct
import sys
import uuid as uuidlib
import zlib

try:
    from easyfs_device import Device, FileDevice, MemDevice, RegionDevice

except ImportError:                                   # 直接以文件路径 import 时兜底
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from easyfs_device import Device, FileDevice, MemDevice, RegionDevice

# 全部格式定义与配置值的唯一来源（改格式 = 改 easyfs_config.py + doc/）
from easyfs_config import *      # noqa: F401,F403

# ================================================================ 1. 常量

# pool 段（anchor 块 [0x200,0x400)，【将来方向】见 raid.md §5）的魔数；v0 只占位、不读写

# 块类型（common.md §3）：0 无效 / 1 位图 / 2 目录 / 3 硬链接 / 4 文件数据 / 5 anchor / 6 坏块


# root_type：根的引用种类（5-anchor.md §2.1）
ROOT_TYPE_NONE, ROOT_TYPE_CHAIN, ROOT_TYPE_OBJECT = 0, 1, 2   # 3–255 保留
ALLOC_HDR = 96         # 位图块：64 通用 + 32 位图扩展（1-alloc.md §3.2）

# TLV 属性类型（2-dir.md §2.1）—— **按家族分段**
#
#   0x00–0x0D 未使用（0x08 曾是 CONT，已退场）→ 读到一律当损坏
#   0x0E/0x0F 占位：PAD1（固定 1 字节）/ PADn（TLV：len 可为 0，最小 2 字节）
#   0x10–0x1F data 家族：承载"文件内容 / 内容映射"
#   0x20–0x2F symlink 家族（软链接）；0x30–0x3F hardlink 家族（硬链接）
#   0x40 起：名字 / 目录 / 时间（同类相邻）


# 曾有一个按 L 寻址的指针属性（ATTR_DATA_PTR_LOGICAL）—— 已退休：
#      "指向对象、由对象再找文件" 由 ATTR_DATA_OBJECT（0x30）承担
# 0x14–0x1F 保留给 data 家族

# 0x23–0x2F 保留给 symlink 家族

# 0x32–0x3F 保留给 hardlink 家族

# 0x45 起继续分配，同类相邻


# 承载体内容的属性：普通文件与软链接**共用同一套逻辑布局**（4-file.md §4）


# 每字节里 1 的个数，用于按字节 popcount（bytearray.translate 走 C 实现）
_POP8 = bytes(bin(i).count("1") for i in range(256))

# 逻辑坐标 `L` 是有符号 64 位；`data_lo_logical` 存在 anchor 里，
# `data_hi_logical` 是派生值（见 layout.md §4），但派生值同样不能越界。


class EasyFSError(Exception):
    """格式/一致性/参数错误。错误码见 1-alloc.md §11。"""


class EasyFSFragmented(EasyFSError):
    """条目装不下一个 4 KiB 目录块（段表太长）。

    **格式允许**条目顺着目录链跨块继续（2-dir.md §3，`CONT` 已退场）；
    但 v0 写入方还没实现它，所以这里报错而不是硬撑（读侧已支持跨块条目）。
    单块大约放得下 285 条 `DATA_PTR`。
    """


# ================================================================ 2. 小工具

def crc32(data):
    """CRC-32/IEEE，与 zlib.crc32 一致（common.md §2）。"""
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_size(text):
    """'64M' / '4K' / '1048576' / '0x1000' -> int"""
    s = str(text).strip().lower().replace("_", "")
    mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(s, 0)


def human(n):
    """人类可读的字节数。"""
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024 or unit == "PiB":
            return ("%d B" % n) if unit == "B" else ("%.2f %s" % (n, unit))
        n /= 1024.0
    return "%d B" % n


def align_down(x, a):
    return (x // a) * a


def align_up(x, a):
    return -(-x // a) * a


def ceil_div(x, y):
    return -(-x // y)


# ================================================================ 3. 通用块头

def stamp_header(buf, block_type, header_bytes, payload_len, seq=0,
                 prev_delta=0, next_delta=0, flags=0, payload_crc=None):
    """把 64 B 通用块头写进 buf（common.md §2）。

    `header_crc32` 覆盖 `[0, header_bytes)`。
    `payload_crc` 为 None 表示不启用载荷 CRC（flags.bit0 = 0）。
    """
    if not (HDR_SIZE <= header_bytes <= len(buf)) or header_bytes % 8:
        raise EasyFSError("header_bytes 非法: %r" % (header_bytes,))
    struct.pack_into("<8sHHI", buf, HDR_OFF_MAGIC,
                     BLOCK_MAGIC.get(block_type, b"\x00" * 8),   # 每类一个独立魔数
                     block_type, VERSION, flags)
    struct.pack_into("<qq", buf, HDR_OFF_PREV, prev_delta, next_delta)
    struct.pack_into("<Q", buf, HDR_OFF_SEQ, seq)
    struct.pack_into("<III", buf, HDR_OFF_PAYLOAD_LEN, payload_len,
                     payload_crc if payload_crc is not None else 0, 0)
    struct.pack_into("<I", buf, HDR_OFF_HEADER_BYTES, header_bytes)
    struct.pack_into("<8s", buf, HDR_OFF_RESERVED, b"\x00" * 8)
    if payload_crc is not None:
        buf[12] |= 0x01                      # flags.bit0 = 载荷 CRC 有效
    struct.pack_into("<I", buf, HDR_OFF_HEADER_CRC, crc32(bytes(buf[0:header_bytes])))


def parse_header(buf):
    """解析 64 B 通用块头，返回 dict（含校验结果）。"""
    magic = bytes(buf[0:8])
    block_type, version, flags = struct.unpack_from("<HHI", buf, 8)
    prev_delta, next_delta = struct.unpack_from("<qq", buf, 16)
    seq, = struct.unpack_from("<Q", buf, 32)
    payload_len, payload_crc, header_crc, header_bytes = struct.unpack_from(
        "<IIII", buf, 40)
    hdr = {
        "magic": magic,
        "magic": magic,
        "magic_expect": BLOCK_MAGIC.get(block_type),
        # 该类型应有的魔数对不对；没有魔数的类型（null）就当"全零即合法"
        "magic_ok": (magic == BLOCK_MAGIC[block_type] if block_type in BLOCK_MAGIC
                     else (magic == b"\x00" * 8 or magic[0:4] == MAGIC_PREFIX)),
        "prefix_ok": magic[0:4] == MAGIC_PREFIX,   # 是我们的块、但类型字段不认识时也看得出来
        "block_type": block_type,
        "version": version,
        "flags": flags,
        "prev_delta": prev_delta,
        "next_delta": next_delta,
        "seq": seq,
        "payload_len": payload_len,
        "payload_crc32": payload_crc,
        "header_crc32": header_crc,
        "header_bytes": header_bytes,
        "header_crc_ok": False,
    }
    if HDR_SIZE <= header_bytes <= len(buf):
        tmp = bytearray(buf[0:header_bytes])
        struct.pack_into("<I", tmp, 48, 0)
        hdr["header_crc_ok"] = (crc32(bytes(tmp)) == header_crc)
    return hdr


def verify_payload_crc(buf, hdr):
    """返回 None 表示没启用载荷 CRC；否则 True/False。"""
    if not (hdr["flags"] & 0x01):
        return None
    start = hdr["header_bytes"]
    end = start + hdr["payload_len"]
    if end > len(buf):
        return False
    return crc32(bytes(buf[start:end])) == hdr["payload_crc32"]


# ================================================================ 4. 设备
#
# 设备实现已经剥到 `easyfs_device.py`（FileDevice / RegionDevice / MemDevice /
# VhdDevice），本模块只从那里 import，并在这里重新导出，方便 `easyfs.FileDevice`。

__device_exports__ = (Device, FileDevice, RegionDevice, MemDevice)


# ================================================================ 5. TLV 属性

def encode_attr(atype, value):
    """编码一个属性：`{u8 type}{u8 len}{value}`（2-dir.md §2）。value ≤ 255 字节。"""
    if len(value) > TINY_MAX:
        raise EasyFSError("属性值超过 255 字节: type=0x%02x len=%d"
                          % (atype, len(value)))
    return bytes((atype, len(value))) + value


def scan_attrs(buf, start, end):
    """**长度驱动**地遍历属性流，yield `(type, value, attr_start, attr_end)`。

    * `PADn`（TLV：`len` 可为 0 → 最小 2 字节）与 `PAD1`（**固定 1 字节**，唯一不带 len 字节的类型）直接**跳过**：
      它们是占位/自由空间，不是内容，也不做条目分隔（2-dir.md §2.1）。
    * 属性**不允许跨块**，所以这里的 `end` 就是本块载荷末尾，不需要续段指针。
    """
    pos = start
    while pos < end:
        atype = buf[pos]
        if atype == ATTR_PAD1:                      # 1 字节占位：没有 len 字节
            pos += 1
            continue
        if atype <= ATTR_RESERVED_MAX:               # 0x00–0x0D 未使用 → 一律当损坏
            raise EasyFSError("未使用的属性类型 0x%02x @%d（0x00–0x%02x 全部保留）"
                              % (atype, pos, ATTR_RESERVED_MAX))
        if pos + 2 > end:
            raise EasyFSError("属性头越界 @%d（剩余 %d 字节，属性至少要 2 字节）"
                              % (pos, end - pos))
        length = buf[pos + 1]
        if pos + 2 + length > end:
            raise EasyFSError("属性值越界: type=0x%02x len=%d @%d"
                              % (atype, length, pos))
        if atype == ATTR_PADN:                       # TLV 占位：跳过
            pos += 2 + length
            continue
        yield atype, bytes(buf[pos + 2:pos + 2 + length]), pos, pos + 2 + length
        pos += 2 + length


def parse_data_ptr(value):
    """`{i64 x}{u32 size}` -> (x, size)。DATA_PTR 的 x 是自相对 delta；
    `DATA_OBJECT` 的 x 是逻辑坐标 L（2-dir.md §2.1）。"""
    if len(value) < 12:
        raise EasyFSError("DATA_PTR 值长度不足: %d" % len(value))
    return struct.unpack_from("<qI", value, 0)


def entry_mtime(ent):
    """条目里的 TMODIFY（没有这个属性就返回 0）。"""
    for atype, value, base in ent["attrs"]:
        if atype == ATTR_TMODIFY and len(value) == 4:
            return struct.unpack("<I", value)[0]
    return 0


# ================================================================ 6. 位图区域

class Region(object):
    """一个位图块 + 它管理的那片区域（1-alloc.md §3）。"""

    def __init__(self, block_off, block_bytes, region_delta, region_bytes,
                 bit_unit, logical_start, bits):
        self.block_off = block_off          # 位图块自己的物理位置
        self.block_bytes = block_bytes      # 位图块占多少字节
        self.region_delta = region_delta    # 区域起点相对本块起点的 delta
        self.region_bytes = region_bytes    # 区域总字节数
        self.bit_unit = bit_unit            # 1 bit 代表多少字节
        self.logical_start = logical_start  # 区域起点的逻辑坐标 L
        self.bits = bits                    # bytearray，LSB first，1 = 已用
        self.dirty = True                   # 有改动 → 提交时只写这一块

    @property
    def region_off(self):
        return self.block_off + self.region_delta

    @property
    def region_end(self):
        return self.region_off + self.region_bytes

    @property
    def nbits(self):
        return ceil_div(self.region_bytes, self.bit_unit)

    def bit(self, i):
        return (self.bits[i >> 3] >> (i & 7)) & 1

    def set_bit(self, i, value):
        self.dirty = True
        if value:
            self.bits[i >> 3] |= 1 << (i & 7)
        else:
            self.bits[i >> 3] &= ~(1 << (i & 7)) & 0xFF

    def set_range(self, first, count, value):
        for i in range(first, first + count):
            self.set_bit(i, value)

    def used_bits(self):
        n, tail = self.nbits // 8, self.nbits % 8
        total = sum(self.bits[:n].translate(_POP8))     # 按字节 popcount（C 级）
        if tail:
            total += bin(self.bits[n] & ((1 << tail) - 1)).count("1")
        return total

    def __repr__(self):
        return ("<Region block@%d %dB region@%d %dB unit=%d L=%d used=%d/%d>"
                % (self.block_off, self.block_bytes, self.region_off,
                   self.region_bytes, self.bit_unit, self.logical_start,
                   self.used_bits(), self.nbits))


def build_bitmap_block(block_off, block_bytes, region_delta, region_bytes,
                       bit_unit, logical_start, bits, seq=0,
                       prev_off=None, next_off=None):
    """打包一个位图块（64 B 通用头 + 32 B 类型扩展 + 位图载荷，1-alloc.md §3）。

    `prev_off` / `next_off` 是链上邻居的**物理位置**（None = 没有）；自相对 delta 在这里算。
    **不要**假设邻居块就是相邻的 —— 按策略选出来的位图块可能天各一方。
    """
    blk = bytearray(block_bytes)
    struct.pack_into("<qQIIq", blk, BM_OFF_REGION_DELTA, region_delta, region_bytes,
                     block_bytes, bit_unit, logical_start)
    nbytes = ceil_div(ceil_div(region_bytes, bit_unit), 8)
    blk[ALLOC_HDR:ALLOC_HDR + nbytes] = bytes(bits[:nbytes])
    stamp_header(blk, BT_ALLOC, ALLOC_HDR, block_bytes - ALLOC_HDR, seq=seq,
                 prev_delta=(0 if prev_off is None else prev_off - block_off),
                 next_delta=(0 if next_off is None else next_off - block_off),
                 flags=(0x02 if next_off is None else 0))    # bit1 = 链尾
    return blk


def anchor_layout():
    """anchor 的字段摆放：`[(名字, tag, tag偏移, 值偏移, 值宽)]`（5-anchor.md §2.1）。

    段起点在 `easyfs_config.ANCHOR_SECTIONS` 里钉住；段内每个字段 16 字节；
    `tag = None` 的是**裸值**（uuid 之类，没有名字可写）。
    """
    out = []
    bare_names = {0x040: ["uuid"], 0x200: ["pool_uuid", "vdev_uuid", "member_uuid"]}
    for _name, base, tags in ANCHOR_SECTIONS:
        off, bi = base, 0
        for t, w in tags:
            if t is None:
                out.append((bare_names[base][bi], None, off, off, w)); bi += 1
                off += w
            else:
                out.append((t, t, off, off + TAG_WIDTH, w))
                off += TAG_WIDTH + w
    return out


def anchor_off(name):
    """值所在的偏移（写/读都用它）。"""
    for n, _t, _toff, voff, _w in anchor_layout():
        if n == name:
            return voff
    raise EasyFSError("anchor 里没有 %r" % name)


def anchor_put(blk, name, value):
    """写一个字段：**先写它的 8 字节名字（tag），再写值**，也就是自描述的那一半。

    `value` 可以是 bytes（裸值 / 字符串）或 int（按 u64 或 i64 打包）。
    """
    for n, t, toff, voff, w in anchor_layout():
        if n == name:
            if t is not None:                     # 有名字的字段：名字本身要落在盘上
                blk[toff:toff + TAG_WIDTH] = (t.encode("ascii") +
                                              b" " * TAG_WIDTH)[:TAG_WIDTH]
            if isinstance(value, (bytes, bytearray)):
                raw = bytes(value)
            else:
                raw = struct.pack("<q" if value < 0 else "<Q", value)
            blk[voff:voff + w] = (raw + b"\x00" * w)[:w]
            return
    raise EasyFSError("anchor 里没有 %r" % name)


def anchor_get(blk, name):
    for n, _t, _toff, voff, w in anchor_layout():
        if n == name:
            return bytes(blk[voff:voff + w])
    raise EasyFSError("anchor 里没有 %r" % name)


def anchor_geti(blk, name, signed=False):
    return struct.unpack("<q" if signed else "<Q", anchor_get(blk, name))[0]


def anchor_crc(blk, crc_name, start, end):
    """算一段的 CRC：把那个 CRC 字段自身按 0 计入。"""
    off = anchor_off(crc_name)
    tmp = bytearray(blk[start:end])
    tmp[off - start:off - start + VALUE_WIDTH] = b"\x00" * VALUE_WIDTH
    return crc32(bytes(tmp))


def build_anchor_block(region_len, peer_delta, data_lo_logical, generation,
                       chunk_shift, policy_id, policy_state, root_type,
                       root_ioffs, alloc_ioffs, alloc_num, alloc_size,
                       state_flags, vol_uuid, geom_version=1,
                       alloc_type=ALLOC_TYPE_CHAIN):
    """打包一个 anchor 块（5-anchor.md §2.1：tag 布局）。

    写在哪由调用方决定；**所有 delta（含 `root_ioffs`）都必须相对那个位置算好再传进来**。
    pool 段 v0 全零 ⇒ **不是池成员**（`easypool` 不出现）。
    """
    blk = bytearray(BLOCK_4K)
    anchor_put(blk, "easypart", ANCHOR_VERSION_STR)      # 名字 + 版本字符串
    anchor_put(blk, "blktype ", BT_ANCHOR)
    anchor_put(blk, "hdrbytes", ANCHOR_VOL_HDR_END)
    anchor_put(blk, "reglen  ", region_len)
    anchor_put(blk, "peer    ", peer_delta)
    anchor_put(blk, "dlolog  ", data_lo_logical)
    anchor_put(blk, "chunk   ", chunk_shift)
    anchor_put(blk, "geover  ", geom_version)
    anchor_put(blk, "geomflag", 0)
    anchor_put(blk, "uuid", vol_uuid)
    anchor_put(blk, "gen     ", generation)
    anchor_put(blk, "stateflg", state_flags)
    anchor_put(blk, "roottype", root_type)
    anchor_put(blk, "rootioff", root_ioffs)
    anchor_put(blk, "allotype", alloc_type)
    anchor_put(blk, "alloioff", alloc_ioffs)
    anchor_put(blk, "allocnum", alloc_num)
    anchor_put(blk, "allosize", alloc_size)
    anchor_put(blk, "policy  ", policy_id)
    anchor_put(blk, "polstate", policy_state)
    anchor_put(blk, "hdrcrc  ", 0)        # 先把名字写到盘上（它也在 CRC 覆盖范围内）
    anchor_put(blk, "hdrcrc  ", anchor_crc(blk, "hdrcrc  ", 0, ANCHOR_VOL_HDR_END))
    return blk

def used_ranges(bits, first, count):
    """`[first, first+count)` 里"已用"bit 的连续区间，按字节扫（0x00/0xFF 走快路径）。

    返回 `[(start_bit, nbits), ...]`。
    """
    out = []
    i = 0
    while i < count:
        b = first + i
        if (b & 7) == 0 and i + 8 <= count:            # 字节对齐时先看整字节
            byte = bits[b >> 3]
            if byte == 0x00:
                i += 8
                continue
            if byte == 0xFF:
                j = i + 8
                while j + 8 <= count and bits[(first + j) >> 3] == 0xFF:
                    j += 8
                out.append((b, j - i))
                i = j
                continue
        if (bits[b >> 3] >> (b & 7)) & 1:
            j = i + 1
            while j < count and ((bits[(first + j) >> 3] >> ((first + j) & 7)) & 1):
                j += 1
            out.append((b, j - i))
            i = j
        else:
            i += 1
    return out


def shift_bits(bits, drop, nbits_new):
    """丢掉最低的 `drop` 个 bit、其余整体右移，得到长度为 `nbits_new` 的新位图。

    用于"向左收缩时最左边那个区域截短"：区域的起点右移了，bit 0 换了含义。
    """
    out = bytearray(ceil_div(nbits_new, 8))
    if nbits_new <= 0:
        return out
    src = int.from_bytes(bytes(bits), "little") >> drop
    raw = src.to_bytes(len(out), "little")
    out[:len(raw)] = raw
    return out


def free_ranges(bits, first, count):
    """`[first, first+count)` 里"空闲"bit 的连续区间，返回 `[(start_bit, nbits), ...]`。"""
    out = []
    i = 0
    while i < count:
        b = first + i
        if (b & 7) == 0 and i + 8 <= count:
            byte = bits[b >> 3]
            if byte == 0xFF:
                i += 8
                continue
            if byte == 0x00:
                j = i + 8
                while j + 8 <= count and bits[(first + j) >> 3] == 0x00:
                    j += 8
                out.append((b, j - i))
                i = j
                continue
        if not ((bits[b >> 3] >> (b & 7)) & 1):
            j = i + 1
            while j < count and not ((bits[(first + j) >> 3]
                                      >> ((first + j) & 7)) & 1):
                j += 1
            out.append((b, j - i))
            i = j
        else:
            i += 1
    return out


def used_count(bits, nbits):
    """数一个位图里置位的个数（按字节 popcount，末字节裁到 nbits）。"""
    n, tail = nbits // 8, nbits % 8
    total = sum(bits[:n].translate(_POP8))
    if tail:
        total += bin(bits[n] & ((1 << tail) - 1)).count("1")
    return total


# ================================================================ 7. 卷

class Volume(object):
    """已挂载的 EasyFS 卷：几何、位图、分配、块与目录/文件读取。"""

    def __init__(self, dev):
        self.dev = dev
        self.head = None
        self.tail = None
        self.regions = []
        # 几何（mount 后填）
        self.region_len = 0
        self.chunk = BLOCK_4K
        self.chunk_shift = 12
        self.data_lo = BLOCK_4K
        self.data_hi = 0
        self.data_lo_logical = 0
        self.policy_id = 3
        self.policy_state = 0
        self.vol_uuid = b"\x00" * 16
        self.generation = 0
        self.flags = 0

    # ------------------------------------------------------------ 挂载

    @classmethod
    def mount(cls, dev, strict=True):
        """读 head/tail anchor、校验、加载位图（layout.md §3）。

        `strict=True`（默认）：head/tail 不一致（I9）或位图链和 `region_len` 对不上（I7）
        就**拒绝**（`ESTALE`）—— 那意味着"上次 resize 没做完"或"几何给错了"，不许猜。
        `strict=False`：把这些记进 `vol.warnings` 继续挂载（给只读的 `probe` 用）。
        """
        vol = cls(dev)
        vol.warnings = []
        size = dev.size
        if size < 3 * BLOCK_4K:
            raise EasyFSError("文件太小，不是 EasyFS 卷: %d B" % size)

        vol.head = vol.read_anchor(0)
        if vol.head is not None:
            # tail 的位置**由卷自己说**（layout.md §3），不由设备大小推
            tail_off = vol.head["region_len"] - BLOCK_4K
            if tail_off < 0 or tail_off + BLOCK_4K > size:
                msg = ("容器比卷小：卷记 region_len=%d，设备只有 %d（被截断了？）"
                       % (vol.head["region_len"], size))
                if strict:
                    raise EasyFSError("EINVAL: " + msg)
                vol.warnings.append(msg)
                vol.tail = None
            else:
                vol.tail = vol.read_anchor(tail_off)
        else:
            vol.tail = vol.read_anchor(size - BLOCK_4K)

        anchor = vol.head or vol.tail
        if anchor is None:
            raise EasyFSError("head/tail 都不是合法 anchor")

        if vol.head is not None and vol.tail is not None:
            # I9（5-anchor.md §2.2）：非 delta 字段逐一相等，delta 字段解算后相等
            diff = [k for k in ("region_len", "uuid", "data_lo_logical",
                                "chunk_shift", "geom_flags", "geom_version",
                                "generation", "policy_id", "policy_state",
                                "root_type", "alloc_num", "alloc_size",
                                "state_flags")
                    if vol.head[k] != vol.tail[k]]
            for k in ("root_off", "alloc_off"):
                if vol.head[k] != vol.tail[k]:
                    diff.append(k)
            if diff:
                msg = ("head/tail 的 %s 不一致（head: %s，tail: %s）—— "
                       "上次 resize 没做完，或 --offs/--size 给错了；"
                       "用 probe 看两个 anchor，然后换另一组几何重试"
                       % (", ".join(diff),
                          " ".join("%s=%s" % (k, vol.head[k]) for k in diff),
                          " ".join("%s=%s" % (k, vol.tail[k]) for k in diff)))
                if strict:
                    raise EasyFSError("ESTALE: " + msg)
                vol.warnings.append(msg)
            if vol.head["region_len"] < size:
                vol.warnings.append(
                    "容器比卷大 %d 字节（卷 region_len=%d，设备 %d）→ 需要 resize 采纳；"
                    "本卷只会在自己的 region_len 内读写"
                    % (size - vol.head["region_len"], vol.head["region_len"], size))

        vol._apply_anchor(anchor)
        vol.load_bitmap(strict=strict)
        return vol

    def read_anchor(self, base):
        """读一个 anchor 并解析（tag 布局，5-anchor.md §2.1）；不合法返回 None。"""
        blk = bytearray(self.dev.read_at(base, BLOCK_4K))
        if len(blk) < ANCHOR_VOL_HDR_END or bytes(blk[0:8]) != ANCHOR_MAGIC_TAG:
            return None
        try:
            for want in ("blktype ", "hdrbytes", "reglen  ", "gen     "):
                toff = [o for _n, t, o, _v, _w in anchor_layout() if t == want][0]
                if bytes(blk[toff:toff + TAG_WIDTH]) != want.encode("ascii"):
                    return None                   # 名字不在 ⇒ 不是 tag 布局，或块坏了
            if anchor_geti(blk, "blktype ") != BT_ANCHOR:
                return None
            if anchor_geti(blk, "hdrbytes") != ANCHOR_VOL_HDR_END:
                return None
            hdrcrc_ok = (anchor_geti(blk, "hdrcrc  ") ==
                         anchor_crc(blk, "hdrcrc  ", 0, ANCHOR_VOL_HDR_END))
        except EasyFSError:
            return None
        if not hdrcrc_ok:
            return None
        pool_here = bytes(blk[ANCHOR_OFF_POOL:ANCHOR_OFF_POOL + 8]) == ANCHOR_POOL_MAGIC_TAG
        poolcrc_ok = True
        if pool_here:
            poolcrc_ok = (anchor_geti(blk, "poolcrc ") ==
                          anchor_crc(blk, "poolcrc ", ANCHOR_OFF_POOL, ANCHOR_POOL_END))
        root_ioffs = anchor_geti(blk, "rootioff", signed=True)
        alloc_ioffs = anchor_geti(blk, "alloioff", signed=True)
        state_flags = anchor_geti(blk, "stateflg")
        return {
            "base": base,
            "version": bytes(blk[8:16]).rstrip(b"\x00").decode("ascii", "replace"),
            "region_len": anchor_geti(blk, "reglen  "),
            "peer_delta": anchor_geti(blk, "peer    ", signed=True),
            "data_lo_logical": anchor_geti(blk, "dlolog  ", signed=True),
            "generation": anchor_geti(blk, "gen     "),
            "chunk_shift": anchor_geti(blk, "chunk   "),
            "policy_id": anchor_geti(blk, "policy  "),
            "policy_state": anchor_geti(blk, "polstate"),
            "geom_flags": anchor_geti(blk, "geomflag"),
            "geom_version": anchor_geti(blk, "geover  "),
            "root_type": anchor_geti(blk, "roottype"),
            "root_ioffs": root_ioffs,
            "root_off": base + root_ioffs,
            "alloc_type": anchor_geti(blk, "allotype"),
            "alloc_ioffs": alloc_ioffs,
            "alloc_off": base + alloc_ioffs,
            "alloc_num": anchor_geti(blk, "allocnum"),
            "alloc_size": anchor_geti(blk, "allosize"),
            "state_flags": state_flags,
            "flags": state_flags,              # 兼容旧名（= state_flags）
            "uuid": anchor_get(blk, "uuid"),
            "hdrcrc_ok": hdrcrc_ok,
            "poolcrc_ok": poolcrc_ok,
            "pool_here": pool_here,
        }

    def _apply_anchor(self, a):
        self.region_len = a["region_len"]
        self.chunk_shift = a["chunk_shift"]
        self.chunk = 1 << self.chunk_shift
        self.data_lo = BLOCK_4K
        self.data_hi = self.region_len - BLOCK_4K
        self.data_lo_logical = a["data_lo_logical"]
        if not (I64_MIN <= self.data_lo_logical
                and self.data_lo_logical + self.data_bytes <= I64_MAX):
            raise EasyFSError(
                "EINVAL: anchor 里的逻辑坐标越界（data_lo_logical=%d，"
                "派生的 data_hi_logical=%d）"
                % (self.data_lo_logical,
                   self.data_lo_logical + self.data_bytes))
        self.policy_id = a["policy_id"]
        self.policy_state = a["policy_state"]
        self.vol_uuid = a["uuid"]
        self.generation = a["generation"]
        self.flags = a["state_flags"]
        self.state_flags = a["state_flags"]
        self.geom_flags = a["geom_flags"]
        self.geom_version = a["geom_version"]
        self.root_type = a["root_type"]
        self.root_off = a["root_off"]
        self.alloc_off = a["alloc_off"]
        self.alloc_type = a.get("alloc_type", ALLOC_TYPE_CHAIN)

    # ------------------------------------------------------------ 几何

    @property
    def data_bytes(self):
        return self.data_hi - self.data_lo

    @property
    def chunk_count(self):
        return self.data_bytes // self.chunk

    def phys_to_logical(self, phys):
        """`L(P) = data_lo_logical + (P − data_lo)`（common.md §1.2）。"""
        return self.data_lo_logical + (phys - self.data_lo)

    def logical_to_phys(self, logical):
        return self.data_lo + (logical - self.data_lo_logical)

    # ------------------------------------------------------------ 位图

    def load_bitmap(self, strict=True):
        """沿链加载所有位图块到 RAM（1-alloc.md §3），并**校验 I7**。"""
        self.regions = []
        off = self.alloc_off
        seen = 0
        while off:
            blk = self.read_block_any(off)
            h = parse_header(blk)
            if not h["magic_ok"] or h["block_type"] != BT_ALLOC:
                raise EasyFSError("位图链在下标 %d 处断开 @%d" % (seen, off))
            region_delta, region_bytes, block_bytes, bit_unit, logical_start = \
                struct.unpack_from("<qQIIq", blk, BM_OFF_REGION_DELTA)
            nbits = ceil_div(region_bytes, bit_unit)
            bits = bytearray(blk[ALLOC_HDR:ALLOC_HDR + ceil_div(nbits, 8)])
            self.regions.append(Region(off, block_bytes, region_delta,
                                       region_bytes, bit_unit, logical_start,
                                       bits))
            if h["next_delta"]:
                off = off + h["next_delta"]
            else:
                off = 0
            seen += 1
            if seen > (1 << 20):
                raise EasyFSError("位图链疑似成环")

        self._build_tree()
        why = self.check_regions()
        if why:
            msg = ("位图链和 region_len 对不上（I7）：%s —— 上次 resize 没做完？"
                   % why)
            if strict:
                raise EasyFSError("ESTALE: " + msg)
            self.warnings.append(msg)

    def _build_tree(self):
        """按"包含"推父子（1-alloc.md §13.2）：父 = 严格包含它的最小区域。

        链本身按 logical_start 递增；这里只算关系，不改链。
        `self.parent[i]` / `self.leaves` 就是全部结果 —— **格式里没有 parent 字段**。
        """
        n = len(self.regions)
        self.parent = [None] * n
        for i, a in enumerate(self.regions):
            best = None
            for j, b in enumerate(self.regions):
                if i == j:
                    continue
                if (b.region_off <= a.region_off and
                        a.region_end <= b.region_end and
                        b.region_bytes > a.region_bytes):
                    if best is None or self.regions[best].region_bytes > b.region_bytes:
                        best = j
            self.parent[i] = best
        self.leaves = [i for i in range(n) if
                       not any(self.parent[k] == i for k in range(n))]

    def leaf_of_phys(self, phys):
        """物理地址落在哪个**叶**区域（没有子区域的那个）；找不到返回 None。"""
        best = None
        for i in self.leaves:
            r = self.regions[i]
            if r.region_off <= phys < r.region_end:
                if best is None or r.region_bytes < self.regions[best].region_bytes:
                    best = i
        return best

    def check_regions(self):
        """校验 I7：区域首尾相接、无缝无重叠、并集 == `[data_lo, data_hi)`。

        通过返回 None，否则返回一句人能看懂的原因。**链比 region_len 长是危险的**
        ——`free_runs()` 会遍历所有加载进来的区域，分配器就可能落到 `data_hi` 之外。
        """
        if not self.regions:
            return "一个位图块都没有"
        for i, r in enumerate(self.regions):
            if r.region_bytes <= 0:
                return "区域 #%d 长度为 %d" % (i, r.region_bytes)
            if r.bit_unit <= 0 or r.bit_unit % self.chunk:
                return "区域 #%d 的 bit_unit=%d 不是 chunk 的整数倍" % (i, r.bit_unit)
        # 链按 logical_start 递增（1-alloc.md §13.7 第 1 条）
        last = None
        for i, r in enumerate(self.regions):
            if last is not None and r.logical_start < last:
                return "链没有按 logical_start 递增（区域 #%d）" % i
            last = r.logical_start
        if getattr(self, "parent", None) is None:
            self._build_tree()
        for i, p in enumerate(self.parent):
            if p is None:
                continue
            a, b = self.regions[i], self.regions[p]
            if not (b.region_off <= a.region_off and a.region_end <= b.region_end):
                return "区域 #%d 不在父区域 #%d 内" % (i, p)
            # 一个 bit 一主：子区域必须**按整单位**对齐（可以跨多个单位，但不能占半格）
            if (a.region_off - b.region_off) % b.bit_unit != 0:
                return ("区域 #%d 没有从父区域 #%d 的单位边界开始（一个 bit 一主）" % (i, p))
            if (a.region_end != b.region_end
                    and (a.region_end - b.region_off) % b.bit_unit != 0):
                return ("区域 #%d 的末尾不在父区域 #%d 的单位边界上（一个 bit 一主）" % (i, p))
        # 根区域（没有父的）必须平铺满数据区
        pos = self.data_lo
        for i, r in enumerate(self.regions):
            if self.parent[i] is not None:
                continue
            if r.region_off != pos:
                return ("区域 #%d 从 %d 开始，但期望 %d（%s）"
                        % (i, r.region_off, pos,
                           "重叠或乱序" if r.region_off < pos else "中间有洞"))
            pos = r.region_end
        if pos != self.data_hi:
            return ("链到 %d 就结束了，数据区要到 %d（%s）"
                    % (pos, self.data_hi,
                       "链比 region_len 长" if pos > self.data_hi
                       else "链比 region_len 短"))
        if self.head is not None:
            if len(self.regions) != self.head["alloc_num"]:
                return ("链上 %d 块，anchor 记的是 %d 块"
                        % (len(self.regions), self.head["alloc_num"]))
            total = sum(r.block_bytes for r in self.regions)
            if total != self.head["alloc_size"]:
                return ("块大小合计 %d，anchor 记的是 %d"
                        % (total, self.head["alloc_size"]))
        return None

    def read_block_any(self, off):
        """按需读一个元数据块：先读 4 KiB 头，必要时按 block_bytes 补读。"""
        blk = self.dev.read_at(off, BLOCK_4K)
        h = parse_header(blk)
        if h["magic_ok"] and h["block_type"] == BT_ALLOC:
            (region_delta, region_bytes, block_bytes, bit_unit,
             logical_start) = struct.unpack_from("<qQIIq", blk, BM_OFF_REGION_DELTA)
            if block_bytes > len(blk):
                blk = self.dev.read_at(off, block_bytes)
        return blk

    def region_of_phys(self, phys):
        """物理地址 → (region_index, bit_index)。**优先叶区域**（有子区域的不算）。"""
        i = self.leaf_of_phys(phys)
        if i is not None:
            r = self.regions[i]
            return i, (phys - r.region_off) // r.bit_unit
        for i, r in enumerate(self.regions):
            if r.region_off <= phys < r.region_end:
                return i, (phys - r.region_off) // r.bit_unit
        raise EasyFSError("物理地址 0x%x 不在任何位图区域内" % phys)

    def region_of_logical(self, logical):
        """逻辑坐标 L → (region_index, bit_index)（layout.md §4）。"""
        for i, r in enumerate(self.regions):
            if r.logical_start <= logical < r.logical_start + r.region_bytes:
                return i, (logical - r.logical_start) // r.bit_unit
        raise EasyFSError("逻辑坐标 %d 不在任何位图区域内" % logical)

    def free_runs(self):
        """枚举所有空闲段：`(region_index, first_bit, nbits)`。不跨区域。

        按**字节**扫，`0x00` / `0xFF` 走快路径 —— 逐 bit 调 `bit()` 在 Python 里
        慢两个数量级（见 1-alloc.md §12 的性能说明）。
        """
        runs = []
        for i, r in enumerate(self.regions):
            bits = r.bits
            n = r.nbits
            nbytes = len(bits)
            run_start = None
            for bi in range(nbytes):
                byte = bits[bi]
                if byte == 0xFF:                        # 整字节都用
                    if run_start is not None:
                        runs.append((i, run_start, bi * 8 - run_start))
                        run_start = None
                elif byte == 0x00:                      # 整字节都空
                    if run_start is None:
                        run_start = bi * 8
                else:                                   # 混合字节：逐 bit
                    base = bi * 8
                    for k in range(8):
                        if (byte >> k) & 1:
                            if run_start is not None:
                                runs.append((i, run_start, base + k - run_start))
                                run_start = None
                        elif run_start is None:
                            run_start = base + k
            if run_start is not None:
                runs.append((i, run_start, n - run_start))   # 末段裁到 nbits
        return runs

    def free_bytes(self):
        # **所有区域都算**：父区域里"已分裂"的那个单位已经标成 used，
        # 所以它不会被当成空闲；子区域自己的空闲照常算 —— 两者不重不漏（1-alloc.md §13.7）。
        total = 0
        for r in self.regions:
            total += (r.nbits - r.used_bits()) * r.bit_unit
        return total

    # ------------------------------------------------------------ 分配

    def alloc(self, nbytes, policy=None, runs=None):
        """分配连续空间，返回 `(物理地址, 字节数)`。

        策略 id 见 1-alloc.md §5。**一次分配不跨区域**（1-alloc.md §2）。
        `runs` 给定时复用它（调用方刚扫过就别再扫一遍）。具体平局规则是实现细节。
        """
        if policy is None:
            policy = self.policy_id
        nbits = ceil_div(nbytes, self.chunk)
        if runs is None:
            runs = self.free_runs()
        # 不按"叶/父"过滤：父区域里**没被分裂**的单位照样可分配；
        # 已分裂的单位在父位图里是 used ⇒ 不会出现在 runs 里（1-alloc.md §13.7 第 3 条）。
        runs = [r for r in runs if r[2] >= nbits]
        # **小分配优先落在已经细粒度化的区域里**（1-alloc.md §13.4）。
        # 少了这一步，每个小文件都会去分裂一个新的粗单位 ⇒ 元数据随文件数爆炸
        # （实测：200 个 4 KiB 文件 ⇒ 200 次分裂）。分裂次数应当 ∝ 已填满的细粒度区域数。
        if runs:
            coarse = [self.regions[x[0]].bit_unit for x in runs
                      if self.regions[x[0]].bit_unit > self.chunk]
            if coarse and min(coarse) > nbytes:
                fine = [x for x in runs if self.regions[x[0]].bit_unit <= self.chunk]
                if fine:
                    runs = fine
        if not runs:
            raise EasyFSError("ENOSPC: 找不到 %d 字节的连续空闲" % nbytes)

        def mid(ri, b, n):
            r = self.regions[ri]
            return r.region_off + (b + n // 2) * r.bit_unit

        centre = self.data_lo + self.data_bytes // 2
        if policy == 3:                                   # middle-out
            ri, b, n = min(runs, key=lambda x: abs(mid(*x) - centre))
            take_high = mid(ri, b, n) < centre            # 靠中点的那一端
        elif policy == 1:                                 # first-fit-right
            ri, b, n = runs[0]
            take_high = True
        elif policy == 2:                                 # last-fit
            ri, b, n = runs[-1]
            take_high = True
        elif policy == 4:                                 # best-fit
            ri, b, n = min(runs, key=lambda x: x[2])
            take_high = False
        elif policy == 5:                                 # worst-fit
            ri, b, n = max(runs, key=lambda x: x[2])
            take_high = False
        elif policy == 6:                                 # random（可复现）
            seed = (self.policy_state * 1103515245 + 12345) & 0x7FFFFFFF
            self.policy_state = seed
            ri, b, n = runs[seed % len(runs)]
            take_high = bool((seed >> 16) & 1)
        elif policy == 7:                                 # edge-reserve：避开贴边的段
            inner = [r for r in runs
                     if r[1] != 0 and (r[1] + r[2]) != self.regions[r[0]].nbits]
            ri, b, n = (inner or runs)[0]
            take_high = False
        else:                                             # 0 first-fit-left
            ri, b, n = runs[0]
            take_high = False

        r = self.regions[ri]
        if (r.bit_unit > self.chunk and nbytes < r.bit_unit
                and nbytes <= r.bit_unit - child_block_bytes(r.bit_unit)):
            # 粗单位装不下这么小的请求 ⇒ 分裂出子区域，**就在这个子区域里分配**
            # （1-alloc.md §13.4："小块优先落在已分裂的子区域"）。
            #
            # ⚠️ 这里**不能**再调一次通用搜索：middle-out 会再次挑中"另一个粗单位"，
            # 于是又分裂……无限分下去（实测 = 看起来卡死）。分裂一次，就用它。
            first_unit = (b + n - 1) if take_high else b
            ci = self._split_unit(ri, first_unit)
            if ci is not None:
                c = self.regions[ci]
                cbits = ceil_div(nbytes, c.bit_unit)
                if cbits <= c.nbits:
                    c.set_range(0, cbits, 1)
                    return c.region_off, cbits * c.bit_unit
        first = (b + n - nbits) if take_high else b
        r.set_range(first, nbits, 1)
        phys = r.region_off + first * r.bit_unit
        return phys, nbits * r.bit_unit

    def free(self, phys, nbytes):
        """释放 `(物理地址, 字节数)`（按分配单位对齐；叶区域粒度）。"""
        ri, b = self.region_of_phys(phys)
        r = self.regions[ri]
        nbits = ceil_div(nbytes, r.bit_unit)
        r.set_range(b, nbits, 0)
        # 注意：**不自动合并**子区域（1-alloc.md §13.6：合并是显式命令）

    def _split_unit(self, ri, bit):
        """把一个粗单位分裂成 `chunk` 粒度的子区域（1-alloc.md §13.4）。

        * 子位图块放在**这个单位的开头**，大小 = `child_block_bytes(unit)`
        * 子区域覆盖单位剩下的 `unit − cbb` 字节，`bit_unit = chunk`
        * 父位图里那一位标为**已用**（= 已分裂；它连子位图块一起算进去了）
        * 返回子区域的下标（失败返回 None）
        """
        r = self.regions[ri]
        p_off = r.region_off + bit * r.bit_unit
        unit = min(r.bit_unit, r.region_end - p_off)   # 最后一个单位可能只有"半格"
        cbb = child_block_bytes(unit)
        if unit < cbb + self.chunk:
            return None
        # **一个 bit 一主**：子区域**整格**占住这个单位；子位图块自己就住在单位的开头，
        # 并在**子区域自己的位图**里标成已用（它属于这个子区域，跟着它一起生灭）
        nblk = ceil_div(cbb, self.chunk)
        bits = bytearray(ceil_div(ceil_div(unit, self.chunk), 8))
        child = Region(p_off, cbb, 0, unit, self.chunk,
                       self.data_lo_logical + (p_off - self.data_lo), bits)
        child.set_range(0, nblk, 1)
        child.dirty = True
        r.set_bit(bit, 1)                       # 父：已分裂（同时把子位图块自己算作已用）
        r.dirty = True
        # 插进链里，保持按 logical_start 递增（1-alloc.md §13.7 第 1 条）
        pos = len(self.regions)
        for i, x in enumerate(self.regions):
            if x.logical_start > child.logical_start:
                pos = i
                break
        self.regions.insert(pos, child)
        if pos > 0:
            self.regions[pos - 1].dirty = True       # 前一块的 next_delta 变了，必须重写
        self._build_tree()
        return pos

    def optimize_alloc(self, dry_run=False):
        """把"全空的子区域"合回粗粒度（1-alloc.md §13.6 的 `optimize alloc`）。

        只动**位图与链**，不搬任何文件数据：
        清掉父位图里那几位（"已分裂"）⇒ 把子位图块从链上摘掉 ⇒ 那个单位又变回粗单位。

        返回 `{"merged": [...], "bytes_freed": n, "dry_run": bool}`。
        """
        merged = []
        while True:
            self._build_tree()
            cand = None
            for i, r in enumerate(self.regions):
                p = self.parent[i]
                if p is None:
                    continue
                own = ceil_div(r.block_bytes, r.bit_unit)        # 它自己的位图块占的前几格
                used = [b for b in range(r.nbits) if r.bit(b)]
                if any(b >= own for b in used):                  # 除自己的位图块外还有别人 ⇒ 不能收
                    continue
                if any(self.parent[k] == i for k in range(len(self.regions))):
                    continue                      # 它自己还有子区域 ⇒ 先收里面的
                cand = i
                break
            if cand is None:
                break
            r = self.regions[cand]
            pr = self.regions[self.parent[cand]]
            merged.append({"off": r.region_off, "bytes": r.region_bytes,
                           "block_off": r.block_off, "block_bytes": r.block_bytes,
                           "parent": pr.region_off})
            if dry_run:
                # 干跑：假装它已经不在链上，免得死循环
                self.regions = [x for k, x in enumerate(self.regions) if k != cand]
                continue
            # ① 父区域里它盖住的那几个单位 ⇒ 清成"没分裂"
            b0 = (r.region_off - pr.region_off) // pr.bit_unit
            b1 = ceil_div(r.region_end - pr.region_off, pr.bit_unit)
            for b in range(b0, b1):
                pr.set_bit(b, 0)
            pr.dirty = True
            # ② 摘链：前后邻居的 prev/next 都变 ⇒ 都要重写
            del self.regions[cand]
            if cand - 1 >= 0:
                self.regions[cand - 1].dirty = True
            if cand < len(self.regions):
                self.regions[cand].dirty = True
        return {"merged": merged, "bytes_freed": sum(m["block_bytes"] for m in merged),
                "dry_run": dry_run}

    def place_metadata(self, region_off, region_bytes, nbytes, policy=None):
        """给"还没进位图的新区域"选一个元数据块位置（1-alloc.md §8.7）。

        返回 `(物理地址, 字节数)`。**不能用 `alloc()`** —— 新区域此刻还不存在位图，
        无从查空闲。这里把整段当作空闲，按策略选点：

        `middle-out` → 中点；`first-fit-right`/`last-fit` → 最右；
        `random` → 区域内随机（可复现）；`edge-reserve` → 避开两端；
        `first-fit-left`/`best-fit`/`worst-fit` → 最左（整段无差别）。
        """
        if policy is None:
            policy = self.policy_id
        n = ceil_div(nbytes, self.chunk)
        room = region_bytes // self.chunk
        if n > room:
            raise EasyFSError("区域只有 %d 个 chunk，放不下 %d chunk 的元数据块"
                              % (room, n))
        spare = room - n
        if policy in (1, 2):                       # first-fit-right / last-fit
            first = spare
        elif policy == 3:                          # middle-out：尽量居中
            first = spare // 2
        elif policy == 6:                          # random（可复现）
            seed = (self.policy_state * 1103515245 + 12345) & 0x7FFFFFFF
            self.policy_state = seed
            first = seed % (spare + 1)
        elif policy == 7:                          # edge-reserve：避开两端
            guard = max(1, room // 8)
            lo, hi = min(guard, spare), max(min(guard, spare), spare - guard)
            first = lo + (hi - lo) // 2 if hi > lo else lo
        else:                                      # 0 / 4 / 5：最左
            first = 0
        return region_off + first * self.chunk, n * self.chunk

    def save_region(self, index):
        """把一个位图块写回（1-alloc.md §3）；链的 prev/next 按**实际位置**重算。"""
        r = self.regions[index]
        prev_off = self.regions[index - 1].block_off if index else None
        next_off = (self.regions[index + 1].block_off
                    if index + 1 < len(self.regions) else None)
        blk = build_bitmap_block(r.block_off, r.block_bytes, r.region_delta,
                                 r.region_bytes, r.bit_unit, r.logical_start,
                                 r.bits, seq=index, prev_off=prev_off,
                                 next_off=next_off)
        self.dev.write_at(r.block_off, blk)

    def save_bitmap(self, force=False):
        """把**有改动**的位图块写回；`force=True` 时全部写回。

        位图可以有很多块（16 TB 卷 = 513 块），每次分配只动其中一块，
        所以默认只写脏块（1-alloc.md §7.2）。
        """
        for i, r in enumerate(self.regions):
            if force or r.dirty:
                self.save_region(i)
                r.dirty = False

    # ------------------------------------------------------------ 元数据块

    def read_block(self, off, size=BLOCK_4K):
        return self.dev.read_at(off, size)

    def write_block(self, off, blk):
        self.dev.write_at(off, blk)

    # ------------------------------------------------------------ 目录 / 文件

    def _block_seq(self, head_off, what="目录链", blocks=None):
        """产出要按顺序当成一条属性流的块地址。

        `blocks` 给定时按**给定顺序**（`DIR_OBJECT` 的内容块表）；否则顺着 `next_delta` 走。
        """
        if blocks is not None:
            for off in blocks:
                yield off
            return
        off, seen = head_off, 0
        while off:
            yield off
            h = parse_header(self.read_block(off))
            off = (off + h["next_delta"]) if h["next_delta"] else 0
            seen += 1
            if seen > (1 << 20):
                raise EasyFSError("%s 疑似成环" % what)

    def _iter_stream(self, head_off, btype=BT_DIR, what="目录链", blocks=None):
        """把一条块链的载荷当成**一条连续的属性流**遍历（2-dir.md §3）。

        `CONT` 已经退场：**链上的下一块就是续段**，不需要任何指针属性。
        属性不跨块，所以每块的载荷边界就是属性边界。

        `blocks` 给定时，按那个**块序列**遍历（`DIR_OBJECT` → 链接块 → 内容块表，
        [`2-dir.md`](2-dir.md) §3.3）：此时不跟 `next_delta`。

        yield `(type, value, base_off, attr_start, attr_end)`；`base_off` 是该属性
        所在块的物理位置 —— 自相对 delta 相对的就是它（common.md §1.1）。
        """
        for off in self._block_seq(head_off, what, blocks):
            blk = self.read_block(off)
            h = parse_header(blk)
            if not h["magic_ok"] or h["block_type"] != btype:
                raise EasyFSError("%s 里 @%d 不是 %s 块（type=%s）"
                                  % (what, off, BT_NAME.get(btype, btype),
                                     BT_NAME.get(h["block_type"], h["block_type"])))
            start = h["header_bytes"]
            ok_crc = verify_payload_crc(blk, h)
            if ok_crc is False:                  # 目录/链接块**必须**开载荷 CRC
                raise EasyFSError("%s 里 @%d 的载荷 CRC 不对（块坏了）"
                                  % (what, off))
            for atype, value, a0, a1 in scan_attrs(blk, start,
                                                   start + h["payload_len"]):
                yield atype, value, off, a0, a1

    def _apply_attr(self, ent, atype, value, base):
        """把一个属性并进条目（解析出 kind / child / size / 链接块 / 时间）。"""
        if atype == ATTR_NAME:
            ent["name"] = value
        elif atype == ATTR_DIR_PTR:
            ent["kind"] = "dir"
            ent["child"] = base + struct.unpack_from("<q", value, 0)[0]
        elif atype == ATTR_DIR_OBJECT:
            # 目录的对象形态：内容是链接块里的**内容块表**（读侧，2-dir.md §3.3）
            if len(value) != 8:
                raise EasyFSError("DIR_OBJECT 的值必须是 8 字节（{i64 L}）")
            ent["kind"] = "dir"
            l, = struct.unpack("<q", value)
            ent["dir_object"] = self.logical_to_phys(l)
            ent["child"] = None
        elif atype in (ATTR_DATA_TINY, ATTR_SYMLINK_TINY):
            ent["size"] += len(value)
            if atype == ATTR_SYMLINK_TINY:
                ent["symlink"] = True
        elif atype in (ATTR_DATA_PTR, ATTR_SYMLINK_PTR, ATTR_SYMLINK_OBJECT):
            ent["size"] += parse_data_ptr(value)[1]
            if atype in (ATTR_SYMLINK_PTR, ATTR_SYMLINK_OBJECT):
                ent["symlink"] = True
        elif atype == ATTR_DATA_OBJECT:
            self._apply_link(ent, value)
        elif atype == ATTR_TMODIFY and len(value) == 4:
            ent["mtime"], = struct.unpack("<I", value)
        elif atype == ATTR_TCREATE and len(value) == 4:
            ent["ctime"], = struct.unpack("<I", value)

    def _apply_link(self, ent, value):
        """`DATA_OBJECT {i64 L}` → 读链接块，把它的属性并进本条目（3-link.md）。

        链接块里的 `DATA_PTR` 的 delta 基准是**链接块自己**，所以并进来时把 base 记成
        链接块地址即可 —— 后面的读取路径（内容、范围读、位图重建）完全不用改。
        条目形态：`NAME + DATA_OBJECT`，**没有数据属性、没有时间属性**。
        """
        if len(value) != 8:
            raise EasyFSError("DATA_OBJECT 值必须是 8 字节（收到 %d）" % len(value))
        lval, = struct.unpack("<q", value)
        loff = self.logical_to_phys(lval)
        ent["link_blocks"].append(loff)
        ent["kind"] = "file"
        for atype, v, b, _a0, _a1 in self._iter_stream(loff, BT_LINK, "链接块链"):
            if atype == ATTR_NLINK:
                if len(v) != 4:
                    raise EasyFSError("NLINK 值必须是 4 字节")
                ent["nlink"], = struct.unpack("<I", v)
                continue
            if atype == ATTR_DATA_OBJECT:
                raise EasyFSError("链接块里不允许再出现 DATA_OBJECT @%d" % b)
            ent["attrs"].append((atype, v, b))
            self._apply_attr(ent, atype, v, b)

    def dir_object_blocks(self, obj_off):
        """读一个**目录链接块**（`DIR_OBJECT` → 链接块），返回内容块表（有序）。

        链接块载荷 = 目录的内容块表（`DATA_PTR` 列表，delta 基准 = 属性所在块），
        内容块是普通的 dir 块（TLV 条目流）。这就是"目录的链 → 块表"
        （[`2-dir.md`](2-dir.md) §3.3、[`cow.md`](cow.md) §11）。
        """
        blocks = []
        for atype, value, base, _a0, _a1 in self._iter_stream(
                obj_off, BT_LINK, "目录链接块"):
            if atype == ATTR_DATA_PTR:
                x, size = parse_data_ptr(value)
                blocks.append((base + x, size))
        if not blocks:
            raise EasyFSError("目录链接块 @%d 的内容块表为空" % obj_off)
        for off, _size in blocks:
            h = parse_header(self.read_block(off))
            if not h["magic_ok"] or h["block_type"] != BT_DIR:
                raise EasyFSError(
                    "目录对象 @%d 的内容块 @%d 不是 dir 块（type=%s）"
                    % (obj_off, off, BT_NAME.get(h["block_type"], "?")))
        return [off for off, _size in blocks]

    def read_dir_of(self, ent):
        """从**条目**出发读它指向的目录（自动选链式 / 对象形态）。"""
        if ent["kind"] != "dir":
            raise EasyFSError("不是目录: %r" % ent["name"])
        return self.read_dir(ent["child"], ent.get("dir_object"))

    def read_dir(self, head_off, dir_object=None):
        """读一个目录（dir 块双向链），返回条目 list。

        条目形态（4-file.md §1 / 3-link.md）：内容内联在条目里（模式①②③④）、
        或 `NAME + DATA_OBJECT` 指向链接块。**条目可以顺着链跨块继续** ——
        下一个 `NAME`（或流的尽头）才是它的终点。

        `dir_object` 给定时，目录内容是那个**链接块里的内容块表**（`DIR_OBJECT` 形态，
        [`2-dir.md`](2-dir.md) §3.3）：此时 `head_off` 不参与（传 None 即可）。
        """
        if dir_object is None:
            stream = self._iter_stream(head_off)
        else:
            stream = self._iter_stream(None, BT_DIR, "目录对象的内容块",
                                       blocks=self.dir_object_blocks(dir_object))
        entries, cur = [], None
        for atype, value, base, a0, a1 in stream:
            if atype == ATTR_NAME:
                if cur is not None:
                    entries.append(cur)
                cur = {"dir_block": head_off, "start": a0, "end": a1,
                       "name": value, "kind": "file", "child": None,
                       "size": 0, "attrs": [], "mtime": 0, "ctime": 0,
                       "nlink": 1, "symlink": False, "link_blocks": [],
                       "dir_object": None,
                       "segs": [[base, a0, a1]]}
                cur["attrs"].append((atype, value, base))
                continue
            if cur is None:
                raise EasyFSError("目录流以非 NAME 属性开头（@%d type=0x%02x）"
                                  % (base, atype))
            cur["attrs"].append((atype, value, base))
            self._apply_attr(cur, atype, value, base)
            seg = cur["segs"][-1]
            if seg[0] == base:
                seg[2] = a1                       # 同一块内继续
            else:
                cur["segs"].append([base, a0, a1])
        if cur is not None:
            entries.append(cur)
        for ent in entries:
            # 回填条目在本块内的真实区间：start/end 必须覆盖**全部**属性 ——
            # 只覆盖 NAME 的话，删除会留下 DATA_PTR 被前一个条目吞掉。
            ent["dir_block"] = ent["segs"][0][0]
            ent["start"] = ent["segs"][0][1]
            ent["end"] = ent["segs"][-1][2]
            ent["spans"] = (len(ent["segs"]) > 1)     # 跨块条目：写侧 v0 不支持
        return entries

    def lookup(self, dir_head_off, name, dir_object=None):
        """按名字查找一条目录条目；找不到返回 None。名字按原始字节比较。

        `dir_object` 同 `read_dir`（对象形态目录）。
        """
        if isinstance(name, str):
            name = name.encode("utf-8")
        for ent in self.read_dir(dir_head_off, dir_object):
            if ent["name"] == name:
                return ent
        return None

    def read_file(self, ent):
        """读出整份内容（就是 `read_range(ent)`，范围读见下面的实现）。"""
        return self.read_range(ent)

    def list_dir(self, head_off, path=""):
        """递归列出目录（给 CLI 用），返回 [(path, kind, size), ...]。"""
        out = []
        for ent in self.read_dir(head_off):
            name = ent["name"].decode("utf-8", "replace")
            full = path + "/" + name
            out.append((full, ent["kind"], ent["size"]))
            if ent["kind"] == "dir" and ent["child"]:
                out.extend(self.list_dir(ent["child"], full))
        return out

    # ------------------------------------------------------------ 目录写路径

    def entry_content(self, ent):
        """把条目解成 `(tiny, runs)`：`tiny` 是内联数据，`runs` 是 `[(物理地址, 长度)]`。

        普通文件与软链接**共用同一套逻辑布局**（4-file.md §4）：内联部分可以是
        `DATA_TINY`（文件内容）或 `SYMLINK_TINY`（软链接目标路径），数据段可以是
        `DATA_PTR` 或 `SYMLINK_PTR` / `SYMLINK_OBJECT`。

        `DATA_PTR` 是相对**属性所在块**的自相对 delta，所以要带上 `base`
        （2-dir.md §2.1）；带 `_LOGICAL` 的先按 `L` 换算成物理地址。
        指向链接块的条目会由 `read_dir` 把链接块的属性并进来，这里不用特殊处理。
        """
        tiny = b""
        runs = []
        for atype, value, base in ent["attrs"]:
            if atype in CONTENT_TINY_ATTRS:
                tiny += value
            elif atype in CONTENT_RUN_ATTRS:
                x, size = parse_data_ptr(value)
                runs.append((base + x, size))
            elif atype in CONTENT_RUN_LOGICAL_ATTRS:
                x, size = parse_data_ptr(value)
                runs.append((self.logical_to_phys(x), size))
        return tiny, runs

    def _encode_entry(self, base, name, kind, tiny, runs, mtime,
                      child=None, extra=()):
        """按 `base`（属性所在块）生成一条条目的属性字节（2-dir.md §2 + 4-file.md §1）。"""
        out = encode_attr(ATTR_NAME, name)
        if kind == "symlink":
            raise EasyFSError("用 Volume.symlink(parent, name, target)，"
                              "不要 create(kind='symlink')")
        if kind == "dir":
            if child is None:
                raise EasyFSError("目录条目必须给 child")
            out += encode_attr(ATTR_DIR_PTR, struct.pack("<q", child - base))
        else:
            if tiny:
                out += encode_attr(ATTR_DATA_TINY, tiny)
            for phys, size in runs:
                out += encode_attr(ATTR_DATA_PTR,
                                   struct.pack("<qI", phys - base, size))
        if mtime:
            out += encode_attr(ATTR_TMODIFY, struct.pack("<I", mtime & 0xFFFFFFFF))
        for atype, value in extra:
            # `value` 可以是 callable：给它属性所在块的地址，自己算 delta
            out += encode_attr(atype, value(base) if callable(value) else value)
        return out

    def _dir_block_write(self, buf, off, payload_len, prev=0, nxt=0, seq=0):
        pcrc = crc32(bytes(buf[HDR_SIZE:HDR_SIZE + payload_len]))
        stamp_header(buf, BT_DIR, HDR_SIZE, payload_len, seq=seq,
                     prev_delta=prev, next_delta=nxt, payload_crc=pcrc)
        self.dev.write_at(off, buf)

    def _read_dir_block(self, off):
        buf = bytearray(self.read_block(off))
        h = parse_header(buf)
        if not h["magic_ok"] or h["block_type"] != BT_DIR:
            raise EasyFSError("不是 dir 块 @%d" % off)
        return buf, h

    def _dir_head(self, off):
        """沿 prev_delta 走到目录链头。"""
        for _ in range(1 << 20):
            blk, h = self._read_dir_block(off)
            if not h["prev_delta"]:
                return off
            off = off + h["prev_delta"]
        raise EasyFSError("目录链疑似成环")

    def _dir_block_new(self, prev_off):
        """分配并写好一个新的（空）dir 块，先占位再返回其地址。"""
        phys, n = self.alloc(BLOCK_4K)
        blk = bytearray(BLOCK_4K)
        self._dir_block_write(blk, phys, 0,
                              prev=(prev_off - phys) if prev_off else 0,
                              nxt=0, seq=0)
        self.save_bitmap()                 # 先占位（1-alloc.md §7.1）
        return phys

    def _dir_insert(self, head_off, build):
        """把一条新条目追加到目录链尾（放不下就新开一块）。

        `build(base) -> bytes`：`base` 是条目最终落地的块地址，用于算自相对 delta。
        条目长度必须与 base 无关（先探长度、再定目标块、最后真正生成）。
        """
        probe = build(0)
        if len(probe) > BLOCK_4K - HDR_SIZE:
            raise EasyFSFragmented(
                "条目装不下（要 %d 字节，单块上限 %d）：格式允许顺着目录链跨块继续，"
                "v0 写入方还没实现（读侧已支持，2-dir.md §8）"
                % (len(probe), BLOCK_4K - HDR_SIZE))
        off = head_off
        prev_off = 0
        for _ in range(1 << 20):
            buf, h = self._read_dir_block(off)
            if HDR_SIZE + h["payload_len"] + len(probe) <= BLOCK_4K:
                break
            prev_off = off
            if h["next_delta"]:
                off = off + h["next_delta"]
            else:
                new_off = self._dir_block_new(prev_off)
                # 写好新块之后，才改老链尾的 next（先写孩子后写指针）
                buf2, h2 = self._read_dir_block(prev_off)
                self._dir_block_write(buf2, prev_off, h2["payload_len"],
                                      prev=h2["prev_delta"],
                                      nxt=(new_off - prev_off), seq=h2["seq"])
                off = new_off
                buf, h = self._read_dir_block(off)
                break
        else:
            raise EasyFSError("目录链疑似成环")
        data = build(off)
        if len(data) != len(probe):
            raise EasyFSError("条目长度随 base 变化（不应发生）")
        start = HDR_SIZE + h["payload_len"]          # 块内绝对偏移
        buf[start:start + len(data)] = data
        self._dir_block_write(buf, off, h["payload_len"] + len(data),
                              prev=h["prev_delta"], nxt=h["next_delta"],
                              seq=h["seq"])
        return {"dir_block": off, "start": start, "end": start + len(data)}

    @staticmethod
    def _entry_extent(ent):
        """拿到条目在**单块内**的 `(块, 起始, 结束)`。

        v0 写入方只会创建单块条目；跨块条目（读侧支持）一律拒绝改写 ——
        否则按第一块的偏移去改会把别的块的字节改坏。
        """
        if ent.get("spans"):
            raise EasyFSError(
                "ENOTSUP: 这条条目跨了多个目录块，v0 写入方还不支持改写它"
                "（读侧支持；2-dir.md §8）")
        return ent["dir_block"], ent["start"], ent["end"]

    def _dir_entry_remove(self, off, start, end):
        """把一条条目从块里删掉（块内 memmove，无墓碑；2-dir.md §5）。

        `start` / `end` 是**块内绝对偏移**（和 `read_dir` 返回的一致）。
        """
        buf, h = self._read_dir_block(off)
        plen_abs = HDR_SIZE + h["payload_len"]
        n = end - start
        if n <= 0 or end > plen_abs or start < HDR_SIZE:
            raise EasyFSError("条目边界非法: %d..%d (payload 末尾=%d)"
                              % (start, end, plen_abs))
        buf[start:plen_abs - n] = bytes(buf[end:plen_abs])
        buf[plen_abs - n:plen_abs] = b"\x00" * n
        self._dir_block_write(buf, off, h["payload_len"] - n,
                              prev=h["prev_delta"], nxt=h["next_delta"],
                              seq=h["seq"])

    def _replace_entry(self, ent, tiny, runs, mtime, kind=None, child=None,
                       name=None, extra=()):
        """改写一条既有条目：能在原块里挪就一次写完，否则"先插新的、再删旧的"。

        `name` 给定时用来改名（长度变化也能处理）。
        """
        kind = kind or ent["kind"]
        child = child if child is not None else ent["child"]
        name = ent["name"] if name is None else name
        off, start, end = self._entry_extent(ent)
        old_len = end - start
        probe = self._encode_entry(0, name, kind, tiny, runs, mtime, child, extra)
        new_len = len(probe)
        buf, h = self._read_dir_block(off)
        plen_abs = HDR_SIZE + h["payload_len"]
        if new_len <= old_len or plen_abs + (new_len - old_len) <= BLOCK_4K:
            data = self._encode_entry(off, name, kind, tiny, runs, mtime, child,
                                      extra)
            tail = bytes(buf[end:plen_abs])
            buf[start:start + new_len] = data
            buf[start + new_len:start + new_len + len(tail)] = tail
            self._dir_block_write(buf, off, h["payload_len"] - old_len + new_len,
                                  prev=h["prev_delta"], nxt=h["next_delta"],
                                  seq=h["seq"])
            return {"dir_block": off, "start": start, "end": start + new_len}
        # 原地放不下：先写到链尾（新的落盘），再从原块删掉
        info = self._dir_insert(self._dir_head(off),
                                lambda base: self._encode_entry(
                                    base, name, kind, tiny, runs, mtime, child))
        self._dir_entry_remove(off, start, end)
        return info

    def _alloc_and_write(self, data):
        """分配并写入数据，返回 `[(物理地址, 长度)]`。

        * 每次请求"**当前最大的连续空闲段**"，而不是固定小块 —— 这样顺序写一个
          大文件通常只有 1 条 `DATA_PTR`，不会把目录项撑爆。
        * `长度`记的是**这段文件数据的真实字节数**（可能不是 chunk 的整数倍），
          而不是分配到的空间；否则 `read` 会把最后一块的 padding 也读出来
          （2-dir.md §2.1）。释放时 `free()` 按 chunk 取整，两者自洽。
        """
        runs = []
        pos = 0
        while pos < len(data):
            free = self.free_runs()
            if not free:
                raise EasyFSError("ENOSPC: 位图里没有空闲段")
            biggest = max(r[2] for r in free) * self.chunk
            want = min(len(data) - pos, biggest)
            phys, got = self.alloc(want, runs=free)      # 复用同一次扫描
            take = min(got, len(data) - pos)
            self.dev.write_at(phys, data[pos:pos + take])
            runs.append((phys, take))
            pos += take
        return runs

    def _prepare_data(self, data):
        """≤255 字节走 DATA_TINY（零分配）；否则写数据块。"""
        if len(data) <= TINY_MAX:
            return data, []
        return b"", self._alloc_and_write(data)

    def _check_entry_fits(self, name, tiny, runs, kind="file", child=None):
        """段数太多、单个 4 KiB 条目装不下时抛 `EasyFSFragmented`。

        这是"写侧跨块条目还没实现"的兜底（2-dir.md §8）。错误信息要**能照着做**：
        给出"要几段 / 最多几段 / 还空多少 / 最大连续段多大 / 平均每段要多大会够"。
        """
        if isinstance(name, str):
            name = name.encode("utf-8")
        probe = self._encode_entry(0, name, kind, tiny, runs, 0, child)
        limit = BLOCK_4K - HDR_SIZE
        if len(probe) <= limit:
            return
        free = self.free_runs()
        biggest = (max(r[2] for r in free) * self.chunk) if free else 0
        overhead = len(probe) - 14 * len(runs)           # NAME / TINY / 时间 等
        max_runs = max(1, (limit - overhead) // 14)
        data_bytes = sum(sz for _, sz in runs)
        need_avg = -(-data_bytes // max_runs)             # 平均每段多大才够
        raise EasyFSFragmented(
            "条目装不下：这个文件被切成 %d 段（数据 %s），要 %d 字节，"
            "单块条目上限约 %d 段。格式允许条目顺着目录链跨块继续，"
            "但 v0 写入方还没实现（读侧已支持，4-file.md §8）。"
            "卷里还有 %s 空闲，最大连续空闲 %s —— "
            "要么腾出平均 ≥ %s 的连续段，要么先删掉一些文件。"
            % (len(runs), human(data_bytes), len(probe), max_runs,
               human(self.free_bytes()), human(biggest), human(need_avg)))

    def _free_allocations(self, ent):
        """释放条目的数据段与链接块（不含子目录链）。"""
        tiny, runs = self.entry_content(ent)
        for phys, size in runs:
            self.free(phys, size)
        for loff in ent["link_blocks"]:
            self.free(loff, BLOCK_4K)

    def _free_dir_chain(self, head_off):
        off = head_off
        for _ in range(1 << 20):
            if not off:
                return
            blk, h = self._read_dir_block(off)
            nxt = (off + h["next_delta"]) if h["next_delta"] else 0
            self.free(off, BLOCK_4K)
            off = nxt
        raise EasyFSError("目录链疑似成环")

    # ------------------------------------------------------------ 对外：create / delete / read / write

    def create(self, parent_dir_off, name, kind="file", data=b"", mtime=None,
               dir_object=None):
        """新建一个文件或目录（4-file.md §1 的①②③模式由 `data` 自动选）。

        * `kind="file"`，`data` ≤255 B → 只有 `DATA_TINY`（**零分配、单块原子**）
        * `kind="file"`，`data` 更长 → 写数据块 + `DATA_PTR`
        * `kind="dir"` → 分配一个空 dir 块 + `DIR_PTR`
        """
        if dir_object is not None:
            raise EasyFSError(
                "ENOTSUP: 往 DIR_OBJECT 形态的目录里写还没实现（只有读侧；"
                "见 2-dir.md §3.3）")
        if isinstance(name, str):
            name = name.encode("utf-8")
        if not (1 <= len(name) <= NAME_MAX):
            raise EasyFSError("名字长度必须在 1..%d 字节" % NAME_MAX)
        if self.lookup(parent_dir_off, name) is not None:
            raise EasyFSError("已存在: %s" % name.decode("utf-8", "replace"))
        if mtime is None:
            mtime = int(__import__("time").time()) & 0xFFFFFFFF

        tiny, runs, child = b"", [], None
        if kind == "dir":
            child = self._dir_block_new(0)          # 先写空目录块
        elif data:
            tiny, runs = self._prepare_data(data)
            if runs:
                try:
                    self._check_entry_fits(name, tiny, runs)
                except EasyFSFragmented:
                    for phys, size in runs:         # 回滚（位图还没落盘）
                        self.free(phys, size)
                    raise
                self.save_bitmap()                  # 先占位
        info = self._dir_insert(
            parent_dir_off,
            lambda base: self._encode_entry(base, name, kind, tiny, runs,
                                            mtime, child))
        # 重新按名字读回来（解析逻辑只有 read_dir 一份，_parse_entry 已并入它）
        ent = self.lookup(parent_dir_off, name)
        if ent is None or ent["start"] != info["start"]:
            raise EasyFSError("写完条目后找不到它：%s @%d"
                              % (name, info["start"]))
        return ent

    def mkdir(self, parent_dir_off, name, mtime=None, dir_object=None):
        return self.create(parent_dir_off, name, kind="dir", mtime=mtime, dir_object=dir_object)

    def read(self, parent_dir_off, name, offset=0, length=None):
        """按名字读文件内容；`offset` / `length` 给定时只读这一范围。

        ``read(dir, name)`` 等价于读整份（向后兼容）。
        """
        ent = self.lookup(parent_dir_off, name)
        if ent is None:
            raise EasyFSError("找不到: %s" % name)
        if ent["kind"] != "file":
            raise EasyFSError("不是文件: %s" % name)
        return self.read_range(ent, offset, length)

    def read_range(self, ent, offset=0, length=None):
        """按范围读文件内容，返回 bytes。

        逻辑布局 = `DATA_TINY`（占 `[0, tiny_len)`）+ 各 `DATA_PTR` /
        `DATA_PTR`（按属性出现顺序，见 4-file.md §4）。

        实现要点：**段是顺序的**，所以先按段累加逻辑位置跳过 `offset` 之前的段，
        再只读真正相交的那几段，越过 `end` 立刻停 —— 不会为了读 4 KiB 去碰整个文件。
        （代价：段的定位要扫一遍属性；段数少时就是几十次循环。顺序分块读时
        每次都会重新扫，将来可以加"读游标"优化。）
        """
        total = ent["size"]
        if offset < 0:
            raise EasyFSError("offset 不能为负: %d" % offset)
        if offset >= total:
            return b""
        if length is None or length > total - offset:
            length = total - offset
        if length <= 0:
            return b""
        end = offset + length

        out = bytearray()
        pos = 0                                     # 当前段在文件里的逻辑起点
        for atype, value, base in ent["attrs"]:
            if pos >= end:
                break
            if atype in CONTENT_TINY_ATTRS:
                blob, seg_phys, seg_len = value, None, len(value)
            elif atype in CONTENT_RUN_ATTRS:
                x, seg_len = parse_data_ptr(value)
                blob, seg_phys = None, base + x
            elif atype in CONTENT_RUN_LOGICAL_ATTRS:
                x, seg_len = parse_data_ptr(value)
                blob, seg_phys = None, self.logical_to_phys(x)
            else:
                continue                    # NAME / 时间 / NLINK 等不是数据
            if pos + seg_len > offset and pos < end:
                lo = max(offset, pos) - pos          # 段内起点
                hi = min(end, pos + seg_len) - pos   # 段内终点
                if blob is not None:
                    out += blob[lo:hi]
                else:
                    out += self.dev.read_at(seg_phys + lo, hi - lo)
            pos += seg_len
            if pos >= end:
                break
        return bytes(out)

    def write(self, parent_dir_off, name, data, offset=None, touch=True):
        """写文件，返回写完后的长度。

        * ``offset=None`` 或 ``offset == 当前大小`` → **追加**（分配新段 + 改条目）
        * ``offset < 当前大小`` → **覆盖**：
            - 落在**数据段**里的部分 → **直接写裸数据块**，不动位图、不动映射、不分配；
            - 落在 `DATA_TINY` 里的部分 → 要重写目录条目（一次 4 KiB 块写）；
            - 越过 EOF 的那部分 → 按追加处理。
        * ``offset > 当前大小`` → `ENOTSUP`（不支持稀疏文件/空洞）
        * ``touch=False`` 且只发生"段内覆盖"时 → **零元数据写**（连 mtime 都不动）

        `DATA_TINY` 可以和新追加的 `DATA_PTR` 共存（4-file.md §4）。
        """
        ent = self.lookup(parent_dir_off, name)
        if ent is None:
            raise EasyFSError("找不到: %s" % name)
        if ent["kind"] != "file":
            raise EasyFSError("不是文件: %s" % name)
        tiny, runs = self.entry_content(ent)
        size = len(tiny) + sum(sz for _, sz in runs)
        if offset is None:
            offset = size
        if offset < 0:
            raise EasyFSError("offset 不能为负: %d" % offset)
        if offset > size:
            raise EasyFSError("ENOTSUP: 不支持空洞（offset=%d > size=%d）"
                              % (offset, size))
        if not data:
            return size

        end = offset + len(data)
        covered = max(0, min(len(data), size - offset))     # 覆盖掉已有内容的字节数

        # ---- 覆盖：DATA_TINY 部分（改条目）
        tiny_new = tiny
        if offset < len(tiny):
            n = min(len(data), len(tiny) - offset)
            tiny_new = tiny[:offset] + data[:n] + tiny[offset + n:]
        # ---- 覆盖：数据段部分（纯数据写）
        if runs and end > len(tiny):
            self._overwrite_runs(runs, len(tiny), offset, data)
        # ---- 越过 EOF 的部分：追加（先占位后引用）
        new_runs = []
        if covered < len(data):
            new_runs = self._alloc_and_write(data[covered:])
            try:
                self._check_entry_fits(ent["name"], tiny_new, runs + new_runs)
            except EasyFSFragmented:
                for phys, size in new_runs:          # 回滚（位图还没落盘）
                    self.free(phys, size)
                raise
            self.save_bitmap()
        runs = runs + new_runs
        self._check_entry_fits(ent["name"], tiny_new, runs)   # 兜底
        if tiny_new != tiny or new_runs or touch:
            if touch:
                mtime = int(__import__("time").time()) & 0xFFFFFFFF
            else:
                mtime = entry_mtime(ent)                    # 保留原来的时间戳
            self._replace_entry(ent, tiny_new, runs, mtime)
        return len(tiny_new) + sum(sz for _, sz in runs)

    def _overwrite_runs(self, runs, tiny_len, offset, data):
        """把 `data` 覆盖进 `[offset, offset+len(data))` 落在**数据段**里的部分。

        数据块是裸的（没有块头、没有校验），所以段内覆盖就是一次 `dev.write_at`
        —— 不碰位图、不碰映射、不碰任何元数据。这是"数据块不带块头"换来的直接好处。
        """
        end = offset + len(data)
        pos = tiny_len                                       # 段的逻辑起点从 tiny 之后开始
        for phys, seg_len in runs:
            seg_start, seg_end = pos, pos + seg_len
            pos = seg_end
            if seg_end <= offset or seg_start >= end:
                continue
            a = max(offset, seg_start) - offset              # 对应 data 的起点
            b = min(end, seg_end) - offset                   # 对应 data 的终点
            self.dev.write_at(phys + (max(offset, seg_start) - seg_start),
                              data[a:b])

    # ------------------------------------------------------------ 链接

    def _object_nlink(self, obj):
        """读链接块的 `NLINK`，并返回它的块字节 / 头 / `NLINK` 属性的绝对偏移。"""
        blk = bytearray(self.read_block(obj))
        h = parse_header(blk)
        if not h["magic_ok"] or h["block_type"] != BT_LINK:
            raise EasyFSError("@%d 不是链接块" % obj)
        for atype, value, a0, a1 in scan_attrs(blk, h["header_bytes"],
                                               h["header_bytes"] + h["payload_len"]):
            if atype == ATTR_NLINK:
                return struct.unpack("<I", value)[0], blk, h, a0
        raise EasyFSError("链接块 @%d 里没有 NLINK" % obj)

    def _set_object_nlink(self, obj, n):
        """原地改链接块的 `NLINK` 并重算载荷 CRC。"""
        _old, blk, h, a0 = self._object_nlink(obj)
        struct.pack_into("<I", blk, a0 + ATTR_TLV_HDR, n)
        payload = bytes(blk[h["header_bytes"]:
                            h["header_bytes"] + h["payload_len"]])
        stamp_header(blk, BT_LINK, h["header_bytes"], h["payload_len"],
                     seq=h["seq"], payload_crc=crc32(payload))
        self.dev.write_at(obj, blk)

    def _new_object(self, tiny, runs, mtime, nlink):
        """建一个链接块，返回它的物理地址（内容 delta 基准 = 链接块自己）。"""
        obj, _n = self.alloc(BLOCK_4K)
        payload = encode_attr(ATTR_NLINK, struct.pack("<I", nlink))
        if mtime:
            payload += encode_attr(ATTR_TMODIFY,
                                   struct.pack("<I", mtime & 0xFFFFFFFF))
        if tiny:
            payload += encode_attr(ATTR_DATA_TINY, tiny)
        for phys, size in runs:
            payload += encode_attr(ATTR_DATA_PTR,
                                   struct.pack("<qI", phys - obj, size))
        blk = bytearray(BLOCK_4K)
        blk[HDR_SIZE:HDR_SIZE + len(payload)] = payload
        stamp_header(blk, BT_LINK, HDR_SIZE, len(payload),
                     payload_crc=crc32(payload))
        self.dev.write_at(obj, blk)
        return obj

    def _object_data(self, obj):
        """链接块引用的数据段 `[(phys, size)]`。"""
        out = []
        for atype, value, base, _a0, _a1 in self._iter_stream(obj, BT_LINK):
            if atype == ATTR_DATA_PTR:
                x, size = parse_data_ptr(value)
                out.append((base + x, size))
        return out

    def link(self, parent_dir_off, name, target_ent, mtime=None,
             dir_object=None):
        """建**硬链接**（`3-link.md` §3 的 copy-on-link 升格）。

        * 目标已经是对象形态 ⇒ 加一条指向同一链接块的条目，`NLINK += 1`
        * 否则 ⇒ **升格**：内容搬进新链接块（`NLINK = 2`），原条目改写成
          `NAME + DATA_OBJECT{L}`，再加新条目 —— 两条指向同一个链接块
        """
        if target_ent["kind"] != "file":
            raise EasyFSError("ENOTSUP: 目录不许硬链接（3-link.md）")
        if target_ent["symlink"]:
            raise EasyFSError("ENOTSUP: 不许硬链接到软链接")
        if self.lookup(parent_dir_off, name, dir_object) is not None:
            raise EasyFSError("已存在: %s" % name)
        tiny, runs = self.entry_content(target_ent)
        if target_ent["link_blocks"]:
            obj = target_ent["link_blocks"][0]
            n = self._object_nlink(obj)[0]
            self._set_object_nlink(obj, n + 1)
        else:
            obj = self._new_object(tiny, runs, target_ent.get("mtime") or 0, 2)
            L = self.phys_to_logical(obj)
            self._replace_entry(target_ent, b"", [], 0,
                                extra=[(ATTR_DATA_OBJECT,
                                        struct.pack("<q", L))])
        L = self.phys_to_logical(obj)
        ent = self.create(parent_dir_off, name, dir_object=dir_object)
        self._replace_entry(ent, b"", [], 0,
                            extra=[(ATTR_DATA_OBJECT, struct.pack("<q", L))])
        return self.lookup(parent_dir_off, name, dir_object)

    def symlink(self, parent_dir_off, name, target, mtime=None,
                dir_object=None):
        """建**软链接**（内容 = 目标路径；`4-file.md` §9）。

        v0 只产出 `SYMLINK_TINY`（目标 ≤255 B）；更长的目标是 `[待定]`。
        """
        t = target.encode("utf-8") if isinstance(target, str) else target
        ent = self.create(parent_dir_off, name, dir_object=dir_object)
        if len(t) <= TINY_MAX:
            self._replace_entry(ent, b"", [], mtime or 0,
                                extra=[(ATTR_SYMLINK_TINY, t)])
        else:
            # 长目标：放一个**数据块**里（③ 形态，不是对象形态）
            phys, _n = self.alloc(ceil_div(len(t), self.chunk) * self.chunk)
            blk = bytearray(ceil_div(len(t), BLOCK_4K) * BLOCK_4K)
            blk[0:len(t)] = t
            self.dev.write_at(phys, blk)
            self._replace_entry(
                ent, b"", [], mtime or 0,
                extra=[(ATTR_SYMLINK_PTR,
                        lambda base: struct.pack("<qI", phys - base, len(t)))])
        return self.lookup(parent_dir_off, name, dir_object)

    def readlink(self, ent):
        """读软链接的目标（`4-file.md` §9）。"""
        if not ent["symlink"]:
            raise EasyFSError("不是软链接: %r" % ent["name"])
        return self.read_file(ent)

    def delete(self, parent_dir_off, name, recursive=False, dir_object=None):
        """删除文件或目录。

        顺序遵守 1-alloc.md §7.1：**先解除引用（删条目），后释放空间（清 bit）**。
        """
        ent = self.lookup(parent_dir_off, name, dir_object)
        was_obj = ent["link_blocks"][0] if ent["link_blocks"] else None
        obj_n = self._object_nlink(was_obj)[0] if was_obj else 0
        obj_runs = self._object_data(was_obj) if was_obj else []
        if ent is None:
            raise EasyFSError("找不到: %s" % name)
        if ent["kind"] == "dir":
            children = self.read_dir_of(ent) if ent["child"] else []
            if children and not recursive:
                raise EasyFSError("目录非空: %s" % name)
            for c in children:
                self.delete(ent["child"], c["name"].decode("utf-8"), recursive=True)
            child_chain = ent["child"]
        else:
            child_chain = None
        self._dir_entry_remove(*self._entry_extent(ent))
        self._free_allocations(ent)
        if was_obj:                       # 对象形态：按 NLINK 决定"只是少个名字"还是真释放
            if obj_n > 1:
                self._mark_used(was_obj, BLOCK_4K)
                for _p, _s in obj_runs:
                    self._mark_used(_p, ceil_div(_s, self.chunk) * self.chunk)
                self._set_object_nlink(was_obj, obj_n - 1)
            else:
                self.free(was_obj, BLOCK_4K)
        if child_chain:
            self._free_dir_chain(child_chain)
        self.save_bitmap()
        return True

    unlink = delete

    def move(self, src_parent_off, name, dst_parent_off=None, new_name=None):
        """改名 / 移动到另一个目录。

        **数据一个字节都不动**：只把目录条目从原位置搬到新位置（改名后长度变化
        也一并处理）。跨目录时"先在新目录插入、再从旧目录删除"，这样崩在中间
        最坏是**同名两份**（fsck 能消解），而不是把文件弄丢。
        """
        ent = self.lookup(src_parent_off, name)
        if ent is None:
            raise EasyFSError("找不到: %s" % name)
        dst_parent_off = src_parent_off if dst_parent_off is None else dst_parent_off
        if new_name is None:
            new_name = ent["name"]
        elif isinstance(new_name, str):
            new_name = new_name.encode("utf-8")
        if not (1 <= len(new_name) <= TINY_MAX):
            raise EasyFSError("名字长度必须在 1..255 字节")
        if dst_parent_off == src_parent_off and new_name == ent["name"]:
            return ent
        if self.lookup(dst_parent_off, new_name) is not None:
            raise EasyFSError("目标已存在: %s" % new_name.decode("utf-8", "replace"))

        tiny, runs = self.entry_content(ent)
        mtime = int(__import__("time").time()) & 0xFFFFFFFF
        if dst_parent_off == src_parent_off:
            self._replace_entry(ent, tiny, runs, mtime, name=new_name)
        else:
            self._dir_insert(
                dst_parent_off,
                lambda base: self._encode_entry(base, new_name, ent["kind"],
                                                tiny, runs, mtime, ent["child"]))
            self._dir_entry_remove(*self._entry_extent(ent))
        return self.lookup(dst_parent_off, new_name)

    def rename(self, parent_off, old_name, new_name):
        """同目录改名。"""
        return self.move(parent_off, old_name, parent_off, new_name)

    # ------------------------------------------------------------ 提交 / 干净标志 / 重建

    def save_anchor(self, generation=None):
        """把当前几何 / 状态写回两份 anchor（tag 布局，1-alloc.md §7.2）。

        分裂会改变链长与链字节数 ⇒ 必须重写 anchor 的 `bmblocks` / `bmbytes`。
        """
        if generation is None:
            generation = self.head.get("generation", 1)
        nbytes = sum(r.block_bytes for r in self.regions)
        for is_head in (True, False):
            base = 0 if is_head else self.region_len - BLOCK_4K
            peer = ((self.region_len - BLOCK_4K) if is_head
                    else -(self.region_len - BLOCK_4K))
            blk = build_anchor_block(
                self.region_len, peer, self.data_lo_logical, generation,
                self.chunk_shift, self.policy_id, self.policy_state,
                self.root_type, self.root_off - base,
                self.alloc_off - base, len(self.regions), nbytes,
                self.state_flags, self.head["uuid"],
                alloc_type=getattr(self, "alloc_type", ALLOC_TYPE_CHAIN))
            self.dev.write_at(base, blk)
        if self.head is not None:
            self.head["alloc_num"] = len(self.regions)
            self.head["alloc_size"] = nbytes
            self.head["generation"] = generation
            self.tail["alloc_num"] = len(self.regions)
            self.tail["alloc_size"] = nbytes
            self.tail["generation"] = generation

    def commit(self, bump_generation=True):
        """提交点：位图落盘 + anchor 重写（1-alloc.md §7.2）。"""
        self.save_bitmap()
        gen = (self.head.get("generation", 1) if self.head else 1)
        if bump_generation:
            gen += 1
        self.save_anchor(gen)
        self.dev.flush()

    def is_dirty(self):
        return not (self.flags & 0x01)

    def set_clean_flag(self, clean):
        """改 head/tail anchor 的 `stateflg` tag（bit0 = clean），并重算 `hdrcrc`。"""
        for base in (0, self.region_len - BLOCK_4K):
            blk = bytearray(self.dev.read_at(base, BLOCK_4K))
            if bytes(blk[0:8]) != ANCHOR_MAGIC_TAG:
                continue
            old = anchor_geti(blk, "stateflg")
            anchor_put(blk, "stateflg", (old | 0x01) if clean else (old & ~0x01))
            anchor_put(blk, "hdrcrc  ", anchor_crc(blk, "hdrcrc  ", 0, ANCHOR_VOL_HDR_END))
            self.dev.write_at(base, blk)
        self.flags = 0x01 if clean else 0x00
        self.state_flags = self.flags

    def mark_dirty(self):
        """读写挂载时第一件事：置 dirty（此后崩溃靠挂载时重建兜底）。"""
        self.set_clean_flag(False)
        self.dev.flush()

    def mark_clean(self):
        self.set_clean_flag(True)
        self.dev.flush()

    def _mark_used(self, phys, size):
        """把 `[phys, phys+size)` 覆盖的 bit 全部置 1（按各区域自己的 `bit_unit`）。"""
        end = phys + size
        while phys < end:
            i, b = self.region_of_phys(phys)
            r = self.regions[i]
            n = min(end - phys, r.region_end - phys)
            r.set_range(b, ceil_div(n, r.bit_unit), 1)
            phys += ceil_div(n, r.bit_unit) * r.bit_unit

    def _walk_used(self, head_off, dir_object=None):
        """从某个目录出发，标出所有可达的块（1-alloc.md §7.4）。

        `dir_object` 给定时，这个目录是**对象形态**：内容块表在链接块里
        （`DIR_OBJECT`，2-dir.md §3.3），要连链接块与内容块一起标记。
        """
        if dir_object is None:
            off = head_off
            for _ in range(1 << 20):
                if not off:
                    break
                blk, h = self._read_dir_block(off)
                self._mark_used(off, BLOCK_4K)
                off = (off + h["next_delta"]) if h["next_delta"] else 0
        else:
            self._mark_used(dir_object, BLOCK_4K)
            for boff in self.dir_object_blocks(dir_object):
                self._mark_used(boff, BLOCK_4K)
        for ent in self.read_dir(head_off, dir_object):
            for loff in ent["link_blocks"]:          # 链接块本身也是元数据块
                self._mark_used(loff, BLOCK_4K)
            tiny, runs = self.entry_content(ent)
            for phys, size in runs:
                self._mark_used(phys, size)
            if ent["kind"] == "dir" and (ent["child"] or ent.get("dir_object")):
                self._walk_used(ent["child"], ent.get("dir_object"))

    def rebuild_bitmap(self, apply=True):
        """全量重建位图：从根可达的块集合的补集 = 空闲（common.md I3）。

        返回 `(used_before, used_after)`；`apply=True` 时写回。
        """
        saved = [bytes(r.bits) for r in self.regions]
        before = [r.used_bits() for r in self.regions]
        for r in self.regions:
            r.bits = bytearray(len(r.bits))
            r.dirty = True
        # 元数据：位图链自身 + 根目录（anchor 区不在位图覆盖范围内）
        for r in self.regions:
            self._mark_used(r.block_off, r.block_bytes)
        if getattr(self, "root_type", ROOT_TYPE_CHAIN) == ROOT_TYPE_OBJECT:
            self._walk_used(None, self.root_off)      # 根是对象形态
        else:
            self._walk_used(self.root_off)
        after = [r.used_bits() for r in self.regions]
        if apply:
            self.save_bitmap(force=True)
        else:
            # 纯干跑：把 RAM 里的位图恢复回去，别在 check 时悄悄"顺手修好"
            for r, b in zip(self.regions, saved):
                r.bits = bytearray(b)
                r.dirty = False
        return sum(before), sum(after)


# ================================================================ 7.5 路径解析

class PathWalker(object):
    """把"远端路径"解析成目录链头或条目。

    `..` 靠**内存里的路径链**维护 —— 卷格式里没有 `..` 条目，
    所以 `..` 只能向上走到根为止，永远不会越出卷。
    CLI 与网络服务器共用这一份实现。
    """

    def __init__(self, vol):
        self.vol = vol
        self.root = vol.root_off
        self.names = []                 # 当前目录的路径分量
        self.offs = [self.root]         # 对应的目录链头（offs[0] = 根）
        self.objs = [None]              # 与 offs 平行：DIR_OBJECT（对象形态目录）

    def clone(self):
        w = PathWalker(self.vol)
        w.names = list(self.names)
        w.offs = list(self.offs)
        w.objs = list(self.objs)
        return w

    def _walk(self, path):
        """内部：解析目录路径，返回 `(names, offs, objs)`（三者在每一层对齐）。"""
        if path.startswith("/"):
            names, offs, objs = [], [self.root], [None]
        else:
            names, offs, objs = (list(self.names), list(self.offs),
                                 list(self.objs))
        for part in str(path).split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if names:
                    names.pop()
                    offs.pop()
                    objs.pop()
                continue
            ent = self.vol.lookup(offs[-1], part, objs[-1])
            if ent is None:
                raise EasyFSError("目录不存在: %s" % part)
            if ent["kind"] != "dir":
                raise EasyFSError("不是目录: %s" % part)
            names.append(part)
            offs.append(ent["child"])
            objs.append(ent.get("dir_object"))
        return names, offs, objs

    def dir_stack(self, path):
        """解析一个**目录**路径，返回 `(names, offs)`；`offs[-1]` 是它的链头。"""
        names, offs, _objs = self._walk(path)
        return names, offs

    def dir_ref(self, path):
        """解析目录路径，返回 `(链头, DIR_OBJECT)` —— 读这个目录需要这两样。"""
        _names, offs, objs = self._walk(path)
        return offs[-1], objs[-1]

    def entry_pos(self, path):
        """解析一个**条目**路径，返回 `(父目录链头, 名字, 条目或 None)`。"""
        path = str(path)
        if "/" in path:
            parent, name = path.rsplit("/", 1)
            _n, offs, objs = self._walk(parent if parent else "/")
            poff, pobj = offs[-1], objs[-1]
        else:
            poff, pobj = self.offs[-1], self.objs[-1]
            name = path
        if name in ("", ".", ".."):
            raise EasyFSError("非法名字: %r" % path)
        return poff, name, self.vol.lookup(poff, name, pobj)

    def resolve_any(self, path):
        """目录优先；不是目录就当条目。返回 `('dir', names, offs)` 或 `('entry', ent)`。"""
        try:
            names, offs = self.dir_stack(path)
            return "dir", names, offs
        except EasyFSError:
            poff, name, ent = self.entry_pos(path)
            if ent is None:
                raise EasyFSError("找不到: %s" % path)
            return "entry", ent

    def cd(self, path):
        self.names, self.offs = self.dir_stack(path)
        return self.disp()

    def disp(self, names=None):
        names = self.names if names is None else names
        return "/" + "/".join(names) if names else "/"


# ================================================================ 8. mkfs

def child_block_bytes(unit):
    """覆盖一个 `unit` 字节空间、粒度到 `chunk` 时，子位图块要多大（1-alloc.md §13.4）。

    条件：`(block_bytes − 96) × 8 × chunk ≥ unit`；从 4 KiB 起按 ×2 阶梯取第一个满足的。
    """
    bb = BLOCK_4K
    while (bb - ALLOC_HDR) * 8 * BLOCK_4K < unit:
        bb *= 2
        if bb > (1 << 30):
            raise EasyFSError("单位太大：子位图块超过 1 GiB")
    return bb


def mixed_bit_unit0(data_bytes, chunk=BLOCK_4K):
    """起始粒度：**一个 4 KiB 位图块尽量覆盖**（1-alloc.md §13.3）。

    `bit_unit0` = 最小的 2 的幂，使 `ceil(data_bytes / bit_unit0) ≤ 4 KiB 块的 bit 数`。
    """
    cap = (BLOCK_4K - ALLOC_HDR) * 8                 # 一个 4 KiB 块的位图 bit 数（4000×8）
    bu = chunk
    while ceil_div(data_bytes, bu) > cap:
        bu *= 2
        if bu > BIT_UNIT_MAX:
            raise EasyFSError("卷太大：起始粒度会超过 %d" % BIT_UNIT_MAX)
    return bu


def find_best_alloc_setting(region_len, chunk=BLOCK_4K, bit_unit=None):
    """算出"最省分配块"的位图方案（1-alloc.md §13.3）。**纯计算，不碰设备。**

    返回 dict：

    * `mode`：`"flat"`（平铺，`bit_unit == chunk`）或 `"mixed"`（粗起步 + 元数据子区域）
    * `bit_unit0`：粗区域的粒度（2 的幂；平铺时就是 `chunk`）
    * `coarse_block_bytes` / `child_block_bytes`：两级位图块各多大
    * `blocks` / `bytes`：**最少需要几个位图块、合计多少字节**
    * `meta_unit`：被分裂出来放元数据的那个粗单位起点
    * 以及 `data_lo` / `data_bytes` 等中间量

    规则：起始粒度取"**一个 4 KiB 块尽量覆盖**"（`ceil(data_bytes/bit_unit0) ≤ 32000`）；
    元数据（位图块自己 + 根目录块，各 4 KiB）必须落在 4 KiB 粒度的子区域里 ——
    否则它们会**各吃掉一个粗单位**（1 TiB 白扔 128 MiB，见 §13.5）。
    """
    data_lo, data_hi = BLOCK_4K, region_len - BLOCK_4K
    data_bytes = data_hi - data_lo

    if bit_unit is not None:                   # `mkfs --fixbitsize`：强制"1 bit = 多少字节"
        bu0 = parse_size(bit_unit) if not isinstance(bit_unit, int) else int(bit_unit)
        if bu0 < chunk or bu0 % chunk or (bu0 & (bu0 - 1)):
            raise EasyFSError("EINVAL: --fixbitsize 必须是 2 的幂、是 chunk 的整数倍，"
                              "且不小于 chunk（%d）" % chunk)
    else:
        bu0 = mixed_bit_unit0(data_bytes, chunk)

    # 粗区域要几个位图块、每块多大：从 4 KiB 起翻倍，直到块数 ≤ MAX_BITMAP_BLOCKS
    bits_total = ceil_div(data_bytes, bu0)
    bb = BLOCK_4K
    while ceil_div(bits_total, (bb - ALLOC_HDR) * 8) > MAX_BITMAP_BLOCKS:
        bb *= 2
        if bb > (1 << 30):
            raise EasyFSError("卷太大 / bit 太小：位图块超过 1 GiB，请调大 --fixbitsize")
    n_coarse = ceil_div(bits_total, (bb - ALLOC_HDR) * 8)   # 粗区域几块（平铺时就是全部块）
    base = {"chunk": chunk, "data_lo": data_lo, "data_hi": data_hi,
            "data_bytes": data_bytes, "bit_unit0": bu0, "coarse_block_bytes": bb,
            "coarse_blocks": n_coarse}
    if bu0 <= 4 * chunk:                       # 粒度和 chunk 差不多：没有可分裂的东西
        # 注意：**两个分支返回的键要一致** —— 少一个键，调用方一句 `r["bit_unit0"]` 就崩
        return dict(base, mode="flat", child_block_bytes=None, child_blocks=0,
                    blocks=n_coarse, bytes=n_coarse * bb, meta_unit=None,
                    unit=bu0, child_units=0, child_bytes=0)
    unit = bu0
    n_unit = max(1, data_bytes // unit)
    k = max(0, min(n_unit - 1, (data_bytes // 2) // unit))   # 默认 middle-out：靠卷中心
    p_off = data_lo + k * unit
    unit_eff = min(unit, data_hi - p_off)      # 最后一个单位可能被数据区截断
    cbb = child_block_bytes(unit_eff)
    # 元数据（粗位图块 × n_coarse + 根目录块）全放进子区域 ⇒ 子区域可能盖住好几个单位
    need = n_coarse * bb + BLOCK_4K
    # **至少 2 个单位**：一个放分配块（位图链）、一个放根目录块 ——
    # 一个粗 bit 里只放"一类可独立挪动的对象"，共用会让那个 bit 永远回收不了（1-alloc.md §13.5）
    units = max(2, ceil_div(need + cbb, unit_eff))
    rbytes = min(units * unit_eff, data_hi - p_off)   # **整格**：盖住 units 个完整单位
    return dict(base, mode="mixed", child_block_bytes=cbb, child_blocks=1,
                blocks=n_coarse + 1, bytes=n_coarse * bb + cbb, meta_unit=p_off,
                unit=unit_eff, child_units=units, child_bytes=rbytes)


def plan_layout(region_len, chunk=BLOCK_4K, logical_origin=0, policy=3,
                bitmap_block=None, mixed=True, bit_unit=None):
    """算出 mkfs 的布局：区域切分、位图链位置、根目录块位置。

    返回 dict；纯计算，不碰设备（方便测试）。规则见 1-alloc.md §3.4/§4。
    """
    if chunk not in (512, 1024, 2048, 4096):
        raise EasyFSError("chunk 只支持 512/1024/2048/4096（layout.md §1）")
    region_len = align_down(region_len, chunk)
    if region_len < 16 * chunk:
        raise EasyFSError("区域太小: %d B" % region_len)
    if logical_origin % chunk:
        raise EasyFSError("logical_origin 必须按 chunk 对齐")

    data_lo = BLOCK_4K
    data_hi = region_len - BLOCK_4K
    data_bytes = data_hi - data_lo
    chunk_count = data_bytes // chunk

    # `L` 是 i64，而且**不存** data_hi_logical（它是派生值）。派生值同样不能越界：
    if not (I64_MIN <= logical_origin and logical_origin + data_bytes <= I64_MAX):
        raise EasyFSError(
            "EINVAL: 逻辑坐标必须落在 i64 内（L 是 i64）："
            "data_lo_logical=%d，派生的 data_hi_logical=%d"
            % (logical_origin, logical_origin + data_bytes))

    if bitmap_block:
        bb = parse_size(bitmap_block) if not isinstance(bitmap_block, int) else bitmap_block
        if bb < chunk or bb % chunk:
            raise EasyFSError("bitmap_block 必须是 chunk 的整数倍且 >= chunk")
    else:
        bb = BLOCK_4K
        while True:
            if ceil_div(chunk_count, (bb - ALLOC_HDR) * 8) <= 1024:
                break
            bb *= 2
            if bb > (1 << 30):
                raise EasyFSError("卷太大：位图块大小超出上限")

    cap_bytes = (bb - ALLOC_HDR) * 8 * chunk
    regions = []                      # (区域起点, 区域字节数, bit_unit, 位图块大小)
    best = find_best_alloc_setting(region_len, chunk, bit_unit)
    if mixed and best["mode"] == "flat":
        mixed = False                  # 粒度和 chunk 差不多：没有可分裂的东西 ⇒ 平铺
    if mixed:
        # 混合粒度（1-alloc.md §13）：粗区域（尽量少块）+ 元数据子区域（4 KiB 粒度）
        bu0, p_off, cbb = best["bit_unit0"], best["meta_unit"], best["child_block_bytes"]
        rbytes, cbb0 = best["child_bytes"], best["coarse_block_bytes"]
        # ① 粗区域：可能不止一块（`--fixbitsize` 强制小粒度时）
        cap = (cbb0 - ALLOC_HDR) * 8 * bu0
        off, rem = data_lo, data_bytes
        while rem > 0:
            n = min(cap, rem)
            regions.append((off, n, bu0, cbb0, None))
            off += n
            rem -= n
        # ② 粗位图块都排在子区域里；子位图块住在被分裂单位的开头（`p_off`）
        run = p_off + cbb
        for k in range(len(regions)):
            regions[k] = (regions[k][0], regions[k][1], regions[k][2], cbb0,
                          run + k * cbb0)
        regions.append((p_off, rbytes, chunk, cbb, p_off))   # 整格：从单位开头起
        if (len(regions) - 1) * cbb0 > best["unit"] - BLOCK_4K:
            raise EasyFSError("卷太小：分配块放不进第一个单位")
        # 根目录块单独占**下一个单位**：一个粗 bit 里只放一类可独立挪动的对象，
        # 共用的话那个 bit 永远回收不了（1-alloc.md §13.5）
        root_off = p_off + best["unit"]
        if root_off + BLOCK_4K > p_off + cbb + rbytes:
            raise EasyFSError("卷太小：目录块放不进元数据子区域")
        bitmap_total = (len(regions) - 1) * cbb0 + cbb
        n_blocks = len(regions)
        return {
            "region_len": region_len, "chunk": chunk,
            "chunk_shift": chunk.bit_length() - 1,
            "data_lo": data_lo, "data_hi": data_hi, "data_bytes": data_bytes,
            "chunk_count": chunk_count, "block_bytes": cbb0,
            "regions": regions, "alloc_num": n_blocks,
            "alloc_size": bitmap_total, "alloc_off": run, "root_off": root_off,
            "logical_origin": logical_origin, "policy_id": policy,
            "bit_unit0": bu0, "meta_unit": p_off, "mixed": True,
            "mixed_units": best["child_units"],
        }
    off, rem = data_lo, data_bytes
    while rem > 0:
        n = min(cap_bytes, rem)
        regions.append((off, n, chunk, bb))
        off += n
        rem -= n
    n_blocks = len(regions)
    bitmap_total = n_blocks * bb
    need = bitmap_total + chunk
    if need > data_bytes:
        raise EasyFSError("卷太小：放不下位图链和根目录块")

    # 默认 middle-out：以数据区中点为中心取一段连续空间（1-alloc.md §4）
    center = data_lo + data_bytes // 2
    run = align_down(center - need // 2, chunk)
    run = max(data_lo, min(run, data_hi - need))
    run = align_down(run, chunk)
    root_off = run + bitmap_total
    for i in range(len(regions)):
        regions[i] = (regions[i][0], regions[i][1], regions[i][2], regions[i][3],
                      run + i * bb)

    return {
        "region_len": region_len,
        "chunk": chunk,
        "chunk_shift": chunk.bit_length() - 1,
        "data_lo": data_lo,
        "data_hi": data_hi,
        "data_bytes": data_bytes,
        "chunk_count": chunk_count,
        "block_bytes": bb,
        "bit_unit0": chunk, "mixed": False, "mixed_units": 0,
        "meta_unit": None,
        "regions": regions,
        "alloc_num": n_blocks,
        "alloc_size": bitmap_total,
        "alloc_off": run,
        "root_off": root_off,
        "logical_origin": logical_origin,
        "policy_id": policy,
    }


def mkfs(path=None, size=None, chunk=BLOCK_4K, policy=3, logical_origin=0,
         bitmap_block=None, device=None, mixed=True, bit_unit=None):
    """建立 EasyFS 卷（1-alloc.md §4）。

    两种用法：

    * ``mkfs("disk.img", size=64<<20)`` —— 文件不存在就按 size 创建/截断；
    * ``mkfs(device=dev)`` —— 直接在一个设备上建卷（大小取 ``dev.size``），
      配合 ``easyfs_device`` 就能在 .vhd / 分区 / 内存块上建卷。

    返回布局报告 dict。
    """
    own = device is None
    if own:
        if size is None:
            size = os.path.getsize(path) if os.path.exists(path) else (64 << 20)
    elif size is None:
        size = device.size
    lay = plan_layout(size, chunk=chunk, logical_origin=logical_origin,
                      policy=policy, bitmap_block=bitmap_block, mixed=mixed,
                      bit_unit=bit_unit)
    region_len = lay["region_len"]
    data_lo, data_bytes = lay["data_lo"], lay["data_bytes"]
    bb, chunk = lay["block_bytes"], lay["chunk"]
    regions = lay["regions"]
    n_blocks = lay["alloc_num"]
    run, root_off = lay["alloc_off"], lay["root_off"]

    # ---- 建位图：全 0（空闲），再把元数据占用的 chunk 置 1
    region_bits = [bytearray(ceil_div(ceil_div(rbytes, unit), 8))
                   for _roff, rbytes, unit, _rbb, _boff in regions]
    region_first = []                 # 每个区域第一个 bit 的「按 chunk 计的全局序号」
    acc = 0
    for _roff, rbytes, unit, _rbb, _boff in regions:
        region_first.append(acc)
        acc += ceil_div(rbytes, unit)

    def mark_used(phys, length, only=None):
        """把 `[phys, phys+length)` 覆盖的 bit 置 1（每个区域按它自己的 bit_unit）。

        `only` 给定时只标那一个区域：混合粒度下要把"已分裂"的单位标在**父**区域里，
        而不能顺手把子区域里对应的格子也标上。
        """
        n_units = 0
        for i, (roff, rbytes, unit, _rbb, _boff) in enumerate(regions):
            if only is not None and i != only:
                continue
            lo, hi = max(phys, roff), min(phys + length, roff + rbytes)
            if lo >= hi:
                continue
            b0 = (lo - roff) // unit
            b1 = ceil_div(hi - roff, unit)
            region_bits[i][b0 >> 3] |= 1 << (b0 & 7)
            for b in range(b0, b1):
                region_bits[i][b >> 3] |= 1 << (b & 7)
            n_units += b1 - b0
        return n_units

    used_chunks = 0
    for _roff, _rbytes, _unit, rbb, boff in regions:      # 位图链自己（按真实块位置）
        used_chunks += mark_used(boff, rbb)
    used_chunks += mark_used(root_off, chunk)             # 根目录块
    if lay.get("mixed_units"):
        croff, crbytes = regions[-1][0], regions[-1][1]   # 子区域盖住的那几段 ⇒ 父区域标"已分裂"
        used_chunks += mark_used(croff, crbytes, only=0)

    # ---- 落盘
    dev = device if device is not None else FileDevice(path, size=region_len)
    for i, ((roff, rbytes, unit, rbb, boff), bits) in enumerate(zip(regions, region_bits)):
        blk = build_bitmap_block(
            boff, rbb,
            roff - boff,                                # region_delta（自相对）
            rbytes,                                     # region_bytes
            unit,                                       # bit_unit
            logical_origin + (roff - data_lo),          # region_logical_start
            bits, seq=i,
            prev_off=(None if i == 0 else regions[i - 1][4]),
            next_off=(None if i + 1 >= n_blocks else regions[i + 1][4]))
        dev.write_at(boff, blk)

    # 根目录块：空目录（payload_len = 0 合法，2-dir.md R9）
    root = bytearray(BLOCK_4K)
    stamp_header(root, BT_DIR, HDR_SIZE, 0, payload_crc=crc32(b""))
    dev.write_at(root_off, root)

    # head / tail anchor（layout.md §2）
    vol_uuid = uuidlib.uuid4().bytes
    for is_head in (True, False):
        base = 0 if is_head else region_len - BLOCK_4K
        peer = (region_len - BLOCK_4K) if is_head else -(region_len - BLOCK_4K)
        dev.write_at(base, build_anchor_block(
            region_len, peer, logical_origin, 1, lay["chunk_shift"], policy, 0,
            ROOT_TYPE_CHAIN, root_off - base, run - base, n_blocks,
            lay["alloc_size"], 0x01, vol_uuid))
    dev.flush()
    if own:
        dev.close()

    report = dict(lay)
    report.update({
        "path": path if path is not None else repr(device),
        "used_chunks": used_chunks,
        "uuid": vol_uuid,
        "tail_off": region_len - BLOCK_4K,
    })
    return report


# ================================================================ 10. 伸缩（resize）
#
# 见 1-alloc.md §8：只改区域内部的元数据，**绝不搬数据**；容器（分区表 / 镜像文件
# 大小）是调用方的事。v0 收缩时只挪位图块；文件数据 / 目录块占边界就 ENOTSUP。
#
# 坐标系：`container` 是容器设备，`old_start` / `new_start` 是**容器内的绝对偏移**。
# `vol` 挂在 `RegionDevice(container, old_start, old_len)` 上，所以 vol 里的物理地址
# 都相对 old_start；本函数内部统一换算成绝对地址再干活。

RESIZE_MODES = ("expandleft", "expandright", "shrinkleft", "shrinkright")


def resize(container, old_start, old_len, new_start, new_len, mode=None,
           log=None, dry_run=False, verify=False):
    """把容器里 `[old_start, +old_len)` 的卷改成 `[new_start, +new_len)`。

    方向由几何**唯一确定**（1-alloc.md §8.6）：同起点 → 右类，同终点 → 左类，
    两端都动 → `EINVAL`（分两步做）。返回 report dict；`log(msg)` 给定时逐步汇报。
    """
    steps, writes = [], []

    def say(msg):
        steps.append(msg)
        if log:
            log(msg)

    def put(off, data, what):
        writes.append((off, len(data), what))
        if not dry_run:
            container.write_at(off, data)

    # ---------- 校验 + 严格挂载旧卷（I9 / I7 必须过）
    if new_len <= 0 or new_start < 0:
        raise EasyFSError("EINVAL: 新几何非法 [%d, +%d)" % (new_start, new_len))
    if new_start + new_len > container.size:
        raise EasyFSError("EINVAL: 新区域 [%d, +%d) 超出容器（%d）"
                          % (new_start, new_len, container.size))
    if old_len <= 0 or old_start < 0 or old_start + old_len > container.size:
        raise EasyFSError("EINVAL: 旧几何 [%d, +%d) 超出容器（%d）"
                          % (old_start, old_len, container.size))

    vol = Volume.mount(RegionDevice(container, old_start, old_len, name="old"))
    L0 = vol.region_len
    if L0 != old_len:
        raise EasyFSError("ESTALE: 卷记的 region_len=%d，--size 给的是 %d"
                          "（旧几何说错位置了？）" % (L0, old_len))
    chunk = vol.chunk
    for label, val in (("--newoffs", new_start), ("--newsize", new_len)):
        if val % chunk:
            raise EasyFSError("EINVAL: %s=%d 不是 chunk(%d) 的整数倍"
                              % (label, val, chunk))

    same_start = (new_start == old_start)
    same_end = (new_start + new_len == old_start + L0)
    if same_start and new_len == L0:
        derived = "none"
    elif same_start and new_len > L0:
        derived = "expandright"
    elif same_end and new_len > L0:
        derived = "expandleft"
    elif same_start and new_len < L0:
        derived = "shrinkright"
    elif same_end and new_len < L0:
        derived = "shrinkleft"
    else:
        raise EasyFSError(
            "EINVAL: 两端不能同时动（旧 [%d,+%d) → 新 [%d,+%d)）；"
            "分两步：先扩/缩一边，再扩/缩另一边"
            % (old_start, L0, new_start, new_len))
    if mode and mode != derived:
        raise EasyFSError("EINVAL: --mode 说 %s，几何算出来是 %s" % (mode, derived))

    free_before = vol.free_bytes()
    dlo_logical = vol.data_lo_logical + (new_start - old_start)   # L 不变 ⇒ 同步平移
    gen = vol.generation + 1
    root_abs = old_start + vol.root_off
    bb = vol.regions[0].block_bytes
    say("卷现状 [%d, +%s)  region_len=%s  data_lo_logical=%d  空闲 %s"
        % (old_start, human(L0), human(L0), vol.data_lo_logical, human(free_before)))

    if derived == "none":
        say("卷已经是这个大小，什么都不用做")
        return {"mode": "none", "changed": False, "writes": [], "steps": steps,
                "old": (old_start, L0), "new": (new_start, new_len), "delta": 0,
                "moved": [], "regions_before": len(vol.regions),
                "regions_after": len(vol.regions),
                "free_before": free_before, "free_after": free_before,
                "dry_run": dry_run}
    say("几何推出方向：%s（%s %s）"
        % (derived, "同起点" if same_start else "同终点",
           "+" + human(new_len - L0) if new_len > L0 else "-" + human(L0 - new_len)))

    # ---------- 用一份"绝对坐标的链"承载所有改动
    chain = [dict(off=old_start + r.block_off, bb=r.block_bytes,
                  roff=old_start + r.region_off, rbytes=r.region_bytes,
                  unit=r.bit_unit, lstart=r.logical_start, bits=r.bits)
             for r in vol.regions]
    dirty, moved = [], []

    def mark(e):
        if not any(x is e for x in dirty):
            dirty.append(e)

    def entry_of(phys):
        for e in chain:
            if e["roff"] <= phys < e["roff"] + e["rbytes"]:
                return e
        return None

    def set_bit(e, phys, val, cnt=1):
        nbits = ceil_div(e["rbytes"], e["unit"])
        for k in range(cnt):
            i = (phys - e["roff"]) // e["unit"] + k
            if i < 0 or i >= nbits:
                raise EasyFSError("BUG: 位图下标越界（phys=%d, 区域 @%d +%d）"
                                  % (phys, e["roff"], e["rbytes"]))
            if val:
                e["bits"][i >> 3] |= 1 << (i & 7)
            else:
                e["bits"][i >> 3] &= ~(1 << (i & 7)) & 0xFF
        mark(e)

    def add_region(roff_abs, rbytes):
        """造一个全新区域：位图块按策略在它内部选址，那个 chunk 置 1。"""
        e = dict(off=roff_abs, bb=bb, roff=roff_abs, rbytes=rbytes, unit=chunk,
                 lstart=vol.phys_to_logical(roff_abs - old_start),
                 bits=bytearray(ceil_div(ceil_div(rbytes, chunk), 8)))
        boff, blen = vol.place_metadata(roff_abs, rbytes, bb)
        e["off"] = boff
        set_bit(e, boff, 1, ceil_div(blen, chunk))
        return e

    def pick_run(cands):
        pol = vol.policy_id
        if pol == 3:                                    # middle-out
            centre = old_start + BLOCK_4K + vol.data_bytes // 2
            return min(cands, key=lambda c: abs(
                c[0]["roff"] + (c[1] + c[2] // 2) * chunk - centre))
        if pol in (1, 2):                               # first-fit-right / last-fit
            return cands[-1]
        if pol == 4:                                    # best-fit
            return min(cands, key=lambda c: c[2])
        if pol == 5:                                    # worst-fit
            return max(cands, key=lambda c: c[2])
        if pol == 6:                                    # random（可复现）
            seed = (vol.policy_state * 1103515245 + 12345) & 0x7FFFFFFF
            return cands[seed % len(cands)]
        return cands[0]                                 # 0 / 7 → 最左

    def add_span(lo, hi):
        """把一个新增数据区 [lo, hi) 按**单块覆盖空间**切成若干区域，各建一个位图块。

        切分规则同 mkfs（1-alloc.md §3.4）：`cap = (block_bytes − header) × 8 × bit_unit`，
        最后一块可以短 —— 千万别按 `block_bytes` 本身去切（那是块占的字节数）。
        """
        cap = (bb - ALLOC_HDR) * 8 * chunk
        out, off = [], lo
        while off < hi:
            rbytes = min(cap, hi - off)
            out.append(add_region(off, rbytes))
            off += rbytes
        return out

    # ---------- 扩 容
    if derived == "expandright":
        lo, hi = old_start + L0 - BLOCK_4K, new_start + new_len - BLOCK_4K
        say("新增数据区 [%d, %d) = %s" % (lo, hi, human(hi - lo)))
        put(lo, bytearray(BLOCK_4K),
            "清旧 tail anchor 的 magic（它的槽位在新数据区开头）")
        old_tail = chain[-1]
        new = add_span(lo, hi)
        chain.extend(new)
        mark(old_tail)                                  # 旧链尾的 next 变了
        say("后插 %d 个位图块（按策略 %s 在各新区域内选址）"
            % (len(new), POLICY_NAME.get(vol.policy_id, "?")))
    elif derived == "expandleft":
        lo, hi = new_start + BLOCK_4K, old_start + BLOCK_4K
        say("新增数据区 [%d, %d) = %s（老数据一个字节不动，L 也不变）"
            % (lo, hi, human(hi - lo)))
        put(old_start, bytearray(BLOCK_4K), "清旧 head anchor 的 magic")
        old_head = chain[0]
        new = add_span(lo, hi)
        chain = new + chain
        mark(old_head)                                  # 原链头的 prev 变了
        say("前插 %d 个位图块（按策略 %s 在各新区域内选址）"
            % (len(new), POLICY_NAME.get(vol.policy_id, "?")))

    # ---------- 收 缩：第一阶段腾空
    else:
        N = L0 - new_len
        if derived == "shrinkright":
            span_lo, span_hi = new_start + new_len - BLOCK_4K, old_start + L0 - BLOCK_4K
            keep_lo, keep_hi = old_start + BLOCK_4K, span_lo
        else:
            span_lo, span_hi = old_start + BLOCK_4K, new_start + BLOCK_4K
            keep_lo, keep_hi = span_hi, old_start + L0 - BLOCK_4K
        say("向%s缩 %s：待腾空 [%d, %d)" % ("右" if derived == "shrinkright"
                                            else "左", human(N), span_lo, span_hi))
        survivors = [e for e in chain
                     if e["roff"] < keep_hi and e["roff"] + e["rbytes"] > keep_lo]

        def is_dead(x):
            return not any(x is y for y in survivors)

        def busy_in_span():
            """跨度内"已用"的位置，**逐个 chunk** 判断。

            注意：不能按"连续已用区间"整体判断 —— 一个区间可能**从**"注定随区域消失的
            位图块"**开始**、却**继续**延伸到后面还要用的东西（比如根目录块）。整体跳过
            就会漏掉后面那些（真出过一次：缩到 128 MiB 时根目录块被漏掉，anchor 指向了
            新卷之外）。
            """
            out = []
            for e in chain:
                lo = max(span_lo, e["roff"])
                hi = min(span_hi, e["roff"] + e["rbytes"])
                if lo >= hi:
                    continue
                first = (lo - e["roff"]) // e["unit"]
                cnt = (hi - lo) // e["unit"]
                for (b, n) in used_ranges(e["bits"], first, cnt):
                    for k in range(n):
                        phys = e["roff"] + (b + k) * e["unit"]
                        if any(x["off"] == phys and is_dead(x) for x in chain):
                            continue                    # 随它自己的区域一起消失
                        out.append((phys, e["unit"]))
            return out

        while True:
            todo = [p for (p, n) in busy_in_span()
                    if any(x["off"] == p and not is_dead(x) for x in chain)]
            if not todo:
                break
            phys = todo[0]
            owner = next(x for x in chain if x["off"] == phys)
            need = ceil_div(bb, chunk)
            cands = []
            for e in survivors:
                lo = max(keep_lo, e["roff"])
                hi = min(keep_hi, e["roff"] + e["rbytes"])
                if lo >= hi:
                    continue
                f = (lo - e["roff"]) // e["unit"]
                c = (hi - lo) // e["unit"]
                for (b, n) in free_ranges(e["bits"], f, c):
                    if n >= need:
                        cands.append((e, b, n))
            if not cands:
                raise EasyFSError(
                    "ENOTSUP: 保留区里找不到 %s 连续空闲，搬不走位图块 @%d；缩得少一点"
                    % (human(bb), phys))
            e, b, n = pick_run(cands)
            newoff = e["roff"] + b * chunk
            set_bit(e, newoff, 1, need)                 # 先占位
            cover = entry_of(phys)                      # 旧位置的 bit 在**覆盖它的**区域里
            if cover is not None:
                set_bit(cover, phys, 0, need)
            owner["off"] = newoff
            mark(owner)
            idx = chain.index(owner)
            if idx:
                mark(chain[idx - 1])
            if idx + 1 < len(chain):
                mark(chain[idx + 1])
            moved.append((phys, newoff))
            say("挪位图块 @%d → @%d（保留区里按策略重选址，region_delta 重算）"
                % (phys, newoff))

        left = busy_in_span()
        if left:
            other = sum(n for _, n in left)
            raise EasyFSError(
                "ENOTSUP: 无法挪动 —— 待缩跨度里还占用 %s（%d 个 chunk）；"
                "位图块已挪走 %d 个，剩下的是**文件数据或目录块**（v0 不挪）。"
                "先删掉/搬走占用边界的数据，或缩得少一点"
                % (human(other), other // chunk, len(moved)))

        # ---------- 收缩第二阶段：摘除 / 截短
        boundary = span_lo if derived == "shrinkright" else span_hi
        keep = []
        for e in chain:
            if derived == "shrinkright":
                if e["roff"] >= boundary:
                    continue                            # 整块落在新边界之外
                if e["roff"] + e["rbytes"] > boundary:  # 跨边界 → 截右边
                    e["rbytes"] = boundary - e["roff"]
                    e["bits"] = e["bits"][:ceil_div(ceil_div(e["rbytes"], chunk), 8)]
                    mark(e)
            else:
                if e["roff"] + e["rbytes"] <= boundary:
                    continue
                if e["roff"] < boundary:                # 跨边界 → 截左边（bit 整体移位）
                    drop = (boundary - e["roff"]) // chunk
                    nbits_new = ceil_div(e["rbytes"], chunk) - drop
                    e["bits"] = shift_bits(e["bits"], drop, nbits_new)
                    e["roff"] = boundary
                    e["rbytes"] = nbits_new * chunk
                    e["lstart"] = vol.phys_to_logical(boundary - old_start)
                    mark(e)
            keep.append(e)
        if not keep:
            raise EasyFSError("ENOTSUP: 缩得太狠，一个位图块都不剩了")
        dead = [e for e in chain if not any(e is y for y in keep)]
        chain = keep
        if dead:                                        # 摘掉块 → 链两端要改写 delta
            mark(chain[0])
            mark(chain[-1])
        say("摘除/截短后剩 %d 个区域块（摘掉 %d 个）" % (len(chain), len(dead)))
        for e in dead:                                  # 摘掉的块，它自己的 chunk 放掉
            c = entry_of(e["off"])
            if c is not None:
                set_bit(c, e["off"], 0, ceil_div(bb, chunk))

    # ---------- 落盘：位图块（脏的）在前，anchor 在后（1-alloc.md §7.1/§8）
    ids = set(id(x) for x in dirty)
    for i, e in enumerate(chain):
        if id(e) not in ids:
            continue
        prev_off = chain[i - 1]["off"] if i else None
        next_off = chain[i + 1]["off"] if i + 1 < len(chain) else None
        put(e["off"], build_bitmap_block(e["off"], e["bb"], e["roff"] - e["off"],
                                         e["rbytes"], e["unit"], e["lstart"],
                                         e["bits"], seq=i, prev_off=prev_off,
                                         next_off=next_off),
            "位图块 #%d @%d（区域 @%d +%s）"
            % (i, e["off"], e["roff"], human(e["rbytes"])))
    if not dirty:
        say("没有位图块需要改写")

    head_off, tail_off = new_start, new_start + new_len - BLOCK_4K
    first_chain = chain[0]["off"]
    bbytes = sum(e["bb"] for e in chain)
    for is_head in (True, False):
        base = head_off if is_head else tail_off
        peer = (tail_off - head_off) if is_head else (head_off - tail_off)
        put(base, build_anchor_block(
            new_len, peer, dlo_logical, gen, vol.chunk_shift, vol.policy_id,
            vol.policy_state, getattr(vol, "root_type", ROOT_TYPE_CHAIN),
            root_abs - base, first_chain - base, len(chain),
            bbytes, 0x01, vol.vol_uuid),
            "写 %s anchor @%d（region_len=%s, gen=%d, data_lo_logical=%d）"
            % ("head" if is_head else "tail", base, human(new_len), gen,
               dlo_logical))

    if derived == "shrinkright":
        put(old_start + L0 - BLOCK_4K, bytearray(BLOCK_4K), "清旧 tail anchor 的 magic")
    elif derived == "shrinkleft":
        put(old_start, bytearray(BLOCK_4K), "清旧 head anchor 的 magic")

    if not dry_run:
        container.flush()

    def chain_free():
        total = 0
        for e in chain:
            nb = ceil_div(e["rbytes"], e["unit"])
            total += (nb - used_count(e["bits"], nb)) * e["unit"]
        return total

    free_after = chain_free()
    say("空闲 %s → %s（%s）"
        % (human(free_before), human(free_after),
           ("+" if new_len >= L0 else "-") + human(abs(new_len - L0))))
    say("写入 %d 次%s" % (len(writes), "（dry-run，没有真的写）" if dry_run else ""))

    if verify and not dry_run:
        v2 = Volume.mount(RegionDevice(container, new_start, new_len, name="new"))
        why = v2.check_regions()
        if why:
            raise EasyFSError("BUG: resize 之后 I7 不成立：%s" % why)
        b, a = v2.rebuild_bitmap(apply=False)
        if b != a:
            raise EasyFSError("BUG: resize 之后位图与可达集合不一致（%d vs %d）"
                              % (b, a))
        say("自检通过：I7 成立、位图与可达集合一致（%d 个 chunk）" % b)

    return {"mode": derived, "changed": True, "writes": writes, "steps": steps,
            "old": (old_start, L0), "new": (new_start, new_len),
            "delta": new_len - L0, "moved": moved,
            "regions_before": len(vol.regions), "regions_after": len(chain),
            "free_before": free_before, "free_after": free_after,
            "dry_run": dry_run}
