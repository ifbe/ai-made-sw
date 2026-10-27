#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 控制/诊断工具：mkfs / probe / device / df / fsck / inspect / resize

这是**外层工具**之一（核心是 ``easyfs.py`` 与 ``easyfs_device.py``）。
也可以用统一入口：``python3 python/tool.py <同样的参数>``。

用法::

    # 整个文件就是一个卷
    python3 python/tool-ctrl.py mkfs  --file disk.img --size 64M
    python3 python/tool-ctrl.py probe --file disk.img

    # 文件里的一段区域（--offs + --size）
    python3 python/tool-ctrl.py mkfs  --file big.img --offs 16M --size 64M
    python3 python/tool-ctrl.py probe --file big.img --offs 16M --size 64M

    # 磁盘镜像（.img / .vhd）：自动识别容器，并可指定分区
    python3 python/tool-ctrl.py device --vdisk vm.vhd
    python3 python/tool-ctrl.py mkfs   --vdisk vm.vhd --part 1
    python3 python/tool-ctrl.py probe  --vdisk vm.vhd --part 1

    # 内存卷（不落盘，演示/测试用）
    python3 python/tool-ctrl.py mkfs --mem 16M
    python3 python/tool-ctrl.py probe --mem 16M        # 两次调用是两个不同的内存卷

    # 改卷占的区域：旧几何 + 新几何都给，方向由几何唯一确定（doc/1-alloc.md §8）
    python3 python/tool-ctrl.py resize --file big.img \\
            --offs 16M --size 64M --newoffs 16M --newsize 80M -v
    python3 python/tool-ctrl.py resize --file big.img \\
            --offs 16M --size 64M --newoffs 0 --newsize 80M --dry-run

``df`` 打印空间用量：默认**字节数**（脚本友好），``-h`` 人类可读；
还会给出明细（位图链 / 目录块 / 链接块 / 文件数据 / 未分类），
"未分类"非零就说明有位图置位但从根不可达的块（泄漏）。

``resize`` 的注意事项：

* **只改区域内部的元数据**，绝不搬数据；容器（分区表 / 镜像文件大小）是你自己的事
  —— 扩容要先扩容器，缩容是缩完卷再收容器。
* 收缩时腾空阶段**只挪位图块**；文件数据 / 目录块占边界就 `ENOTSUP`（一个字节都不改）。
* 前置检查 head/tail 一致（I9）与位图链 tiling（I7），任一不过即 `ESTALE` 拒绝 ——
  那多半意味着"上次 resize 没做完"或几何给错了，换另一组几何重试。

格式规格在 ``doc/``；格式层在 ``easyfs.py``；设备层在 ``easyfs_device.py``。

.. note:: ``--mem`` 每次调用都会新建一块内存，所以 mkfs 与 probe 之间**不共享**，
   它主要用于在一句话里演示（或配合 ``python -i`` 手工玩）；``resize`` 也不支持它。
"""

import time
import copy
import fnmatch
import shlex
import argparse
import os
import struct
import sys
import uuid as uuidlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import easyfs
import easyfs_device
from easyfs import (
    anchor_layout, anchor_off, anchor_put, anchor_get, anchor_geti, anchor_crc,
    ANCHOR_VOL_HDR_END, ANCHOR_POOL_END, ANCHOR_OFF_POOL, ANCHOR_MAGIC_TAG,
    ANCHOR_POOL_MAGIC_TAG, ANCHOR_VERSION_STR,
    ROOT_TYPE_NONE, ROOT_TYPE_CHAIN, ROOT_TYPE_OBJECT, ATTR_CRC32, ATTR_DATA_PTR, ATTR_DIR_PTR, ATTR_DIR_OBJECT,
                    ATTR_DATA_OBJECT, ATTR_NAME, ATTR_NAME_HASH, ATTR_NLINK, ATTR_PADN,
                    ATTR_PAD1, ATTR_TCREATE, ATTR_DATA_TINY, ATTR_TMODIFY,
                    ATTR_SYMLINK_PTR, ATTR_SYMLINK_OBJECT, ATTR_SYMLINK_TINY,
                    ATTR_NAME_STR, BLOCK_4K, BT_ALLOC, BT_ANCHOR, BT_BAD, BT_DIR,
                    BT_FILE, BT_LINK, BT_NAME, BT_NULL, EasyFSError, PathWalker,
                    POLICY_NAME, SYMLINK_ATTRS, Volume, human, parse_data_ptr,
                    parse_header, parse_size, scan_attrs, verify_payload_crc)
from easyfs_device import EasyFSDeviceError

ERRORS = (EasyFSError, EasyFSDeviceError)


def _fmt_unix_sec(t):
    """`u32` unix 秒（UTC）→ 人类可读；0 = 未设置；越界不炸。

    显示成本地时间 + 时区标签：`(utc+8=2026-10-11 00:02:19)`（TZ=UTC 时是 `utc+0=…`）。
    """
    if t == 0:
        return "0（未设置）"
    try:
        utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))
    except (ValueError, OSError, OverflowError):
        return "%d  （超出可表示范围）" % t
    lt = time.localtime(t)
    off = int(getattr(lt, "tm_gmtoff", 0) or 0)
    sign = "+" if off >= 0 else "-"
    o = abs(off)
    hh, mm = o // 3600, (o % 3600) // 60
    zone = "utc%s%d" % (sign, hh) + (":%02d" % mm if mm else "")
    return "%d  (%s=%s)" % (t, zone, time.strftime("%Y-%m-%d %H:%M:%S", lt))


def _dw(s):
    """字符串的**显示宽度**：CJK / 全角算 2 列。"""
    w = 0
    for ch in s:
        o = ord(ch)
        w += 2 if (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF
                   or 0xAC00 <= o <= 0xD7A3 or 0xF900 <= o <= 0xFAFF
                   or 0xFE30 <= o <= 0xFE6F or 0xFF00 <= o <= 0xFF60
                   or 0xFFE0 <= o <= 0xFFE6 or 0x20000 <= o <= 0x3FFFD) else 1
    return w


def _pad(s, width):
    """按显示宽度左对齐补齐（`_pad` 后接另一列，屏幕上就是对齐的）。"""
    return s + " " * max(0, width - _dw(s))


def _fmt_delta(base, delta):
    return "%+#x -> @%d" % (delta, base + delta)


ROOT_NAME = {0: "无根（空卷）", 1: "链式目录（→ 第一个 dir 块）",
             2: "object（对象根：内容块表在链接块里）"}

# 分配结构的类型（anchor 的 `allotype` tag）—— 与 ROOT_NAME 对称
ALLOC_NAME = {1: "扁平位图链", 2: "分配器对象（结构在链接块里）【将来】"}


def _print_anchor(name, a, peer_name):
    print("=== %s anchor @%d ===" % (name, a["base"]))
    print("  header        %s %s   hdrbytes=%d  hdrcrc[%s]"
          % (ANCHOR_MAGIC_TAG.decode(), a.get("version", "?"),
             ANCHOR_VOL_HDR_END, "ok" if a.get("hdrcrc_ok") else "BAD"))
    print("  region_len    %d  (%s)" % (a["region_len"], human(a["region_len"])))
    print("  peer_delta    %s   [→%s 互指]"
          % (_fmt_delta(a["base"], a["peer_delta"]), peer_name))
    print("  data_lo_logical %d" % a["data_lo_logical"])
    print("  generation    %d   chunk_shift %d (chunk %d)"
          % (a["generation"], a["chunk_shift"], 1 << a["chunk_shift"]))
    print("  policy        %d (%s)   state %d"
          % (a["policy_id"], POLICY_NAME.get(a["policy_id"], "?"),
             a["policy_state"]))
    print("  root_type     %d  (%s)"
          % (a["root_type"], ROOT_NAME.get(a["root_type"], "?")))
    print("  root_ioffs    %s   [→@%d]"
          % (_fmt_delta(a["base"], a["root_ioffs"]), a["root_off"]))
    print("  alloc_type    %d  (%s)"
          % (a["alloc_type"], ALLOC_NAME.get(a["alloc_type"], "?")))
    print("  alloc_ioffs   %s   [→@%d]"
          % (_fmt_delta(a["base"], a["alloc_ioffs"]), a["alloc_off"]))
    print("  alloc         %d 块  %s"
          % (a["alloc_num"], human(a["alloc_size"])))
    print("  state_flags   0x%x  [%s]"
          % (a["state_flags"],
             "clean" if a["state_flags"] & 1 else "DIRTY：需要重建位图"))
    print("  pool          %s%s"
          % ("含 pool 段（poolcrc %s）" % ("ok" if a.get("poolcrc_ok") else "BAD")
             if a.get("pool_here") else "无（普通卷，不是池成员）", ""))
    print("  uuid          %s" % uuidlib.UUID(bytes=a["uuid"]))


def _ptype_str(t):
    """分区类型的显示：MBR 整数 ⇒ 0xNN；其余（GPT GUID 串等）原样。"""
    return ("0x%02X" % t) if isinstance(t, int) else str(t)


def _partid_create(args, kind):
    """`mbr --create` / `gpt --create`：建一张表 + 一个占满的分区。"""
    index = args.part or 1
    # ① 先**只读**看一眼：已经有表 / 已经是我们的卷 / 开头不空 ⇒ 先拒绝（不打搅用户、不碰盘）
    dev, desc = _partid_container(args, need_write=False, for_create=True, quiet=True)
    try:
        t, ps = easyfs_device.read_partitions(dev)
        head = dev.read_at(0, 4096)
    finally:
        dev.close()
    if not getattr(args, "disk_force", False):
        if t != "none":
            raise EasyFSError("这个容器已经有 %s 分区表了（要重建请加 --force；"
                              "只想改标识用 --seteasy）" % t.upper())
        if head[:8] == ANCHOR_MAGIC_TAG:          # 卷 / 分区标记（anchor 魔数）
            raise EasyFSError("这个容器里已经是 EasyFS 卷了 —— 建分区表会毁掉它"
                              "（真要这么干：--force）")
        if any(head):
            raise EasyFSError("容器开头不是空的（建表会覆盖它；确认无误再加 --force）")
    # ② 真正写之前：`--disk` 在这里打印盘信息 + 问 [y/N]（可写句柄是**问完才开**的 ✓）
    dev, desc = _partid_container(args, need_write=True, for_create=True)
    try:
        start = (parse_size(args.offs)
                 if getattr(args, "offs", "0") not in (None, "0", 0) else None)
        size = parse_size(args.size) if getattr(args, "size", None) else None
        if kind == "mbr":
            info = easyfs_device.create_mbr(dev, index, start, size)
        else:
            info = easyfs_device.create_gpt(dev, index, start, size)
        print("设备          %s" % desc)
        print("已建 %s 分区表" % kind.upper())
        print("  分区 #%d      %s … %s（%s）"
              % (info["index"], human(info["start"]),
                 human(info["start"] + info["length"]), human(info["length"])))
        print("  类型          %s%s"
              % (_ptype_str(info["type"]),
                 ("  名字 %s" % info["name"]) if info.get("name") else ""))
        print("  提示          分区标识已经就是我们的了 ✓"
              "（对旧分区用 `--seteasy` ✓；接着 `mkfs --vdisk … --part %d` 建卷 ✓）"
              % info["index"])
        if kind == "gpt":
            bad = easyfs_device.verify_gpt(dev)
            print("  复核          主/备 GPT %s" % ("自洽 ✓" if not bad else "✗ " + "; ".join(bad)))
        return 0
    finally:
        dev.close()


def _partid_container(args, need_write=True, for_create=False, quiet=False):
    """`mbr` / `gpt` 命令的容器：整块容器（不是某个分区）。"""
    if getattr(args, "mem", None):
        raise EasyFSError("内存设备没有分区表")
    if getattr(args, "offs", "0") not in (None, "0", 0) or getattr(args, "size", None):
        raise EasyFSError("mbr/gpt 改的是分区表本身：不要给 --offs/--size")
    if getattr(args, "disk", None):
        path = args.disk
        if not easyfs_device.is_block_device(path):
            raise EasyFSError("--disk 只接块设备（%s 不是）；镜像请用 --vdisk" % path)
        if not need_write:                       # 只读 → 不打仪式（也不碰盘）
            if not quiet:
                print("设备          %s（只读查看）" % path)
                for _ln in easyfs_device.disk_info_lines(path):
                    print(_ln)
            return (easyfs_device.FileDevice(path, read_only=True),
                    "块设备 %s（只读查看）" % path)
        if for_create:
            extra = ("  （本命令会**重建整张分区表**：现有分区和里面的数据都会没）")
        else:
            extra = "  （本命令**只改分区类型**，不动任何数据）"
        easyfs_device.confirm_dangerous_disk(
            path, easyfs_device.disk_info_lines(path),
            force=bool(getattr(args, "disk_force", False)),
            assume_yes=bool(getattr(args, "yes", False)),
            extra=extra,
            allow_mounted=not for_create)         # 重建表绝不允许挂载中
        return easyfs_device.FileDevice(path, read_only=False), "块设备 %s" % path
    if getattr(args, "vdisk", None):
        dev, kind = easyfs_device.open_container(args.vdisk, read_only=not need_write)
        return dev, "%s（%s）%s" % (kind, args.vdisk, "" if need_write else "（只读查看）")
    if getattr(args, "file", None):
        return (easyfs_device.FileDevice(args.file, read_only=not need_write),
                args.file + ("" if need_write else "（只读查看）"))
    raise EasyFSError("要给个容器：--file / --vdisk / --disk")


def cmd_partid(args):
    """`mbr` / `gpt`：**建表**（`--create`）/ **看**分区标识 / **改**标识（`--seteasy`）。

    三者都只动分区表，不碰数据 —— 除了 `--create` 会**重建整张表**（所以它要求确认 /
    `--force`，见下）。
    """
    kind = args.part_kind
    want = bool(getattr(args, "seteasy", False))
    if getattr(args, "create", False):
        return _partid_create(args, kind)
    if want and not args.part:
        raise EasyFSError("要指定分区号：--part N")
    dev, desc = _partid_container(args, need_write=want)
    try:
        table, parts = easyfs_device.read_partitions(dev)
        ours = (easyfs_device.guid_text(easyfs_device.GPT_TYPE_EASYFS) if kind == "gpt"
                else "0x%02X" % easyfs_device.MBR_TYPE_EASYFS)
        print("设备          %s" % desc)
        print("分区表        %s（%d 个分区）" % (table.upper(), len(parts)))
        if not parts:
            print("  （没有分区表，或一个分区都没有）")
        for q in parts:
            t = _ptype_str(q["type"])
            mark = ""
            if t == ours:
                mark = "   ← 已经是我们的标识 ✓"
            elif want and q["index"] == args.part:
                mark = "   ← 改这个"
            print("  #%d %-38s @%-12d %-11s %s%s"
                  % (q["index"], t, q["start"], human(q["length"]), q.get("name", ""), mark))
        if not want:
            print("我们的标识    %s" % ours)
            print("              （加 --seteasy 就把 --part N 改成它）")
            return
        print("  " + easyfs_device.set_partition_type(dev, args.part, kind))
        if kind == "gpt":
            bad = easyfs_device.verify_gpt(dev)
            print("复核          主/备 GPT %s" % ("自洽 ✓" if not bad else "✗ " + "; ".join(bad)))
            print("我们的标识    %s（= 16 字节 ASCII %r）"
                  % (ours, easyfs_device.GPT_TYPE_EASYFS.decode("ascii")))
        else:
            t2, ps2 = easyfs_device.read_partitions(dev)
            got = [q for q in ps2 if q["index"] == args.part]
            if not got:
                raise EasyFSError("复核失败：改完之后读不到 #%d" % args.part)
            print("复核          分区 #%d 类型 = %s ✓" % (args.part, _ptype_str(got[0]["type"])))
            print("我们的标识    %s" % ours)
    finally:
        dev.close()
def cmd_mkfs(args):
    if getattr(args, "object", False):
        print("注意：对象形态的根（root_type=2）写侧尚未实现，本次仍写链式根（root_type=1）")
    # --offs/--size 由 open_device 统一解释；这里只给"容器不存在时建多大"的默认值
    dev, desc = easyfs_device.open_device(args, create_size=64 << 20)
    print("设备: %s" % desc)
    r = easyfs.mkfs(device=dev,
                    chunk=parse_size(args.chunk),
                    policy=args.policy,
                    logical_origin=parse_size(args.logical_origin),
                    bitmap_block=args.bitmap_block,
                    bit_unit=getattr(args, "fixbitsize", None))
    dev.flush()
    dev.close()
    print("mkfs 完成")
    print("  区域          [0, %d)  %s" % (r["region_len"], human(r["region_len"])))
    print("  anchor        head @0   tail @%d" % r["tail_off"])
    print("  chunk         %d B  (chunk_shift=%d)" % (r["chunk"], r["chunk_shift"]))
    print("  数据区        [%d, %d)  %s  = %d chunk"
          % (r["data_lo"], r["data_hi"], human(r["data_bytes"]), r["chunk_count"]))
    print("  位图          %d 块 x %s = %s  (%s)"
          % (r["alloc_num"], human(r["block_bytes"]),
             human(r["alloc_size"]),
             ("--bitmap-block" if args.bitmap_block else
              ("--fixbitsize " + args.fixbitsize if getattr(args, "fixbitsize", None)
               else "自动选型（1-alloc.md §13.3）"))))
    print("  位图链 @%d ... 根目录块 @%d" % (r["alloc_off"], r["root_off"]))
    print("  粒度          1 bit = %s%s"
          % (human(r.get("bit_unit0", r["chunk"])),
             "（粗区域；元数据/小块走 4 KiB 粒度的子区域）" if r.get("mixed") else "（平铺）"))
    print("  已用 chunk    %d（位图链 + 根目录块）" % r["used_chunks"])
    print("  逻辑坐标      L ∈ [%d, %d)"
          % (r["logical_origin"], r["logical_origin"] + r["data_bytes"]))
    print("  policy        %d (%s)"
          % (r["policy_id"], POLICY_NAME.get(r["policy_id"], "?")))
    print("  uuid          %s" % uuidlib.UUID(bytes=r["uuid"]))


def cmd_probe(args):
    dev, desc = easyfs_device.open_device(args, read_only=True)
    print("设备          %s" % desc)
    print("")
    # 诊断工具：撕裂/尺寸不一致也要能看，所以 strict=False（其它工具默认拒绝）
    vol = Volume.mount(dev, strict=False)
    for w in getattr(vol, "warnings", []):
        print("[!] %s" % w)
    if getattr(vol, "warnings", None):
        print("")
    if vol.head:
        _print_anchor("head", vol.head, "tail")
    else:
        print("=== head anchor @0 ===\n  不合法（磁盘上没有）")
    print("")
    if vol.tail:
        _print_anchor("tail", vol.tail, "head")
    else:
        print("=== tail anchor @%d ===\n  不合法（磁盘上没有）" % (dev.size - BLOCK_4K))
    print("")

    if vol.head and vol.tail:
        same = (vol.head["region_len"] == vol.tail["region_len"]
                and vol.head["uuid"] == vol.tail["uuid"]
                and vol.head["data_lo_logical"] == vol.tail["data_lo_logical"]
                and vol.head["generation"] == vol.tail["generation"]
                and vol.head["chunk_shift"] == vol.tail["chunk_shift"])
        print("=== head/tail 一致性 ===")
        print("  " + ("一致" if same
                      else "不一致（撕裂的 resize，按 generation 大者为准）"))
        if vol.region_len != dev.size:
            print("  [!] 卷记的 region_len=%d 与设备大小 %d 不同 —— 需要 adopt（resize）"
                  % (vol.region_len, dev.size))
        print("")

    print("=== 卷摘要 ===")
    print("  数据区        [%d, %d)  %s  = %d chunk"
          % (vol.data_lo, vol.data_hi, human(vol.data_bytes), vol.chunk_count))
    print("  逻辑坐标      L ∈ [%d, %d)"
          % (vol.data_lo_logical, vol.data_lo_logical + vol.data_bytes))
    print("")

    print("=== 位图链（%d 块）===" % len(vol.regions))
    for i, r in enumerate(vol.regions):
        par = vol.parent[i] if getattr(vol, "parent", None) else None
        print("    [%d] @%-12d %10d B  bit_unit=%-10d 块=%-8d %s"
              % (i, r.region_off, r.region_bytes, r.bit_unit, r.block_bytes,
                 "根" if par is None else "父=[%d]" % par))
    for i, r in enumerate(vol.regions):
        print("  #%d @%d  block_bytes=%d" % (i, r.block_off, r.block_bytes))
        print("       region    %s  %s"
              % (_fmt_delta(r.block_off, r.region_delta), human(r.region_bytes)))
        print("       bit_unit  %d   region_logical_start %d   → L ∈ [%d, %d)"
              % (r.bit_unit, r.logical_start, r.logical_start,
                 r.logical_start + r.region_bytes))
        print("       已用       %d / %d bit   （空闲 %s）"
              % (r.used_bits(), r.nbits,
                 human((r.nbits - r.used_bits()) * r.bit_unit)))
    print("  合计          空闲 %s" % human(vol.free_bytes()))
    print("")

    print("=== 根目录 @%d ===" % vol.root_off)
    blk = vol.read_block(vol.root_off)
    h = parse_header(blk)
    pcrc = verify_payload_crc(blk, h)
    print("  block_type    %d (%s)" % (h["block_type"],
                                       BT_NAME.get(h["block_type"], "?")))
    print("  payload_len   %d" % h["payload_len"])
    print("  header_crc    [%s]   载荷 CRC [%s]"
          % ("ok" if h["header_crc_ok"] else "BAD",
             "未启用" if pcrc is None else ("ok" if pcrc else "BAD")))
    entries = vol.read_dir(vol.root_off)
    print("  条目          %d" % len(entries))
    for ent in entries:
        print("    %s %10d  %s"
              % ("d" if ent["kind"] == "dir" else "-", ent["size"],
                 ent["name"].decode("utf-8", "replace")))
    dev.close()


def cmd_device(args):
    """只打印"容器 + 分区表"，不碰 EasyFS 层。（四种载体都走这里）"""
    # `--disk` 的盘信息（名字/容量/扇区/挂载/系统盘）由 open_device 负责打印
    dev, desc = easyfs_device.open_device(args, read_only=True)
    if getattr(args, "disk", None):
        cont = easyfs_device.FileDevice(args.disk, read_only=True)
        print("容器        块设备 %s" % args.disk)
    elif getattr(args, "mem", None):
        cont = dev
        print("容器        内存（不落盘）")
    elif args.file:
        cont = easyfs_device.FileDevice(args.file, read_only=True)
        print("容器        raw（整个文件 / 整个设备）")
    else:
        cont, kind = easyfs_device.open_container(args.vdisk, read_only=True)
        print("容器        %s" % kind)
    print("路径        %s" % (args.disk or args.mem or args.file or args.vdisk))
    print("大小        %d B (%s)" % (cont.size, human(cont.size)))
    if desc and dev is not cont:
        print("卷所在      %s" % desc)
    print("")
    table, parts = easyfs_device.read_partitions(cont)
    print("分区表      %s" % table.upper())
    if not parts:
        print("  没有分区（或不是分区表）")
    for p in parts:
        print("  #%d  %-8s 起始 %-12d 长度 %-12d  %s%s"
              % (p["index"], p["type"], p["start"], p["length"],
                 human(p["length"]),
                 ("  引导" if p["boot"] else "")
                 + ("  扩展分区（未展开）" if p["extended"] else "")
                 + (("  " + p["name"]) if p["name"] else "")))
    if cont is not dev:
        cont.close()
    dev.close()


def cmd_df(args):
    """打印空间用量。默认输出**字节数**（好给脚本用），`-h` 人类可读。

    只读：不做任何重建（位图 dirty 时给出警告，并额外打印"未分类"一行 ——
    那通常就是"已分配但从根不可达"的泄漏量）。
    """
    dev, desc = easyfs_device.open_device(args, read_only=True)
    vol = Volume.mount(dev, strict=False)
    fmt = human if args.human else (lambda n: "%d" % n)
    chunk = vol.chunk

    def ck(nbytes):
        """字节 → chunk 数（向上取整）。"""
        return (nbytes + chunk - 1) // chunk

    total = vol.data_bytes
    free = vol.free_bytes()
    used = total - free

    # ---- 明细：从根走一遍树，分门别类地算
    alloc_size = sum(r.block_bytes for r in vol.regions)
    dir_bytes = link_bytes = data_bytes = data_alloc = 0
    n_dirs = n_links = 0
    seen = set()
    run_seen = {}          # (phys,size) → 去重：硬链接共享同一段，只能算一次
    chunk_owner = {}       # chunk 序号 → 段，用来发现"两段重叠"（别名，不该发生）
    overlap = []

    def count_chain(head, want):
        """数一条链（dir / link）里**尚未计数过**的块；顺带校验块类型。

        链接块会被多个条目共享，所以"重复出现"不等于成环：
        成环只在**单次走链内**判定，全局按块去重。
        """
        off, n, local = head, 0, set()
        while off:
            if off in local:
                raise EasyFSError("链成环 @%d" % off)
            local.add(off)
            h = parse_header(vol.read_block(off))
            if not h["magic_ok"] or h["block_type"] != want:
                raise EasyFSError("@%d 不是 %s 块（type=%s）"
                                  % (off, BT_NAME.get(want, want),
                                     BT_NAME.get(h["block_type"], h["block_type"])))
            if off not in seen:
                seen.add(off)
                n += 1
            off = (off + h["next_delta"]) if h["next_delta"] else 0
        return n

    def walk_dir(head, dir_object=None):
        nonlocal dir_bytes, link_bytes, data_bytes, data_alloc, n_dirs, n_links
        if dir_object is None:
            n_dirs += count_chain(head, BT_DIR)
        else:                                     # 对象形态目录：链接块 + 内容块表
            n_links += count_chain(dir_object, BT_LINK)
            for boff in vol.dir_object_blocks(dir_object):
                n_dirs += count_chain(boff, BT_DIR)
        for ent in vol.read_dir(head, dir_object):
            for loff in ent["link_blocks"]:
                n_links += count_chain(loff, BT_LINK)
            _tiny, runs = vol.entry_content(ent)
            for phys, size in runs:
                key = (phys, size)
                if key in run_seen:        # 硬链接：同一段被多个名字共享，只算一次
                    continue
                run_seen[key] = size
                first = (phys - vol.data_lo) // chunk
                for i in range(first, first + ck(size)):
                    if i in chunk_owner and chunk_owner[i] != key:
                        overlap.append(i)
                    chunk_owner[i] = key
            if ent["kind"] == "dir" and (ent["child"] or ent.get("dir_object")):
                walk_dir(ent["child"], ent.get("dir_object"))

    walk_err = None
    try:
        if getattr(vol, "root_type", ROOT_TYPE_CHAIN) == ROOT_TYPE_OBJECT:
            walk_dir(None, vol.root_off)
        else:
            walk_dir(vol.root_off)
    except EasyFSError as e:
        walk_err = str(e)                    # 树坏了也要能报总量，只是明细不可信
    dir_bytes = BLOCK_4K * n_dirs
    link_bytes = BLOCK_4K * n_links
    data_bytes = sum(run_seen.values())          # 去重后的真实字节数
    data_alloc = len(chunk_owner) * chunk        # 去重后的实际占用
    n_files_shared = 0
    accounted = None if walk_err else (alloc_size + dir_bytes + link_bytes
                                      + data_alloc)
    leak = (used - accounted) if accounted is not None else 0

    # ---- 输出
    print("设备          %s" % desc)
    for w in getattr(vol, "warnings", []):
        print("[!] %s" % w)
    if vol.is_dirty():
        print("[!] 位图是 dirty 的（上次没干净卸载）：下面的数字可能不准")
    print("")
    print("  区域        %s  = %d chunk（chunk %d B）"
          % (fmt(vol.region_len), ck(vol.region_len), chunk))
    print("  数据区      %s  = %d chunk" % (fmt(total), ck(total)))
    print("  已用        %s  = %d chunk   (%.2f%%)"
          % (fmt(used), ck(used), 100.0 * used / total if total else 0.0))
    print("  空闲        %s  = %d chunk   (%.2f%%)"
          % (fmt(free), ck(free), 100.0 * free / total if total else 0.0))
    print("")
    if walk_err:
        print("  明细        不可用（遍历失败：%s）" % walk_err)
        print("  合计已用    %s" % fmt(used))
        return
    print("  明细                    块数      占用")
    print("  位图链                  %4d    %s" % (len(vol.regions), fmt(alloc_size)))
    print("  目录块                  %4d    %s" % (n_dirs, fmt(dir_bytes)))
    print("  链接块                %4d    %s" % (n_links, fmt(link_bytes)))
    print("  文件数据                            %s（%d chunk）"
          % (fmt(data_alloc), ck(data_alloc)))
    print("    其中真实字节                      %s" % fmt(data_bytes))
    print("    向上取整余量                      %s" % fmt(data_alloc - data_bytes))
    if leak:
        print("  未分类（泄漏？）                    %s（%d chunk）"
              % (fmt(leak), ck(leak)))
    print("  合计已用                            %s%s"
          % (fmt(used), "（明细不可信，见上）" if walk_err else ""))
    if leak:
        print("")
        print("  提示：未分类为正 = 位图里置位但从根走不到 → 泄漏（可离线重建位图回收）；"
              "为负 = 有共享/重复计入，属异常")
    if overlap:
        print("")
        print("  [!] 发现 %d 个 chunk 被两段同时占用（别名！）—— 格式不该出现，请跑 check"
              % len(set(overlap)))


# ================================================================ fsck -n（只读检查）


class _Check(object):
    """只读一致性检查的账本（v0 只有 -n；清单见 2-dir.md §7 / 5-anchor.md / 1-alloc.md §10）。"""

    def __init__(self, vol, verbose=False):
        self.vol = vol
        self.verbose = verbose
        self.fails = []
        self.notes = []
        self.n_ok = 0
        self.n_dirs = 0
        self.n_entries = 0
        self.n_links = 0
        self.chunks = {}        # chunk 地址 → 占用者描述（重叠检测）
        self.reach = set()      # 可达 chunk 地址
        self.link_refs = {}     # 链接块地址 → 引用它的条目数
        self.link_nlink = {}    # 链接块地址 → 它声明的 NLINK
        self.link_seen = set()  # 已登记过的链接块（避免重复计数）
        self.root_bad = False   # 根目录/目录链不可读 → 跳过可达性比对

    # ---------------------------------------------------------- 记账
    def ok(self, name, extra=""):
        self.n_ok += 1
        print("  [ok]   %s%s" % (name, ("  " + extra) if extra else ""))

    def fail(self, name, why):
        self.fails.append((name, why))
        print("  [FAIL] %s：%s" % (name, why))

    def note(self, text):
        self.notes.append(text)
        print("  [note] %s" % text)

    def mark(self, phys, size, what):
        """登记物理区间。同一 (phys,size) 重复出现 = 共享（硬链接），允许。"""
        vol, chunk = self.vol, self.vol.chunk
        if phys < vol.data_lo or phys + size > vol.data_hi:
            self.fail("段越界", "%s @%d+%d 不在数据区 [%d,%d)"
                      % (what, phys, size, vol.data_lo, vol.data_hi))
            return
        n = (size + chunk - 1) // chunk
        for k in range(n):
            a = phys + k * chunk
            owner = self.chunks.get(a)
            if owner is None:
                self.chunks[a] = (phys, size, what)
            elif (owner[0], owner[1]) != (phys, size):
                self.fail("段重叠（别名）", "@%d 同属 %s 与 %s"
                          % (a, owner[2], what))
            self.reach.add(a)

    # ---------------------------------------------------------- 链
    def chain(self, head, btype, what):
        """校验一条链，返回 [(块地址, 块内容, 头)]。"""
        off, prev, seqs, blocks, seen = head, 0, [], [], set()
        while off:
            if off in seen:
                self.fail("%s 成环" % what, "@%d" % off)
                break
            seen.add(off)
            blk = bytearray(self.vol.read_block(off))
            h = parse_header(blk)
            if not h["magic_ok"] or h["block_type"] != btype:
                self.fail("%s 链块类型" % what,
                          "@%d 是 %s，应为 %s" % (off,
                          BT_NAME.get(h["block_type"], h["block_type"]),
                          BT_NAME.get(btype, btype)))
                break
            if not h["header_crc_ok"]:
                self.fail("%s 头 CRC" % what, "@%d" % off)
            pc = verify_payload_crc(blk, h)
            if pc is False:
                self.fail("%s 载荷 CRC" % what, "@%d" % off)
            elif pc is None and btype in (BT_DIR, BT_LINK):
                self.fail("%s 未启用载荷 CRC" % what, "@%d（dir/link 必须启用）" % off)
            if h["prev_delta"]:
                if off + h["prev_delta"] != prev:
                    self.fail("%s prev 不互指" % what,
                              "@%d 指回 @%d，实际应是 @%d"
                              % (off, off + h["prev_delta"], prev))
            elif prev:
                self.fail("%s 中间块 prev=0" % what, "@%d" % off)
            if seqs and h["seq"] < seqs[-1]:
                self.fail("%s seq 倒退" % what, "@%d: %d < %d"
                          % (off, h["seq"], seqs[-1]))
            seqs.append(h["seq"])
            start = h["header_bytes"]
            try:                                  # R8 + R11：恰好走到 payload_len，且属性不跨块
                list(scan_attrs(blk, start, start + h["payload_len"]))
            except EasyFSError as e:
                self.fail("%s 属性流" % what, "@%d %s" % (off, e))
            self.mark(off, BLOCK_4K, what)
            blocks.append((off, blk, h))
            nxt = (off + h["next_delta"]) if h["next_delta"] else 0
            prev, off = off, nxt
        return blocks

    # ---------------------------------------------------------- 目录树
    def walk_dir(self, head, path, dir_object=None):
        self.n_dirs += 1
        if dir_object is None:
            self.chain(head, BT_DIR, "目录链")
        else:                                     # 对象形态目录：链接块 + 内容块表
            self.chain(dir_object, BT_LINK, "目录链接块")
            for boff in self.vol.dir_object_blocks(dir_object):
                self.chain(boff, BT_DIR, "目录内容块")
        try:
            entries = self.vol.read_dir(head, dir_object)
        except EasyFSError as e:
            self.fail("目录解析", "%s: %s" % (path or "/", e))
            return
        names = set()
        for ent in entries:
            self.n_entries += 1
            name = ent["name"]
            disp = name.decode("utf-8", "replace")
            if not (0 < len(name) <= 255):
                self.fail("R2 NAME 长度 1..255", "%s/%r 长度 %d"
                          % (path, name, len(name)))
            if name in names:
                self.fail("R3 同目录重名", "%s/%s" % (path, disp))
            names.add(name)
            # 注意：read_dir 会把**链接块的属性内联**进 ent["attrs"]（base 指向链接块），
            # 所以"条目自己的属性"要按 segs 里的块过滤，否则会误报。
            own_blocks = set(seg[0] for seg in ent["segs"])
            own = [(t, v, b) for (t, v, b) in ent["attrs"] if b in own_blocks]
            atypes = [t for t, _v, _b in own]
            if atypes and atypes[0] != ATTR_NAME:
                self.fail("R1 NAME 必须是首属性", "%s/%s" % (path, disp))
            sym = [t for t in atypes if t in SYMLINK_ATTRS]
            normal = [t for t in atypes
                      if t in (ATTR_DATA_TINY, ATTR_DATA_PTR)]
            if sym and normal:
                self.fail("软链接与普通内容混用", "%s/%s" % (path, disp))
            if ent["link_blocks"]:
                banned = [t for t in atypes if t in
                          (ATTR_DATA_TINY, ATTR_DATA_PTR, 
                           ATTR_TMODIFY, ATTR_TCREATE, ATTR_CRC32, ATTR_DIR_PTR)]
                if banned:
                    self.fail("链接形态条目带了不该有的属性",
                              "%s/%s: %s" % (path, disp,
                              ", ".join(ATTR_NAME_STR.get(t, hex(t)) for t in banned)))
                if ent["nlink"] < 2:
                    self.fail("NLINK < 1", "%s/%s: nlink=%d" % (path, disp, ent["nlink"]))
                for lo in ent["link_blocks"]:
                    blocks = self.chain(lo, BT_LINK, "链接块链")
                    nl = 0
                    for off2, blk2, h2 in blocks:
                        start = h2["header_bytes"]
                        try:
                            attrs2 = list(scan_attrs(blk2, start,
                                                     start + h2["payload_len"]))
                        except EasyFSError:
                            attrs2 = []
                        for t, v, _a0, _a1 in attrs2:
                            if t == ATTR_DATA_OBJECT:
                                self.fail("链接块内嵌套 DATA_OBJECT", "@%d" % off2)
                            if t == ATTR_NLINK and len(v) == 4:
                                nl = struct.unpack("<I", v)[0]
                            if t in SYMLINK_ATTRS:
                                self.fail("硬链接到软链接（不允许）", "@%d" % off2)
                    if lo not in self.link_seen:
                        self.link_seen.add(lo)
                        self.n_links += 1
                        self.link_nlink[lo] = nl
                    self.link_refs[lo] = self.link_refs.get(lo, 0) + 1
            try:
                _tiny, runs = self.vol.entry_content(ent)
            except EasyFSError as e:
                self.fail("条目内容解析", "%s/%s: %s" % (path, disp, e))
                runs = []
            for phys, size in runs:
                self.mark(phys, size, "文件 %s" % disp)
            if ent["kind"] == "dir":
                if not (ent["child"] or ent.get("dir_object")):
                    self.fail("目录条目既没有 DIR_PTR 也没有 DIR_OBJECT",
                              "%s/%s" % (path, disp))
                else:
                    self.walk_dir(ent["child"], path + "/" + disp,
                                  ent.get("dir_object"))

    # ---------------------------------------------------------- 位图 / NLINK
    def compare_bitmap(self):
        vol = self.vol
        bitmap_used = set()
        for r in vol.regions:
            for i in range(r.nbits):
                if r.bit(i):
                    bitmap_used.add(r.region_off + i * r.bit_unit)
        orphan = sorted(bitmap_used - self.reach)
        missing = sorted(self.reach - bitmap_used)
        if orphan:
            self.fail("orphan（位图置位但从根不可达）",
                      "%d chunk，如 %s" % (len(orphan),
                      ", ".join("@%d" % a for a in orphan[:6])))
        else:
            self.ok("无 orphan / 泄漏")
        if missing:
            self.fail("可达但位图未置位",
                      "%d chunk，如 %s" % (len(missing),
                      ", ".join("@%d" % a for a in missing[:6])))
        else:
            self.ok("可达集合与位图一致", "%d chunk" % len(self.reach))

    def check_nlink(self):
        for lo in sorted(self.link_nlink):
            refs = self.link_refs.get(lo, 0)
            if self.link_nlink[lo] != refs:
                self.fail("NLINK 与引用条目数不一致",
                          "@%d: NLINK=%d，被 %d 个条目引用"
                          % (lo, self.link_nlink[lo], refs))
        if self.link_nlink:
            self.ok("链接块 NLINK 计数", "%d 块" % len(self.link_nlink))


def _check_anchors(chk, vol):
    if vol.head is None:
        chk.fail("head anchor", "不合法或缺失")
    if vol.tail is None:
        chk.fail("tail anchor", "不合法或缺失")
    if vol.head is None or vol.tail is None:
        return
    # I9（5-anchor.md §2.2）：非 delta 字段逐一相等 + delta 字段**解算成绝对地址后**相等
    keys = ["region_len", "uuid", "data_lo_logical", "chunk_shift", "geom_flags",
            "geom_version", "generation", "policy_id", "policy_state", "root_type",
            "alloc_num", "alloc_size", "state_flags"]
    diff = [(k, vol.head.get(k), vol.tail.get(k)) for k in keys
            if vol.head.get(k) != vol.tail.get(k)]
    if diff:
        chk.fail("I9 head/tail 非 delta 字段一致（ESTALE）",
                 "；".join("%s: %r != %r" % d for d in diff))
    else:
        chk.ok("I9 head/tail 非 delta 字段一致",
               "generation=%d root_type=%d"
               % (vol.head["generation"], vol.head["root_type"]))
    for fld, what in (("root_off", "根"), ("alloc_off", "位图链头")):
        xh, xt = vol.head[fld], vol.tail[fld]
        if xh != xt:
            chk.fail("head/tail 的 %s 解算目标不一致（%s）" % (fld, what),
                     "@%d != @%d" % (xh, xt))
        else:
            chk.ok("head/tail 的 %s 解算目标一致" % fld, "@%d" % xh)
    for nm, a in (("head", vol.head), ("tail", vol.tail)):
        if a.get("hdrcrc_ok") and a.get("poolcrc_ok"):
            chk.ok("%s anchor CRC" % nm,
                   "hdrcrc ok" + (" / poolcrc ok" if a.get("pool_here") else " / 无 pool 段"))
        else:
            chk.fail("%s anchor CRC" % nm,
                     "hdrcrc %s / poolcrc %s" % ("ok" if a.get("hdrcrc_ok") else "BAD",
                                                 "ok" if a.get("poolcrc_ok") else "BAD"))
    h = parse_header(vol.dev.read_at(vol.head["root_off"], 4096))
    want = {ROOT_TYPE_CHAIN: BT_DIR, ROOT_TYPE_OBJECT: BT_LINK}.get(
        vol.head["root_type"])
    if want is None:
        chk.ok("root_type 与根块类型", "root_type=%d（无需校验）"
               % vol.head["root_type"])
    elif h["magic_ok"] and h["block_type"] == want:
        chk.ok("root_type=%d → 根块类型正确" % vol.head["root_type"],
               "@%d type=%s" % (vol.head["root_off"],
                                BT_NAME.get(h["block_type"], "?")))
    else:
        chk.fail("root_type=%d → 根块类型不符" % vol.head["root_type"],
                 "@%d 实际 type=%s（应为 %s）"
                 % (vol.head["root_off"], h["block_type"],
                    BT_NAME.get(want, "?")))
    ph = vol.head["base"] + vol.head["peer_delta"]
    pt = vol.tail["base"] + vol.tail["peer_delta"]
    if ph != vol.tail["base"] or pt != vol.head["base"]:
        chk.fail("head/tail 互指", "head→@%d（应 @%d）；tail→@%d（应 @%d）"
                 % (ph, vol.tail["base"], pt, vol.head["base"]))
    else:
        chk.ok("head/tail 互指")


def cmd_fsck(args):
    """只读一致性检查 —— v0 只实现 `-n`。

    退出码（照 fsck(8) 的约定取子集）：0 无错 / 4 有错未修 / 8 操作错误。
    """
    if args.preen or args.yes or args.media or args.full:
        print("error: v0 的 fsck 只实现了 -n（只读检查）；"
              "-p / -y / -c / -f 尚未实现", file=sys.stderr)
        return 16
    dev, desc = easyfs_device.open_device(args, read_only=True)
    try:
        try:
            vol = Volume.mount(dev, strict=False)
        except EasyFSError as e:
            print("error: 不能挂载：%s" % e, file=sys.stderr)
            return 8
        print("=== fsck -n（只读检查，不改任何字节）===")
        print("设备          %s" % desc)
        chk = _Check(vol, verbose=args.verbose)
        if vol.is_dirty():
            chk.note("位图标记为 dirty（上次没干净卸载）→ 不一致项多半可以靠离线重建修复")
        _check_anchors(chk, vol)
        try:
            vol.check_regions()
            chk.ok("I7 区域 tiling", "%d 个区域恰好拼满数据区" % len(vol.regions))
        except EasyFSError as e:
            chk.fail("I7 区域 tiling", str(e))
        # 位图块自身属于永久元数据（carve-out），不算数据区的"可达"就没有意义
        for r in vol.regions:
            chk.mark(r.block_off, r.block_bytes, "位图块")
        chk.ok("位图链", "%d 块" % len(vol.regions))
        if getattr(vol, "root_type", ROOT_TYPE_CHAIN) == ROOT_TYPE_OBJECT:
            chk.walk_dir(None, "", vol.root_off)
        else:
            chk.walk_dir(vol.root_off, "")
        if any("目录链" in n or "目录解析" in n for n, _w in chk.fails):
            chk.note("根目录/目录链本身不可读 → 下面的可达性比对没有意义，已跳过")
            chk.root_bad = True
        chk.ok("目录树", "%d 个目录 / %d 个条目 / %d 个链接块"
               % (chk.n_dirs, chk.n_entries, chk.n_links))
        if not getattr(chk, "root_bad", False):
            chk.compare_bitmap()
        else:
            chk.note("未做 orphan/漏置位比对（见上）")
        chk.check_nlink()
        print("")
        if chk.fails:
            print("结果：发现 %d 个问题（%d 项通过）；-n 只读，未修复 → exit 4"
                  % (len(chk.fails), chk.n_ok))
            return 4
        print("结果：未发现问题（%d 项通过）→ exit 0" % chk.n_ok)
        return 0
    finally:
        dev.close()


# ================================================================ inspect（单块解剖）


def _hexdump(buf, base, limit=None):
    n = len(buf) if limit is None else min(limit, len(buf))
    for off in range(0, n, 16):
        row = buf[off:off + 16]
        print("  %5d  %-47s  %s"
              % (base + off, " ".join("%02x" % b for b in row),
                 "".join(chr(b) if 32 <= b < 127 else "." for b in row)))


def _attr_value(vol, off, atype, val):
    if atype == ATTR_NAME:
        return "  %r" % val.decode("utf-8", "replace")
    if atype == ATTR_SYMLINK_TINY:
        return "  %r" % val.decode("utf-8", "replace")
    if atype == ATTR_DATA_TINY:
        return "  %r" % (val[:20] + (b"..." if len(val) > 20 else b""))
    if atype in (ATTR_DATA_PTR, ATTR_SYMLINK_PTR):
        x, sz = parse_data_ptr(val)
        return "  x=%+#x -> @%d  size=%d (%s)" % (x, off + x, sz, human(sz))
    if atype in (ATTR_SYMLINK_OBJECT,):
        x, sz = parse_data_ptr(val)
        return "  L=%d -> @%d  size=%d (%s)" % (x, vol.logical_to_phys(x), sz, human(sz))
    if atype == ATTR_DIR_OBJECT and len(val) == 8:
        x, = struct.unpack("<q", val)
        return "  L=%d -> @%d（目录链接块：内容块表）" % (x, vol.logical_to_phys(x))
    if atype == ATTR_DIR_PTR and len(val) == 8:
        x, = struct.unpack("<q", val)
        return "  x=%+#x -> @%d" % (x, off + x)
    if atype == ATTR_DATA_OBJECT and len(val) == 8:
        x, = struct.unpack("<q", val)
        return "  L=%d -> @%d（链接块）" % (x, vol.logical_to_phys(x))
    if atype == ATTR_NLINK and len(val) == 4:
        return "  nlink=%d" % struct.unpack("<I", val)[0]
    if atype in (ATTR_TMODIFY, ATTR_TCREATE) and len(val) == 4:
        return "  t=" + _fmt_unix_sec(struct.unpack("<I", val)[0])
    if atype == ATTR_CRC32 and len(val) == 4:
        return "  crc=0x%08x" % struct.unpack("<I", val)[0]
    if atype == ATTR_PADN:
        return "  （PADn 占位：len=%d → 总长 %d 字节）" % (len(val), 2 + len(val))
    if atype == ATTR_NAME_HASH and len(val) == 1:
        return "  hash=%d" % val[0]
    return ("  %s" % val[:16].hex()) if val else ""


ANCHOR_DELTA_TAGS = ("peer", "rootioff", "alloioff")  # 自相对 delta（基准 = 所在 anchor）
ANCHOR_L_TAGS = ("dlolog",)                          # 逻辑坐标原点（不是地址）
ANCHOR_TYPE_TAGS = ("roottype", "allotype")          # 类型字段（打印它的名字）


def anchor_tag_table():
    from easyfs import anchor_layout
    return list(anchor_layout())


def resolve_anchor_tag(vol, name):
    """把一个 anchor tag 解算成 `(值, 绝对地址或 None, 说明)`。"""
    from easyfs import anchor_layout, anchor_get, anchor_geti, TAG_WIDTH
    want = name.strip().lower()
    names = [(n.strip(), n) for n, _t, _o, _v, _w in anchor_layout()]
    hit = [(n, t, toff, voff, w) for n, t, toff, voff, w in anchor_layout()
           if n.strip().lower() == want]
    if not hit:
        raise EasyFSError("anchor 里没有 tag %r；可用：%s"
                          % (name, ", ".join(n for n, _r in names)))
    n, _t, _toff, voff, w = hit[0]
    if n.strip() in ANCHOR_L_TAGS:
        return anchor_geti(vol.dev.read_at(0, 4096), n, signed=True), None, "逻辑坐标原点（不是地址）"
    if n.strip() in ANCHOR_DELTA_TAGS:
        d = anchor_geti(vol.dev.read_at(0, 4096), n, signed=True)
        why = "自相对 delta（基准 = head anchor @0）"
        if n.strip() == "rootioff":                 # 指向什么由 roottype 决定
            rt = anchor_geti(vol.dev.read_at(0, 4096), "roottype")
            why += " → 根：%s" % ROOT_NAME.get(rt, "?")
        elif n.strip() == "alloioff":               # 指向什么由 allotype 决定
            at = anchor_geti(vol.dev.read_at(0, 4096), "allotype")
            why += " → 分配结构：%s" % ALLOC_NAME.get(at, "?")
        return d, 0 + d, why
    if n.strip() in ANCHOR_TYPE_TAGS:               # 类型字段：打印名字，不是地址
        v = anchor_geti(vol.dev.read_at(0, 4096), n)
        table = ROOT_NAME if n.strip() == "roottype" else ALLOC_NAME
        return "%d  (%s)" % (v, table.get(v, "?")), None, "类型字段（不是地址）"
    raw = anchor_get(vol.dev.read_at(0, 4096), n)
    if any(raw):
        if n.strip() in ("uuid", "pool_uuid", "vdev_uuid", "member_uuid"):
            import uuid as _u
            return str(_u.UUID(bytes=raw)), None, "uuid（裸值）"
        v = int.from_bytes(raw, "little")
        if n.strip().endswith("crc"):
            return "0x%x" % v, None, "CRC"
        if n.strip() in ("easypart", "easypool"):
            return raw.rstrip(b"\x00").decode("ascii", "replace"), None, "版本字符串"
        return "%d(0x%x)" % (v, v), None, "普通字段（不是地址）"
    return 0, None, "（全零 / 未使用）"


def dump_by_tag(vol, name, chain=False, with_hex=False):
    """`inspect --tag` / shell 的 `dump`：解算一个 anchor tag，必要时 dump 它指向的块。"""
    val, abs_off, why = resolve_anchor_tag(vol, name)
    if abs_off is None:
        print("  %s = %s   (%s)" % (name, val, why))
        return 0
    print("  %s = %s -> @%d   (%s)" % (name, val, abs_off, why))
    _dump_block(vol, abs_off, with_hex)
    return 0


def _dump_anchor_tags(blk, base):
    """anchor 是 tag 布局（没有通用头）⇒ 按文档那样的三列打印：offs / tag / 值。"""
    import uuid as _u
    print("=== anchor @%d ===" % base)
    print("  %-11s %-12s %s" % ("offs", "tag", "value"))
    for name, tag, toff, voff, w in anchor_layout():
        start = toff if tag is not None else voff
        end = voff + w - 1
        raw = bytes(blk[voff:voff + w])
        if name == "easypart":
            val = '"%s"' % raw.rstrip(b"\x00").decode("ascii", "replace")
        elif name in ("uuid", "pool_uuid", "vdev_uuid", "member_uuid"):
            val = str(_u.UUID(bytes=raw)) if any(raw) else "（全零）"
        elif name.strip().endswith("crc"):
            val = "0x%x" % int.from_bytes(raw, "little")
        else:
            n = int.from_bytes(raw, "little")
            val = "%d(0x%x)" % (n, n) if n else "0"
        if tag is None:
            lab = "（无 tag）"
        elif not any(blk[toff:toff + 8]) and not any(raw):
            lab, val = "（未使用）", ""
        else:
            lab = '"%s"' % bytes(blk[toff:toff + 8]).decode("ascii", "replace")
        print("  %-11s %-12s %s" % ("[%x,%x]" % (start, end), lab, val))
    print("  （hdrcrc 覆盖 [0,0x200)；pool 段 [0x200,0x3d0) 由 poolcrc 覆盖）")


def _dump_block(vol, off, with_hex=False):
    blk = bytearray(vol.read_block(off))
    try:
        if (anchor_geti(blk, "blktype ") == BT_ANCHOR
                and anchor_geti(blk, "hdrbytes") == ANCHOR_VOL_HDR_END):
            _dump_anchor_tags(blk, off)
            return
    except EasyFSError:
        pass                              # 不是 anchor（或字段缺失）⇒ 走通用头路径
    h = parse_header(blk)
    print("=== 块 @%d ===" % off)
    if not h["magic_ok"]:
        print("  块头魔数不对（应 %s，实际 %r）→ 按裸数据 / 损坏处理"
              % (h["magic_expect"].decode() if h["magic_expect"] else "无（null/未初始化）",
                 h["magic"]))
        _hexdump(blk, off, 256)
        return
    pc = verify_payload_crc(blk, h)
    print("  magic/type  %s / %d (%s)  version %d  flags 0x%x"
          % (h["magic"].decode(), h["block_type"],
             BT_NAME.get(h["block_type"], "?"), h["version"], h["flags"]))
    print("  header      header_bytes=%d  payload_len=%d  header_crc=%s  payload_crc=%s"
          % (h["header_bytes"], h["payload_len"],
             "ok" if h["header_crc_ok"] else "BAD",
             {True: "ok", False: "BAD", None: "未启用"}[pc]))
    print("  chain       prev=%s  next=%s  seq=%d"
          % ("@%d" % (off + h["prev_delta"]) if h["prev_delta"] else "-",
             "@%d" % (off + h["next_delta"]) if h["next_delta"] else "-", h["seq"]))
    bt = h["block_type"]
    if bt == BT_ANCHOR:
        a = vol.read_anchor(off)
        _print_anchor("head" if off == 0 else "tail", a, "peer")
    elif bt == BT_ALLOC:
        rd, rb, bb, bu, ls = struct.unpack_from("<qQIIq", blk, 64)
        print("  位图扩展    region_delta=%+#x -> region @%d  region_bytes=%d (%s)"
              % (rd, off + rd, rb, human(rb)))
        print("              block_bytes=%d  bit_unit=%d  region_logical_start=%d"
              % (bb, bu, ls))
        used = sum(bin(x).count("1")
                   for x in blk[h["header_bytes"]:h["header_bytes"] + h["payload_len"]])
        print("  位图用量    载荷 %d 字节 = %d bit 中已用 %d"
              % (h["payload_len"], h["payload_len"] * 8, used))
    elif bt in (BT_DIR, BT_LINK):
        print("  " + _pad("偏移", 7) + _pad("名字", 14) + _pad("类型", 7) + _pad("len", 6) + "值 / 解析     ← 右边三列就是 TLV")
        pos, end = h["header_bytes"], h["header_bytes"] + h["payload_len"]
        while pos < end:
            t = blk[pos]
            if t == ATTR_PAD1:
                print("  " + _pad("%d" % pos, 7)
                      + _pad(ATTR_NAME_STR.get(t, "?"), 14) + _pad("0x%02X" % t, 7)
                      + _pad("1", 6) + "（1 字节占位）")
                pos += 1
                continue
            ln = blk[pos + 1]
            val = bytes(blk[pos + 2:pos + 2 + ln])
            print("  " + _pad("%d" % pos, 7)
                  + _pad(ATTR_NAME_STR.get(t, "?"), 14) + _pad("0x%02X" % t, 7)
                  + _pad("%d" % ln, 6) + _attr_value(vol, off, t, val).lstrip())
            pos += 2 + ln
    else:
        print("  （该类型没有专属解析：%s）" % BT_NAME.get(bt, bt))
    if with_hex:
        _hexdump(blk, off, h["header_bytes"] + h["payload_len"])


def cmd_hexdump(args):
    """十六进制转储一个块：`--tag` 解算 anchor 字段，或 `--block` 直接给偏移。

    偏移都是**卷内偏移**（区域相对）；`--len` 默认 512 字节。
    """
    dev, desc = easyfs_device.open_device(args, read_only=True)
    print("设备          %s" % desc)
    vol = Volume.mount(dev, strict=False)
    n = parse_size(args.len) if args.len else 512
    if args.tag:
        val, off, why = resolve_anchor_tag(vol, args.tag)
        if off is None:
            print("  %s = %s   (%s)  —— 不是地址，没有块可 dump"
                  % (args.tag, val, why))
            return 0
        print("  %s = %s -> @%d   (%s)" % (args.tag, val, off, why))
    else:
        off = args.block if args.block is not None else 0
        print("  块 @%d" % off)
    if off < 0 or off >= dev.size:
        raise EasyFSError("偏移越界: @%d（区域 [0, %d)）" % (off, dev.size))
    n = min(n, dev.size - off)
    data = bytearray(dev.read_at(off, n))
    head = bytearray(dev.read_at(off, min(64, dev.size - off)))   # 块头判定用整块头
    is_anchor = False
    if bytes(head[0:8]) == ANCHOR_MAGIC_TAG:
        try:
            is_anchor = anchor_geti(head, "hdrbytes") == ANCHOR_VOL_HDR_END
        except EasyFSError:
            is_anchor = False
    if is_anchor:
        print("  anchor（tag 布局，%s %s）—— 逐字段看：inspect --block 0"
              % (ANCHOR_MAGIC_TAG.decode(),
                 bytes(head[8:16]).rstrip(b"\x00").decode("ascii", "replace")))
    elif bytes(head[0:8]) == ANCHOR_MAGIC_TAG:
        h = parse_header(head)
        print("  magic/type  %s / %d (%s)  version %d"
              % (h["magic"].decode(), h["block_type"],
                 BT_NAME.get(h["block_type"], "?"), h["version"]))
    else:
        print("  （块头魔数不对 ⇒ 按裸数据看）")
    _hexdump(data, off, n)
    return 0


def cmd_inspect(args):
    """离线调试：把单个块按格式逐字段/逐属性摊开（纯读）。"""
    dev, desc = easyfs_device.open_device(args, read_only=True)
    try:
        vol = Volume.mount(dev, strict=False)
        print("设备          %s" % desc)
        targets = []
        if args.block is not None:
            targets.append(args.block)
        if args.tag:
            return dump_by_tag(vol, args.tag, args.chain, args.hex)
        if args.path:
            walk = PathWalker(vol)
            try:
                _poff, _name, ent = walk.entry_pos(args.path)
            except EasyFSError as e:
                raise EasyFSError("路径解析失败: %s" % e)
            if ent is None:
                raise EasyFSError("找不到: %s" % args.path)
            targets.append(ent["dir_block"])
            for lo in ent.get("link_blocks", []):
                targets.append(lo)
            if ent["kind"] == "dir" and ent["child"]:
                targets.append(ent["child"])
        if not targets:
            raise EasyFSError("用法: inspect (--block N | --path P) [--chain] [--hex]")
        for off in targets:
            if off < 0 or off + BLOCK_4K > vol.region_len:
                raise EasyFSError("偏移越界: @%d（区域 [0, %d)）" % (off, vol.region_len))
            _dump_block(vol, off, args.hex)
            if args.chain:
                cur, seen = off, set()
                while True:
                    if cur in seen:
                        print("  [!] 链成环 @%d" % cur)
                        break
                    seen.add(cur)
                    h = parse_header(bytearray(vol.read_block(cur)))
                    if not h["next_delta"]:
                        break
                    cur = cur + h["next_delta"]
                    _dump_block(vol, cur, args.hex)
    finally:
        dev.close()


OPT_FAMILIES = (
    ("alloc", "--alloc-merge", "合并全空的子区域：清掉父位图那一位、把子位图块从链上摘掉、"
                             "把它管的那个单位还成粗单位", True),
    ("dir",   "--dir-compact",  "压实目录链：把 `PADn` / 尾追加撑出来的空洞收掉（后面的条目往前挪）", False),
    ("link",  "--link-merge", "合并链接块的内容块表：把相邻的 `DATA_PTR` 段并成一段（块表变短）", False),
)
OPT_DONE = dict((f, d) for f, _, _, d in OPT_FAMILIES)
FLAG_OF = dict((f, flag) for f, flag, _, _ in OPT_FAMILIES)


def _optimize_help(fam=None):
    """打 `optimize` 帮助：给家族 = 只列那一族；不给 = 全列。**不碰盘** ✓"""
    print("optimize —— 整理卷（「只用不还」的补偿：删东西不会自动回收元数据 ✓）")
    print("")
    print("用法：")
    print("   optimize --alloc | --dir | --link      # 看某一族有哪些动作（只打帮助 ✓）")
    print("   optimize --<family>-<action>             # 执行（加 --dry-run 先看能回收多少 ✓）")
    print("   optimize --all                          # 依次跑所有已实现的动作")
    print("")
    for f, flag, desc, done in OPT_FAMILIES:
        if fam and f != fam:
            continue
        print("   %s 家族：" % f)
        print("     %-12s %s" % (flag, desc))
        print("     %-12s %s" % ("", "已实现 ✓" if done else "还没实现 ✗（设计见 1-alloc.md §13.6）"))
    return 0


def cmd_optimize(args):
    """整理卷（1-alloc.md §13.6）：`--家族` 看帮助 / `--家族-动作` 执行 / `--all` 全跑。"""
    fam = "alloc" if args.alloc else ("dir" if args.dir else ("link" if args.link else None))
    acts = [f for f, flag, _, _ in OPT_FAMILIES
            if {"--alloc-merge": args.alloc_merge, "--dir-compact": args.dir_compact,
                "--link-merge": args.link_merge}[flag]]
    if args.all:
        acts = [f for f, _, _, _ in OPT_FAMILIES]
    if fam is not None or not acts:
        return _optimize_help(fam)                   # 只打帮助 ⇒ 不开设备 ✓
    if not args.all:                                 # 点名要的没实现 ⇒ 直接拦（不碰盘 ✓）
        for f in acts:
            if not OPT_DONE[f]:
                raise EasyFSError("ENOTSUP: optimize %s 还没实现（设计见 1-alloc.md §13.6）"
                                  % (FLAG_OF.get(f, "")))
    acts = [f for f in acts if OPT_DONE[f]]          # `--all` 只跑已实现的，其余打一行说明 ✓
    dev, desc = easyfs_device.open_device(args, read_only=getattr(args, "dry_run", False))
    print("设备          %s" % desc)
    vol = Volume.mount(dev)
    if vol.is_dirty():
        if getattr(args, "dry_run", False):
            print("  （卷是 dirty 的：dry-run 不重建位图，只看现状）")
        else:
            print("  （卷是 dirty 的：先重建位图）")
            vol.rebuild_bitmap(apply=True)
            vol.mark_clean()
    rep = vol.optimize_alloc(dry_run=getattr(args, "dry_run", False))
    n = len(rep["merged"])
    print("  optimize --alloc-merge   %s %d 个全空子区域，回收 %s"
          % ("可以合并" if rep["dry_run"] else "已合并", n, human(rep["bytes_freed"])))
    for m in rep["merged"]:
        if getattr(args, "verbose", False) or rep["dry_run"]:
            print("    - 子区域 @%d（%s，位图块 @%d %s）← 父 @%d"
                  % (m["off"], human(m["bytes"]), m["block_off"],
                     human(m["block_bytes"]), m["parent"]))
    if not rep["dry_run"] and n:
        vol.commit()
        vol.mark_clean()
        print("  ✓ 已提交：位图 %d 块 / %s"
              % (len(vol.regions), human(sum(r.block_bytes for r in vol.regions))))
    if args.all:
        print("  （--dir-compact / --link-merge 还没实现，见 python/README.md ✓）")
    if not getattr(args, "dry_run", False):          # dry-run 是只读句柄：不许写 clean 标志
        vol.mark_clean()
    dev.close()
    return 0


def cmd_resize(args):
    """改卷在容器里占的区域（1-alloc.md §8）。只改区域内部，不碰容器。"""
    cont, cdesc = easyfs_device.open_container_device(args)
    pnote, pspan = "", None
    if getattr(args, "part", None):
        if (getattr(args, "offs", "0") not in (None, "0", 0)) or args.size:
            cont.close()
            raise EasyFSError("--part 与 --offs/--size 二选一（都是【改前在哪】）")
        table, parts = easyfs_device.read_partitions(cont)
        sel = [q for q in parts if q["index"] == args.part]
        if not sel:
            cont.close()
            raise EasyFSError("没有 %d 号分区（共 %d 个）" % (args.part, len(parts)))
        q = sel[0]
        old_start, old_len = q["start"], q["length"]
        pspan = q
        pnote = "   ← %s 分区 #%d" % (table.upper(), q["index"])
    else:
        old_start = parse_size(args.offs) if args.offs else 0
        old_len = (parse_size(args.size) if args.size else (cont.size - old_start))
    new_start = (parse_size(args.newoffs) if args.newoffs else old_start)
    new_len = (parse_size(args.newsize) if args.newsize
               else (cont.size - new_start))
    print("容器        %s" % cdesc)
    print("旧几何      [%s, +%s)%s" % (human(old_start), human(old_len), pnote))
    print("新几何      [%s, +%s)%s"
          % (human(new_start), human(new_len),
             "      （dry-run，不会真写）" if args.dry_run else ""))
    if not args.dry_run:                       # 真动之前问一句（--yes = 用户答了 y）
        warn = []
        if pspan is not None and (new_start < pspan["start"]
                                  or new_start + new_len > pspan["start"] + pspan["length"]):
            warn.append("提醒        新几何超出了那个分区的范围 —— 分区表是你自己的事"
                        "（扩容得先改分区表）")
        easyfs_device.confirm_ask(
            warn + ["变化        %s → %s（%s）"
                    % (human(old_len), human(new_len),
                       "缩容" if new_len < old_len else
                       ("扩容" if new_len > old_len else "不动"))],
            assume_yes=bool(getattr(args, "yes", False)),
            question="确认按上面的几何 resize 吗？[y/N]（脚本里加 --yes 就免问） ")
    if args.verbose:
        print("步骤：")
    rep = easyfs.resize(cont, old_start, old_len, new_start, new_len,
                        mode=args.mode,
                        log=(lambda m: print("  · " + m)) if args.verbose else None,
                        dry_run=args.dry_run, verify=not args.no_verify)
    print("结果        方向 %s  区域块 %d → %d  空闲 %s → %s  (%s%s)"
          % (rep["mode"], rep["regions_before"], rep["regions_after"],
             human(rep["free_before"]), human(rep["free_after"]),
             "+" if rep["delta"] >= 0 else "-", human(abs(rep["delta"]))))
    if rep["moved"]:
        print("挪位图块    %d 个" % len(rep["moved"]))
    if args.verbose:
        print("写入序列（%d 次）：" % len(rep["writes"]))
        for off, n, what in rep["writes"]:
            print("  %-12s %6d B  %s" % (human(off), n, what))
    cont.close()
    if rep["changed"] and not args.dry_run:
        print("提醒        容器（分区表 / 镜像文件大小）是你自己的事："
              "扩容要先把容器弄大，缩容现在可以把容器收掉")



# ================================================================ ctrl 交互模式

UNSUPPORTED = {
    "chmod": "格式里没有权限位（2-dir.md 没有 mode/uid/gid 属性）",
    "chown": "格式里没有属主（同上）",
    "chgrp": "格式里没有属组（同上）",
    "mount": "卷不需要挂载：直接用 --file/--vdisk/--mem 打开容器",
    "umount": "同上",
    "su": "没有用户概念", "sudo": "没有用户概念",
    "dd": "没有块设备语义；用 cp 或 tool-sftpcli 的 get/put",
    "mkfs": "先退出，用 `tool mkfs` 建卷",
    "ln": None,                     # 支持（见下）
}

HELP_TEXT = """\
命令（相对路径基于当前目录；支持引号）：
  导航   pwd | cd [PATH] | ls [-l] [-h] [PATH] | tree [PATH] [-L DEPTH] | find [PATH] [-name PAT]
  查看   stat PATH | cat PATH | head PATH [-n N] | du [PATH] [-h] | df [-h] | readlink PATH
  修改   mkdir [-p] PATH | rmdir PATH | rm [-r] PATH... | cp [-r] SRC DST | mv SRC DST | touch PATH
  链接   ln TARGET LINKNAME | ln -s TARGET LINKNAME | readlink PATH
  卷     sync（提交+标干净） | probe | device | df [-h] | fsck [-n]
         dump <tag>（解算 anchor 字段并 dump 它指向的块）
         hexdump --tag <名字> | --block N [--len N]
         optimize alloc|dir|link|all [--dry-run] [-v]
         inspect --block N | --path P | --tag <tag>
         （后 5 个直接委派给 argv 侧同一实现；resize / mkfs 交互里拒绝，见理由）
  其它   help | quit / exit（或 Ctrl-D）
不支持：chmod chown chgrp mount umount su sudo dd（格式里没有权限/用户概念）
"""


class CtrlShell(object):
    """`tool shell` 的交互循环。

    只做"把命令翻译成 Volume / PathWalker 调用"这一件事；所有语义在库里。
    """

    def __init__(self, vol, allow_object=False, args=None, backed=True):
        self.vol = vol
        self.allow_object = allow_object      # 只有命令行给了 --object 才允许对象形态
        self.args = args                      # 解析好的 ctrl 参数（委派子命令时要复用）
        self.backed = backed                  # 容器能否被"再打开一份"（内存容器不行）
        self.walker = PathWalker(vol)
        self.quit = False

    # ---------------------------------------------------------- 辅助
    def _p(self):
        return self.walker.disp() if hasattr(self.walker, "disp") else "/"

    def _ref(self, path):
        """-> (链头, DIR_OBJECT)：读一个目录需要的两样。"""
        return self.walker.dir_ref(path)

    def _entries(self, path):
        head, obj = self._ref(path)
        return self.vol.read_dir(head, obj)

    def _parent_ref(self, path):
        """一个条目的父目录 `(链头, DIR_OBJECT)`（对象形态父目录也对）。"""
        if "/" in path:
            parent = path.rsplit("/", 1)[0] or "/"
        else:
            parent = "."
        return self._ref(parent)

    def _name(self, ent):
        return ent["name"].decode("utf-8", "replace")

    def _kind(self, ent):
        if ent["symlink"]:
            return "l"
        return "d" if ent["kind"] == "dir" else "-"

    def _fmt(self, n, human_flag):
        return human(n) if human_flag else "%d" % n

    # ---------------------------------------------------------- 命令
    def do_help(self, a):
        print(HELP_TEXT.rstrip())

    def do_pwd(self, a):
        print(self._p())

    def do_cd(self, a):
        path = a[0] if a else "/"
        self.walker.cd(path)
        print(self._p())

    def do_ls(self, a):
        long_fmt, hum, paths = False, False, []
        for x in a:
            if x in ("-l", "--long"):
                long_fmt = True
            elif x == "-h":
                hum = True
            elif x in ("-a", "-la", "-al"):
                long_fmt = long_fmt or "l" in x
            elif x.startswith("-"):
                raise EasyFSError("ls: 不认识的选项 %s" % x)
            else:
                paths.append(x)
        for path in (paths or ["."]):
            head, obj = self._ref(path)
            ents = sorted(self.vol.read_dir(head, obj), key=self._name)
            if len(paths) > 1:
                print("%s:" % path)
            if not ents:
                print("  （空）")
            for e in ents:
                if long_fmt:
                    print("  %s %8s %s %s" % (self._kind(e),
                                              self._fmt(e["size"], hum),
                                              self._name(e),
                                              ("-> " + self.vol.readlink(e).decode(
                                                  "utf-8", "replace")) if e["symlink"] else ""))
                else:
                    print("  %s%s" % (self._name(e), "/" if e["kind"] == "dir" else
                                      ("@" if e["symlink"] else "")))

    def do_tree(self, a):
        path, depth, hum = ".", None, False
        i = 0
        while i < len(a):
            if a[i] in ("-L", "--depth"):
                depth = int(a[i + 1]); i += 2; continue
            if a[i] == "-h":
                hum = True
            elif not a[i].startswith("-"):
                path = a[i]
            i += 1
        head, obj = self._ref(path)
        print(path if path != "." else self._p())
        self._tree(head, obj, "", 1, depth, hum)

    def _tree(self, head, obj, prefix, level, maxdepth, hum):
        ents = sorted(self.vol.read_dir(head, obj), key=self._name)
        for i, e in enumerate(ents):
            last = (i == len(ents) - 1)
            print("%s%s%s%s" % (prefix, "`-- " if last else "|-- ", self._name(e),
                                "/" if e["kind"] == "dir" else
                                (" -> " + self.vol.readlink(e).decode("utf-8", "replace")
                                 if e["symlink"] else "")))
            if e["kind"] == "dir" and (maxdepth is None or level < maxdepth):
                self._tree(e["child"], e.get("dir_object"),
                           prefix + ("    " if last else "|   "), level + 1,
                           maxdepth, hum)

    def do_find(self, a):
        path, pat = ".", None
        if a and not a[0].startswith("-"):
            path = a[0]; a = a[1:]
        if "-name" in a:
            pat = a[a.index("-name") + 1]
        base = self._p().rstrip("/")
        head, obj = self._ref(path)

        def rec(h, o, rel):
            for e in sorted(self.vol.read_dir(h, o), key=self._name):
                full = rel + "/" + self._name(e)
                if pat is None or fnmatch.fnmatch(self._name(e), pat):
                    print(full)
                if e["kind"] == "dir":
                    rec(e["child"], e.get("dir_object"), full)
        rec(head, obj, base)

    def do_stat(self, a):
        if not a:
            raise EasyFSError("用法: stat PATH")
        _p, _n, e = self.walker.entry_pos(a[0])
        if e is None:
            raise EasyFSError("找不到: %s" % a[0])
        print("  name     %s" % self._name(e))
        print("  type     %s%s" % ("dir" if e["kind"] == "dir" else "file",
                                   "（软链接）" if e["symlink"] else ""))
        print("  size     %d" % e["size"])
        print("  nlink    %d" % e["nlink"])
        print("  mtime    %d" % e["mtime"])
        if e["symlink"]:
            print("  target   %s" % self.vol.readlink(e).decode("utf-8", "replace"))
        if e.get("dir_object"):
            print("  dir_object @%d（内容块表）" % e["dir_object"])
        elif e["child"]:
            print("  dir_head  @%d" % e["child"])
        if e["link_blocks"]:
            print("  object   @%d（硬链接共享）" % e["link_blocks"][0])
        print("  attrs    %s" % ", ".join(
            ATTR_NAME_STR.get(t, "0x%02x" % t) for t, _v, _b in e["attrs"]))

    def do_cat(self, a):
        if not a:
            raise EasyFSError("用法: cat PATH")
        _p, _n, e = self.walker.entry_pos(a[0])
        if e is None:
            raise EasyFSError("找不到: %s" % a[0])
        if e["kind"] == "dir":
            raise EasyFSError("是目录: %s" % a[0])
        data = self.vol.read_file(e)
        sys.stdout.write(data.decode("utf-8", "replace"))
        if not data.endswith(b"\n"):
            sys.stdout.write("\n")

    def do_head(self, a):
        n, path = 10, None
        i = 0
        while i < len(a):
            if a[i] == "-n":
                n = int(a[i + 1]); i += 2; continue
            path = a[i]; i += 1
        if path is None:
            raise EasyFSError("用法: head PATH [-n N]")
        _p, _nm, e = self.walker.entry_pos(path)
        if e is None:
            raise EasyFSError("找不到: %s" % path)
        data = self.vol.read_file(e)[:n]
        sys.stdout.write(data.decode("utf-8", "replace"))
        if not data.endswith(b"\n"):
            sys.stdout.write("\n")

    def do_du(self, a):
        hum = "-h" in a
        path = [x for x in a if not x.startswith("-")]
        path = path[0] if path else "."
        head, obj = self._ref(path)
        total = [0]

        def rec(h, o):
            for e in self.vol.read_dir(h, o):
                if e["kind"] == "dir":
                    rec(e["child"], e.get("dir_object"))
                else:
                    total[0] += e["size"]
        rec(head, obj)
        print("%s\t%s" % (self._fmt(total[0], hum), path))

    def _delegate(self, fn, **kw):
        """把命令**委派给 argv 侧的同一个实现**（`cmd_df` / `cmd_fsck` / `cmd_inspect`…）。

        它们各自会 `open_device` 一份，所以：
        * 先 `commit()`，让它们看到最新状态；
        * 内存容器（`--mem`）没法再打开一份 → 明确拒绝。
        """
        if not self.backed:
            print("error: 这个容器不能在交互里再打开一份（内存容器）；"
                  "请用 --file / --vdisk 容器")
            return
        self.vol.commit()
        a = copy.copy(self.args)
        for k, v in kw.items():
            setattr(a, k, v)
        try:
            rc = fn(a)
        except SystemExit:
            rc = 0
        except EasyFSError as e:
            print("error: %s" % e)
            return
        if rc:
            print("（%s 退出码 %s）" % (fn.__name__, rc))

    def do_df(self, a):
        self._delegate(cmd_df, human=("-h" in a or "--human" in a))

    def do_device(self, a):
        self._delegate(cmd_device)

    def do_inspect(self, a):
        kw = {"block": None, "path": None, "tag": None, "chain": False, "hex": False}
        i = 0
        while i < len(a):
            if a[i] == "--block":
                kw["block"] = int(a[i + 1], 0); i += 2; continue
            if a[i] == "--path":
                kw["path"] = a[i + 1]; i += 2; continue
            if a[i] == "--tag":
                kw["tag"] = a[i + 1]; i += 2; continue
            if a[i] == "--chain":
                kw["chain"] = True
            elif a[i] == "--hex":
                kw["hex"] = True
            elif not a[i].startswith("-") and kw["tag"] is None:
                kw["tag"] = a[i]                 # 裸名字也算 --tag
            else:
                raise EasyFSError("inspect 用法: --block N | --path P | --tag 名字 [--chain] [--hex]")
            i += 1
        if kw["block"] is None and kw["path"] is None and kw["tag"] is None:
            raise EasyFSError("inspect 用法: --block N | --path P | --tag 名字 [--chain] [--hex]")
        self._delegate(cmd_inspect, **kw)

    def do_resize(self, a):
        print("error: 交互模式里不允许改几何 —— 卷还挂着，改完内存里的几何就过期了；\n"
              "       请 quit 之后用 `tool resize ...`（1-alloc.md §8）")

    def do_mkdir(self, a):
        par = "-p" in a
        path = [x for x in a if not x.startswith("-")]
        if not path:
            raise EasyFSError("用法: mkdir [-p] PATH")
        target = path[0]
        if par:
            parts = [x for x in target.split("/") if x not in ("", ".")]
            cur = "/" if target.startswith("/") else "."
            for part in parts:
                sub = (cur.rstrip("/") + "/" + part) if cur != "/" else "/" + part
                if self.walker.entry_pos(sub)[2] is None:
                    head, obj = self._ref(cur)
                    self.vol.mkdir(head, part, dir_object=obj)
                cur = sub
            print(self.walker.disp() if False else "ok")
            return
        parent, name, _e = self.walker.entry_pos(target)
        head, obj = self._parent_ref(target)
        self.vol.mkdir(head, name, dir_object=obj)
        print("ok")

    def do_rmdir(self, a):
        if not a:
            raise EasyFSError("用法: rmdir PATH")
        parent, name, _e = self.walker.entry_pos(a[0])
        head, obj = self._parent_ref(a[0])
        self.vol.delete(head, name, dir_object=obj)
        print("ok")

    def do_rm(self, a):
        flags = [x for x in a if x.startswith("-")]
        rec = any(("r" in f or "R" in f or f == "--recursive") for f in flags)
        force = any(("f" in f or f == "--force") for f in flags)
        paths = [x for x in a if not x.startswith("-")]
        if not paths:
            raise EasyFSError("用法: rm [-r|-R] [-f] PATH...")
        for path in paths:
            parent, name, e = self.walker.entry_pos(path)
            if e is None:
                if force:
                    continue                      # -f：缺失不报错
                raise EasyFSError("找不到: %s" % path)
            head, obj = self._parent_ref(path)
            self.vol.delete(head, name, recursive=rec, dir_object=obj)
            if not force:
                print("removed %s" % path)

    def do_cp(self, a):
        rec = "-r" in a or "-R" in a
        paths = [x for x in a if not x.startswith("-")]
        if len(paths) != 2:
            raise EasyFSError("用法: cp [-r] SRC DST")
        src, dst = paths
        _p, _n, se = self.walker.entry_pos(src)
        if se is None:
            raise EasyFSError("找不到: %s" % src)
        if se["kind"] == "dir":
            if not rec:
                raise EasyFSError("是目录（要 -r）: %s" % src)
            parent, name, _e = self.walker.entry_pos(dst)
            head, obj = self._parent_ref(dst)
            self.vol.mkdir(head, name, dir_object=obj)
            self._copy_dir(se, dst)
            print("ok")
            return
        data = self.vol.read_file(se)
        parent, name, _e = self.walker.entry_pos(dst)
        head, obj = self._parent_ref(dst)
        self.vol.create(head, name, data=data, dir_object=obj)
        print("ok")

    def _copy_dir(self, se, dst):
        for e in self.vol.read_dir_of(se):
            sub = dst.rstrip("/") + "/" + self._name(e)
            if e["kind"] == "dir":
                parent, name, _x = self.walker.entry_pos(sub)
                head, obj = self._parent_ref(sub)
                self.vol.mkdir(head, name, dir_object=obj)
                self._copy_dir(e, sub)
            else:
                data = self.vol.read_file(e)
                parent, name, _x = self.walker.entry_pos(sub)
                head, obj = self._parent_ref(sub)
                self.vol.create(head, name, data=data, dir_object=obj)

    def do_mv(self, a):
        if len(a) != 2:
            raise EasyFSError("用法: mv SRC DST")
        src, dst = a
        sp, sn, _e = self.walker.entry_pos(src)
        dp, dn, de = self.walker.entry_pos(dst)
        shead, sobj = self._parent_ref(src)
        dhead, dobj = self._parent_ref(dst)
        if de is not None and de["kind"] == "dir":
            dhead, dobj = self._ref(dst)
            dn = sn
        self.vol.move(shead, sn, dhead, dn)
        print("ok")

    def do_touch(self, a):
        if not a:
            raise EasyFSError("用法: touch PATH")
        parent, name, e = self.walker.entry_pos(a[0])
        head, obj = self._parent_ref(a[0])
        if e is None:
            self.vol.create(head, name, dir_object=obj)
            print("created")
        else:
            print("已存在（格式里时间存在条目里，v0 不改）")

    def do_ln(self, a):
        soft = "-s" in a
        paths = [x for x in a if not x.startswith("-")]
        if len(paths) != 2:
            raise EasyFSError("用法: ln [-s] TARGET LINKNAME")
        target, link = paths
        parent, name, _e = self.walker.entry_pos(link)
        head, obj = self._parent_ref(link)
        if soft:
            if self.allow_object:
                print("error: SYMLINK_OBJECT（软链接的对象形态）尚未实现；"
                      "默认走 SYMLINK_TINY → SYMLINK_PTR")
                return
            self.vol.symlink(head, name, target, dir_object=obj)
            print("%s -> %s" % (link, target))
            return
        if not self.allow_object:
            print("error: 硬链接**必须**用对象形态（3-link.md）—— 要加 --object；"
                  "默认的 ①②③ 形态给不出两个名字共享一份内容")
            return
        _tp, _tn, te = self.walker.entry_pos(target)
        if te is None:
            raise EasyFSError("找不到: %s" % target)
        self.vol.link(head, name, te, dir_object=obj)
        print("%s => %s（nlink=%d）" % (link, target,
                                       self.walker.entry_pos(link)[2]["nlink"]))

    def do_readlink(self, a):
        if not a:
            raise EasyFSError("用法: readlink PATH")
        _p, _n, e = self.walker.entry_pos(a[0])
        if e is None:
            raise EasyFSError("找不到: %s" % a[0])
        sys.stdout.write(self.vol.readlink(e).decode("utf-8", "replace") + "\n")

    def do_sync(self, a):
        self.vol.commit()
        self.vol.mark_clean()
        self.vol.mark_dirty()
        print("committed（已落盘并标干净）")

    def do_optimize(self, a):
        """`optimize alloc|dir|link|all [--dry-run] [-v]`。"""
        kw = {"what": None, "dry_run": False, "verbose": False}
        for x in a:
            if x in ("--dry-run", "-n"):
                kw["dry_run"] = True
            elif x in ("--verbose", "-v"):
                kw["verbose"] = True
            elif not x.startswith("-") and kw["what"] is None:
                kw["what"] = x
        if kw["what"] not in ("alloc", "dir", "link", "all"):
            raise EasyFSError("用法: optimize alloc|dir|link|all [--dry-run] [-v]")
        if kw["what"] in ("dir", "link"):
            raise EasyFSError("ENOTSUP: optimize %s 还没实现（设计见 1-alloc.md §13.6）" % kw["what"])
        # **在本进程里做**（不要委派：那会再开一个进程写同一个卷 ✗）
        rep = self.vol.optimize_alloc(dry_run=kw["dry_run"])
        print("  optimize alloc   %s %d 个全空子区域，回收 %s"
              % ("可以合并" if rep["dry_run"] else "已合并", len(rep["merged"]),
                 human(rep["bytes_freed"])))
        for m in rep["merged"]:
            if kw["verbose"] or rep["dry_run"]:
                print("    - 子区域 @%d（%s）← 父 @%d" % (m["off"], human(m["bytes"]),
                                                         m["parent"]))
        if not rep["dry_run"] and rep["merged"]:
            self.vol.commit()
            self.sync_needed = True

    def do_hexdump(self, a):
        """`hexdump --tag <名字>` / `hexdump --block N [--len N]`。"""
        kw = {"tag": None, "block": None, "len": None}
        i2 = 0
        while i2 < len(a):
            if a[i2] in ("--tag", "-t"):
                kw["tag"] = a[i2 + 1]; i2 += 2; continue
            if a[i2] in ("--block", "-b"):
                kw["block"] = int(a[i2 + 1], 0); i2 += 2; continue
            if a[i2] in ("--len", "-n"):
                kw["len"] = a[i2 + 1]; i2 += 2; continue
            if not a[i2].startswith("-") and kw["tag"] is None:
                kw["tag"] = a[i2]          # 裸名字也算 --tag
            i2 += 1
        if not kw["tag"] and kw["block"] is None:
            raise EasyFSError("用法: hexdump --tag <名字> | --block N [--len N]")
        self._delegate(cmd_hexdump, **kw)

    def do_dump(self, a):
        """`dump <anchor tag>`：解算一个 anchor 字段，指向块就 dump 出来。"""
        if not a:
            raise EasyFSError("用法: dump <tag>，如 dump rootioff / dump alloioff")
        return dump_by_tag(self.vol, a[0], chain=("-c" in a or "--chain" in a),
                           with_hex=("-x" in a or "--hex" in a))

    def do_probe(self, a):
        self._delegate(cmd_probe)

    def do_fsck(self, a):
        self._delegate(cmd_fsck, n=("-n" in a), preen=("-p" in a), yes=("-y" in a),
                       media=("-c" in a), full=("-f" in a),
                       verbose=("-v" in a or "--verbose" in a))

    def do_quit(self, a):
        self.quit = True

    # ---------------------------------------------------------- 分发
    def run_line(self, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return
        try:
            argv = shlex.split(line)
        except ValueError as e:
            print("error: 引号不配对: %s" % e)
            return
        cmd, rest = argv[0], argv[1:]
        if cmd in UNSUPPORTED and cmd != "ln":
            print("不支持 %s：%s" % (cmd, UNSUPPORTED[cmd]))
            return
        fn = getattr(self, "do_" + cmd.replace("-", "_"), None)
        if fn is None:
            print("error: 没有这个命令: %s（help 看列表）" % cmd)
            return
        try:
            fn(rest)
        except EasyFSError as e:
            print("error: %s" % e)
        except (ValueError, IndexError) as e:
            print("error: 参数不对: %s" % e)

    def loop(self, lines, prompt=True):
        """逐行跑命令。提示符由**读取处**打印（`input(prompt)`），这里不再打，
        否则 TTY 下会双提示符、无回显环境下提示符会堆在一行上。"""
        for line in lines:
            self.run_line(line)
            if self.quit:
                break


def cmd_shell(args):
    """交互式 ctrl 命令行（无限循环；`--script FILE` 可跑脚本）。"""
    dev, desc = easyfs_device.open_device(
        args, create_size=64 << 20)
    if getattr(args, "mkfs", False):
        easyfs.mkfs(device=dev, chunk=BLOCK_4K, policy=3)
    vol = Volume.mount(dev)
    if vol.is_dirty():
        vol.rebuild_bitmap(apply=True)
        vol.mark_clean()
    vol.mark_dirty()
    print("设备: %s" % desc)
    print("卷: region_len=%d chunk=%d 策略=%s（help 看命令，quit 退出）"
          % (vol.region_len, vol.chunk, POLICY_NAME.get(vol.policy_id, "?")))
    print("形态策略：默认只产出 %s；对象形态（%s）只有 --object 才尝试（写侧 v0 未实现）"
          % ("①②③（tiny → ptr）", "DIR_OBJECT / DATA_OBJECT / SYMLINK_OBJECT"))
    sh = CtrlShell(vol, allow_object=getattr(args, "object", False), args=args,
                   backed=not isinstance(dev, easyfs_device.MemDevice))
    try:
        if args.script:
            with open(args.script, "r") as f:
                sh.loop(f.read().split("\n"), prompt=False)
        else:
            def _read():
                try:
                    line = input("easyfs:%s> " % sh._p())
                except EOFError:
                    return None
                # 只在**没有终端回显**时补换行（管道/重定向喂输入）；真终端会自己回显回车，
                # 再补就多出空行 ⇒ 空输入堆提示符的根因是"循环又打了一次提示符"，已在上面的 loop() 里去掉
                if not sys.stdin.isatty():
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                return line

            sh.loop(iter(_read, None))
    except (KeyboardInterrupt, EOFError):
        print("")
    finally:
        vol.commit()
        vol.mark_clean()
        dev.close()
    return 0


def _mig_uuid(dst_dev, start, length, uuid_bytes):
    """把两份 anchor 的 uuid 换掉（uuid 是裸值 ⇒ 改完要重算 hdrcrc）。"""
    n = 0
    for base in (start, start + length - BLOCK_4K):
        blk = bytearray(dst_dev.read_at(base, BLOCK_4K))
        if bytes(blk[0:8]) != ANCHOR_MAGIC_TAG:
            continue
        anchor_put(blk, "uuid", uuid_bytes)
        anchor_put(blk, "hdrcrc  ", anchor_crc(blk, "hdrcrc  ", 0, ANCHOR_VOL_HDR_END))
        dst_dev.write_at(base, blk)
        n += 1
    dst_dev.flush()
    return n


def cmd_migrate(args):
    """把整个卷**复制/迁移**到另一个容器的另一个位置（1-alloc.md §9）。

    卷内引用只有"自相对 delta"和逻辑坐标 `L`（基准 `data_lo_logical` 随卷一起搬），
    所以**同尺寸时是纯字节复制，一个指针都不用改**。
    `--newsize` 与源不同时：复制完再调 `easyfs.resize`（等价于"复制 + 伸缩"）。
    """
    src, src_desc = easyfs_device.open_device(args, read_only=True)
    size = src.size
    newoffs = parse_size(args.newoffs) if args.newoffs else 0
    newsize = parse_size(args.newsize) if args.newsize else size
    chunk = getattr(args, "io_chunk", None)
    io_chunk = parse_size(chunk) if isinstance(chunk, str) else (chunk or (1 << 20))
    print("源      %s  长度 %s" % (src_desc, human(size)))
    print("目标    %s @%s（%s）" % (args.newfile, human(newoffs), human(newsize)))
    if newsize != size:
        print("        （尺寸不同 ⇒ 复制后再 resize：%s → %s）"
              % (human(size), human(newsize)))
    if args.dry_run:
        print("dry-run：不写任何字节")
        return 0
    if (os.path.abspath(args.newfile) == os.path.abspath(getattr(args, "file", "") or "")
            and newoffs < (getattr(args, "offs", 0) or 0) + size
            and newoffs + size > (getattr(args, "offs", 0) or 0)):
        raise EasyFSError("EINVAL: 源与目标区间重叠且同文件；v0 不做重叠搬移"
                          "（请分两步或换目标文件）")
    with open(args.newfile, "wb") as f:                # 目标容器就位
        f.truncate(newoffs + newsize)
    dst_file = easyfs_device.FileDevice(args.newfile)
    dst = easyfs_device.RegionDevice(dst_file, newoffs, newsize)
    done = 0
    while done < size:
        n = min(io_chunk, size - done)
        dst.write_at(done, src.read_at(done, n))
        done += n
        if args.verbose:
            print("  复制 %s / %s" % (human(done), human(size)))
    dst.flush()
    if newsize != size:
        easyfs.resize(dst_file, newoffs, size, newoffs, newsize,
                      log=(say if args.verbose else None))
    if not args.keep_uuid:
        n = _mig_uuid(dst_file, newoffs, newsize, uuidlib.uuid4().bytes)
        print("  新 uuid 已写入 %d 份 anchor（--keep-uuid 可保留）" % n)
    dst.flush()
    # 目标自检：挂载 + fsck
    if not args.no_verify:
        ok = True
        try:
            v = Volume.mount(easyfs_device.RegionDevice(dst_file, newoffs, newsize))
            print("  自检：挂载 ✓  region_len=%s  uuid=%s"
                  % (human(v.region_len), uuidlib.UUID(bytes=v.vol_uuid)))
        except EasyFSError as e:
            ok = False
            print("  自检：挂载失败 ✗ %s" % e)
        ns = argparse.Namespace(**vars(args))
        ns.file, ns.vdisk, ns.mem, ns.part = args.newfile, None, None, None
        ns.offs, ns.size = "%d" % newoffs, "%d" % newsize
        ns.preen = ns.yes = ns.media = ns.full = False
        ns.n, ns.verbose = True, False
        rc = cmd_fsck(ns)
        print("  自检：fsck %s" % ("通过 ✓" if rc == 0 else "有问题（退出码 %s）" % rc))
        ok = ok and rc == 0
    dst_file.close()
    src.close()
    print("迁移完成：%s 字节" % human(size))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tool-ctrl.py",
        description="EasyFS 控制/诊断工具：mkfs / probe / device / df / fsck / inspect / resize")
    sub = ap.add_subparsers(dest="cmd")

    # `tool mbr … --seteasy` / `tool gpt … --seteasy`：看/改分区标识（见 doc/medium-parttable.md）
    for _nm, _kind, _hlp in (("mbr", "mbr", "看/改 MBR 分区的标识（我们的 = 0x7F）"),
                             ("gpt", "gpt", "看/改 GPT 分区的标识（GUID 用 16 字节 ASCII）")):
        _x = sub.add_parser(_nm, help=_hlp)
        easyfs_device.add_device_args(_x, with_create=False)
        _x.add_argument("--create", action="store_true",
                        help="建一张新分区表 + 一个占满的分区（分区类型直接写成我们的标识）")
        _x.add_argument("--seteasy", action="store_true",
                        help="把 --part 指的那个分区的标识改成我们的（**只动分区表**）")
        _x.add_argument("--yes", dest="yes", action="store_true", help="跳过确认（脚本用）")
        _x.add_argument("--force", dest="disk_force", action="store_true",
                        help="越过【已挂载】之类的保护")
        _x.set_defaults(func=cmd_partid, part_kind=_kind)

    m = sub.add_parser("mkfs", help="建立 EasyFS 卷")
    m.add_argument("--object", action="store_true",
                   help="（未实现）用对象形态的根；现在恒为链式根")
    easyfs_device.add_device_args(m)
    easyfs_device.add_disk_safety_args(m)
    m.add_argument("--chunk", default="4K", help="分配单位大小，默认 4K（v0 上限 4K）")
    m.add_argument("--policy", type=int, default=3, help="分配策略 id，默认 3 = middle-out")
    m.add_argument("--logical-origin", default="0",
                   help="数据区的逻辑坐标起点（chunk 对齐整数），默认 0")
    m.add_argument("--fixbitsize",
                   help="强制『1 bit 代表多少字节』（2 的幂、chunk 的整数倍，"
                        "如 4K/64K/1M）；不给 = 自动选型（1-alloc.md §13.3）")
    m.add_argument("--bitmap-block", help="位图块大小，如 4K/64K/1M；省略时自动选")
    m.set_defaults(func=cmd_mkfs)

    p = sub.add_parser("probe", help="打印 head/tail anchor、位图链、根目录")
    easyfs_device.add_device_args(p, with_create=False)
    p.set_defaults(func=cmd_probe)

    d = sub.add_parser("device", help="只打印容器类型与分区表")
    easyfs_device.add_device_args(d, with_create=False)
    d.set_defaults(func=cmd_device)

    # `-h` 按 GNU df 的惯例留给"人类可读"，所以关掉自动 -h 并自己加 --help
    f = sub.add_parser("df", help="打印空间用量（默认字节，-h 人类可读）",
                       add_help=False)
    easyfs_device.add_device_args(f, with_create=False)
    f.add_argument("-h", "--human", action="store_true",
                   help="人类可读（KiB/MiB/...）；默认输出原始字节数")
    f.add_argument("--help", action="help", help="显示本命令帮助并退出")
    f.set_defaults(func=cmd_df)

    c = sub.add_parser("fsck", help="只读一致性检查（v0 只实现 -n）")
    easyfs_device.add_device_args(c, with_create=False)
    c.add_argument("-n", action="store_true",
                   help="只读检查、不做任何修改（v0 唯一实现的模式，也是默认）")
    c.add_argument("-v", "--verbose", action="store_true", help="逐项细节")
    c.add_argument("-p", dest="preen", action="store_true",
                   help="（尚未实现）自动安全修复")
    c.add_argument("-y", dest="yes", action="store_true", help="（尚未实现）全部按 yes 修复")
    c.add_argument("-c", dest="media", action="store_true",
                   help="（尚未实现）媒体扫描 / 坏块")
    c.add_argument("-f", dest="full", action="store_true",
                   help="（尚未实现）强制全量检查")
    c.set_defaults(func=cmd_fsck)

    op = sub.add_parser("optimize", help="整理卷：`--家族` 看帮助 / `--家族-动作` 执行（见 --help）")
    easyfs_device.add_device_args(op, required=False)   # 帮助路径不需要载体 ✓
    easyfs_device.add_disk_safety_args(op, with_force=True)
    op.add_argument("--alloc", action="store_true", help="看 alloc 家族有哪些整理动作（只打帮助，不碰盘）")
    op.add_argument("--alloc-merge", dest="alloc_merge", action="store_true",
                    help="把\"全空的子区域\"合回粗粒度（已实现 ✓）")
    op.add_argument("--dir", action="store_true", help="看 dir 家族有哪些整理动作（只打帮助，不碰盘）")
    op.add_argument("--dir-compact", dest="dir_compact", action="store_true",
                    help="压实目录链：收掉 PADn / 尾追加撑出来的空洞（还没实现 ✗）")
    op.add_argument("--link", action="store_true", help="看 link 家族有哪些整理动作（只打帮助，不碰盘）")
    op.add_argument("--link-merge", dest="link_merge", action="store_true",
                    help="合并链接块的内容块表：相邻 DATA_PTR 并成一段（还没实现 ✗）")
    op.add_argument("--all", action="store_true", help="依次跑所有已实现的动作")
    op.add_argument("--dry-run", action="store_true", help="只报告能回收多少，不写盘")
    op.add_argument("--verbose", "-v", action="store_true", help="逐项打印")
    op.set_defaults(func=cmd_optimize)

    hx = sub.add_parser("hexdump", help="十六进制转储一个块（--tag 解算 anchor 字段）")
    easyfs_device.add_device_args(hx)
    hx.add_argument("--tag", help="anchor tag 名（如 rootioff / alloioff / uuid）")
    hx.add_argument("--block", type=lambda x: int(x, 0), help="块偏移（卷内，支持 0x…）")
    hx.add_argument("--len", help="转储字节数（默认 512，支持 4K 这种写法）")
    hx.set_defaults(func=cmd_hexdump)

    i = sub.add_parser("inspect", help="单块 / 属性流解剖（离线调试，纯读）")
    easyfs_device.add_device_args(i, with_create=False)
    i.add_argument("--block", type=lambda x: int(x, 0),
                   help="块的物理偏移（支持 0x…）")
    i.add_argument("--tag",
                   help="按 anchor tag 名解算（如 rootioff / alloioff / uuid），"
                        "并 dump 它指向的块")
    i.add_argument("--path", help="路径：定位它所在的块（含链接块、子目录链头）")
    i.add_argument("--chain", action="store_true", help="顺着 next_delta 打完整条链")
    i.add_argument("--hex", action="store_true", help="额外附十六进制转储")
    i.set_defaults(func=cmd_inspect)

    mg = sub.add_parser("migrate", help="把整个卷复制/迁移到另一个容器的另一个位置")
    easyfs_device.add_device_args(mg)
    mg.add_argument("--newfile", required=True, help="目标容器文件（会被创建/截断）")
    mg.add_argument("--newoffs", help="目标偏移（省略 = 0）")
    mg.add_argument("--newsize", help="目标长度（省略 = 与源相同 ⇒ 纯复制）")
    mg.add_argument("--keep-uuid", action="store_true", help="保留源 uuid（默认换新）")
    mg.add_argument("--no-verify", action="store_true", help="跳过目标自检（挂载 + fsck）")
    mg.add_argument("--dry-run", action="store_true", help="只打印计划，不写字节")
    mg.add_argument("-v", "--verbose", action="store_true", help="逐块打印进度")
    mg.set_defaults(func=cmd_migrate)

    sh = sub.add_parser("shell", help="交互式命令行（ls/tree/df/ln/cp/rm…）")
    easyfs_device.add_device_args(sh)
    easyfs_device.add_disk_safety_args(sh)
    sh.add_argument("--script", help="从文件读命令（非交互，便于测试）")
    sh.add_argument("--object", action="store_true",
                    help="允许对象形态写入（默认永不用；v0 只有 ln 硬链接可用）")
    sh.add_argument("--mkfs", action="store_true", help="容器不存在时先建卷")
    sh.set_defaults(func=cmd_shell)

    r = sub.add_parser("resize", help="改卷占的区域（四个方向由几何推出）")
    easyfs_device.add_device_args(r, with_create=False)
    easyfs_device.add_disk_safety_args(r)
    r.add_argument("--newoffs", help="新区域起点；省略 = 与 --offs 相同")
    r.add_argument("--newsize", help="新区域长度；省略 = 到容器末尾")
    r.add_argument("--mode", choices=easyfs.RESIZE_MODES,
                   help="显式指定方向（默认由几何推出；给了就当断言校验）")
    r.add_argument("--dry-run", action="store_true", help="只推导+检查+打印，不落盘")
    r.add_argument("--no-verify", action="store_true",
                   help="跳过收尾自检（I7 + 位图与可达集合比对）")
    r.add_argument("-v", "--verbose", action="store_true", help="打印步骤与写入序列")
    r.set_defaults(func=cmd_resize)

    args = ap.parse_args(argv)
    if not getattr(args, "cmd", None):
        ap.print_help()
        return 2
    try:
        if not getattr(args, "func", None):
            ap.print_help()
            return 2
        rc = args.func(args)
    except ERRORS as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0 if rc is None else rc


if __name__ == "__main__":
    sys.exit(main())
