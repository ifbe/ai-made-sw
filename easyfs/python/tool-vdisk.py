#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vdisk：虚拟磁盘（.vhd / .vmdk / .dmg / .img）的新建与详情

用法::

    python3 python/tool.py vdisk --file x.vhd                  # 只显示这个虚拟磁盘的详情
    python3 python/tool.py vdisk --file x.vhd --create         # 按后缀新建，然后结束
    python3 python/tool.py vdisk --file x.vmdk --create --size 64M

* 新建格式**由后缀决定**：``.vhd``（动态）/ ``.vhd`` + ``--fixed``（固定）/ ``.vmdk``（单文件稀疏）/
  ``.dmg`` / ``.img`` / ``.raw``；
* 只看详情时**什么都不改** ✓（不读卷、不碰分区表、不写文件 ✓）；
* 已存在的文件要 ``--create`` 会被拒 ⇒ 加 ``--force`` 才覆盖 ✓。
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from easyfs_config import *          # noqa: F401,F403
from easyfs import EasyFSError, human, parse_size
from easyfs_device import (EasyFSDeviceError, SECTOR, create_dmg, create_vhd, create_vmdk,
                           describe_size, dmg_info, open_container, vmdk_info)

NAME = "vdisk"


def _kind_of(path):
    """按后缀决定新建哪种格式。"""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".vhd":
        return "vhd"
    if ext == ".vmdk":
        return "vmdk"
    if ext in (".img", ".raw", ""):
        return "raw"
    if ext == ".dmg":
        return "dmg"
    raise EasyFSDeviceError(
        "不认识的虚拟磁盘后缀 %r（支持 .vhd / .vmdk / .dmg / .img / .raw）" % ext)


def cmd_create(args):
    path = args.file
    kind = _kind_of(path)
    if os.path.exists(path) and not args.force:
        raise EasyFSDeviceError("文件已存在：%s（要覆盖请加 --force）" % path)
    size = parse_size(args.size)
    if kind == "vhd":
        real = create_vhd(path, size, dynamic=not args.fixed)
        print("新建 VHD（%s）：%s" % ("固定" if args.fixed else "动态", path))
    elif kind == "vmdk":
        real = create_vmdk(path, size)
        print("新建 VMDK（monolithicSparse，单文件稀疏）：%s" % path)
    elif kind == "dmg":
        real = create_dmg(path, size)
        print("新建 DMG（UDIF 未压缩 / UDRO）：%s" % path)
    else:
        with open(path, "wb") as f:
            f.truncate(size)
        real = size
        print("新建 raw：%s" % path)
    print("  虚拟容量      %s (%d B)" % (describe_size(real), real))
    print("  文件实占      %s (%d B)" % (describe_size(os.path.getsize(path)),
                                         os.path.getsize(path)))
    return 0


def cmd_info(args):
    path = args.file
    if not os.path.exists(path):
        raise EasyFSDeviceError("文件不存在：%s" % path)
    n = os.path.getsize(path)
    with open(path, "rb") as f:                    # 先按尾巴认 DMG（它不能当卷载体）
        f.seek(max(0, n - 512))
        tail = f.read(4)
        f.seek(0)
        head = f.read(4)
    if tail == b"koly":
        i = dmg_info(path)
        print("文件          %s" % path)
        print("格式          dmg（UDIF，未压缩）")
        print("文件大小      %s (%d B)" % (describe_size(n), n))
        print("虚拟容量      %s (%d B)"
              % (describe_size(i["sector_count"] * SECTOR), i["sector_count"] * SECTOR))
        print("koly          版本 %d  标志 0x%x  变体 %d  段 %s"
              % (i["version"], i["flags"], i["image_variant"], "1/1"))
        print("数据叉        @%d 长 %s（校验和 %s）"
              % (i["data_fork_offset"], describe_size(i["data_fork_length"]),
                 "ok ✓" if i.get("data_crc") is not None else "?"))
        print("XML plist     @%d 长 %d B（主校验和 %s）"
              % (i["xml_offset"], i["xml_bytes"], "ok ✓" if i["master_crc_ok"] else "✗ 不对"))
        if i.get("mish_entry_type") is not None:
            print("BLKX 条目     类型 %d（1 = 未压缩）  数据长度 %s"
                  % (i["mish_entry_type"], describe_size(i["mish_data_length"])))
        print("注意          这是 UDIF 包，**不能当 EasyFS 的卷载体** ✓"
              "（要载体请用 .vhd / .vmdk / .img）")
        return 0
    dev, kind = open_container(path, read_only=True)
    print("文件          %s" % path)
    print("格式          %s" % kind)
    print("文件大小      %s (%d B)" % (describe_size(os.path.getsize(path)),
                                       os.path.getsize(path)))
    print("虚拟容量      %s (%d B)" % (describe_size(dev.size), dev.size))
    if kind == "vmdk":
        i = vmdk_info(path)
        used, grains = 0, 0
        for gt_i in range(dev.n_gt):
            base = dev.gd[gt_i]
            if base == 0:
                continue
            used += 1
            for gte in dev._gt_of(gt_i * dev.gtes):
                if gte:
                    grains += 1
        print("稀疏头        版本 %d  标志 0x%x  压缩 %s"
              % (i["version"], i["flags"], "是" if i["compress"] else "无"))
        print("颗粒          1 颗粒 = %s" % describe_size(dev.grain_bytes))
        print("颗粒表        每表 %d 项 × %d 表；已落盘 %d 张"
              % (dev.gtes, dev.n_gt, used))
        print("已分配颗粒    %d（数据区实占 %s）" % (grains, describe_size(grains * dev.grain_bytes)))
    elif kind == "vhd":
        print("类型          %s（disk_type=%d）"
              % ("固定" if dev.disk_type == 2 else "动态", dev.disk_type))
        if dev.disk_type == 3:
            print("块大小        %s；BAT 项 %d"
                  % (describe_size(dev.block_size), len(dev.bat)))
            nz = sum(1 for b in dev.bat if b)
            print("已分配块      %d / %d" % (nz, len(dev.bat)))
        print("页脚校验和    ✓（打开时就验过了）")
    else:
        print("（raw：没有任何头部，整文件就是数据）")
    dev.close()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tool-vdisk.py",
        description="虚拟磁盘（.vhd / .vmdk / .img / .raw）：新建与详情")
    ap.add_argument("--file", required=True, help="虚拟磁盘文件")
    ap.add_argument("--create", action="store_true", help="按后缀新建（然后结束）")
    ap.add_argument("--size", default="64M", help="新建时的虚拟容量，默认 64M")
    ap.add_argument("--fixed", action="store_true", help="--vhd：建成固定盘（默认动态）")
    ap.add_argument("--force", action="store_true", help="--create 时允许覆盖已存在的文件")
    args = ap.parse_args(argv)
    try:
        return cmd_create(args) if args.create else cmd_info(args)
    except (EasyFSError, EasyFSDeviceError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
