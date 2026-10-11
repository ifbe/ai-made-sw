# -*- coding: utf-8 -*-
"""（由会话内的临时脚本整理而来；路径全部按 __file__ 推导，可在任意目录运行）"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))    # 仓库根（本文件在 test/rt/ 下，要上两级）
WORK = os.environ.get("EASYFS_TEST_DIR") or os.path.join(
    ROOT, "test", ".work")                       # 落盘的测试镜像都放这儿（都很小）
os.makedirs(WORK, exist_ok=True)
sys.path.insert(0, os.path.join(ROOT, "python"))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "rt"))

"""resize 验收脚手架：造 fixture → 跑 resize → 断言 A1..A8。"""
import hashlib, os, shutil, sys
sys.path.insert(0, os.path.join(ROOT, "python"))
import easyfs
from easyfs import FileDevice, RegionDevice, Volume, human

CH = 4096
CONT = 96 << 20
OFFS = 16 << 20
SIZE = 64 << 20

FILES = {
    "tiny.txt":     b"hello tiny\n",
    "onechunk.bin": bytes(bytearray(i % 251 for i in range(4096))),
    "mid.bin":      bytes(bytearray(i % 251 for i in range(300000))),
    "big.bin":      bytes(bytearray(i % 251 for i in range(3 << 20))),
    "mixed.bin":    b"x" * 12 + bytes(bytearray(i % 251 for i in range(50000))),
}

def make(path, with_files=True, empty_middle=False):
    """容器 96 MiB，卷在 [16M, 80M)。empty_middle=True 时把中间的文件全删掉，
    只留下位图块在中间（用来测"挪位图块"）。"""
    if os.path.exists(path):
        os.remove(path)
    with open(path, "wb") as f:
        f.truncate(CONT)
    base = FileDevice(path)
    easyfs.mkfs(device=RegionDevice(base, OFFS, SIZE, name="vol"))
    vol = Volume.mount(RegionDevice(base, OFFS, SIZE, name="vol"))
    vol.mark_dirty()
    if with_files:
        for name, data in FILES.items():
            vol.create(vol.root_off, name, data=data)
        for i in range(6):
            vol.create(vol.root_off, "junk%d" % i, data=b"j" * 4096)
        for i in range(0, 6, 2):
            vol.delete(vol.root_off, "junk%d" % i)
    if empty_middle:
        for name in list(FILES):
            vol.delete(vol.root_off, name)
        for i in range(6):
            try:
                vol.delete(vol.root_off, "junk%d" % i)
            except easyfs.EasyFSError:
                pass
    vol.mark_clean()
    vol.commit()
    base.close()

def snapshot(path, start, length):
    base = FileDevice(path, read_only=True)
    vol = Volume.mount(RegionDevice(base, start, length, name="vol"), strict=False)
    root = vol.root_off
    out = {}
    for ent in vol.read_dir(root):
        if ent["kind"] != "file":
            continue
        name = ent["name"].decode()
        _tiny, runs = vol.entry_content(ent)
        out[name] = {"sha": hashlib.sha256(vol.read_file(ent)).hexdigest(),
                     "size": ent["size"],
                     # 记**绝对地址**：左操作会让区域相对地址平移 N，但数据没动
                     "runs": [(start + p, sz) for p, sz in runs],
                     "Ls": [vol.phys_to_logical(p) for p, sz in runs]}
    out["__free"] = vol.free_bytes()
    out["__regions"] = [(r.region_off, r.region_bytes, r.block_off) for r in vol.regions]
    out["__dlo_logical"] = vol.data_lo_logical
    out["__len"] = vol.region_len
    out["__head"] = dict(vol.head)
    base.close()
    return out

def expect_free_delta(N, expand, cap, chunk=CH):
    """扩容：+N 再减去新增位图块占的空间；缩容：-N（不新增块）。"""
    if not expand:
        return -N
    import math
    return N - chunk * ((N + cap - 1) // cap)


def check(tag, before, after, expect_free_delta, slack=0):
    """`slack`：允许空闲增量与期望差这么多个 chunk（增减/摘除位图块会占/还 chunk）。"""
    bad = []
    a = {k: v for k, v in before.items() if not k.startswith("__")}
    b = {k: v for k, v in after.items() if not k.startswith("__")}
    if set(a) != set(b):
        bad.append("A1 文件集合变了: %s -> %s" % (sorted(a), sorted(b)))
    for n in sorted(set(a) & set(b)):
        if a[n]["sha"] != b[n]["sha"]:
            bad.append("A1 %s 内容变了" % n)
        if a[n]["runs"] != b[n]["runs"]:
            bad.append("A1 %s 物理段表变了: %s -> %s" % (n, a[n]["runs"], b[n]["runs"]))
        if a[n]["Ls"] != b[n]["Ls"]:
            bad.append("A2 %s 的 L 变了: %s -> %s" % (n, a[n]["Ls"], b[n]["Ls"]))
        if a[n]["size"] != b[n]["size"]:
            bad.append("A1 %s 大小变了" % n)
    d = after["__free"] - before["__free"]
    if abs(d - expect_free_delta) > slack * CH:
        bad.append("A4 空闲变化 %+d，期望 %+d（容差 %d chunk）"
                   % (d, expect_free_delta, slack))
    print("  [%-11s] %s  空闲 %s → %s (%+d)  区域块 %d→%d  L 原点 %d→%d"
          % (tag, "OK" if not bad else "FAIL", human(before["__free"]),
             human(after["__free"]), d, len(before["__regions"]),
             len(after["__regions"]), before["__dlo_logical"],
             after["__dlo_logical"]))
    for x in bad:
        print("      ✗ " + x)
    return not bad

def run(path, old_start, old_len, new_start, new_len, mode=None, **kw):
    base = FileDevice(path)
    rep = easyfs.resize(base, old_start, old_len, new_start, new_len, mode=mode, **kw)
    base.close()
    return rep

def remount(path, start, length):
    """A3/A5/A6/A8。"""
    base = FileDevice(path, read_only=True)
    vol = Volume.mount(RegionDevice(base, start, length, name="vol2"))
    bad = []
    why = vol.check_regions()
    if why:
        bad.append("A5 I7: %s" % why)
    b, a = vol.rebuild_bitmap(apply=False)
    if b != a:
        bad.append("A3 位图 %d vs 可达 %d" % (b, a))
    for k in ("region_len", "data_lo_logical", "uuid", "generation", "chunk_shift"):
        if vol.head[k] != vol.tail[k]:
            bad.append("A6 head/tail %s 不一致" % k)
    free = vol.free_bytes()
    base.close()
    print("      A3/A5/A6/A8 重新挂载: %s%s"
          % ("OK" if not bad else "FAIL", "" if not bad else " " + "; ".join(bad)))
    return (not bad), free
