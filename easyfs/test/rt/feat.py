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

"""新格式能力测试：跨块条目 / 硬链接块 / 软链接 / PAD 跳过（手工构造）。"""
import os, struct, sys
sys.path.insert(0, os.path.join(ROOT, "python"))
import easyfs
from easyfs import (FileDevice, RegionDevice, Volume, BLOCK_4K, HDR_SIZE,
                    ATTR_NAME, ATTR_DATA_TINY, ATTR_DATA_PTR, ATTR_TMODIFY,
                    ATTR_PADN, ATTR_PAD1, ATTR_NLINK, ATTR_DATA_OBJECT,
                    ATTR_SYMLINK_TINY, ATTR_SYMLINK_PTR, encode_attr,
                    parse_header, human)

P = os.path.join(WORK, "feat.img")
if os.path.exists(P): os.remove(P)
easyfs.mkfs(P, size=16 << 20)
dev = FileDevice(P)
vol = Volume.mount(dev); vol.mark_dirty()
root = vol.root_off
ok = True
def chk(tag, cond, extra=""):
    global ok
    print("  %-46s %s %s" % (tag, "OK ✓" if cond else "FAIL ✗", extra))
    ok = ok and cond

# ---------- 1) 软链接：SYMLINK_TINY
vol.create(root, "real.txt", data=b"hello real\n")
ent = vol.lookup(root, "real.txt")
phys, _ = vol.alloc(1024)                       # 给软链接长目标用一块
vol.save_bitmap()
path = b"/dir/sub/real.txt"
payload = encode_attr(ATTR_NAME, b"short.lnk") + encode_attr(ATTR_SYMLINK_TINY, path) \
          + encode_attr(ATTR_TMODIFY, struct.pack("<I", 1234))
vol._dir_block_write  # noqa
e = vol._dir_new_entry if False else None
# 用 _dir_insert 插入（build 回调拿 base）
info = vol._dir_insert(root, lambda base: payload)
vol.commit()
ent = vol.lookup(root, "short.lnk")
chk("软链接(短)：解析出内容=目标路径", vol.read(root, "short.lnk") == path,
    "content=%r" % vol.read(root, "short.lnk"))
chk("软链接(短)：symlink 标记 + size=路径长度",
    ent["symlink"] and ent["size"] == len(path), "size=%d" % ent["size"])
chk("软链接(短)：mtime 解析", ent["mtime"] == 1234)

# ---------- 2) 软链接：SYMLINK_PTR（长目标放数据块）
long_path = b"/" + b"x" * 400
vol.dev.write_at(phys, long_path)
payload = encode_attr(ATTR_NAME, b"long.lnk") + \
          encode_attr(ATTR_SYMLINK_PTR, struct.pack("<qI", phys, len(long_path)))
# 注意：delta 基准是条目最终落地的块 → 用 _dir_insert 的两步式
vol._dir_insert(root, lambda base: encode_attr(ATTR_NAME, b"long.lnk") +
                encode_attr(ATTR_SYMLINK_PTR,
                            struct.pack("<qI", phys - base, len(long_path))))
vol.commit()
chk("软链接(长)：内容=数据块里的路径",
    vol.read(root, "long.lnk") == long_path, "len=%d" % len(vol.read(root, "long.lnk")))

# ---------- 3) PAD / PAD1 必须被跳过，不影响解析
vol.create(root, "padded.txt", data=b"P" * 100)
payload = (encode_attr(ATTR_NAME, b"padded2.txt") +
           encode_attr(ATTR_PADN, b"\x00" * 10) +          # TLV 占位
           bytes((ATTR_PAD1,)) +                          # 1 字节占位
           encode_attr(ATTR_DATA_TINY, b"P" * 100) +
           bytes((ATTR_PAD1,)))
vol._dir_insert(root, lambda base: payload)
vol.commit()
chk("PAD/PAD1 被跳过：内容与大小正确",
    vol.read(root, "padded2.txt") == b"P" * 100 and
    vol.lookup(root, "padded2.txt")["size"] == 100)

# ---------- 4) 硬链接块：NAME + LINK_PTR → 链接块(NLINK+TMODIFY+DATA_PTR)
target = b"H" * 50000
vol.create(root, "orig.bin", data=target)
oe = vol.lookup(root, "orig.bin")
_t, runs = vol.entry_content(oe)
lo, ln = vol.alloc(BLOCK_4K)                    # 链接块自己的存储
vol.save_bitmap()
lp = encode_attr(ATTR_NLINK, struct.pack("<I", 2)) + \
     encode_attr(ATTR_TMODIFY, struct.pack("<I", 777)) + \
     encode_attr(ATTR_DATA_PTR, struct.pack("<qI", runs[0][0] - lo, runs[0][1]))
blk = bytearray(BLOCK_4K); blk[HDR_SIZE:HDR_SIZE + len(lp)] = lp
easyfs.stamp_header(blk, easyfs.BT_LINK, HDR_SIZE, len(lp), seq=0,
                    prev_delta=0, next_delta=0,
                    payload_crc=easyfs.crc32(lp))
dev.write_at(lo, blk)
L = vol.phys_to_logical(lo)
vol._dir_insert(root, lambda base: encode_attr(ATTR_NAME, b"linked.bin") +
                encode_attr(ATTR_DATA_OBJECT, struct.pack("<q", L)))
vol._dir_insert(root, lambda base: encode_attr(ATTR_NAME, b"linked2.bin") +
                encode_attr(ATTR_DATA_OBJECT, struct.pack("<q", L)))
vol.commit()
ent = vol.lookup(root, "linked.bin")
chk("硬链接：通过链接块读到同样内容", vol.read(root, "linked.bin") == target,
    "len=%d" % len(vol.read(root, "linked.bin")))
chk("硬链接：nlink / mtime 来自链接块", ent["nlink"] == 2 and ent["mtime"] == 777,
    "nlink=%d mtime=%d" % (ent["nlink"], ent["mtime"]))
chk("硬链接：link_blocks 记录到位", ent["link_blocks"] == [lo])

# ---------- 5) 位图一致性：链接块与软链接数据块都必须算"可达"
b, a = vol.rebuild_bitmap(apply=False)
chk("位图 == 可达集合（含链接块/软链接块）", b == a, "%d vs %d" % (b, a))

# ---------- 6) 跨块条目：改用**独立卷**（不要覆盖已经装了条目的 root 块）
vol.mark_clean(); vol.commit()
P2 = os.path.join(WORK, "feat2.img")
if os.path.exists(P2): os.remove(P2)
easyfs.mkfs(P2, size=16 << 20)
dev = FileDevice(P2); vol = Volume.mount(dev); vol.mark_dirty()
root = vol.root_off
nxt = vol._dir_block_new(root)
# 块 1（root）载荷 = A 的 NAME；块 2 载荷 = A 的 DATA_PTR + B 的 NAME + TINY
big = bytes(bytearray(i % 251 for i in range(60000)))
phys2, _ = vol.alloc(len(big)); vol.dev.write_at(phys2, big); vol.save_bitmap()
p1 = encode_attr(ATTR_NAME, b"span.bin")
p2 = (encode_attr(ATTR_DATA_PTR, struct.pack("<qI", phys2 - nxt, len(big))) +
      encode_attr(ATTR_NAME, b"after.txt") + encode_attr(ATTR_DATA_TINY, b"tail!"))
blk = bytearray(BLOCK_4K)
blk[HDR_SIZE:HDR_SIZE + len(p1)] = p1
vol._dir_block_write(blk, root, len(p1), prev=0, nxt=nxt - root)
blk2 = bytearray(BLOCK_4K)
blk2[HDR_SIZE:HDR_SIZE + len(p2)] = p2
vol._dir_block_write(blk2, nxt, len(p2), prev=root - nxt)
vol.commit()
e_span = vol.lookup(root, "span.bin")
chk("跨块条目：能读回（属性在下一块）",
    e_span is not None and vol.read(root, "span.bin") == big and e_span["spans"],
    "spans=%s size=%d" % (e_span["spans"] if e_span else None,
                          e_span["size"] if e_span else -1))
chk("跨块条目：它后面的条目仍正常",
    vol.read(root, "after.txt") == b"tail!")
try:
    vol.delete(root, "span.bin"); chk("跨块条目的删除被明确拒绝", False)
except easyfs.EasyFSError as ex:
    chk("跨块条目的删除被明确拒绝（写侧 v0）", "ENOTSUP" in str(ex), str(ex)[:48])
b, a = vol.rebuild_bitmap(apply=False)
chk("跨块条目下位图仍一致", b == a, "%d vs %d" % (b, a))
vol.mark_clean(); vol.commit()
dev.close()

# 重新挂载再验一遍（脱离内存状态）
dev2 = FileDevice(P); v2 = Volume.mount(dev2)
chk("重挂载(卷1)：硬链接 + 软链接都还在",
    v2.read(v2.root_off, "linked.bin") == target and
    v2.read(v2.root_off, "short.lnk") == path and
    v2.read(v2.root_off, "long.lnk") == long_path and
    v2.read(v2.root_off, "padded2.txt") == b"P" * 100)
dev2.close()
dev3 = FileDevice(P2); v3 = Volume.mount(dev3)
chk("重挂载(卷2)：跨块条目还在", v3.read(v3.root_off, "span.bin") == big and
    v3.read(v3.root_off, "after.txt") == b"tail!")
dev3.close()
print("\n%s" % ("全部通过 ✓" if ok else "有失败 ✗"))
