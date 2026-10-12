# -*- coding: utf-8 -*-
"""（由会话内的临时脚本整理而来；路径全部按 __file__ 推导，可在任意目录运行）"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                     # 仓库根
WORK = os.environ.get("EASYFS_TEST_DIR") or os.path.join(
    ROOT, "test", ".work")                       # 落盘的测试镜像都放这儿（都很小）
os.makedirs(WORK, exist_ok=True)
sys.path.insert(0, os.path.join(ROOT, "python"))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "rt"))

"""DIR_OBJECT 读侧验证（手工把一个子目录改造成"链接块 + 内容块表"形态）。

不依赖库的写侧（写侧还没做）：用内部 API 拼出链接块，再走读路径，
检查 解析 / 块表 / 列目录 / 跨目录查找 / PathWalker / df 记账 / 反例 / 写侧拒绝。
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(ROOT, "python"))
from easyfs import (FileDevice, Volume, EasyFSError, PathWalker, mkfs,
                    parse_header, encode_attr, stamp_header, crc32,
                    BT_LINK, BT_DIR, HDR_SIZE, BLOCK_4K,
                    ATTR_DATA_PTR, ATTR_DIR_OBJECT, ATTR_NLINK, ATTR_NAME, ATTR_PAD1, ATTR_PADN)

P = os.path.join(WORK, "dirobj.img")
if os.path.exists(P):
    os.remove(P)
mkfs(path=P, size=8 << 20)

d = FileDevice(P)
v = Volume.mount(d)
root = v.root_off
sub = v.create(root, "sub", kind="dir")
v.create(sub["child"], "f1", data=b"one")
v.create(sub["child"], "f2", data=b"two-longer-content")
v.commit()

# ---------- 1) sub 目录链上的块（小块就是 1 块）----------
ent = v.lookup(root, "sub")
blocks, off = [], ent["child"]
while off:
    h = parse_header(v.read_block(off))
    blocks.append(off)
    off = (off + h["next_delta"]) if h["next_delta"] else 0
print("A1 sub 的 dir 链块数 =", len(blocks))


# ---------- 2) 造链接块：载荷 = 内容块表（DATA_PTR × n，delta 基准 = 链接块自己）----------
obj, _n = v.alloc(BLOCK_4K)
tbl = b""
for b in blocks:
    tbl += encode_attr(ATTR_DATA_PTR, struct.pack("<qI", b - obj, BLOCK_4K))
tbl += encode_attr(ATTR_NLINK, struct.pack("<I", 1))      # 目录对象：NLINK 恒 1
blk = bytearray(BLOCK_4K)
blk[HDR_SIZE:HDR_SIZE + len(tbl)] = tbl
stamp_header(blk, BT_LINK, HDR_SIZE, len(tbl), payload_crc=crc32(tbl))
v.dev.write_at(obj, blk)
v.dev.flush()

# ---------- 3) 把 sub 条目改成 DIR_OBJECT 形态 ----------
L = v.data_lo_logical + (obj - v.data_lo)                 # = phys_to_logical(obj)
# 手工把 sub 条目改写为 NAME + DIR_OBJECT{L}（剩下的字节用 PADn/PAD1 填满）
off, start, end = v._entry_extent(ent)
old_len = end - start
newdata = (encode_attr(ATTR_NAME, b"sub")
           + encode_attr(ATTR_DIR_OBJECT, struct.pack("<q", L)))


def pad(n):
    if n <= 0:
        return b""
    if n == 1:
        return encode_attr(ATTR_PAD1)
    return encode_attr(ATTR_PADN, b"\x00" * (n - 2))


newdata += pad(old_len - len(newdata))
assert len(newdata) == old_len, (len(newdata), old_len)
buf, h = v._read_dir_block(off)
buf[start:end] = newdata
v._dir_block_write(buf, off, h["payload_len"], prev=h["prev_delta"],
                   nxt=h["next_delta"], seq=h["seq"])
v.commit()
v.mark_clean()
d.close()

# ---------- 4) 重新挂载，验证读路径 ----------
d = FileDevice(P)
v = Volume.mount(d)
e = v.lookup(v.root_off, "sub")
print("A2 认成目录且有 dir_object =", e["kind"] == "dir" and e["dir_object"] == obj)
print("A3 read_dir_of 列出 =", sorted(x["name"] for x in v.read_dir_of(e)))
print("A4 跨目录 lookup 命中 =",
      v.lookup(None, "f2", e["dir_object"])["name"] == b"f2")
w = PathWalker(v)
print("A5 dir_ref('/sub') =", w.dir_ref("/sub") == (None, obj))
print("A6 entry_pos('/sub/f1') =", w.entry_pos("/sub/f1")[2]["name"] == b"f1")
print("A7 内容可读 =",
      v.read_file(v.lookup(None, "f1", e["dir_object"])) == b"one")

# 块表顺序必须生效：反序的表 → 条目顺序也应该反过来
tbl2 = b""
for b in reversed(blocks):
    tbl2 += encode_attr(ATTR_DATA_PTR, struct.pack("<qI", b - obj, BLOCK_4K))
b2 = bytearray(BLOCK_4K)
b2[HDR_SIZE:HDR_SIZE + len(tbl2)] = tbl2
stamp_header(b2, BT_LINK, HDR_SIZE, len(tbl2), payload_crc=crc32(tbl2))
v.dev.write_at(obj, b2)
v.dev.flush()
names = [x["name"] for x in v.read_dir_of(v.lookup(v.root_off, "sub"))]
print("A8 块表顺序生效 =", sorted(names) == names)

# ---------- 4b) df 记账：对象形态目录的内容块也要算"已用" ----------
import subprocess
r = subprocess.run([sys.executable, os.path.join(ROOT, "python", "tool.py"),
                    "ctrl", "df", "--file", P], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
out = r.stdout.decode("utf-8", "replace")
print("A12 df 未报泄漏 =", ("泄漏" not in out))

# ---------- 5) 反例：块表指向非 dir 块 → 必须报错 ----------
badobj, _n = v.alloc(BLOCK_4K)
tb = encode_attr(ATTR_DATA_PTR, struct.pack("<qI", 0 - badobj, BLOCK_4K))  # 指向 anchor
b3 = bytearray(BLOCK_4K)
b3[HDR_SIZE:HDR_SIZE + len(tb)] = tb
stamp_header(b3, BT_LINK, HDR_SIZE, len(tb), payload_crc=crc32(tb))
v.dev.write_at(badobj, b3)
v.dev.flush()
try:
    v.dir_object_blocks(badobj)
    print("A9 块表指向非 dir 块 → 没报错")
except EasyFSError as ex:
    print("A9 块表指向非 dir 块 → 报错", "dir" in str(ex))

# 空块表 → 报错
empty, _n = v.alloc(BLOCK_4K)
b4 = bytearray(BLOCK_4K)
stamp_header(b4, BT_LINK, HDR_SIZE, 0, payload_crc=crc32(b""))
v.dev.write_at(empty, b4)
v.dev.flush()
try:
    v.dir_object_blocks(empty)
    print("A10 空块表 → 没报错")
except EasyFSError as ex:
    print("A10 空块表 → 报错", "空" in str(ex))

# ---------- 6) 写侧必须明确拒绝 ----------
try:
    v.create(None, "x", dir_object=obj)
    print("A11 写对象目录 → 没报错")
except EasyFSError as ex:
    print("A11 写对象目录 → ENOTSUP", "ENOTSUP" in str(ex))

