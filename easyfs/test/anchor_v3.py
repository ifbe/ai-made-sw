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

"""anchor v3（tag 布局）用例：结构 / 裸 uuid / hdrcrc / pool 段可选 / I9。"""
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.join(ROOT, "python"))
from easyfs import (FileDevice, Volume, EasyFSError, parse_header,
                    anchor_put, anchor_get, anchor_geti, anchor_crc, anchor_off,
                    build_anchor_block, ANCHOR_VOL_HDR_END, ANCHOR_OFF_POOL,
                    ANCHOR_MAGIC_TAG, ANCHOR_POOL_MAGIC_TAG, BLOCK_4K)

W = WORK
SRC = W + "/a.img"
if not os.path.exists(SRC):                      # 自带环境
    import subprocess as _sp
    _sp.run([sys.executable, os.path.join(ROOT, "python", "tool.py"),
             "ctrl", "mkfs", "--file", SRC, "--size", "8M"],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, check=True)


def blk0(path):
    d = FileDevice(path)
    b = d.read_at(0, BLOCK_4K)
    d.close()
    return bytearray(b)


print("A1 魔数 tag + 版本字符串 =",
      bytes(blk0(SRC)[0:8]) == ANCHOR_MAGIC_TAG and bytes(blk0(SRC)[8:16]).startswith(b"0.0.0"))
print("A2 hdrbytes = 0x200 =", anchor_geti(blk0(SRC), "hdrbytes") == ANCHOR_VOL_HDR_END)

d = FileDevice(SRC)
v = Volume.mount(d)
a, t = v.head, v.tail
print("A3 两份 hdrcrc 都 ok =", a["hdrcrc_ok"] and t["hdrcrc_ok"])
print("A4 uuid 是裸值（16 字节、无 tag）= ",
      bytes(d.read_at(0, BLOCK_4K)[anchor_off("uuid"):anchor_off("uuid") + 16]) == a["uuid"])
print("A5 当前不是池成员 =", a["pool_here"] is False and a["poolcrc_ok"] is True)
v.mark_clean()
d.close()

# A6 改一个状态字段但**忘了重算 hdrcrc** ⇒ 该份 anchor 不可用 → 回落到另一份
p = W + "/a_crc.img"
import shutil
shutil.copy(SRC, p)
b = blk0(p)
anchor_put(b, "gen     ", 999)                      # 故意不修 hdrcrc
d = FileDevice(p)
d.write_at(0, b)
d.flush()
d.close()
d = FileDevice(p)
vol = Volume.mount(d)
print("A6 hdrcrc 坏 → 回落另一份 =", vol.head is None and vol.tail is not None)
d.close()

# A7 两份 anchor 的 gen 不同（各自 hdrcrc 都合法）⇒ I9 必须拒绝
q = W + "/a_mis.img"
shutil.copy(SRC, q)
d = FileDevice(q)
v2 = Volume.mount(d)
a2 = v2.head
tb = a2["region_len"] - BLOCK_4K
tblk = build_anchor_block(a2["region_len"], -(a2["region_len"] - BLOCK_4K),
                          a2["data_lo_logical"], a2["generation"] + 1,
                          a2["chunk_shift"], a2["policy_id"], a2["policy_state"],
                          a2["root_type"], a2["root_off"] - tb,
                          a2["alloc_off"] - tb, a2["alloc_num"],
                          a2["alloc_size"], a2["state_flags"], a2["uuid"])
d.write_at(tb, tblk)
d.flush()
d.close()
d = FileDevice(q)
try:
    Volume.mount(d)
    print("A7 头尾不一致 → 没检出")
except EasyFSError as e:
    print("A7 头尾不一致 → ESTALE 拒绝", "ESTALE" in str(e))
d.close()

# A8 pool 段随便写垃圾（只要没有 easypool）⇒ hdrcrc 不受影响，卷照常挂载
r = W + "/a_pool.img"
shutil.copy(SRC, r)
d = FileDevice(r)
d.write_at(ANCHOR_OFF_POOL, b"\xAA" * 256)           # 卷头之外，随便脏
d.flush()
d.close()
d = FileDevice(r)
vol = Volume.mount(d)
print("A8 卷头外的垃圾不影响挂载 =", vol.head["hdrcrc_ok"] is True)

# A9 反过来：写上 easypool 但 poolcrc 不对 ⇒ 池层该拒绝（这里看 poolcrc_ok）
d2 = FileDevice(r)
b = bytearray(d2.read_at(0, BLOCK_4K))
b[ANCHOR_OFF_POOL:ANCHOR_OFF_POOL + 8] = ANCHOR_POOL_MAGIC_TAG
d2.write_at(0, b)
d2.flush()
d2.close()
d2 = FileDevice(r)
vol = Volume.mount(d2)
print("A9 有 easypool 但 poolcrc 不匹配 =", vol.head["pool_here"] is True
      and vol.head["poolcrc_ok"] is False)
vol.mark_clean()
d2.close()

# A10 dirty 往返后 hdrcrc 仍自洽
s2 = W + "/a_dirty.img"
shutil.copy(SRC, s2)
d = FileDevice(s2)
v3 = Volume.mount(d)
v3.mark_dirty()
d.close()
d = FileDevice(s2)
v3 = Volume.mount(d)
print("A10 dirty 往返 =", v3.is_dirty() and v3.head["hdrcrc_ok"] and v3.tail["hdrcrc_ok"])
v3.mark_clean()
d.close()
