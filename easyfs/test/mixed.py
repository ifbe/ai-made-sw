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

"""混合粒度（mkfs --mixed）用例。

⚠️ 资源纪律（宿主机内存 / 磁盘有限）：
* 真正落盘的卷一律 <= 1.5 GiB（稀疏文件，实占几十 KB ~ 几百 KB）；
* 1 TiB / 16 TiB / 2 PiB 这类大卷只用 plan_layout / find_best_alloc_setting **纯计算**
  （位图选型本来就是个公式，不需要真造一个 TB 卷来验证）。
"""
import os, subprocess, sys
sys.path.insert(0, os.path.join(ROOT, "python"))
from easyfs import FileDevice, Volume, find_best_alloc_setting, plan_layout

EASYFS = ROOT
TOOL = EASYFS + "/python/tool.py"
G = 1 << 30
ok = []


def cli(*a):
    return subprocess.run([sys.executable, TOOL, "ctrl"] + list(a),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()


def fsck(path, offs=None, size=None):
    args = ["fsck", "-n", "--file", path]
    if offs:
        args += ["--offs", offs]
    if size:
        args += ["--size", size]
    return subprocess.run([sys.executable, TOOL] + args, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode


def mkfs(path, size, fix=None):
    """默认就是混合粒度（mkfs 新默认）；`fix` 给定时走 --fixbitsize。"""
    if os.path.exists(path):
        os.remove(path)
    cmd = ["mkfs", "--file", path, "--size", size]
    if fix:
        cmd += ["--fixbitsize", fix]
    assert "uuid" in cli(*cmd), "mkfs 失败"


# ============ M1~M3c：选型是纯数学（不落盘）============
L = plan_layout(1 << 40, mixed=True)
ok.append(("M1 1 TiB bit_unit0 是 2 的幂且一块盖得住",
           L["bit_unit0"] == (1 << 26) and
           -(-L["data_bytes"] // L["bit_unit0"]) <= (4096 - 96) * 8))
ok.append(("M2 1 TiB 起步 2 块、元数据 < 16 KiB",
           L["alloc_num"] == 2 and L["alloc_size"] < 16384))
ok.append(("M3 64 MiB 自动退回平铺（1 块）",
           plan_layout(64 << 20, mixed=True)["alloc_num"] == 1))
b16 = find_best_alloc_setting(16 << 40)
ok.append(("M3b 16 TiB 仍 2 块（子块 64 KiB）",
           b16["blocks"] == 2 and b16["child_block_bytes"] == 65536))
L0 = plan_layout(1 << 40)
# 新默认 = 混合；--fixbitsize 4K 正好复现"旧的平铺布局"（513 块 / 32 MiB）
Lfix = plan_layout(1 << 40, bit_unit="4K")
ok.append(("M3c --fixbitsize 4K 复现旧平铺布局（513 块 / 32 MiB）",
           Lfix["alloc_num"] == 513 and Lfix["alloc_size"] == 33619968 and
           all(r[2] == 4096 for r in Lfix["regions"])))
ok.append(("M3d 默认（不加参数）= 混合：1 TiB 只要 2 块 / 8 KiB",
           L0["alloc_num"] == 2 and L0["alloc_size"] == 8192))
ok.append(("M3e --fixbitsize 64K：粗区域多块 + 子区域盖 33 个单位",
           (lambda b: b["blocks"] == 526 and b["child_units"] == 33)(
               find_best_alloc_setting(1 << 40, bit_unit="64K"))))

# ============ M4~M5：1 GiB 真实卷（稀疏）============
P1 = os.path.join(WORK, "mt_1g.img")
mkfs(P1, "1G")
d = FileDevice(P1); v = Volume.mount(d)
ok.append(("M4 1 GiB 挂载 + 空闲约 1 GiB",
           len(v.regions) == 2 and abs(v.free_bytes() - G) < (8 << 20)))
for i in range(5):
    v.create(v.root_off, "s%d" % i, data=b"hello%d" % i)
v.commit(); v.mark_clean(); d.close()
ok.append(("M5 写完 5 个小文件 fsck 干净", fsck(P1) == 0))

# ============ M6~M8：填满细粒度子区域 => 自动分裂 ============
P2 = os.path.join(WORK, "mt_1g2.img")
mkfs(P2, "1G")
d = FileDevice(P2); v = Volume.mount(d)
n = 0
while len(v.regions) < 3 and n < 200:
    v.create(v.root_off, "f%03d" % n, data=b"x" * 4096); n += 1
splits = len(v.regions) - 2
parents = [v.parent[i] for i in range(len(v.regions))]
v.commit(); v.mark_clean()
data = v.read(v.root_off, "f005"); d.close()
ok.append(("M6 写满后自动分裂、子区域挂粗区域下（%d 次）" % splits,
           splits >= 1 and parents.count(0) == 2))
ok.append(("M7 分裂后 fsck 干净", fsck(P2) == 0))
ok.append(("M8 分裂后数据读回正确", data == b"x" * 4096))

# ============ M10~M11：混合卷 resize（1 GiB <-> 1.5 GiB）============
P3 = os.path.join(WORK, "mt_rt.img")
if os.path.exists(P3):
    os.remove(P3)
with open(P3, "wb") as f:
    f.truncate(int(1.5 * G))
assert "uuid" in cli("mkfs", "--file", P3, "--size", "1G")
cli("resize", "--file", P3, "--size", "1G", "--newsize", str(int(1.5 * G)), "--yes")
d = FileDevice(P3); v = Volume.mount(d)
ok.append(("M10 右扩 1G->1.5G 空闲对得上（%.2fG）" % (v.free_bytes() / float(G)),
           abs(v.free_bytes() - 1.5 * G) < (8 << 20) and fsck(P3) == 0))
d.close()
cli("resize", "--file", P3, "--size", str(int(1.5 * G)), "--newsize", "1G", "--yes")
d = FileDevice(P3); v = Volume.mount(d)
ok.append(("M11 右缩 1.5G->1G 空闲对得上（%.2fG）" % (v.free_bytes() / float(G)),
           abs(v.free_bytes() - G) < (8 << 20) and fsck(P3) == 0))
before = len(v.regions)

# ============ M12：分裂风暴回归 ============
for i in range(200):
    v.create(v.root_off, "z%03d" % i, data=b"y" * 4096)
v.commit(); v.mark_clean()
after = len(v.regions); d.close()
# 分裂次数应当 ∝ "小文件总字节 ÷ 粗单位"，而不是 ∝ 文件个数（1-alloc.md §13.4）
#   200 × 4 KiB = 800 KiB；粗单位 = bit_unit0（这个卷是 64 KiB）⇒ 上界 = 13 + 余量
unit = v.regions[0].bit_unit
bound = -(-(200 * 4096) // unit) + 2
ok.append(("M12 200 个 4 KiB 文件 => 分裂 %d 次（上界 %d，与文件数无关）"
           % (after - before, bound), (after - before) <= bound and fsck(P3) == 0))


# ============ M13~M14：optimize 命令（1-alloc.md §13.6）============
P4 = os.path.join(WORK, "mt_opt.img")
mkfs(P4, "1G")
d = FileDevice(P4); v = Volume.mount(d)
for i in range(40):
    v.create(v.root_off, "o%02d" % i, data=b"x" * 4096)
v.commit(); v.mark_clean()
r_after_write = len(v.regions)
for i in range(40):
    v.delete(v.root_off, "o%02d" % i)
v.commit(); v.mark_clean()
r_after_del = len(v.regions)
dry = cli("optimize", "--alloc-merge", "--dry-run", "--file", P4)
real = cli("optimize", "--alloc-merge", "--file", P4)
d.close()
d = FileDevice(P4); v = Volume.mount(d)
r_after_opt = len(v.regions)
v.create(v.root_off, "still", data=b"y" * 4096)
v.commit(); v.mark_clean()
readable = v.read(v.root_off, "still")
d.close()
ok.append(("M13 optimize alloc：写 40 个文件 %d 区域 ⇒ 删光仍 %d ⇒ 整理后 %d"
           % (r_after_write, r_after_del, r_after_opt),
           r_after_write > 2 and r_after_del == r_after_write and
           r_after_opt == 2 and "可以合并" in dry and "已合并" in real and
           readable == b"y" * 4096 and fsck(P4) == 0))
ok.append(("M14 optimize --dir-compact / --link-merge 明确报未实现（不是静默成功）",
           "ENOTSUP" in cli("optimize", "--dir-compact", "--file", P4) and
           "ENOTSUP" in cli("optimize", "--link-merge", "--file", P4)))
ok.append(("M14b optimize --dir / --link 打家族帮助、optimize 无参数打总帮助（都不需要载体 ✓）",
           "--dir-compact" in cli("optimize", "--dir") and
           "--link-merge" in cli("optimize", "--link") and
           "用法" in cli("optimize") and
           "--alloc-merge" in cli("optimize")))
ok.append(("M15 optimize --alloc-merge 幂等（再跑一次 0 个可合并）",
           "已合并 0 个" in cli("optimize", "--alloc-merge", "--file", P4)))


# ---- M16：一个 bit 一主（分配块与目录块不共用同一个粗 bit）----
d = FileDevice(P4); v = Volume.mount(d)
p0 = v.regions[0]
mixed = len(v.regions) > 1 and p0.bit_unit > v.chunk
if mixed:
    owners = {}
    for b in range(p0.nbits):
        if not p0.bit(b):
            continue
        lo, hi = p0.region_off + b * p0.bit_unit, p0.region_off + (b + 1) * p0.bit_unit
        kinds = set()
        if any(lo <= r.block_off < hi for r in v.regions):
            kinds.add("alloc")
        if lo <= v.root_off < hi:
            kinds.add("dir")
        owners[b] = kinds
    shared = [b for b, k in owners.items() if len(k) > 1]
    ok.append(("M16 一个 bit 一主：分配块与根目录块不共用粗 bit（共 %d 个已用 bit）"
               % len(owners), not shared and len(owners) >= 2))
d.close()

# ---- M17：运行时分裂出来的子区域，重挂载也要过"一个 bit 一主" ----
P5 = os.path.join(WORK, "mt_split.img")
mkfs(P5, "1G")
d = FileDevice(P5); v = Volume.mount(d)
n = 0
while len(v.regions) < 3 and n < 200:              # 逼出至少 1 次运行时分裂
    v.create(v.root_off, "s%03d" % n, data=b"x" * 4096); n += 1
v.commit(); v.mark_clean(); d.close()
d = FileDevice(P5)
try:
    v = Volume.mount(d)                            # ← 挂载时 check_regions 会校验整格
    ok17 = v.head["hdrcrc_ok"]
    kids = [i for i in range(len(v.regions)) if v.parent[i] is not None]
    ok17 = ok17 and len(kids) >= 2
    d.close()
except Exception as e:
    ok17 = False
    print("      （重挂载失败：%s）" % str(e)[:80])
ok.append(("M17 运行时分裂的子区域重挂载通过（整格占单位）", ok17 and fsck(P5) == 0))

for name, good in ok:
    print("  %-58s %s" % (name, "True" if good else "False"))
print("  ALL = %s  （%d 项）" % (all(g for _n, g in ok), len(ok)))
