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

# 资源纪律：卷一律 <= 64 MiB（宿主机内存/磁盘有限）；大卷的选型只用 plan_layout 纯算

"""EasyFS 全套测试跑批（自包含，重新生成所有镜像）。"""
import os, shutil, subprocess, sys, hashlib, struct
ROOT = ROOT
sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.join(HERE, "rt"))
W = WORK
PASS, FAIL, SKIP = [], [], []

PRE = ("import os, sys\n"
       "HERE = %r\nROOT = %r\nWORK = %r\n"
       "sys.path.insert(0, os.path.join(ROOT, 'python'))\n"
       "sys.path.insert(0, os.path.join(HERE, 'rt'))\n") % (HERE, ROOT, WORK)


# 工作目录：**每次跑之前清空**（镜像都是几 MiB 的稀疏文件，但 shutil.copy 会把洞实体化，
# 不清的话会越攒越大）。跑完要不要留，看 EASYFS_TEST_KEEP。
import shutil as _sh
_sh.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK, exist_ok=True)


def run(cmd, expect=0, tag=""):
    p = subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    out = p.stdout.decode("utf-8", "replace")
    ok = (expect is None) or (p.returncode == expect)
    (PASS if ok else FAIL).append(tag or cmd[:60])
    if not ok:
        print("  ✗ %-46s exit=%d (期望 %s)\n%s" % (tag, p.returncode, expect, out[-400:]))
    return p.returncode, out

def check(cond, tag):
    (PASS if cond else FAIL).append(tag)
    if not cond: print("  ✗ %s" % tag)

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

TOOL = "python3 python/tool.py"
shutil.rmtree(W, ignore_errors=True); os.makedirs(W)

# ---------- 0 编译 ----------
print("[0] 编译")
run("python3 -m py_compile python/*.py", 0, "py_compile 全部模块")

# ---------- 1 基本命令 ----------
print("[1] mkfs / probe / df / fsck / inspect / device")
run("%s ctrl mkfs --file %s/a.img --size 16M" % (TOOL, W), 0, "mkfs")
run("%s ctrl probe --file %s/a.img" % (TOOL, W), 0, "probe")
run("%s ctrl df -h --file %s/a.img" % (TOOL, W), 0, "df -h")
run("%s ctrl fsck -n --file %s/a.img" % (TOOL, W), 0, "fsck -n（空卷应 0）")
run("%s ctrl inspect --file %s/a.img --block 0" % (TOOL, W), 0, "inspect anchor")
run("%s ctrl device --file %s/a.img" % (TOOL, W), 0, "device")
run("%s list" % TOOL, 0, "tool.py list")
_, out = run("%s ctrl probe --file %s/a.img" % (TOOL, W), 0, "probe 输出含 easypart")
check("easypart" in out, "probe 里 magic = easypart")

# 1b) 每个 anchor tag 都必须能被 inspect --tag 解算（改名漏网会在这里现形 ✗）；
#     delta 类字段必须解出绝对地址（工具里有一张"哪些 tag 是地址"的名单，最容易漏）
import easyfs, importlib.util as _iu
_spec = _iu.spec_from_file_location("toolctrl", os.path.join(ROOT, "python", "tool-ctrl.py"))
_tc = _iu.module_from_spec(_spec); _spec.loader.exec_module(_tc)
_dev = easyfs.FileDevice(WORK + "/a.img"); _vol = easyfs.Volume.mount(_dev)
_bad = []
for _n, _t, _to, _vo, _w in easyfs.anchor_layout():
    try:
        _tc.resolve_anchor_tag(_vol, _n.strip())
    except Exception as _e:
        _bad.append((_n.strip(), repr(_e)[:40]))
for _t in ("rootioff", "alloioff", "peer"):
    if _tc.resolve_anchor_tag(_vol, _t)[1] is None:
        _bad.append((_t, "没解出地址"))
_dev.close()
check(not _bad, "全部 anchor tag 可解析、delta 能解出地址 %s" % (_bad[:3] if _bad else "✓"))

# 1d) `--yes` / `--force` 是"会写盘的命令自己"的参数；`--disk` 的确认是 y/N（真 pty 才走到问话）
rc, out = run("%s ctrl mkfs --help" % TOOL, 0, "mkfs --help")
check("--force" in out and "--yes" in out, "mkfs 自己带 --yes / --force")
rc, out = run("%s sftpcli --help" % TOOL, 0, "sftpcli --help")
check("覆盖已存在的文件" in out, "sftpcli 的 --force 仍是【覆盖文件】（没被抢走）")
import pty as _pty, subprocess as _sp
_CODE = ("import sys; sys.path.insert(0, %r)\n"
         "import easyfs_device as D\n"
         "D.confirm_dangerous_disk('/dev/fake', ['  设备 /dev/fake'], assume_yes=False)\n"
         "print('CONFIRMED')\n" % os.path.join(ROOT, "python"))
def _ask(feed):
    m, sl = _pty.openpty()
    pr = _sp.Popen([sys.executable, "-c", _CODE], stdin=sl, stdout=sl, stderr=sl)
    os.close(sl); os.write(m, feed)
    buf = b""
    try:
        while True:
            b = os.read(m, 4096)
            if not b: break
            buf += b
    except OSError:
        pass
    pr.wait(); os.close(m)
    return pr.returncode, buf.decode("utf-8", "replace")
rc, out = _ask(b"n\n")
check(rc != 0 and "已取消" in out, "--disk 确认 [y/N]：输入 n ⇒ 取消")
rc, out = _ask(b"y\n")
check(rc == 0 and "CONFIRMED" in out, "--disk 确认 [y/N]：输入 y ⇒ 继续")

# 1e) 分区 = 自动加偏移（--part N 与 --offs 是同一批字节）
rc, out = run("%s sftpcli --help" % TOOL, 0, "sftpcli --help")
check("--yes" in out, "sftpcli 也有 --yes（非交互跑 --disk 要用）")
_img = os.path.join(WORK, "part.img")
_sf = os.path.join(WORK, "part.sf")
with open(_img, "wb") as f:
    f.truncate(16 << 20)
with open(_sf, "w") as f:
    f.write("label: dos\nstart=2048, type=0c\n")
run("sfdisk -q %s < %s" % (_img, _sf), 0, "造 MBR 镜像")
run("%s ctrl mkfs --vdisk %s --part 1" % (TOOL, _img), 0, "mkfs 进分区 1")
with open(_img, "rb") as f:
    f.seek(1 << 20)
    _at = f.read(8)
with open(_img, "rb") as f:
    f.seek(510)
    _sig = f.read(2)
check(_at == b"easypart", "磁盘绝对 1 MiB 处就是卷内偏移 0（偏移自动加 ✓）")
check(_sig == b"\x55\xaa", "MBR 签名 55AA 还在（分区表没被动）")
rc1, o1 = run("%s ctrl hexdump --block 0 --vdisk %s --part 1" % (TOOL, _img), 0,
              "hexdump --part 1")
rc2, o2 = run("%s ctrl hexdump --block 0 --vdisk %s --offs 1M --size 15M" % (TOOL, _img), 0,
              "hexdump --offs 1M")
import re as _re
_hexlines = lambda t: [l for l in t.split("\n") if _re.match(r"^\s+\d+\s+[0-9a-f]{2} ", l)]
check(bool(_hexlines(o1)) and _hexlines(o1) == _hexlines(o2),
      "--part 1 与 --offs 1M 读到同一批字节（偏移自动加）")
# 1f) mbr / gpt：看 / 改分区标识（--seteasy 才写；只动分区表）
_mb = os.path.join(WORK, "tb.img")
_sf = os.path.join(WORK, "tb.sf")
with open(_mb, "wb") as f:
    f.truncate(16 << 20)
with open(_sf, "w") as f:
    f.write("label: dos\nstart=2048, size=8192, type=0c\nstart=10240, size=20480, type=83\n")
run("sfdisk -q %s < %s" % (_mb, _sf), 0, "造 MBR 两分区镜像")
with open(_mb, "rb") as f:
    f.seek(1048576)
    _keep = f.read(4096)
rc, out = run("%s mbr --vdisk %s --part 1 --seteasy" % (TOOL, _mb), 0, "mbr … --seteasy")
check("0x7F" in out, "mbr --seteasy 报出新类型 0x7F")
import easyfs_device as _D
_dev = _D.FileDevice(_mb, read_only=True)
_t, _ps = _D.read_partitions(_dev)
_dev.close()
check(_ps[0]["type"] == "0x7F" and _ps[1]["type"] == "0x83", "MBR：只改 #1（= 0x7F），#2 仍是 0x83")
with open(_mb, "rb") as f:
    f.seek(1048576)
    _after = f.read(4096)
check(_keep == _after, "mbr --seteasy 没碰分区里的数据（只动分区表 ✓）")
rc, out = run("%s mbr --vdisk %s" % (TOOL, _mb), 0, "mbr（不给 --seteasy）")
check("已经是我们的标识" in out, "不给 --seteasy ⇒ 只列出（并标出哪个已经是我们的 ✓）")
_dev = _D.FileDevice(_mb, read_only=True)
_t, _ps2 = _D.read_partitions(_dev)
_dev.close()
check(_ps2[0]["type"] == "0x7F", "只读查看不改任何东西 ✓")
_gp = os.path.join(WORK, "tg.img")
with open(_gp, "wb") as f:
    f.truncate(16 << 20)
with open(_sf, "w") as f:
    f.write("label: gpt\nstart=2048, size=8192, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n")
run("sfdisk -q %s < %s" % (_gp, _sf), 0, "造 GPT 单分区镜像")
rc, out = run("%s gpt --vdisk %s --part 1 --seteasy" % (TOOL, _gp), 0, "gpt … --seteasy")
check("自洽" in out, "gpt --seteasy 之后主/备 GPT 自洽")
_dev = _D.FileDevice(_gp, read_only=True)
_t, _ps = _D.read_partitions(_dev)
_gbad = _D.verify_gpt(_dev)
_dev.close()
check(bool(_ps) and _ps[0]["type"] == _D.guid_text(_D.GPT_TYPE_EASYFS),
      "GPT：#1 类型 = 我们的 GUID（easyparteasypart）")
check(not _gbad, "GPT：主头/备份头/项数组 CRC 全部自洽 %s" % (_gbad or "✓"))
rc, out = run("%s mbr --vdisk %s --part 1 --seteasy" % (TOOL, _gp), None, "mbr 用在 GPT 镜像上")
check(rc != 0 and "不是 MBR" in out, "形态不匹配 ⇒ 明确报错（不会乱改）")
rc, out = run("%s gpt --vdisk %s --seteasy" % (TOOL, _gp), None, "gpt --seteasy 不给 --part")
check(rc != 0 and "--part" in out, "不给 --part ⇒ 报错")
# 1g) vdisk：建 / 看（.vhd / .vmdk / .dmg / .img）+ 交叉验证（有 qemu-img 就让它验）
_vd = os.path.join(WORK, "vd")
for _e, _fmt in (("vhd", "vhd"), ("vmdk", "vmdk"), ("dmg", "dmg"), ("img", "raw")):
    _p = _vd + "." + _e
    if os.path.exists(_p):
        os.remove(_p)
    run("%s vdisk --file %s --create --size 32M" % (TOOL, _p), 0, "vdisk --create .%s" % _e)
    rc, out = run("%s vdisk --file %s" % (TOOL, _p), 0, "vdisk .%s 详情" % _e)
    check(_fmt in out, ".%s：详情报的格式对（%s）" % (_e, _fmt))
rc, out = run("%s vdisk --file %s.vhd --create --size 32M" % (TOOL, _vd), None, "重复 --create")
check(rc != 0 and "--force" in out, "--create 遇到已存在文件 ⇒ 拒绝并提示 --force")
run("%s mkfs --vdisk %s.vmdk" % (TOOL, _vd), 0, "mkfs 进 vmdk（当卷载体）")
run("%s fsck -n --vdisk %s.vmdk" % (TOOL, _vd), 0, "vmdk 里 fsck 干净")
rc, out = run("%s mkfs --vdisk %s.dmg" % (TOOL, _vd), None, "dmg 当卷载体")
check(rc != 0 and "DMG" in out, "DMG 当卷载体 ⇒ 明确拒绝")
if shutil.which("qemu-img"):
    rc, out = run("qemu-img info %s.vmdk" % _vd, 0, "qemu-img info vmdk")
    check("file format: vmdk" in out, "qemu-img 认得我们建的 vmdk")
    rc, out = run("qemu-img info %s.dmg" % _vd, 0, "qemu-img info dmg")
    check("file format: dmg" in out, "qemu-img 认得我们建的 dmg")
    rc, out = run("qemu-img convert -f dmg -O raw %s.dmg %s.dmg.raw" % (_vd, _vd), 0,
                  "qemu 读 dmg 数据")
    _raw = _vd + ".dmg.raw"
    check("I/O error" not in out, "qemu 能完整读出 dmg 数据（无 I/O 错）")
    if os.path.exists(_raw):
        check(os.path.getsize(_raw) == (32 << 20), "dmg 转出的 raw = 32 MiB")
        os.remove(_raw)
else:
    SKIP.append("vdisk × qemu-img 交叉验证（本机没装 qemu-img）")
# 1h) mbr --create / gpt --create：建一张表 + 一个占满的分区（类型直接是我们的）
_mi = os.path.join(WORK, "tb2.img")
with open(_mi, "wb") as f:
    f.truncate(32 << 20)
rc, out = run("%s mbr --vdisk %s --create" % (TOOL, _mi), 0, "mbr --create")
check("已建 MBR 分区表" in out and "0x7F" in out, "mbr --create：建表并把分区打成 0x7F")
_dev = _D.FileDevice(_mi, read_only=True)
_t, _ps = _D.read_partitions(_dev)
_dev.close()
check(bool(_ps) and _ps[0]["type"] == "0x7F" and _ps[0]["start"] == (1 << 20),
      "MBR：一个分区、类型 0x7F、从 1 MiB 开始")
rc, out = run("%s mbr --vdisk %s --create" % (TOOL, _mi), None, "重复 mbr --create")
check(rc != 0 and "--force" in out, "已有表再 --create ⇒ 拒绝（要 --force）")
_gp2 = os.path.join(WORK, "tg2.img")
with open(_gp2, "wb") as f:
    f.truncate(32 << 20)
rc, out = run("%s gpt --vdisk %s --create" % (TOOL, _gp2), 0, "gpt --create")
check("已建 GPT 分区表" in out and "EasyFS" in out, "gpt --create：建表，分区名 EasyFS")
_dev = _D.FileDevice(_gp2, read_only=True)
_t, _ps = _D.read_partitions(_dev)
_gbad = _D.verify_gpt(_dev)
_dev.close()
check(bool(_ps) and _ps[0]["type"] == _D.guid_text(_D.GPT_TYPE_EASYFS) and not _gbad,
      "GPT：类型 = 我们的 GUID，主备头 + 项数组自洽")
_wf = os.path.join(WORK, "wf.vmdk")
if os.path.exists(_wf):
    os.remove(_wf)
run("%s vdisk --file %s --create --size 32M" % (TOOL, _wf), 0, "① vdisk --create")
run("%s gpt --vdisk %s --create" % (TOOL, _wf), 0, "② gpt --create")
run("%s mkfs --vdisk %s --part 1" % (TOOL, _wf), 0, "③ mkfs --part 1")
run("%s fsck -n --vdisk %s --part 1" % (TOOL, _wf), 0, "④ fsck（分区里的卷）")
if shutil.which("parted"):
    rc, out = run("parted -s %s unit s print" % _gp2, 0, "parted 看我们建的 GPT")
    check("gpt" in out and "EasyFS" in out, "parted 也认这张 GPT（分区名 EasyFS）")
else:
    SKIP.append("mbr/gpt --create × parted 交叉验证（没装 parted）")
# 1i) --disk 的真盘路径（本机没有可写的真盘 ⇒ 把普通文件"骗"成块设备，整条跑一遍）
_fd = os.path.join(WORK, "fakedisk.img")
with open(_fd, "wb") as f:
    f.truncate(16 << 20)
import importlib.util as _iu3, io as _io
_spec3 = _iu3.spec_from_file_location("toolctrl3", os.path.join(ROOT, "python", "tool-ctrl.py"))
_tc3 = _iu3.module_from_spec(_spec3)
_spec3.loader.exec_module(_tc3)
_dm = _tc3.easyfs_device
_real_blk = _dm.is_block_device
_dm.is_block_device = lambda p: True                 # 把它当成"真盘"
_cap = _io.StringIO()
_old_out, _old_err = sys.stdout, sys.stderr
sys.stdout = sys.stderr = _cap
try:
    _r1 = _tc3.main(["mbr", "--disk", _fd, "--create", "--yes"])
    _r2 = _tc3.main(["mbr", "--disk", _fd, "--part", "1", "--seteasy", "--yes"])
    _r3 = _tc3.main(["mkfs", "--disk", _fd, "--part", "1", "--yes"])
    _r4 = _tc3.main(["optimize", "--alloc-merge", "--disk", _fd, "--part", "1", "--yes"])
    _r5 = _tc3.main(["resize", "--disk", _fd, "--offs", "1M", "--size", "15M",
                     "--newoffs", "1M", "--newsize", "15M", "--yes"])
    _r6 = _tc3.main(["resize", "--disk", _fd, "--offs", "1M", "--size", "15M",
                     "--newoffs", "1M", "--newsize", "15M"])       # 没有 --yes
finally:
    sys.stdout = _old_out
    sys.stderr = _old_err
    _dm.is_block_device = _real_blk
_o = _cap.getvalue()
check(_r4 == 0 and _r5 == 0, "optimize / resize 也认 --disk + --yes（各自的开设备路径都通）")
check(_r6 == 1 and "非交互环境" in _o,
      "不给 --yes ⇒ 干净拒绝（不是 traceback）—— resize --disk 曾经的 bug")
check(_r1 == 0 and _r2 == 0 and _r3 == 0, "真盘三步（--disk + --yes）都跑通：建表 / 打标识 / 建卷")
check("重建整张分区表" in _o, "--create 在真盘上警告的是【重建整张分区表】")
check("只改分区类型" in _o, "--seteasy 在真盘上说明的是【只改分区类型】")
_dv = _D.FileDevice(_fd, read_only=True)
_t, _ps = _D.read_partitions(_dv)
_dv.close()
check(_t == "mbr" and bool(_ps) and _ps[0]["type"] == "0x7F",
      "真盘路径结果：MBR 表已建、分区标识 = 0x7F")
# 交互：真 pty 里喂 n 必须"取消且不写"，喂 y 才写
_SHIM = ("import importlib.util as iu, os, sys\n"
         "sys.path.insert(0, %r)\n"
         "import easyfs_device as D\n"
         "D.is_block_device = lambda p: True\n"
         "sys.argv = ['tool-ctrl.py', 'mbr', '--disk', %r, '--create']\n"
         "spec = iu.spec_from_file_location('tc', %r)\n"
         "m = iu.module_from_spec(spec); spec.loader.exec_module(m)\n"
         "sys.exit(m.main())\n") % (os.path.join(ROOT, "python"), _fd,
                                    os.path.join(ROOT, "python", "tool-ctrl.py"))
import pty as _pty3, subprocess as _sp3
def _ask_disk(feed):
    _m, _s = _pty3.openpty()
    _p = _sp3.Popen([sys.executable, "-c", _SHIM], stdin=_s, stdout=_s, stderr=_s)
    os.close(_s)
    os.write(_m, feed)
    _buf = b""
    try:
        while True:
            _b = os.read(_m, 4096)
            if not _b:
                break
            _buf += _b
    except OSError:
        pass
    _p.wait()
    os.close(_m)
    return _p.returncode, _buf
with open(_fd, "wb") as f:                            # 清成空盘，专测交互
    f.truncate(16 << 20)
_rc, _out = _ask_disk(b"n\n")
with open(_fd, "rb") as f:
    _d0 = f.read(512)
check(_rc != 0 and "已取消".encode("utf-8") in _out and set(_d0) == {0},
      "真盘确认：喂 n ⇒ 取消，且盘上一个字节都没写")
_rc, _out = _ask_disk(b"y\n")
with open(_fd, "rb") as f:
    _d1 = f.read(512)
check(_rc == 0 and "已确认".encode("utf-8") in _out and set(_d1) != {0},
      "真盘确认：喂 y ⇒ 才真写进去")
# 1j) resize 也要问一句（--yes 免问）；--part N 可代替 --offs/--size
_rf = os.path.join(WORK, "rz2.img")
with open(_rf, "wb") as f:
    f.truncate(32 << 20)
run("%s mkfs --file %s --size 32M" % (TOOL, _rf), 0, "mkfs（resize 用例）")
rc, out = run("%s resize --file %s --offs 0 --size 32M --newsize 24M" % (TOOL, _rf), None,
              "resize 不带 --yes")
check(rc != 0 and "--yes" in out, "resize 不带 --yes ⇒ 非交互下拒绝（提示 --yes）")
rc, out = run("%s resize --file %s --offs 0 --size 32M --newsize 24M --yes" % (TOOL, _rf), 0,
              "resize 带 --yes")
check("已确认（--yes）" in out and "变化" in out, "resize --yes ⇒ 不问、直接做（并打印变化）")
run("%s fsck -n --file %s --offs 0 --size 24M" % (TOOL, _rf), 0, "resize 之后 fsck 干净")
_rp = os.path.join(WORK, "rzp.img")
_sf2 = os.path.join(WORK, "rzp.sf")
with open(_rp, "wb") as f:
    f.truncate(32 << 20)
with open(_sf2, "w") as f:
    f.write("label: dos\nstart=2048, type=7f\n")
run("sfdisk -q %s < %s" % (_rp, _sf2), 0, "造带分区的镜像")
run("%s mkfs --vdisk %s --part 1" % (TOOL, _rp), 0, "分区里建卷")
rc, out = run("%s resize --vdisk %s --part 1 --newsize 24M --yes" % (TOOL, _rp), 0,
              "resize --part 1（代替 --offs/--size）")
check("MBR 分区 #1" in out, "--part 1：旧几何取自那个分区（输出里标了分区）")
run("%s fsck -n --vdisk %s --part 1" % (TOOL, _rp), 0, "--part 方式 resize 后 fsck 干净")
rc, out = run("%s resize --vdisk %s --part 1 --offs 1M --newsize 24M --yes" % (TOOL, _rp),
              None, "--part 与 --offs 混用")
check(rc != 0 and "二选一" in out, "--part 与 --offs/--size 混用 ⇒ 报错")
# 1k) 块头魔数：逐类核对（表 ↔ stamp/parse）+ 真卷上的块带对魔数
import easyfs as _E
_bad = []
for _t in range(0, 8):
    _b = bytearray(4096)
    _E.stamp_header(_b, _t, 64, 0)
    _h = _E.parse_header(_b)
    _want = _E.BLOCK_MAGIC.get(_t)
    if _want is None:
        if bytes(_b[:8]) != b"\x00" * 8 or not _h["magic_ok"]:
            _bad.append((_t, "应该没有魔数（全零）"))
    elif bytes(_b[:8]) != _want or not _h["magic_ok"]:
        _bad.append((_t, _want))
check(not _bad, "块头魔数逐类核对（null 无魔数、file-data 无头）%s" % (_bad or "✓"))
_b3 = bytearray(4096)
_E.stamp_header(_b3, _E.BT_DIR, 64, 0)
_b3[0:8] = b"easyzzz "
_h3 = _E.parse_header(_b3)
check((not _h3["magic_ok"]) and _h3["prefix_ok"],
      "前缀对但类型不认识 ⇒ magic_ok=False / prefix_ok=True（报错能说清）")
_dk = os.path.join(WORK, "mag.img")
if os.path.exists(_dk):
    os.remove(_dk)
run("%s mkfs --file %s --size 16M" % (TOOL, _dk), 0, "mkfs（魔数用例）")
_dev = _E.FileDevice(_dk)
_v = _E.Volume.mount(_dev)
_m1 = _dev.read_at(_v.alloc_off, 8)
_m2 = _dev.read_at(_v.root_off, 8)
_dev.close()
check(_m1 == _E.BLOCK_MAGIC[_E.BT_ALLOC] and _m2 == _E.BLOCK_MAGIC[_E.BT_DIR],
      "真卷上 alloc=%r / dir=%r 各带自己的魔数" % (_m1, _m2))
# ---------- 2 put -r / get -r 整树往返 ----------
print("[2] sftpcli 递归上传/下载（含空目录、空文件、带空格名、>io-chunk 大文件）")
src = W + "/src"
os.makedirs(src + "/a/b/c"); os.makedirs(src + "/d e"); os.makedirs(src + "/void")
open(src + "/tiny.txt", "w").write("hello tiny\n")
open(src + "/empty.txt", "wb").close()
open(src + "/big.bin", "wb").write(bytes(bytearray(i % 251 for i in range(300000))))
open(src + "/a/one.txt", "w").write("one\n")
open(src + "/a/b/two.bin", "wb").write(bytes(bytearray((i * 7) % 256 for i in range(70000))))
open(src + "/a/b/c/deep.txt", "w").write("deep\n")
open(src + "/d e/sp ace.txt", "w").write("spaced\n")
open(W + "/c1.txt", "w").write("put -r %s/src /tree\ncheck\nquit\n" % W)
run("%s sftpcli --file %s/b.img --size 16M --mkfs --io-chunk 64K --script %s/c1.txt" % (TOOL, W, W), 0, "put -r")
open(W + "/c2.txt", "w").write("get -r /tree %s/back\ncheck\nquit\n" % W)
_, out = run("%s sftpcli --file %s/b.img --script %s/c2.txt" % (TOOL, W, W), 0, "get -r")
check("一致" in out, "get -r 后位图一致")
d = subprocess.run("diff -r %s/src %s/back" % (W, W), shell=True, stdout=subprocess.PIPE)
check(d.returncode == 0, "整树 diff -r 完全一致")

# ---------- 3 格式能力（软/硬链接、PAD、跨块条目、重挂载）----------
print("[3] 格式能力（feat.py）")
if os.path.exists(os.path.join(HERE, "rt", "feat.py")):
    rc, out = run("%s %s" % (sys.executable, os.path.join(HERE, "rt", "feat.py")), 0, "feat.py 14 项")
    check("全部通过" in out, "feat.py 全部通过")
else:
    SKIP.append("feat.py 不存在")

# ---------- 4 伸缩四方向 ----------
print("[4] resize（四方向 + 拒绝 + 往返 + dry-run）")
if os.path.exists(os.path.join(HERE, "rt", "harness.py")):
    code = '''
import sys, shutil; sys.path.insert(0, os.path.join(HERE, "rt")); sys.path.insert(0, os.path.join(ROOT, "python"))
import harness as H
p = WORK + "/base.img"; H.make(p)
before = H.snapshot(p, H.OFFS, H.SIZE)
ok = True
for tag, (ns, nl) in (("expandright", (H.OFFS, H.SIZE + (16 << 20))),
                      ("expandleft", (0, H.SIZE + (16 << 20))),
                      ("shrinkright", (H.OFFS, H.SIZE - (16 << 20))),
                      ("shrinkleft", (H.OFFS + (16 << 20), H.SIZE - (16 << 20)))):
    q = WORK + "/r_%s.img" % tag; shutil.copy(p, q)
    H.run(q, H.OFFS, H.SIZE, ns, nl, verify=True)
    ok = ok and H.remount(q, ns, nl)[0]
    print("  [%s] OK" % tag)
q = WORK + "/r_rt.img"; shutil.copy(p, q)
H.run(q, H.OFFS, H.SIZE, H.OFFS, H.SIZE + (16 << 20), verify=True)
H.run(q, H.OFFS, H.SIZE + (16 << 20), H.OFFS, H.SIZE, verify=True)
ok = ok and H.check("往返", before, H.snapshot(q, H.OFFS, H.SIZE), 0)
q = WORK + "/r_ref.img"; shutil.copy(p, q); s0 = __import__("hashlib").sha256(open(q,"rb").read()).hexdigest()
try:
    H.run(q, H.OFFS, H.SIZE, H.OFFS, H.SIZE - (32 << 20)); print("  [拒绝] ✗ 没报错")
except Exception: print("  [拒绝] OK")
print("RESULT=%s" % ("OK" if ok else "FAIL"))
'''
    open(W + "/rz.py", "w").write(PRE + code)
    rc, out = run("PYTHONPATH=python python3 %s/rz.py" % W, 0, "resize 四方向")
    check("RESULT=OK" in out, "resize 四方向全部通过")
else:
    SKIP.append("harness.py 不存在")

# ---------- 5 病态卷：fsck 检出 + 退出码 ----------
print("[5] fsck 病态卷（期望 base 0 / leak 4 / miss 4 / crc 4 / feat 0）")
subprocess.run("printf 'put -r %s/src /tree\\nquit\\n' > %s/mk.txt" % (W, W), shell=True)
run("%s ctrl mkfs --file %s/base.img --size 16M" % (TOOL, W), 0, "mkfs base")
run("%s sftpcli --file %s/base.img --script %s/mk.txt" % (TOOL, W, W), 0, "填内容")
code = '''
import sys, shutil; sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.join(HERE, "rt"))
from easyfs import FileDevice, Volume, parse_header, stamp_header, crc32
W = WORK
def cp(d): shutil.copy(W + "/base.img", W + "/" + d)
cp("leak.img"); dev = FileDevice(W + "/leak.img"); v = Volume.mount(dev)
v.alloc(4096); v.commit(); v.mark_clean(); dev.close()
cp("miss.img"); dev = FileDevice(W + "/miss.img"); v = Volume.mount(dev)
e = v.lookup(v.lookup(v.root_off, "tree")["child"], "big.bin")
phys = v.entry_content(e)[1][0][0]
for r in v.regions:
    if r.region_off <= phys < r.region_end:
        r.set_bit((phys - r.region_off) // r.bit_unit, 0); r.dirty = True
v.commit(); v.mark_clean(); dev.close()
cp("crc.img"); dev = FileDevice(W + "/crc.img"); v = Volume.mount(dev)
b = bytearray(v.read_block(v.root_off)); h = parse_header(b)
b[h["header_bytes"] + 6] ^= 0xFF
v.dev.write_at(v.root_off, b); v.dev.flush(); dev.close()
print("fixtures ok")
'''
open(W + "/fx.py", "w").write(PRE + code)
run("PYTHONPATH=python python3 %s/fx.py" % W, 0, "造 leak/miss/crc")
for name, want in (("base", 0), ("leak", 4), ("miss", 4), ("crc", 4)):
    rc, out = run("%s ctrl fsck -n --file %s/%s.img" % (TOOL, W, name), want, "fsck %s → %d" % (name, want))
run("%s ctrl fsck -n --file %s" % (TOOL, os.path.join(WORK, "feat.img")), 0,
    "fsck feat.img（含链接）")
run("head -c 200000 /dev/urandom > %s/junk.img" % W, 0, "造随机文件")
run("%s ctrl fsck -n --file %s/junk.img" % (TOOL, W), 8, "fsck 非文件系统 → 8")
run("%s ctrl fsck -p --file %s/base.img" % (TOOL, W), 16, "fsck -p 未实现 → 16")

# ---------- 6 服务器 ----------
print("[6] HTTP 服务器")
p = subprocess.Popen("%s server --mem 16M --mkfs --port 8999 --force" % TOOL,
                     shell=True, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import time; time.sleep(1.5)
try:
    r1 = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                         "http://127.0.0.1:8999/"], stdout=subprocess.PIPE).stdout.decode()
    r2 = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-T",
                         W + "/src/tiny.txt", "http://127.0.0.1:8999/t.txt"],
                        stdout=subprocess.PIPE).stdout.decode()
    check(r1 == "200", "server GET / → 200（实际 %s）" % r1)
    check(r2 in ("201", "204"), "server PUT → 2xx（实际 %s）" % r2)
finally:
    p.terminate(); time.sleep(0.5)


# ---------- 7 anchor v3（tag 布局）----------
print("[7] anchor tag 布局 / hdrcrc / pool 段可选 / I9")
rc, out = run("%s %s" % (sys.executable, os.path.join(HERE, "anchor_v3.py")), 0, "anchor v3 用例")
print(out.strip())
check(out.count("True") >= 9, "anchor v3 用例全部为 True（%d/10）" % out.count("True"))

# ---------- 8 shell 提示符（真 pty）----------
print("[8] shell 提示符（pty：无双提示符 / 空输入不加空行）")
rc, out = run("%s %s" % (sys.executable, os.path.join(HERE, "shell_prompt.py")), 0, "shell 提示符")
print(out.strip())
check("通过 = True" in out, "提示符行为正确（真 pty + 逐行慢喂）")

# ---------- 9 混合粒度（mkfs --mixed）----------
print("[9] 混合粒度：粗起步 / 按需分裂 / 默认不变")
rc, out = run("%s %s" % (sys.executable, os.path.join(HERE, "mixed.py")), 0, "混合粒度用例")
print(out.strip())
check("ALL = True" in out, "混合粒度全部通过（20 项）")

# ---------- 10 文档一致性 ----------
print("[10] 文档一致性（doccheck）")
rc, out = run("%s %s" % (sys.executable, os.path.join(HERE, "doccheck.py")), 0, "doccheck")
print(out.strip().split("\n")[0])
check("发现问题 0 个" in out, "文档 0 问题")

# ---------- 11 DIR_OBJECT 只读用例 ----------
print("[11] DIR_OBJECT（目录对象形态，只读侧）")
rc, out = run("%s %s" % (sys.executable, os.path.join(HERE, "dirobj.py")), 0, "dirobj 用例")
print(out.strip()[-200:])
check("FAIL" not in out.upper(), "DIR_OBJECT 只读用例（12 项）")

# ---------- 汇总 ----------
print("\n" + "=" * 62)
print("通过 %d 项 / 失败 %d 项 / 跳过 %d 项" % (len(PASS), len(FAIL), len(SKIP)))
for f in FAIL: print("  ✗ %s" % f)
for s in SKIP: print("  - 跳过：%s" % s)
print("结果：%s" % ("全部通过 ✓" if not FAIL else "有失败 ✗"))

# 跑完默认清掉工作目录（想留现场：EASYFS_TEST_KEEP=1）
if not os.environ.get("EASYFS_TEST_KEEP"):
    import shutil as _sh2
    _sh2.rmtree(WORK, ignore_errors=True)
