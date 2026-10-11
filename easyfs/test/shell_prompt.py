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

"""shell 提示符回归测试：真 pty + 逐行慢喂（模拟人打字），确保
   ① 不出现双提示符 ② 空输入不产生多余空行 ③ 提示符都另起一行。"""
import os, pty, select, subprocess, sys, time

IMG = os.path.join(WORK, "v3t.img")
if not os.path.exists(IMG):                      # 自带环境：没有就建一个 16 MiB 小卷
    import subprocess as _sp
    _sp.run([sys.executable, os.path.join(ROOT, "python", "tool.py"),
             "ctrl", "mkfs", "--file", IMG, "--size", "16M"], stdout=_sp.DEVNULL,
            stderr=_sp.DEVNULL, check=True)
ENTER = [" \n", "\n", "   \n"]


def run(inputs):
    master, slave = pty.openpty()
    p = subprocess.Popen([sys.executable, "python/tool.py", "ctrl", "shell", "--file", IMG],
                         stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    out = b""

    def drain(sec):
        nonlocal out
        end = time.time() + sec
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.05)
            if not r:
                continue
            try:
                c = os.read(master, 4096)
            except OSError:
                return
            if not c:
                return
            out += c

    drain(1.0)
    for s in inputs:
        os.write(master, s.encode())
        drain(0.35)
    drain(0.5)
    p.wait()
    os.close(master)
    return out.decode("utf-8", "replace")


txt = run(ENTER + ["ls /\n", "pwd\n", "quit\n"])
lines = [l for l in txt.split("\n") if "easyfs:" in l]
double = any(l.count("easyfs:/>") > 1 for l in lines)
blank = sum(1 for l in lines if l.strip() == "easyfs:/>")
print("  提示符行 =", len(lines), " 双提示符 =", double, " 纯空提示符行 =", blank)
print("  通过 =", (not double) and blank == len(ENTER) and len(lines) == len(ENTER) + 3)
