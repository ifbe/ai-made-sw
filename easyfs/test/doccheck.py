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
os.chdir(ROOT)          # 本脚本用相对 doc/*.md

import io, glob, os, re, sys
sys.path.insert(0, os.path.join(ROOT, "python"))
import easyfs
DOCS = sorted(glob.glob("doc/*.md"))
base = lambda p: os.path.basename(p)
text = {base(p): io.open(p, encoding="utf-8").read() for p in DOCS}
issues = []

# 内容规则豁免名单（当前为空 ✓：`doc/` 里不再放历史文件 ✓，历史移到 `python/gotcha.md` ✓）
LINT_SKIP = set()
LINT = dict((b, t) for b, t in text.items() if b not in LINT_SKIP)

# ---- 1 索引覆盖 ----
idx = text["README.md"]
for b in sorted(text):
    if b != "README.md" and ("(%s)" % b) not in idx:
        issues.append(("索引缺条目", "README.md", b))

# ---- 2 链接 / 锚点 ----
def slug(h): return re.sub(r" ", "-", re.sub(r"[^\w\s\u4e00-\u9fff-]", "", h.strip().lower()))
anchors = {b: set([""] + [slug(m.group(2)) for m in re.finditer(r"^(#{2,4})\s+(.+)$", t, re.M)])
            for b, t in text.items()}
for b, t in LINT.items():
    for m in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", t):
        tgt = m.group(2)
        if tgt.startswith(("http", "mailto")): continue
        f, _, anc = tgt.partition("#")
        if not f:
            f = b
        elif f.startswith("..") or "/" in f:          # 相对 doc/ 的路径
            if not os.path.exists(os.path.join("doc", f)): issues.append(("链接缺文件", b, tgt))
            continue
        else:
            f = base(f)
        if f not in anchors:
            if not os.path.exists(os.path.join("doc", f)): issues.append(("链接缺文件", b, tgt))
            continue
        if anc and anc not in anchors[f]: issues.append(("锚点不存在", b, tgt))

# ---- 3 属性注册表 vs 代码 ----
rows = re.findall(r"^\|\s*\*{0,2}`?(0x[0-9A-Fa-f]{2})`?\*{0,2}\s*\|\s*\*{0,2}([A-Za-z_0-9]+)\*{0,2}\s*\|",
                  text["2-dir.md"], re.M)
doc_attrs = {name: int(h, 16) for h, name in rows}
code_attrs = {v: k for k, v in easyfs.ATTR_NAME_STR.items()}
for name, val in sorted(code_attrs.items()):
    if name not in doc_attrs: issues.append(("注册表缺属性", "2-dir.md", "%s=0x%02X" % (name, val)))
    elif doc_attrs[name] != val: issues.append(("属性号不一致", "2-dir.md", "%s 文档0x%02X ≠ 代码0x%02X" % (name, doc_attrs[name], val)))
for name, val in sorted(doc_attrs.items()):
    if name not in code_attrs: issues.append(("代码无此属性", "2-dir.md", "%s=0x%02X" % (name, val)))

# ---- 4 块类型表 vs 代码 ----
rows = re.findall(r"^\|\s*\*{0,2}(\d)\*{0,2}\s*\|\s*`([a-z\-]+)`\s*\|", text["detail-common.md"], re.M)
doc_bt = {int(n): nm for n, nm in rows}
for k, v in sorted(easyfs.BT_NAME.items()):
    if doc_bt.get(k) != v: issues.append(("块类型表不一致", "detail-common.md", "%d: 文档%r ≠ 代码%r" % (k, doc_bt.get(k), v)))

# ---- 5 陈旧用语 ----
stale = ["TINY_DATA", "HARDLINK_PTR", "SYMLINK_PTR_LOGICAL", "3-object", "硬链接块",
         "对象块", "对象家族", "对象表", "objectid", "optimize object",
         "DATA_LINK", "DIR_LINK", "rootid",
         "EASYFS4K", "EASYFSPL", "形态即策略", "=> 一律",
         "block_type=2（空闲位图）", "block_type=1（anchor", "block_type=3（dir）",
         "block_type=4（cont", "按逻辑位置（模式④）"]
for b, t in LINT.items():
    for s in stale:
        for m in re.finditer(re.escape(s), t):
            line = t[:m.start()].count("\n") + 1
            issues.append(("陈旧用语", "%s:%d" % (b, line), s))

# ---- 6 交叉引用 §N 是否真存在 ----
secref = re.compile(r"\[`?([0-9a-z\-]+\.md)`?\]\(([^)]*)\)\s*§([0-9]+)")
for b, t in LINT.items():
    for m in secref.finditer(t):
        f = base(m.group(1)); sec = m.group(3)
        if f not in text: continue
        if not re.search(r"^#{2,3} %s\." % sec, text[f], re.M):
            issues.append(("§引用指向不存在的节", "%s → %s §%s" % (b, f, sec), ""))

# ---- 9 章节编号：不许重号 ----
for b, t in LINT.items():
    nums = [int(m.group(1)) for m in re.finditer(r"^##\s+(\d+)\.", t, re.M)]
    dup = sorted(set(n for n in nums if nums.count(n) > 1))
    if dup:
        issues.append(("章节编号重号", b, "§" + "、§".join(str(n) for n in dup)))
    # 只对"从 §1 开始"的文档查跳号；5-anchor.md 这类故意接着别的文档编号的不查
    miss = ([n for n in range(1, max(nums) + 1) if n not in nums]
            if nums and nums[0] == 1 else [])
    if miss:
        issues.append(("章节编号跳号", b, "缺 §" + "、§".join(str(n) for n in miss)))

# ---- 10 文档内部的 §N 引用必须指向存在的节 ----
for b, t in LINT.items():
    secs = set(int(m.group(1)) for m in re.finditer(r"^##\s+(\d+)\.", t, re.M))
    for m in re.finditer(r"§(\d+)", t):
        n = int(m.group(1))
        if secs and n not in secs:
            issues.append(("§引用指向不存在的节（本文内）", "%s §%d" % (b, n), ""))

# ---- 11 不许再有跨文档的 §N 精确引用（只允许"详见 xxx 文档"这种模糊说法）----
for b, t in LINT.items():
    for m in re.finditer(r"\.md`?\]?\(?[^)\n]{0,20}\)?\s*[–\-、,，]?\s*§\d+", t):
        issues.append(("跨文档 §引用（应改模糊说法）", b, m.group(0)[:40]))

# ---- 15 anchor tag 表 vs 代码（5-anchor.md ↔ anchor_layout()）----
# 表的每一行是 `| \`[起,止]\` | \`tag\` |`（裸值那行写「（无 tag）」）；顺序必须与代码一致。
try:
    rows = re.findall(r"^\|\s*`\[([0-9a-f]+),([0-9a-f]+)\]`\s*\|\s*(?:`([^`]+)`|（无 tag）)\s*\|",
                      text["5-anchor.md"], re.M)
    got = [(t if t else None, int(a, 16), int(b, 16)) for a, b, t in rows]
    # 文档写的是**整个 16 字节槽**：tag 8 字节 + 值 8 字节（值只占前 width 字节，其余为 0）
    exp = [(tag, toff, toff + 15) for _n, tag, toff, _voff, _w in easyfs.anchor_layout()]
    if len(got) != len(exp):
        issues.append(("anchor tag 表行数不一致", "5-anchor.md",
                       "文档 %d 行 / 代码 %d 个字段" % (len(got), len(exp))))
    for i in range(min(len(got), len(exp))):
        if got[i] != exp[i]:
            issues.append(("anchor tag 表与代码不一致", "5-anchor.md",
                           "第 %d 行：文档 %r / 代码 %r" % (i + 1, got[i], exp[i])))
except Exception as e:
    issues.append(("anchor tag 表检查失败", "5-anchor.md", repr(e)[:90]))

# ---- 16 块头魔数表 vs 代码（detail-common.md ↔ easyfs_config.BLOCK_MAGIC）----
try:
    rows = re.findall(r"^\|\s*(\d+)\s*`([a-z\-]+)`\s*\|\s*"
                      r"(?:\*\*（无）\*\*|\*\*（裸块，没有头）\*\*|`([^`]+)`)\s*\|",
                      text["detail-common.md"], re.M)
    got = dict((int(_n), (_m if _m else None)) for _n, _name, _m in rows)
    exp = dict((_t, _m.decode("ascii")) for _t, _m in easyfs.BLOCK_MAGIC.items())
    exp[easyfs.BT_NULL] = None
    exp[easyfs.BT_FILE] = None
    for _k in sorted(set(list(got.keys()) + list(exp.keys()))):
        if got.get(_k) != exp.get(_k):
            issues.append(("块头魔数表与代码不一致", "detail-common.md",
                           "type %s：文档 %r / 代码 %r"
                           % (_k, got.get(_k), exp.get(_k))))
except Exception as e:
    issues.append(("块头魔数表检查失败", "detail-common.md", repr(e)[:90]))

print("发现问题 %d 个\n" % len(issues))
from collections import Counter
for kind, n in Counter(i[0] for i in issues).most_common():
    print("  [%s] %d" % (kind, n))
for i in issues[:40]:
    print("   - %-22s %-22s %s" % i)
