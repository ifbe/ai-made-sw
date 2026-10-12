#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 工具统一入口：把 ``tool-*.py`` 的代码**直接拿来用**

``tool-xxx.py <参数>`` 与 ``tool.py xxx <参数>`` **完全等价**：

* ``tool-xxx.py`` 自己可以单独跑（每个文件末尾都有 ``if __name__ == "__main__"``）；
* ``tool.py`` 用 importlib **按文件路径**把 ``tool-xxx.py`` 当模块加载，
  然后直接调用它的 ``main(argv)`` —— **同一个进程**，不是子进程。
  所以异常栈、断点、signal、``--mem`` 之类的进程内状态都跟直接跑那个工具一样。

（文件名带连字符没法用普通 ``import``，所以这里用 ``spec_from_file_location``。）

用法::

    python3 python/tool.py help                        # 列出可用工具
    python3 python/tool.py mkfs  --file disk.img --size 64M
    python3 python/tool.py migrate --file src.img --newfile dst.img --newoffs 3M
    python3 python/tool.py optimize --dir              # 子命令可直接当顶层命令用 ✓
    python3 python/tool.py probe --vdisk vm.vhd --part 1
    python3 python/tool.py sftpcli --file disk.img
    python3 python/tool.py server  --mem 64M --port 8080

``mkfs`` / ``migrate`` / ``optimize`` … 都是 **tool-ctrl 的子命令** ✓ ——
写 ``tool.py <子命令>`` 就行（认不出的名字自动转给 ``tool-ctrl`` ✓），
也可以直接跑 ``python3 python/tool-ctrl.py <子命令>`` ✓。

核心是 ``easyfs.py``（格式层）与 ``easyfs_device.py``（设备层）；
``tool-*.py`` 都是外层工具。

**新增外层工具时不用改本文件** —— 任何带 ``main(argv)`` 的 ``tool-*.py`` 都会被自动发现。
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PREFIX = "tool-"
SUFFIX = ".py"
ABOUT = {
    "ctrl": "控制/诊断：mkfs / probe / device",
    "sftpcli": "本地 sftp 风格命令行（ls/cd/put/get/mkdir/mv/rm/...）",
    "server": "HTTP / WebDAV-lite 网络服务器（局域网访问）",
    "vdisk": "虚拟磁盘（.vhd / .vmdk / .img）：新建与详情",
}

_LOADED = {}


def discover():
    """扫描本目录下的 ``tool-*.py``，返回 ``{工具名: 文件名}``。"""
    found = {}
    for name in sorted(os.listdir(HERE)):
        if not (name.startswith(PREFIX) and name.endswith(SUFFIX)):
            continue
        if os.path.isfile(os.path.join(HERE, name)):
            found[name[len(PREFIX):-len(SUFFIX)]] = name
    return found


def load(tool, filename):
    """按路径加载 ``tool-xxx.py`` 成模块（缓存起来，重复调用不重复执行）。"""
    mod = _LOADED.get(filename)
    if mod is None:
        path = os.path.join(HERE, filename)
        spec = importlib.util.spec_from_file_location("easyfs_" + tool, path)
        if spec is None or spec.loader is None:
            raise ImportError("加载不了工具模块: " + path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)              # __name__ != __main__，不会自己跑
        _LOADED[filename] = mod
    return mod


def call(tool, filename, argv):
    """在**本进程**里调用某个工具的 ``main(argv)``，返回退出码。"""
    try:
        mod = load(tool, filename)
    except Exception as e:                        # 工具自身 import 失败
        print("error: 加载 %s 失败: %s" % (filename, e), file=sys.stderr)
        return 1
    fn = getattr(mod, "main", None)
    if not callable(fn):
        print("error: %s 里没有 main(argv)" % filename, file=sys.stderr)
        return 2
    try:
        rc = fn(list(argv))
    except SystemExit as e:                       # argparse 报错 / --help 走这里
        code = e.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1
    except KeyboardInterrupt:
        return 130
    return 0 if rc is None else rc


def usage(tools):
    print(__doc__.strip())
    print("")
    print("可用工具:")
    for tool in sorted(tools):
        print("  %-10s %-18s %s"
              % (tool, tools[tool], ABOUT.get(tool, "")))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    tools = discover()
    if not argv or argv[0] in ("-h", "--help", "help"):
        usage(tools)
        return 0 if argv else 2
    if argv[0] in ("-l", "-list", "--list", "list"):
        for tool in sorted(tools):
            print("  %-10s %-18s %s"
                  % (tool, tools[tool], ABOUT.get(tool, "")))
        return 0
    name, rest = argv[0], argv[1:]
    if name in tools:
        return call(name, tools[name], rest)
    # 不是工具名 ⇒ 当成 **tool-ctrl 的子命令**（方便：`tool migrate …` ≡ `tool migrate …`）
    if "ctrl" in tools:
        return call("ctrl", tools["ctrl"], [name] + rest)
    print("error: 没有这个工具: %r" % name, file=sys.stderr)
    print("可用: %s" % ", ".join(sorted(tools)), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
