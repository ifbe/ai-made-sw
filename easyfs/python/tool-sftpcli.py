#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 本地命令行：像 sftp 一样操作一个 EasyFS 卷（**不是**真的 sftp 协议）

这是**外层工具**之一（核心是 ``easyfs.py`` 与 ``easyfs_device.py``）。
也可以用统一入口：``python3 python/tool.py sftpcli <同样的参数>``。
要让**别的机器**访问，用 ``tool-server.py``。

用法::

    python3 python/tool-sftpcli.py --file disk.img                     # 打开已有卷
    python3 python/tool-sftpcli.py --file disk.img --mkfs --size 64M  # 先建卷
    python3 python/tool-sftpcli.py --file disk.img --script cmds.txt  # 批处理
    python3 python/tool-sftpcli.py --file disk.img --force            # 默认覆盖已存在文件
    python3 python/tool-sftpcli.py --vdisk vm.vhd --part 1            # .vhd 里的分区
    python3 python/tool-sftpcli.py --file big.img --offset 1M --length 64M   # 文件里的一段
    python3 python/tool-sftpcli.py --mem 16M                          # 内存卷（演示）

命令（远端 / 本地成对）::

    ls [路径]              lls [路径]            列目录
    cd [路径]              lcd [路径]            切换目录
    pwd                    lpwd                  显示当前目录
    put [-f] [--offset N] 本地 [远端]             上传（--offset 从第 N 字节续传）
    get [-f] 远端 [本地]                         下载
    mkdir 路径                                    建目录
    rm 路径                                       删文件
    rmdir [-r] 路径                               删目录
    cat 路径                                      打印文件内容（文本）
    stat 路径                                     显示条目信息
    df                                            空闲空间
    check                                         校验位图 vs 可达集合
    help / quit

远端路径：以 `/` 开头是绝对路径，否则相对远端当前目录。
**`..` 由本程序在内存里维护路径链**（卷格式里没有 `..` 条目，见 doc/2-dir.md）。

格式层在 ``easyfs.py``；本文件只是薄壳。
"""

import argparse
import os
import shlex
import stat as statmod
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import easyfs
import easyfs_device
from easyfs import (ATTR_NAME_STR, EasyFSError, PathWalker, Volume, human,
                    parse_size)
from easyfs_device import EasyFSDeviceError

ERRORS = (EasyFSError, EasyFSDeviceError)

HELP = """命令:
  ls [路径]              lls [路径]            列目录（远端 / 本地）
  cd [路径]              lcd [路径]            切换目录（远端 / 本地）
  pwd                    lpwd                  显示当前目录
  put [-r] [-f] [--offset N] 本地 [远端]        上传（-r 整个目录树；--offset 续传）
  get [-r] [-f] 远端 [本地]                    下载（-r 整个目录树）
  mkdir 路径                                    建目录
  rm 路径                                       删文件
  rmdir [-r] 路径                               删目录
  mv 源 目标                                    改名 / 移动（数据不动，只搬条目）
  cat 路径                                      打印文件内容（文本）
  stat 路径 / df / check                        条目信息 / 空闲空间 / 一致性
  quit                                         退出（会正常卸载）"""


class Shell(object):

    COMMANDS = {
        "ls": "do_ls", "lls": "do_lls",
        "cd": "do_cd", "lcd": "do_lcd",
        "pwd": "do_pwd", "lpwd": "do_lpwd",
        "put": "do_put", "get": "do_get",
        "mkdir": "do_mkdir", "rm": "do_rm", "rmdir": "do_rmdir", "mv": "do_mv",
        "cat": "do_cat", "stat": "do_stat",
        "df": "do_df", "check": "do_check",
        "help": "do_help", "?": "do_help",
        "quit": "do_quit", "exit": "do_quit", "bye": "do_quit",
    }

    def __init__(self, dev, desc="", overwrite=False, io_chunk=8 << 20):
        self.dev = dev
        self.desc = desc or repr(dev)
        self.io_chunk = io_chunk
        self.overwrite = overwrite
        self.vol = Volume.mount(self.dev)
        # 位图没有载荷 CRC：dirty 就意味着上次没干净卸载，必须重建（1-alloc.md §7.5）
        if self.vol.is_dirty():
            print("[!] 位图标记为 dirty（上次非正常卸载）→ 重建位图 ...")
            before, after = self.vol.rebuild_bitmap(apply=True)
            print("    重建完成: 可达 used %d（重建前 %d）" % (after, before))
        self.vol.mark_dirty()                      # 之后崩溃靠重建兜底
        self.walk = PathWalker(self.vol)            # 远端当前目录（`..` 在内存里）
        self.lcwd = os.getcwd()

    # ------------------------------------------------------------ 路径（共用 easyfs.PathWalker）

    @staticmethod
    def _rpath(path):
        """远端路径规整：容忍尾斜杠（`/dst/` 与 `/dst` 等价；`/` 保持原样）。"""
        if path in ("", "/"):
            return path
        return path.rstrip("/") or "/"

    def _dir_stack(self, path):
        return self.walk.dir_stack(self._rpath(path))

    def _entry_pos(self, path):
        return self.walk.entry_pos(self._rpath(path))

    def _resolve_any(self, path):
        return self.walk.resolve_any(self._rpath(path))

    def _rdisp(self, names=None):
        return self.walk.disp(names)

    def _local(self, path):
        return path if os.path.isabs(path) else os.path.join(self.lcwd, path)

    @staticmethod
    def _flag(args, flag):
        if flag in args:
            args = list(args)
            args.remove(flag)
            return True, args
        return False, list(args)

    @staticmethod
    def _opt(args, name, default=None):
        """把 ``--name VALUE`` / ``--name=VALUE`` 从参数表里摘出来。"""
        out, rest, i = default, [], 0
        args = list(args)
        while i < len(args):
            a = args[i]
            if a == name and i + 1 < len(args):
                out = args[i + 1]
                i += 2
                continue
            if a.startswith(name + "="):
                out = a[len(name) + 1:]
                i += 1
                continue
            rest.append(a)
            i += 1
        return out, rest

    # ------------------------------------------------------------ 列目录 / 切目录

    def do_ls(self, args):
        path = args[0] if args else "."
        kind = self._resolve_any(path)
        if kind[0] == "dir":
            entries = self.vol.read_dir(*easyfs.PathWalker(self.vol).dir_ref(path))
        else:
            entries = [kind[1]]
        for e in sorted(entries, key=lambda x: x["name"]):
            print("  %s %10d  %s" % ("d" if e["kind"] == "dir" else "-",
                                     e["size"],
                                     e["name"].decode("utf-8", "replace")))
        print("  （%d 项，远端 %s）" % (len(entries), self._rdisp()))

    def do_lls(self, args):
        path = args[0] if args else "."
        full = self._local(path)
        if os.path.isdir(full):
            for n in sorted(os.listdir(full)):
                st = os.lstat(os.path.join(full, n))
                print("  %s %10d  %s" % (statmod.filemode(st.st_mode)[1:],
                                         st.st_size, n))
            print("  （本地 %s）" % full)
        elif os.path.exists(full):
            st = os.lstat(full)
            print("  %s %10d  %s" % (statmod.filemode(st.st_mode)[1:],
                                     st.st_size, path))
        else:
            raise EasyFSError("本地路径不存在: %s" % full)

    def do_cd(self, args):
        print("远端当前目录: %s" % self.walk.cd(args[0] if args else "/"))

    def do_lcd(self, args):
        path = args[0] if args else os.path.expanduser("~")
        full = os.path.abspath(self._local(path))
        if not os.path.isdir(full):
            raise EasyFSError("本地目录不存在: %s" % full)
        self.lcwd = full
        print("本地当前目录: %s" % self.lcwd)

    def do_pwd(self, args):
        print(self._rdisp())

    def do_lpwd(self, args):
        print(self.lcwd)

    # ------------------------------------------------------------ 上传 / 下载

    @staticmethod
    def _disp(name):
        """名字可能是 str 也可能是 bytes —— 统一成可打印的 str。"""
        return name.decode("utf-8", "replace") if isinstance(name, bytes) else name

    def _upload_file(self, local, poff, name, force, offset=0):
        """把一个本地文件写进远端 `(poff, name)`，返回 `(字节数, 用时)`。

        `offset > 0` = 续传（远端必须已存在且大小正好等于 offset）。
        """
        size = os.path.getsize(local)
        resuming = bool(offset)
        exist = self.vol.lookup(poff, name)
        if resuming:
            if exist is None:
                raise EasyFSError("远端不存在，--offset 只能用于续传: %s"
                                  % self._disp(name))
            if exist["kind"] != "file":
                raise EasyFSError("不是文件: %s" % self._disp(name))
            if exist["size"] != offset:
                raise EasyFSError("远端已有 %d 字节，与 --offset %d 不符"
                                  % (exist["size"], offset))
            if offset > size:
                raise EasyFSError("--offset %d 超过本地文件大小 %d" % (offset, size))
        elif exist is not None:
            if not (force or self.overwrite):
                raise EasyFSError("远端已存在: %s（加 -f 覆盖）" % self._disp(name))
            self.vol.delete(poff, name, recursive=True)
        t0 = time.time()
        if not resuming and size <= self.io_chunk:
            with open(local, "rb") as f:
                self.vol.create(poff, name, data=f.read())
        else:
            if not resuming:
                self.vol.create(poff, name)
            done = offset
            with open(local, "rb") as f:
                f.seek(offset)
                while True:
                    buf = f.read(self.io_chunk)
                    if not buf:
                        break
                    self.vol.write(poff, name, buf, offset=done)
                    done += len(buf)
                    if size > self.io_chunk:
                        print("    ... %s / %s" % (human(done), human(size)))
        self.vol.commit()
        return size, time.time() - t0

    def _download_file(self, ent, lpath, force):
        """把一条远端文件条目写到本地 `lpath`（分块范围读），返回字节数。"""
        if os.path.exists(lpath) and not (force or self.overwrite):
            raise EasyFSError("本地已存在: %s（加 -f 覆盖）" % lpath)
        total = ent["size"]
        done = 0
        with open(lpath, "wb") as f:
            while done < total:
                buf = self.vol.read_range(ent, done,
                                          min(self.io_chunk, total - done))
                if not buf:
                    break
                f.write(buf)
                done += len(buf)
                if total > self.io_chunk:
                    print("    ... %s / %s" % (human(done), human(total)))
        return done

    def do_put(self, args):
        recursive, args = self._flag(args, "-r")
        force, args = self._flag(args, "-f")
        off_arg, args = self._opt(args, "--offset")
        if not args:
            raise EasyFSError("用法: put [-r] [-f] [--offset N] <本地> [远端]")
        local = self._local(args[0])
        if recursive and os.path.isdir(local):
            if off_arg:
                raise EasyFSError("--offset 不能与 -r 一起用")
            remote_arg = (args[1] if len(args) > 1
                          else os.path.basename(os.path.normpath(local)))
            self._put_tree(local, remote_arg, force)
            return
        if not os.path.isfile(local):
            raise EasyFSError("本地文件不存在: %s" % local)
        base = os.path.basename(local)
        remote_arg = args[1] if len(args) > 1 else base
        # 远端若是已存在的目录 → 落到它下面，用本地文件名
        try:
            _, offs = self._dir_stack(remote_arg)
            poff, name = offs[-1], base
        except EasyFSError:
            poff, name, _ = self._entry_pos(remote_arg)
        offset = parse_size(off_arg) if off_arg else 0
        size, dt = self._upload_file(local, poff, name, force, offset)
        print("put%s: %s -> %s  (%s, %.2fs)"
              % (" --offset %d" % offset if offset else "", base,
                 self._disp(name), human(size), dt))

    # ------------------------------------------------------------ 递归（put -r / get -r）

    def _ensure_rdir(self, path):
        """确保远端目录 `path` 存在（缺则逐级建，等价 `mkdir -p`），返回它的 dir 块偏移。"""
        try:
            return self._resolve_any(path)[2][-1]
        except EasyFSError:
            pass
        trimmed = path.rstrip("/")
        parent = os.path.dirname(trimmed) or "."
        name = os.path.basename(trimmed)
        if not name or name in (".", ".."):
            raise EasyFSError("非法远端目录: %s" % path)
        pdir = self._ensure_rdir(parent)
        ent = self.vol.lookup(pdir, name)
        if ent is None:
            self.vol.mkdir(pdir, name)
            self.vol.commit()
            ent = self.vol.lookup(pdir, name)
        if ent["kind"] != "dir":
            raise EasyFSError("远端已存在同名文件: %s" % path)
        return ent["child"]

    @staticmethod
    def _join_remote(base, rel):
        rel = rel.replace(os.sep, "/").strip("/")
        return base if rel in ("", ".") else base.rstrip("/") + "/" + rel

    def _put_tree(self, local_dir, remote_arg, force):
        """`put -r`：把本地目录树写进远端。

        目标语义与单文件一致：`remote_arg` 已存在 → 落到它下面（用本地目录名）；
        不存在 → 它本身就是目标目录。
        """
        base = os.path.basename(os.path.normpath(local_dir))
        try:
            self._resolve_any(remote_arg)                 # 目标已存在
            root = self._join_remote(remote_arg, base)    # → 落到它下面
        except EasyFSError:
            root = remote_arg                             # → 目标就是它本身
        root_off = self._ensure_rdir(root)
        nf = nd = tot = 0
        skipped = []
        t0 = time.time()
        for dirpath, dirnames, filenames in os.walk(local_dir):
            rel = os.path.relpath(dirpath, local_dir)
            if rel in (".", ""):
                poff = root_off
            else:
                poff = self._ensure_rdir(self._join_remote(root, rel))
                nd += 1
            for fn in sorted(filenames):
                lp = os.path.join(dirpath, fn)
                if os.path.islink(lp) or not os.path.isfile(lp):
                    skipped.append(os.path.relpath(lp, local_dir))
                    continue
                name = fn.encode("utf-8")
                size, _dt = self._upload_file(lp, poff, name, force)
                nf += 1
                tot += size
                print("  + %s  (%s)"
                      % (self._join_remote(root, os.path.join(rel, fn)), human(size)))
        print("put -r: %s -> %s  (%d 文件 / %d 目录, %s, %.2fs)"
              % (base, root, nf, nd, human(tot), time.time() - t0))
        if skipped:
            print("  跳过 %d 个非普通文件: %s"
                  % (len(skipped), ", ".join(skipped[:5])))

    def _get_tree(self, dir_off, ldir, force, rdisp=""):
        """`get -r` 的递归部分；返回 `(文件数, 目录数, 字节数)`。"""
        os.makedirs(ldir, exist_ok=True)
        nf = nd = tot = 0
        for ent in sorted(self.vol.read_dir(dir_off), key=lambda e: e["name"]):
            name = ent["name"].decode("utf-8", "replace")
            lp = os.path.join(ldir, name)
            if ent["kind"] == "dir":
                print("  d %s/" % (rdisp + "/" + name))     # 前序，像 find
                a, b, c = self._get_tree(ent["child"], lp, force,
                                         rdisp + "/" + name)
                nf += a
                nd += b + 1
                tot += c
            else:
                nf += 1
                tot += self._download_file(ent, lp, force)
                print("  - %s  (%s)" % (rdisp + "/" + name, human(ent["size"])))
        return nf, nd, tot

    def do_get(self, args):
        recursive, args = self._flag(args, "-r")
        force, args = self._flag(args, "-f")
        if not args:
            raise EasyFSError("用法: get [-r] [-f] <远端> [本地]")
        poff, name, ent = self._entry_pos(args[0])
        if ent is None:
            raise EasyFSError("找不到: %s" % args[0])
        disp = ent["name"].decode("utf-8", "replace")
        ltarget = self._local(args[1]) if len(args) > 1 else self.lcwd
        t0 = time.time()
        if ent["kind"] == "dir":
            if not recursive:
                raise EasyFSError("是目录，加 -r: %s" % args[0])
            ldir = os.path.join(ltarget, disp) if os.path.isdir(ltarget) else ltarget
            nf, nd, tot = self._get_tree(ent["child"], ldir, force, "/" + disp)
            print("get -r: %s -> %s  (%d 文件 / %d 目录, %s, %.2fs)"
                  % (disp, ldir, nf, nd, human(tot), time.time() - t0))
            return
        lpath = os.path.join(ltarget, disp) if os.path.isdir(ltarget) else ltarget
        done = self._download_file(ent, lpath, force)
        print("get: %s -> %s  (%s, %.2fs)"
              % (disp, lpath, human(done), time.time() - t0))

    # ------------------------------------------------------------ 增删

    def do_mkdir(self, args):
        if not args:
            raise EasyFSError("用法: mkdir <路径>")
        poff, name, ent = self._entry_pos(args[0])
        if ent is not None:
            raise EasyFSError("已存在: %s" % args[0])
        self.vol.mkdir(poff, name)
        self.vol.commit()
        print("mkdir: %s" % args[0])

    def do_rm(self, args):
        if not args:
            raise EasyFSError("用法: rm <路径>")
        poff, name, ent = self._entry_pos(args[0])
        if ent is None:
            raise EasyFSError("找不到: %s" % args[0])
        if ent["kind"] == "dir":
            raise EasyFSError("是目录，用 rmdir: %s" % args[0])
        self.vol.delete(poff, name)
        self.vol.commit()
        print("rm: %s" % args[0])

    def do_rmdir(self, args):
        recursive, args = self._flag(args, "-r")
        if not args:
            raise EasyFSError("用法: rmdir [-r] <路径>")
        if args[0] in ("/", ".", ".."):
            raise EasyFSError("不允许删根目录")
        poff, name, ent = self._entry_pos(args[0])
        if ent is None:
            raise EasyFSError("找不到: %s" % args[0])
        if ent["kind"] != "dir":
            raise EasyFSError("不是目录，用 rm: %s" % args[0])
        self.vol.delete(poff, name, recursive=recursive)
        self.vol.commit()
        print("rmdir%s: %s" % (" -r" if recursive else "", args[0]))

    def do_mv(self, args):
        if len(args) != 2:
            raise EasyFSError("用法: mv <源> <目标>")
        spoff, sname, sent = self._entry_pos(args[0])
        if sent is None:
            raise EasyFSError("找不到: %s" % args[0])
        dpoff, dname, dent = self._entry_pos(args[1])
        if dent is not None:
            raise EasyFSError("目标已存在: %s" % args[1])
        self.vol.move(spoff, sname, dpoff, dname)
        self.vol.commit()
        print("mv: %s -> %s" % (args[0], args[1]))

    # ------------------------------------------------------------ 查看
    def do_cat(self, args):
        if not args:
            raise EasyFSError("用法: cat <路径>")
        poff, name, ent = self._entry_pos(args[0])
        if ent is None or ent["kind"] != "file":
            raise EasyFSError("不是文件: %s" % args[0])
        data = self.vol.read_file(ent)
        sys.stdout.write(data.decode("utf-8", "replace"))
        if data and not data.endswith(b"\n"):
            sys.stdout.write("\n")

    def do_stat(self, args):
        if not args:
            raise EasyFSError("用法: stat <路径>")
        poff, name, ent = self._entry_pos(args[0])
        if ent is None:
            raise EasyFSError("找不到: %s" % args[0])
        print("  名字      %s" % ent["name"].decode("utf-8", "replace"))
        print("  类型      %s" % ("目录" if ent["kind"] == "dir" else "文件"))
        print("  大小      %d (%s)" % (ent["size"], human(ent["size"])))
        print("  所在      目录块 @%d，块内偏移 %d..%d"
              % (ent["dir_block"], ent["start"], ent["end"]))
        if ent["kind"] == "dir":
            print("  子目录链  @%d" % ent["child"])
        for atype, value, base in ent["attrs"]:
            extra = ""
            if atype in (easyfs.ATTR_DATA_PTR, easyfs.ATTR_SYMLINK_OBJECT):
                x, size = easyfs.parse_data_ptr(value)
                extra = "  x=%+#x size=%d" % (x, size)
            elif atype == easyfs.ATTR_DIR_PTR:
                extra = "  x=%+#x" % struct.unpack_from("<q", value, 0)[0]
            elif atype == easyfs.ATTR_DATA_OBJECT:
                extra = "  L=%d -> @%d" % (
                    struct.unpack_from("<q", value, 0)[0],
                    self.vol.logical_to_phys(struct.unpack_from("<q", value, 0)[0]))
            elif atype == easyfs.ATTR_NLINK:
                extra = "  nlink=%d" % struct.unpack_from("<I", value, 0)[0]
            print("  属性      0x%02x %-16s len=%d%s"
                  % (atype, ATTR_NAME_STR.get(atype, "?"), len(value), extra))

    def do_df(self, args):
        total = self.vol.data_bytes
        free = self.vol.free_bytes()
        print("  区域      %s" % human(self.vol.region_len))
        print("  数据区    %s  = %d chunk（chunk %d B）"
              % (human(total), total // self.vol.chunk, self.vol.chunk))
        print("  已用      %s  (%d chunk)"
              % (human(total - free), (total - free) // self.vol.chunk))
        print("  空闲      %s  (%.2f%%)" % (human(free), 100.0 * free / total))
        print("  位图      %d 块 x %s" % (len(self.vol.regions),
                                          human(self.vol.regions[0].block_bytes)))

    def do_check(self, args):
        before, after = self.vol.rebuild_bitmap(apply=False)
        print("  位图 used=%d   可达集合 used=%d   →   %s"
              % (before, after,
                 "一致" if before == after else "不一致（需要 fsck/重建）"))

    def do_help(self, args):
        print(HELP)

    def do_quit(self, args):
        return False

    # ------------------------------------------------------------ 驱动

    def run_line(self, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return True
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print("error: %s" % e)
            return True
        if not parts:
            return True
        fn = getattr(self, self.COMMANDS.get(parts[0], ""), None)
        if fn is None:
            print("error: 未知命令 %r（help 看用法）" % parts[0])
            return True
        try:
            return fn(parts[1:]) is not False
        except EasyFSError as e:
            print("error: %s" % e)
            return True
        except OSError as e:
            print("error: %s" % e)
            return True

    def banner(self):
        v = self.vol
        print("EasyFS 卷 %s" % self.desc)
        print("  区域 %s   数据区 %s   空闲 %s"
              % (human(v.region_len), human(v.data_bytes), human(v.free_bytes())))
        print("  chunk %d B   位图 %d 块   策略 %s   逻辑原点 %d"
              % (v.chunk, len(v.regions),
                 easyfs.POLICY_NAME.get(v.policy_id, "?"), v.data_lo_logical))
        print("  命令 help；远端当前目录 %s；本地 %s" % (self._rdisp(), self.lcwd))

    def close(self):
        try:
            self.vol.commit()
            self.vol.mark_clean()          # 先落盘，再置 clean
        finally:
            self.dev.close()


def main(argv=None):
    import sys as _sys
    if "--object" in (_sys.argv[1:] if argv is None else argv):
        print("error: --object（对象形态写入）尚未实现；v0 只产出 ①②③",
              file=_sys.stderr)
        return 2
    ap = argparse.ArgumentParser(prog="tool-sftpcli.py",
                                 description="EasyFS 本地命令行（sftp 风格，"
                                             "不是真的 sftp 协议）")
    easyfs_device.add_device_args(ap)
    easyfs_device.add_disk_safety_args(ap, with_force=False)
    ap.add_argument("--mkfs", action="store_true", help="先建立卷")
    ap.add_argument("--chunk", default="4K", help="配合 --mkfs：分配单位")
    ap.add_argument("--policy", type=int, default=3, help="配合 --mkfs：分配策略")
    ap.add_argument("--logical-origin", default="0", help="配合 --mkfs：逻辑坐标起点")
    ap.add_argument("--force", action="store_true", help="默认覆盖已存在的文件")
    ap.add_argument("--io-chunk", "--put-chunk", dest="io_chunk", default="8M",
                    help="上传/下载的分块大小，默认 8M")
    ap.add_argument("--script", help="从文件读命令，执行完退出（批处理）")
    args = ap.parse_args(argv)

    try:
        dev, desc = easyfs_device.open_device(args, create_size=64 << 20)
        if args.mkfs:
            r = easyfs.mkfs(device=dev,
                            chunk=parse_size(args.chunk),
                            policy=args.policy,
                            logical_origin=parse_size(args.logical_origin))
            print("已建立卷: %s  (%s)" % (desc, human(r["region_len"])))
        sh = Shell(dev, desc, overwrite=args.force,
                   io_chunk=parse_size(args.io_chunk))
    except ERRORS as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    try:
        if args.script:
            with open(args.script) as f:
                for line in f:
                    if not sh.run_line(line):
                        break
        else:
            sh.banner()
            while True:
                try:
                    line = input("easyfs:%s> " % sh._rdisp())
                except EOFError:
                    print("")
                    break
                if not sh.run_line(line):
                    break
    finally:
        sh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
