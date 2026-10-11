#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 网络服务器：把 EasyFS 卷通过 HTTP / WebDAV-lite 暴露到局域网

这是**外层工具**之一（核心是 ``easyfs.py`` 与 ``easyfs_device.py``）。
也可以用统一入口：``python3 python/tool.py server <同样的参数>``。

用法::

    python3 python/tool-server.py --file disk.img --port 8080
    python3 python/tool-server.py --file disk.img --mkfs --size 64M
    python3 python/tool-server.py --vdisk vm.vhd --part 1 --port 8080
    python3 python/tool-server.py --mem 64M --port 8080        # 内存卷，演示用
    python3 python/tool-server.py --file disk.img --port 8080 --user alice --pass secret
    python3 python/tool-server.py --file disk.img --ro          # 只读（不写位图、不置 dirty）

浏览器打开 ``http://<本机ip>:8080/`` 就能浏览、下载、上传；也可以用::

    curl -T 本地文件  http://<ip>:8080/远端路径      # 上传（PUT）
    curl -O          http://<ip>:8080/远端路径/文件  # 下载
    curl -X MKCOL    http://<ip>:8080/新目录         # 建目录
    curl -X MOVE -H 'Destination: /新名字' http://<ip>:8080/旧名字
    curl -X DELETE   http://<ip>:8080/路径           # 删文件（目录加 ?recursive=1）

**断点续传**（两个方向都有）::

    # 下载：支持 Range，返回 206 + Content-Range；越界 416
    curl -r 1000000-  http://<ip>:8080/大文件 -o 后半段
    # 上传：支持 Content-Range，从指定偏移续写（远端大小必须正好等于起点）
    curl -H 'Content-Range: bytes 1000000-2999999/3000000' -T 后半段 http://<ip>:8080/大文件

响应体是**流式**发送的（每次读一块，大小由 ``--io-chunk`` 决定），上传也是边收边写，
所以大文件不会整个进内存。

另外实现了最小的 WebDAV（OPTIONS / PROPFIND / MKCOL / MOVE / DELETE），
macOS Finder、Linux 的 davfs2/gvfs 可以**只读挂载**这个卷。

受限/已知缺口：没有 HTTPS（Basic 认证是明文）、不支持 LOCK（Windows 资源管理器挂不上）、
只有全局只读开关没有目录级权限。

⚠ 卷是**单写者**设计（无日志、无并发保护），所以本服务器用一把全局锁把所有
   文件系统操作串行化：慢速下载期间别的请求会排队。这是有意为之。

格式层在 ``easyfs.py``；本文件只是薄壳。
"""

import argparse
import base64
import html
import mimetypes
import os
import signal
import socketserver
import sys
import threading
import time
import urllib.parse
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import easyfs
import easyfs_device
from easyfs import (EasyFSError, PathWalker, Volume, entry_mtime, human,
                    parse_size)
from easyfs_device import EasyFSDeviceError

VOL = None                  # 挂载好的卷（所有访问都在 LOCK 里）
LOCK = threading.RLock()    # 单写者：一把锁串行化所有 FS 操作
OPTS = None

PAGE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EasyFS __PATHTXT__</title>
<style>
 body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;margin:2em;max-width:72em}
 h2{margin:0 0 .2em} table{border-collapse:collapse;width:100%}
 td,th{padding:4px 14px 4px 0;text-align:left;border-bottom:1px solid #eee}
 th{border-bottom:2px solid #ccc} .d{font-weight:600} .s{color:#666;font-size:.9em}
 #bar{margin:1em 0;padding:.7em;background:#f4f4f4;border-radius:6px}
 .num{text-align:right;color:#666}
</style>
<h2>EasyFS <code>__PATHTXT__</code></h2>
<p class="s">__INFO__</p>
<div id="bar">
  <input type="file" id="f" multiple>
  <button onclick="up()">上传到当前目录</button>
  <span id="st" class="s"></span>
</div>
<table>
<tr><th>名字</th><th class="num">大小</th><th>类型</th></tr>
__ROWS__
</table>
<p class="s">GET 下载 · PUT 上传（<code>curl -T</code>）· MKCOL 建目录 ·
MOVE 改名 · DELETE 删除（目录加 <code>?recursive=1</code>）</p>
<script>
async function up(){
  var fs=document.getElementById('f').files, st=document.getElementById('st'), i;
  if(!fs.length){ st.textContent='先选文件'; return; }
  for(i=0;i<fs.length;i++){
    st.textContent='上传 '+(i+1)+'/'+fs.length+'：'+fs[i].name+' ...';
    try{
      var r=await fetch('__PATHURL__'+encodeURIComponent(fs[i].name)+'?overwrite=1',
                        {method:'PUT',body:fs[i]});
      if(!r.ok){ st.textContent='失败 '+r.status+'：'+(await r.text()); return; }
    }catch(e){ st.textContent='失败：'+e; return; }
  }
  st.textContent='完成，刷新中 ...';
  location.reload();
}
</script>
"""


def _q(path):
    return urllib.parse.quote(path, safe="/")


def render_page(vol, names, head_off):
    base = "/" + "/".join(names) if names else ""
    rows = []
    if names:
        parent = "/" + "/".join(names[:-1]) if len(names) > 1 else "/"
        rows.append('<tr><td class="d"><a href="%s">..</a></td>'
                    '<td class="num"></td><td>目录</td></tr>' % _q(parent))
    for e in sorted(vol.read_dir(head_off), key=lambda x: x["name"]):
        nm = e["name"].decode("utf-8", "replace")
        isdir = e["kind"] == "dir"
        href = _q(base + "/" + nm) + ("/" if isdir else "")
        rows.append('<tr><td class="d"><a href="%s">%s</a></td>'
                    '<td class="num">%s</td><td>%s</td></tr>'
                    % (href, html.escape(nm) + ("/" if isdir else ""),
                       "" if isdir else human(e["size"]),
                       "目录" if isdir else "文件"))
    disp = (base + "/") if base else "/"
    info = "空闲 %s / %s　·　%s" % (human(vol.free_bytes()), human(vol.data_bytes),
                                    "只读模式" if OPTS.ro else "可读写")
    page = PAGE.replace("__PATHTXT__", html.escape(disp))
    page = page.replace("__PATHURL__", _q(disp))
    page = page.replace("__INFO__", info)
    page = page.replace("__ROWS__", "\n".join(rows))
    return page


def propfind_xml(items):
    """最小 PROPFIND 响应（够 Finder / davfs2 只读挂载）。"""
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<D:multistatus xmlns:D="DAV:">']
    for href, is_dir, size, mtime in items:
        out.append('<D:response><D:href>%s</D:href><D:propstat><D:prop>'
                   % html.escape(href))
        if is_dir:
            out.append('<D:resourcetype><D:collection/></D:resourcetype>')
        else:
            out.append('<D:resourcetype/>')
            out.append('<D:getcontentlength>%d</D:getcontentlength>' % size)
        if mtime:
            out.append('<D:getlastmodified>%s</D:getlastmodified>'
                       % formatdate(mtime, usegmt=True))
        leaf = urllib.parse.unquote(href.rstrip("/").rsplit("/", 1)[-1]) or "/"
        out.append('<D:displayname>%s</D:displayname>' % html.escape(leaf))
        out.append('</D:prop><D:status>HTTP/1.1 200 OK</D:status>'
                   '</D:propstat></D:response>')
    out.append('</D:multistatus>')
    return "".join(out).encode("utf-8")


class Handler(BaseHTTPRequestHandler):

    server_version = "EasyFS"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ 基础设施

    def log_message(self, fmt, *args):
        pass                                  # 用 _send 里的统一日志

    def _log(self, code):
        print("%s %-7s %-40s -> %s" % (time.strftime("%H:%M:%S"), self.command,
                                       self.path[:40], code))

    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8",
              extra=None, length=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length",
                             str(len(body) if length is None else length))
            self.send_header("Connection", "close")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True
        self._log(code)

    @staticmethod
    def _parse_range(header, total):
        """解析 ``Range: bytes=a-b``，返回闭区间 ``(start, end)``。

        支持 ``a-b`` / ``a-`` / ``-n``（最后 n 字节）。没有这个头或看不懂就返回 None
        （按整份处理）；越界抛 ValueError（→ 416）。
        """
        if not header or not header.lower().startswith("bytes="):
            return None
        spec = header[6:].split(",")[0].strip()
        if "-" not in spec:
            return None
        first, last = spec.split("-", 1)
        try:
            if first == "":
                n = int(last)
                if n <= 0:
                    raise ValueError
                start, end = max(0, total - n), total - 1
            else:
                start = int(first)
                end = int(last) if last else total - 1
        except ValueError:
            return None
        end = min(end, total - 1)
        if start < 0 or start > end or start >= total:
            raise ValueError("范围不可满足")
        return start, end

    def _401(self):
        self._send(401, "需要认证\n",
                   extra={"WWW-Authenticate": 'Basic realm="EasyFS"'})

    def _authorized(self):
        if not OPTS.user:
            return True
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(h[6:].strip()).decode("utf-8")
            user, passwd = raw.split(":", 1)
        except Exception:
            return False
        return user == OPTS.user and passwd == OPTS.passwd

    def _target(self):
        u = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(u.path) or "/"
        return path, urllib.parse.parse_qs(u.query)

    def _fs_error(self, e):
        if isinstance(e, easyfs.EasyFSFragmented) or "ENOSPC" in str(e):
            return self._send(507, "%s\n" % e)
        self._send(500, "%s\n" % e)

    # ------------------------------------------------------------ 读

    def do_GET(self):
        self._get()

    def do_HEAD(self):
        self._get(head=True)

    def _get(self, head=False):
        if not self._authorized():
            return self._401()
        path, query = self._target()
        try:
            with LOCK:
                w = PathWalker(VOL)
                kind = w.resolve_any(path)
                if kind[0] == "dir":
                    body = render_page(VOL, kind[1], kind[2][-1])
                    return self._send(200, b"" if head else body,
                                      "text/html; charset=utf-8")
                ent = kind[1]
                name = ent["name"].decode("utf-8", "replace")
                total = ent["size"]
                try:
                    rng = self._parse_range(self.headers.get("Range"), total)
                except ValueError:
                    return self._send(416, "范围不可满足\n",
                                      extra={"Content-Range":
                                             "bytes */%d" % total})
                start, end = rng if rng else (0, total - 1)
                length = (end - start + 1) if total else 0
                ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
                extra = {"Accept-Ranges": "bytes"}
                if "download" in query:
                    extra["Content-Disposition"] = (
                        'attachment; filename="%s"' % name.replace('"', ""))
                code = 200
                if rng:
                    code = 206
                    extra["Content-Range"] = ("bytes %d-%d/%d"
                                              % (start, end, total))
                # 手写响应头 + 分块流式发送（不再把整份读进内存）
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(length))
                self.send_header("Connection", "close")
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                if not head:
                    pos = start
                    while pos <= end:
                        n = min(OPTS.io_chunk, end - pos + 1)
                        chunk = VOL.read_range(ent, pos, n)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        pos += len(chunk)
                self.close_connection = True
                self._log(code)
                return
        except EasyFSError as e:
            return self._send(404, "404 %s\n" % e)
        except (BrokenPipeError, ConnectionResetError):
            return

    # ------------------------------------------------------------ 写

    def do_PUT(self):
        self._put()

    def do_POST(self):
        self._put()

    def _put(self):
        if not self._authorized():
            return self._401()
        if OPTS.ro:
            return self._send(403, "只读模式\n")
        path, query = self._target()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, "Content-Length 非法\n")
        if self.headers.get("Expect", "").lower() == "100-continue":
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            self.wfile.flush()
        overwrite = ("overwrite" in query) or OPTS.force
        # 断点续传上传：Content-Range: bytes <start>-<end>/<total>
        start = 0
        crange = self.headers.get("Content-Range")
        if crange:
            try:
                spec = crange.split(" ", 1)[1].split("/")[0]
                start = int(spec.split("-")[0])
            except Exception:
                return self._send(400, "Content-Range 非法\n")
        t0 = time.time()
        try:
            with LOCK:
                w = PathWalker(VOL)
                poff, name, ent = w.entry_pos(path)
                if start:
                    # 续传：远端必须已存在，且大小正好等于 start
                    if ent is None:
                        return self._send(409, "续传目标不存在（先从头传）\n")
                    if ent["kind"] != "file":
                        return self._send(405, "目标是目录\n")
                    if ent["size"] != start:
                        return self._send(409, "远端已有 %d 字节，与 Content-Range 起点 %d 不符\n"
                                          % (ent["size"], start))
                    self._stream(poff, name, length, offset=start)
                elif ent is not None:
                    if ent["kind"] == "dir":
                        return self._send(405, "目标是目录\n")
                    if not overwrite:
                        return self._send(409, "已存在（加 ?overwrite=1 或 --force）\n")
                    # 覆盖：先写到临时名字，成功后再替换 —— 上传中断不会毁掉旧文件
                    tmp = ".easyfs-upload-%d" % (int(time.time() * 1000) & 0xFFFFFF)
                    self._stream(poff, tmp, length)
                    VOL.commit()
                    VOL.delete(poff, name)
                    VOL.move(poff, tmp, poff, name)
                else:
                    self._stream(poff, name, length)
                VOL.commit()
        except EasyFSError as e:
            return self._fs_error(e)
        except (BrokenPipeError, ConnectionResetError):
            return
        self._send(201, "写入 %d 字节，%.2fs\n" % (length, time.time() - t0))

    def _stream(self, poff, name, length, offset=None):
        """把请求体写进 `(poff, name)`。

        `offset` 给定时是**续传**：直接写进已有文件的那个位置（段内直接写裸数据块）。
        否则从头写：≤255 B 走 DATA_TINY，更长则分块追加。
        """
        if offset:
            done, left = offset, length
            while left > 0:
                buf = self.rfile.read(min(OPTS.io_chunk, left))
                if not buf:
                    break
                VOL.write(poff, name, buf, offset=done)
                done += len(buf)
                left -= len(buf)
            if left:
                raise EasyFSError("上传中断：还差 %d 字节" % left)
            return
        if length <= 255:
            VOL.create(poff, name, data=self.rfile.read(length))
            return
        VOL.create(poff, name)
        left = length
        while left > 0:
            buf = self.rfile.read(min(OPTS.io_chunk, left))
            if not buf:
                break
            VOL.write(poff, name, buf)
            left -= len(buf)
        if left:
            raise EasyFSError("上传中断：还差 %d 字节" % left)

    def do_DELETE(self):
        if not self._authorized():
            return self._401()
        if OPTS.ro:
            return self._send(403, "只读模式\n")
        path, query = self._target()
        try:
            with LOCK:
                w = PathWalker(VOL)
                poff, name, ent = w.entry_pos(path)
                if ent is None:
                    return self._send(404, "找不到\n")
                recursive = "recursive" in query
                if ent["kind"] == "dir" and not recursive:
                    return self._send(409, "目录需要加 ?recursive=1\n")
                VOL.delete(poff, name, recursive=recursive)
                VOL.commit()
        except EasyFSError as e:
            return self._fs_error(e)
        self._send(204, b"")

    def do_MKCOL(self):
        if not self._authorized():
            return self._401()
        if OPTS.ro:
            return self._send(403, "只读模式\n")
        path, query = self._target()
        try:
            with LOCK:
                w = PathWalker(VOL)
                poff, name, ent = w.entry_pos(path)
                if ent is not None:
                    return self._send(405, "已存在\n")
                VOL.mkdir(poff, name)
                VOL.commit()
        except EasyFSError as e:
            return self._fs_error(e)
        self._send(201, "目录已建\n")

    def do_MOVE(self):
        if not self._authorized():
            return self._401()
        if OPTS.ro:
            return self._send(403, "只读模式\n")
        dest = self.headers.get("Destination")
        if not dest:
            return self._send(400, "缺少 Destination 头\n")
        src = self._target()[0]
        dpath = urllib.parse.unquote(urllib.parse.urlsplit(dest).path)
        try:
            with LOCK:
                w = PathWalker(VOL)
                spoff, sname, sent = w.entry_pos(src)
                if sent is None:
                    return self._send(404, "找不到源\n")
                dpoff, dname, dent = w.entry_pos(dpath)
                if dent is not None:
                    return self._send(412, "目标已存在\n")
                VOL.move(spoff, sname, dpoff, dname)
                VOL.commit()
        except EasyFSError as e:
            return self._fs_error(e)
        self._send(201, "已移动\n")

    # ------------------------------------------------------------ WebDAV-lite

    def do_OPTIONS(self):
        self._send(200, b"", extra={
            "Allow": "GET, HEAD, PUT, POST, DELETE, MKCOL, MOVE, OPTIONS, PROPFIND",
            "DAV": "1",
        })

    def do_PROPFIND(self):
        if not self._authorized():
            return self._401()
        depth = (self.headers.get("Depth") or "1").strip()
        path, query = self._target()
        items = []
        try:
            with LOCK:
                w = PathWalker(VOL)
                kind = w.resolve_any(path)
                if kind[0] == "dir":
                    names, offs = kind[1], kind[2]
                    base = "/" + "/".join(names)
                    items.append((_q(base + "/"), True, 0, 0))
                    if depth != "0":
                        for e in VOL.read_dir(offs[-1]):
                            nm = e["name"].decode("utf-8", "replace")
                            if e["kind"] == "dir":
                                items.append((_q(base + "/" + nm) + "/", True, 0,
                                              entry_mtime(e)))
                            else:
                                items.append((_q(base + "/" + nm), False,
                                              e["size"], entry_mtime(e)))
                else:
                    ent = kind[1]
                    items.append((_q(path), False, ent["size"], entry_mtime(ent)))
        except EasyFSError as e:
            return self._send(404, "404 %s\n" % e)
        self._send(207, propfind_xml(items), "application/xml; charset=utf-8")


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def local_ips():
    ips = set()
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        import socket
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(i for i in ips if not i.startswith("127."))


def main(argv=None):
    import sys as _sys
    if "--object" in (_sys.argv[1:] if argv is None else argv):
        print("error: --object（对象形态写入）尚未实现；v0 只产出 ①②③",
              file=_sys.stderr)
        return 2
    global VOL, OPTS
    ap = argparse.ArgumentParser(prog="tool-server.py",
                                 description="把 EasyFS 卷通过 HTTP 暴露到局域网")
    easyfs_device.add_device_args(ap)
    easyfs_device.add_disk_safety_args(ap, with_force=False)
    ap.add_argument("--bind", default="0.0.0.0", help="监听地址，默认 0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--mkfs", action="store_true", help="先建立卷")
    ap.add_argument("--chunk", default="4K", help="配合 --mkfs：分配单位")
    ap.add_argument("--policy", type=int, default=3)
    ap.add_argument("--logical-origin", default="0")
    ap.add_argument("--ro", action="store_true", help="只读（不置 dirty、不重建位图）")
    ap.add_argument("--force", action="store_true", help="PUT 默认覆盖已存在文件")
    ap.add_argument("--user", help="HTTP Basic 用户名")
    ap.add_argument("--pass", dest="passwd", help="HTTP Basic 密码")
    ap.add_argument("--io-chunk", "--upload-chunk", dest="io_chunk", default="8M",
                    help="上传/下载/流式的分块大小，默认 8M")
    args = ap.parse_args(argv)
    OPTS = args
    OPTS.io_chunk = parse_size(args.io_chunk)
    if args.user and not args.passwd:
        ap.error("--user 需要同时给 --pass")

    try:
        dev, desc = easyfs_device.open_device(args, create_size=64 << 20,
                                              read_only=args.ro)
        if args.mkfs:
            r = easyfs.mkfs(device=dev,
                            chunk=parse_size(args.chunk),
                            policy=args.policy,
                            logical_origin=parse_size(args.logical_origin))
            print("已建立卷: %s (%s)" % (desc, human(r["region_len"])))
        VOL = Volume.mount(dev)
        OPTS.desc = desc
    except (EasyFSError, EasyFSDeviceError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    if not args.ro:
        if VOL.is_dirty():
            print("[!] 位图 dirty（上次非正常卸载）→ 重建 ...")
            before, after = VOL.rebuild_bitmap(apply=True)
            print("    重建完成: 可达 used %d（重建前 %d）" % (after, before))
        VOL.mark_dirty()

    try:
        httpd = Server((args.bind, args.port), Handler)
    except OSError as e:
        print("error: 无法监听 %s:%d —— %s" % (args.bind, args.port, e),
              file=sys.stderr)
        if not args.ro:
            VOL.mark_clean()
        dev.close()
        return 1

    print("EasyFS 网络服务器已启动%s" % ("（只读）" if args.ro else ""))
    print("  卷        %s" % getattr(OPTS, "desc", args.file or args.vdisk))
    print("  区域      %s   空闲 %s" % (human(VOL.region_len), human(VOL.free_bytes())))
    print("  数据区    %s = %d chunk   位图 %d 块"
          % (human(VOL.data_bytes), VOL.chunk_count, len(VOL.regions)))
    if args.user:
        print("  认证      HTTP Basic（用户 %s）" % args.user)
    for ip in local_ips():
        print("  访问      http://%s:%d/" % (ip, args.port))
    print("  本机      http://127.0.0.1:%d/" % args.port)
    print("  Ctrl-C 退出（会正常卸载）")

    def _bye(signum, frame):
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, _bye)
    except (ValueError, OSError):
        pass
    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n收到退出信号 ...")
    finally:
        httpd.server_close()
        try:
            if not args.ro:
                VOL.commit()
                VOL.mark_clean()
            VOL.dev.close()
        except Exception as e:
            print("卸载时出错: %s" % e, file=sys.stderr)
        print("已干净卸载")
    return 0


if __name__ == "__main__":
    sys.exit(main())
