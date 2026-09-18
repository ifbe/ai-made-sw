#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""棋类 App 的局域网中继服务端：HTTP 静态页 + WebSocket 转发，同一个地址端口。

用法：

    python3 server.py                                  # 0.0.0.0:8765
    python3 server.py --addr 192.168.1.7 --port 9000    # 只绑 192.168.1.7 这块网卡
    python3 server.py -a 127.0.0.1 -p 8765

和 Android 端（``android/.../net/ws/WsSession.kt``）的约定：

* **HTTP**：把 ``static/`` 里的 html / js / css 发给浏览器，``/`` 默认给 ``index.html``；
* **WebSocket**：任何路径都能升级（Android 客机连的是 ``ws://host:port``，路径就是 ``/``）。
  除了握手和 ping / pong，服务端**不解析、不缓存、不产生**任何棋类消息 ——
  ``a`` 发来的每一帧原样转发给 **b、c**（所有其它连接），不回给发送者。

只用到 Python 标准库，没有第三方依赖（Python 3.6+ 可直接跑）。

注意：**必须用 Python 3**。Ubuntu 上 `python` 往往还是 Python 2.7，
而 Python 2 里这个模块叫 `SocketServer`、也没有 `http.server`，所以
`python server.py` 会报 `ImportError: No module named socketserver`；
`pip install socketserver` 也没用（它是标准库，不是 PyPI 上的包）。
请用 `python3 server.py`，或者直接 `./server.py`（shebang 已经指向 python3）。
"""

import sys

# 在导入别的模块之前先拦一下 Python 2，给一句人话而不是一串 ImportError。
if sys.version_info[0] < 3:
    sys.stderr.write(
        "server.py 需要 Python 3，但当前解释器是 Python %s。\n"
        "请改用：  python3 server.py --addr 0.0.0.0 --port 8765\n"
        "（`python` 在这台机器上是 Python 2.7；也没有 pip 包可装，socketserver 是标准库）\n"
        % sys.version.split()[0]
    )
    raise SystemExit(1)

import argparse
import base64
import hashlib
import os
import posixpath
import socket
import socketserver
import struct
import threading
import time
from http import server as http_server
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------- 常量

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

CONTINUE = 0x0
FINISH = 0x80

#: 单帧上限，防止一个畸形长度把内存吃光（棋盘报文只有几十字节）。
MAX_PAYLOAD = 4 * 1024 * 1024

DEFAULT_PORT = 8765
VERBOSE = False

#: 静态目录，main() 里按脚本位置设好。
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".webp": "image/webp",
}


def log(message):
    """一条带时间的控制台日志；跟 Android 端右下角日志框的格式保持一致。"""
    sys.stdout.write("%s  %s\n" % (time.strftime("%H:%M:%S"), message))
    sys.stdout.flush()


def local_ipv4():
    """本机默认出口网卡的 IPv4（连不上外网时返回 None）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.2)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


# ------------------------------------------------------------------ WebSocket 帧


class ConnectionClosed(Exception):
    """对端断开或数据读完了。"""


class FrameError(Exception):
    """报文不合法（长度越界、帧结构坏掉）。"""


def encode_frame(opcode, payload):
    """服务端 → 客户端的帧（不加掩码）。"""
    header = bytearray()
    header.append(FINISH | opcode)
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header += struct.pack("!H", length)
    else:
        header.append(127)
        header += struct.pack("!Q", length)
    return bytes(header) + payload


def read_exact(rfile, size):
    """一定要读满 size 个字节，否则说明连接断了。"""
    if size == 0:
        return b""
    data = rfile.read(size)
    if not data or len(data) < size:
        raise ConnectionClosed()
    return data


def read_frame(rfile):
    """读一帧，返回 (fin, opcode, payload)。客户端来的帧一定带掩码。"""
    first, second = read_exact(rfile, 2)
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(rfile, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(rfile, 8))[0]
    if length > MAX_PAYLOAD:
        raise FrameError("帧太大：%d 字节" % length)

    mask = read_exact(rfile, 4) if masked else None
    payload = read_exact(rfile, length) if length else b""
    if mask:
        payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    return fin, opcode, payload


# ---------------------------------------------------------------------- 连接


class Client(object):
    """一条已经升级成 WebSocket 的连接。"""

    def __init__(self, sock, rfile, address, user_agent):
        self.sock = sock
        self.rfile = rfile
        self.address = address
        self.user_agent = user_agent
        self._send_lock = threading.Lock()
        self._closed = False

    def label(self):
        return "%s:%s" % (self.address[0], self.address[1])

    def send_frame(self, opcode, payload):
        with self._send_lock:
            if self._closed:
                return False
            try:
                self.sock.sendall(encode_frame(opcode, payload))
                return True
            except OSError:
                self._closed = True
                return False

    def send_close(self, code=1000, reason=""):
        payload = struct.pack("!H", code) + reason.encode("utf-8")[:123]
        self.send_frame(OP_CLOSE, payload)

    def mark_closed(self):
        with self._send_lock:
            self._closed = True


class Relay(object):
    """连着的所有 WebSocket 连接：加进来、踢出去、把消息发给除发送者外的所有人。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._clients = []

    def add(self, client):
        with self._lock:
            self._clients.append(client)
            return len(self._clients)

    def remove(self, client):
        client.mark_closed()
        with self._lock:
            if client in self._clients:
                self._clients.remove(client)
            return len(self._clients)

    def count(self):
        with self._lock:
            return len(self._clients)

    def broadcast(self, sender, opcode, payload):
        """把 sender 的一帧发给其它所有连接，返回成功送达的连接数。"""
        with self._lock:
            targets = [c for c in self._clients if c is not sender]
        delivered = 0
        for client in targets:
            if client.send_frame(opcode, payload):
                delivered += 1
        return delivered


RELAY = Relay()


# ---------------------------------------------------------------------- HTTP


class ChessHandler(http_server.BaseHTTPRequestHandler):
    """静态文件 + WebSocket 升级，一个 handler 全包了。"""

    protocol_version = "HTTP/1.1"
    server_version = "ChessRelay/1.0"

    # BaseHTTPRequestHandler 默认往 stderr 打日志，这里改成我们自己的格式。
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            self.handle_websocket()
            return
        self.serve_static(head_only=False)

    def do_HEAD(self):
        self.serve_static(head_only=True)

    # ---------------------------------------------------------- 静态文件

    def serve_static(self, head_only):
        path = unquote(urlparse(self.path).path)
        if path == "" or path.endswith("/"):
            path += "index.html"
        path = posixpath.normpath(path).lstrip("/")
        if path.startswith("..") or os.path.isabs(path):
            self.send_simple(404, "404", "路径不合法")
            return

        full = os.path.join(STATIC_DIR, *path.split("/"))
        if not os.path.isfile(full):
            self.send_simple(404, "404", "没有这个文件：/%s" % path)
            return

        try:
            with open(full, "rb") as handle:
                body = handle.read()
        except OSError as ex:
            self.send_simple(500, "500", "读文件失败：%s" % ex)
            return

        content_type = CONTENT_TYPES.get(os.path.splitext(full)[1].lower(), "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def send_simple(self, code, title, message):
        body = (
            "<!doctype html><meta charset='utf-8'>"
            "<title>%s</title>"
            "<body style='background:#000;color:#d8e8ff;font-family:sans-serif'>"
            "<h1>%s</h1><p>%s</p></body>" % (title, title, message)
        ).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    # ---------------------------------------------------------- WebSocket

    def handle_websocket(self):
        key = self.headers.get("Sec-WebSocket-Key")
        path = urlparse(self.path).path or "/"
        user_agent = self.headers.get("User-Agent") or ""
        if not key:
            self.send_simple(400, "400", "缺少 Sec-WebSocket-Key，不是合法的 WebSocket 握手")
            return

        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("utf-8")).digest()
        ).decode("ascii")
        self.wfile.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n"
                "\r\n" % accept
            ).encode("utf-8")
        )
        self.wfile.flush()
        # 升级之后这个 socket 就归我们自己读了，不要再当 HTTP 连接复用。
        self.close_connection = True

        client = Client(self.connection, self.rfile, self.client_address, user_agent)
        count = RELAY.add(client)
        # 用 nc / curl 之类不是 WebSocket 的客户端试探时（见 gotcha.md 第 8 条），
        # 这两行日志能证明「服务端确实收到了握手」。
        log("收到握手请求 %s：%s，UA=%s" % (client.label(), path, user_agent or "(无)"))
        log("客户端接入 %s，当前 %d 个" % (client.label(), count))

        try:
            self.pump(client)
        except (ConnectionClosed, FrameError) as ex:
            if VERBOSE and str(ex):
                log("%s 断开：%s" % (client.label(), ex))
        except OSError as ex:
            if VERBOSE:
                log("%s socket 出错：%s" % (client.label(), ex))
        finally:
            remaining = RELAY.remove(client)
            log("客户端断开 %s，当前 %d 个" % (client.label(), remaining))

    def pump(self, client):
        """把这条连接上收到的每一帧，原样转发给其它连接。"""
        buffer = b""
        buffer_opcode = None

        while True:
            fin, opcode, payload = read_frame(client.rfile)

            if opcode == OP_CLOSE:
                client.send_close()
                return
            if opcode == OP_PING:
                client.send_frame(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue

            if opcode == OP_CONT:
                if buffer_opcode is None:
                    raise FrameError("没有开头的续帧")
                buffer += payload
            else:
                buffer_opcode = opcode
                buffer = payload

            if not fin:
                continue

            data = buffer
            kind = buffer_opcode
            buffer = b""
            buffer_opcode = None

            delivered = RELAY.broadcast(client, kind, data)
            if VERBOSE:
                log(
                    "转发一帧（%d 字节，类型 %s）给 %d 个连接"
                    % (len(data), "文本" if kind == OP_TEXT else "二进制", delivered)
                )


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http_server.HTTPServer):
    daemon_threads = True
    # 关掉再开立刻重绑同一个端口（见 gotcha.md 第 3 条）。
    allow_reuse_address = True


# ---------------------------------------------------------------------- main


def main(argv=None):
    global STATIC_DIR, VERBOSE

    parser = argparse.ArgumentParser(
        description="棋类 App 的 HTTP + WebSocket 中继服务端（纯标准库，HTTP 和 WS 同一个端口）",
    )
    parser.add_argument(
        "--addr", "-a", default="0.0.0.0",
        help="监听地址（默认 0.0.0.0 所有网卡；填 192.168.x.x 就只绑那块网卡）",
    )
    parser.add_argument(
        "--port", "-p", type=int, default=DEFAULT_PORT,
        help="监听端口（默认 %d，和 Android 端一致）" % DEFAULT_PORT,
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="把每一帧的转发也打到控制台（默认只记连接 / 断开）",
    )
    args = parser.parse_args(argv)

    if not 0 < args.port < 65536:
        parser.error("端口要在 1..65535 之间")

    VERBOSE = args.verbose
    STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    if not os.path.isdir(STATIC_DIR):
        log("警告：找不到静态目录 %s（HTTP 会全 404）" % STATIC_DIR)

    try:
        server = ThreadingHTTPServer((args.addr, args.port), ChessHandler)
    except OSError as ex:
        log("启动失败：绑定 %s:%d 出错（%s）" % (args.addr, args.port, ex))
        return 1

    bound_host, bound_port = server.server_address[0], server.server_address[1]
    log("服务已启动，实际监听 %s:%d" % (bound_host, bound_port))
    log("静态目录：%s" % STATIC_DIR)
    if args.addr in ("0.0.0.0", "::", ""):
        ip = local_ipv4()
        if ip:
            log("局域网地址：http://%s:%d/ （Android 客机填 %s:%d）" % (ip, bound_port, ip, bound_port))
    log("浏览器打开 http://%s:%d/  （Ctrl+C 停止）" % ("127.0.0.1" if args.addr == "0.0.0.0" else args.addr, bound_port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("收到 Ctrl+C，正在停止…")
    finally:
        server.server_close()
        log("已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
