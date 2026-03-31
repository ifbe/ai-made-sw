#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logintest 命令行客户端
python3 client.py --server 127.0.0.1 --port 9999
支持: login, login <username>, list
"""

import os
import sys
import json
import argparse
import socket
import hashlib
import hmac
import binascii
import base64
import struct
import secrets
import errno
import threading

IS_WINDOWS = sys.platform == 'win32'
if IS_WINDOWS:
    import msvcrt

WS_MAGIC = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
DEBUG = False

connected = False
ws_sock = None
recv_buf = b''

# 等待 challenge 的登录上下文
pending_auth = None

# 线程安全的消息队列
input_queue = []
queue_lock = threading.Lock()


def log(msg):
    print(msg)
    sys.stdout.flush()


def dbg(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


# ====== WebSocket 编解码 ======

def ws_handshake(sock, host, port):
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.send(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        try:
            d = sock.recv(4096)
        except Exception:
            d = b""
        if not d:
            return False
        resp += d
    return b"101 Switching Protocols" in resp


def ws_encode(payload_bytes):
    frame = bytearray()
    frame.append(0x81)
    n = len(payload_bytes)
    if n < 126:
        frame.append(0x80 | n)
    elif n < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack('>H', n))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack('>Q', n))
    mask = secrets.token_bytes(4)
    frame.extend(mask)
    for i in range(n):
        frame.append(payload_bytes[i] ^ mask[i % 4])
    return bytes(frame)


def ws_recv():
    global recv_buf
    if len(recv_buf) < 2:
        return None
    first, second = recv_buf[0], recv_buf[1]
    opcode = first & 0x0F
    masked = (second & 0x80) >> 7
    length = second & 0x7F
    offset = 2
    if length == 126:
        if len(recv_buf) < 4:
            return None
        length = struct.unpack('>H', recv_buf[2:4])[0]
        offset = 4
    elif length == 127:
        if len(recv_buf) < 10:
            return None
        length = struct.unpack('>Q', recv_buf[2:10])[0]
        offset = 10
    if masked:
        if len(recv_buf) < offset + 4:
            return None
        mask = recv_buf[offset:offset+4]
        offset += 4
    if len(recv_buf) < offset + length:
        return None
    payload = recv_buf[offset:offset+length]
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    recv_buf = recv_buf[offset+length:]
    if opcode == 0x8:
        return None
    if opcode == 0x1:
        return payload.decode('utf-8', errors='replace')
    return None


def ws_send(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    framed = ws_encode(data)
    sock.send(framed)
    dbg(f"[SEND] {json.dumps(obj)}")


# ====== 输入线程（Windows 专用） ======

def windows_input_thread():
    """Windows 下非阻塞读取键盘输入，放入队列"""
    while connected:
        if msvcrt.kbhit():
            try:
                line = sys.stdin.readline()
            except:
                line = ''
            if not line:
                with queue_lock:
                    input_queue.append(None)
                break
            with queue_lock:
                input_queue.append(line.strip())
        else:
            import time; time.sleep(0.05)


# ====== 帮助 ======

def print_help():
    log("=== logintest 客户端 ===")
    log("  login            - 交互式登录（提示输入用户名和密码）")
    log("  login <username> - 登录，随后提示输入密码")
    log("  list             - 发送 list")
    log("  help             - 显示帮助")
    log("  quit             - 退出")


# ====== 处理消息 ======

def handle_server_message(obj):
    global pending_auth

    if obj.get('type') == 'challenge':
        if pending_auth is None:
            log("收到 challenge，但没有待完成的登录，请先输入 login <username>")
            return
        username, = pending_auth  # pending_auth 现在是 (username,)
        challenge = obj.get('challenge', '')
        salt = obj.get('salt', '')
        password = input("密码: ").strip()
        if not password:
            pending_auth = None
            log("取消登录")
            return
        # SHA256(password + salt) -> HMAC(challenge)
        pw_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        response = hmac.new(
            binascii.unhexlify(pw_hash),
            binascii.unhexlify(challenge),
            hashlib.sha256
        ).hexdigest()
        ws_send(ws_sock, {
            "type": "login",
            "username": username,
            "response": response
        })
        pending_auth = None

    elif obj.get('type') == 'login_ok':
        log(f"登录成功: {obj.get('username', '')}")
    elif obj.get('type') == 'list_result':
        users = obj.get('users', [])
        if not users:
            log("(无在线用户)")
        for u in users:
            log(f"  {u.get('username',''):<16} {u.get('ip','')}:{u.get('port','')}")
    elif obj.get('type') == 'user_joined':
        log(f"+ 用户上线: {obj.get('username','')}")
    elif obj.get('type') == 'user_left':
        log(f"- 用户下线: {obj.get('username','')}")
    elif obj.get('type') == 'error':
        log(f"错误: {obj.get('message','')}")
    elif obj.get('type') == 'kicked':
        log(f"被踢: {obj.get('message','')}")
    else:
        log(f"[消息] {json.dumps(obj)}")


def process_input_line(line):
    global pending_auth
    parts = line.split(maxsplit=1)
    cmd = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else ''

    if cmd == 'quit':
        return False
    elif cmd == 'help':
        print_help()
    elif cmd == 'login':
        if not arg:
            username = input("用户名: ").strip()
            if not username:
                return True
        else:
            username = arg
        # 先发 login username，等收到 challenge 后再要密码
        pending_auth = (username,)
        ws_send(ws_sock, {"type": "login", "username": username})
        log(f"等待服务器验证...")
    elif cmd == 'list':
        ws_send(ws_sock, {"type": "list"})
    else:
        log(f"未知命令: {cmd}，输入 help")
    return True


# ====== 主循环 ======

def main():
    global connected, ws_sock, recv_buf, pending_auth, DEBUG

    parser = argparse.ArgumentParser(description='logintest 命令行客户端')
    parser.add_argument('--server', default='127.0.0.1', help='服务器地址')
    parser.add_argument('--port', type=int, default=9999, help='服务器端口')
    parser.add_argument('--debug', action='store_true', help='打印所有消息')
    args = parser.parse_args()
    DEBUG = args.debug

    # 建立 TCP 连接
    ws_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ws_sock.settimeout(10)
    try:
        ws_sock.connect((args.server, args.port))
    except Exception as e:
        log(f"连接失败: {e}")
        sys.exit(1)

    # WebSocket 握手
    if not ws_handshake(ws_sock, args.server, args.port):
        log("WebSocket 握手失败")
        ws_sock.close()
        sys.exit(1)

    ws_sock.setblocking(False)
    connected = True
    log(f"已连接至 {args.server}:{args.port}（输入 help 查看命令）")

    # Windows 启动输入线程
    input_t = None
    if IS_WINDOWS:
        input_t = threading.Thread(target=windows_input_thread, daemon=True)
        input_t.start()

    running = True
    while running:
        # ---- 接收网络数据 ----
        try:
            data = ws_sock.recv(4096)
        except socket.error as e:
            if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                if IS_WINDOWS:
                    data = b''
                else:
                    import time; time.sleep(0.05); data = b''
            elif e.args[0] == 10035:  # Windows WSAEWOULDBLOCK
                data = b''
            else:
                data = b''
        except Exception:
            data = b''

        if not data:
            import time; time.sleep(0.05)
        else:
            recv_buf += data

        # 解码完整帧
        while True:
            msg = ws_recv()
            if msg is None:
                break
            try:
                obj = json.loads(msg)
            except:
                obj = {"raw": msg}
            dbg(f"[RECV] {json.dumps(obj)}")
            handle_server_message(obj)

        # ---- 处理用户输入 ----
        line = None

        if IS_WINDOWS:
            with queue_lock:
                if input_queue:
                    line = input_queue.pop(0)
        else:
            import select
            try:
                r_stdin, _, _ = select.select([sys.stdin], [], [], 0)
                if sys.stdin in r_stdin:
                    line = sys.stdin.readline()
                    if not line:
                        line = None
                    else:
                        line = line.strip()
            except (OSError, IOError):
                pass

        if line is not None:
            if line == '':
                continue
            if line == None:
                running = False
                break
            keep = process_input_line(line)
            if not keep:
                running = False
                break

    connected = False
    try:
        ws_sock.close()
    except:
        pass
    log("已退出")


if __name__ == '__main__':
    main()
