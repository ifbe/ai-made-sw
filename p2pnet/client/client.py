#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet 命令行客户端
python3 client.py --server 127.0.0.1 --port 10000
支持: login, login <username>, list, p2pudp
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

# 后台 UDP hello 线程
udp_hello_running = False
udp_hello_thread = None
udp_hello_sock = None
if IS_WINDOWS:
    import msvcrt

WS_MAGIC = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
DEBUG = False

connected = False
ws_sock = None
recv_buf = b''

# 等待 challenge 的登录上下文
pending_auth = None
logged_in_user = None

# 服务器地址（主循环设置，handle_server_message 读取）
SERVER_IP = None
SERVER_PORT = None

# 本地模式：
#   None        -> fake（默认）
#   'auto'      -> auto（tun→tap→fake）
#   'tun' / 'tap' -> clientsocket（子进程连 client.py 的 Unix socket）
LOCAL_MODE = None  # 初始为 fake
LOCAL_DEVICE = None  # 设备名，如 '/dev/utun3'（仅展示用）

# 线程安全的消息队列
input_queue = []
queue_lock = threading.Lock()


def ts():
    import time as _time
    return _time.strftime("%H:%M:%S")

def log(msg):
    print(f"[{ts()}][client] {msg}")
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


# ====== UDP Hello 后台线程 ======

def start_udp_hello(server_ip, server_udp_port, username, local_port):
    """后台线程：持续往服务器 UDP 端口发 hello，直到 stop_udp_hello 被调用"""
    global udp_hello_running, udp_hello_sock
    import time

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', local_port))
    except Exception:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))
    local_bound_port = sock.getsockname()[1]
    udp_hello_sock = sock
    udp_hello_running = True
    log(f"[UDP hello] 开始，往 {server_ip}:{server_udp_port} 发送 hello (本地端口 {local_bound_port})")

    while udp_hello_running:
        try:
            msg = json.dumps({'type': 'p2pudp_hello', 'username': username}).encode()
            sock.sendto(msg, (server_ip, server_udp_port))
        except Exception as e:
            pass
        time.sleep(1)

    sock.close()
    log("[UDP hello] 已停止")


def stop_udp_hello():
    global udp_hello_running, udp_hello_sock, udp_hello_thread
    udp_hello_running = False
    if udp_hello_thread:
        udp_hello_thread.join(timeout=2)
        udp_hello_thread = None
    if udp_hello_sock:
        try:
            udp_hello_sock.close()
        except:
            pass
        udp_hello_sock = None


def start_udp_hello_thread(server_ip, server_udp_port, username):
    """启动 UDP hello 线程，使用随机可用端口"""
    import threading
    import random
    local_port = random.randint(50000, 65000)
    t = threading.Thread(target=start_udp_hello, args=(server_ip, server_udp_port, username, local_port), daemon=True)
    t.start()
    global udp_hello_thread
    udp_hello_thread = t
    return t

def print_help():
    log("=== p2pnet 客户端 ===")
    log("  login            - 交互式登录（提示输入用户名和密码）")
    log("  login <username> - 登录，随后提示输入密码")
    log("  list             - 发送 list")
    log("  p2pudp <user>   - 请求与对方建立 UDP P2P 连接")
    log("  p2ptcp <user>   - 请求与对方建立 TCP P2P 连接")
    log("  local            - 显示当前模式")
    log("  local fake       - 模式: fake（子进程独立 tun，不汇入 client.py）")
    log("  local tun [dev] - 模式: clientsocket（子进程汇入 client.py）")
    log("  local tap [dev] - 模式: clientsocket（子进程汇入 client.py）")
    log("  local auto      - 模式: auto（tun→tap→fake）")
    log("  help            - 显示帮助")
    log("  quit             - 退出")


# ====== 处理消息 ======

def handle_server_message(obj):
    global pending_auth, logged_in_user

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
        logged_in_user = obj.get('username', '')
        log(f"登录成功: {logged_in_user}")
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
        logged_in_user = None
        stop_udp_hello()
        log(f"被踢: {obj.get('message','')}")
    elif obj.get('type') == 'incoming_p2pudp':
        from_user = obj.get('from_username', '')
        log(f"⚠️  {from_user} 请求和你建立 UDP P2P 连接，输入 p2pudp {from_user} 回应")
    elif obj.get('type') == 'send_udp_to_server':
        udpport = obj.get('udpport', 9999)
        log(f"[P2P] 服务器要求往 UDP {udpport} 发包，开始 UDP hello...")
        # 启动 UDP hello 线程
        start_udp_hello_thread(SERVER_IP, udpport, logged_in_user)
    elif obj.get('type') == 'thisisyourpeer_udp':
        peer_name = obj.get('name', '')
        peer_ip = obj.get('ip', '')
        peer_port = obj.get('port', 0)
        log(f"[P2P] 收到对端 {peer_name} 地址: {peer_ip}:{peer_port}，停止 UDP hello，启动 udp.py...")
        hello_port = udp_hello_sock.getsockname()[1] if udp_hello_sock else 0
        stop_udp_hello()
        import subprocess
        env = {**os.environ, 'PYTHONUNBUFFERED': '1'}

        # 根据 LOCAL_MODE 决定 nettype
        if LOCAL_MODE == 'fake':
            remote_args = [sys.executable, 'remote/udp.py', peer_ip, str(peer_port), str(hello_port),
                           '--nettype', 'fake']
        elif LOCAL_MODE == 'clientsocket':
            sock_path = f'/tmp/p2p/{logged_in_user}-{peer_name}.sock'
            remote_args = [sys.executable, 'remote/udp.py', peer_ip, str(peer_port), str(hello_port),
                           '--nettype', 'clientsocket', '--socketpath', sock_path]
            log(f"[P2P] clientsocket 模式，socket={sock_path}")
        else:  # 'auto' or None(default)
            remote_args = [sys.executable, 'remote/udp.py', peer_ip, str(peer_port), str(hello_port),
                           '--nettype', 'auto']

        try:
            p = subprocess.Popen(
                remote_args,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
                stdout=None,
                stderr=None,
                start_new_session=True,
            )
            log(f"[P2P] udp.py 已启动 PID={p.pid} -> {peer_ip}:{peer_port}")
        except Exception as e:
            log(f"[P2P] 启动 udp.py 失败: {e}")
    elif obj.get('type') == 'p2pudp_pending':
        target = obj.get('target', '')
        log(f"P2P UDP 等待 {target} 确认...")
    elif obj.get('type') == 'send_tcp_to_server':
        tcpport = obj.get('tcpport', SERVER_PORT)
        log(f"[P2P] 服务器要求连接 TCP P2P 端口 {tcpport}（打洞用）...")
        # 停止 UDP hello（如果还在跑）
        stop_udp_hello()
        import socket as _socket
        try:
            tcp_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            tcp_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            tcp_sock.connect((SERVER_IP, tcpport))
            tcp_sock.sendall((json.dumps({'username': logged_in_user}) + '\n').encode())
            log(f"[P2P] 已发送 TCP 注册到 {SERVER_IP}:{tcpport}，NAT 映射已建立")
            # 打洞用，发完就关闭，映射留在 NAT 里
            tcp_sock.close()
        except Exception as e:
            log(f"[P2P] 连接 TCP P2P 端口失败: {e}")
    elif obj.get('type') == 'thisisyourpeer_tcp':
        peer_name = obj.get('name', '')
        peer_ip = obj.get('ip', '')
        peer_port = obj.get('port', 0)
        my_ip = obj.get('my_ip', '')
        my_port = obj.get('my_port', 0)
        log(f"[P2P] 收到对端 {peer_name} TCP 地址: {peer_ip}:{peer_port}，本端: {my_ip}:{my_port}，启动 tcp.py...")
        import subprocess
        env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'P2P_USER': logged_in_user or ''}

        # 根据 LOCAL_MODE 决定 nettype
        if LOCAL_MODE == 'fake':
            remote_args = [sys.executable, 'remote/tcp.py', peer_ip, str(peer_port), str(my_port), peer_name,
                           '--nettype', 'fake']
        elif LOCAL_MODE == 'clientsocket':
            sock_path = f'/tmp/p2p/{logged_in_user}-{peer_name}.sock'
            remote_args = [sys.executable, 'remote/tcp.py', peer_ip, str(peer_port), str(my_port), peer_name,
                           '--nettype', 'clientsocket', '--socketpath', sock_path]
            log(f"[P2P] clientsocket 模式，socket={sock_path}")
        else:  # 'auto' or None(default)
            remote_args = [sys.executable, 'remote/tcp.py', peer_ip, str(peer_port), str(my_port), peer_name,
                           '--nettype', 'auto']

        try:
            p = subprocess.Popen(
                remote_args,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
                stdout=None,
                stderr=None,
                start_new_session=True,
            )
            log(f"[P2P] tcp.py 已启动 PID={p.pid} -> {peer_ip}:{peer_port} (bind {my_port})")
        except Exception as e:
            log(f"[P2P] 启动 tcp.py 失败: {e}")
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
    elif cmd == 'local':
        global LOCAL_MODE, LOCAL_DEVICE
        if not arg:
            mode = LOCAL_MODE if LOCAL_MODE else 'fake'
            dev = LOCAL_DEVICE or '(无)'
            log(f"当前模式: {mode}  设备: {dev}")
            return True
        parts = arg.strip().split(maxsplit=1)
        sub = parts[0]
        dev = parts[1] if len(parts) > 1 else None
        if sub == 'fake':
            LOCAL_MODE = 'fake'
            LOCAL_DEVICE = None
            log("模式: fake（子进程独立 tun，不走 client.py 汇聚）")
        elif sub in ('tun', 'tap'):
            LOCAL_MODE = 'clientsocket'
            LOCAL_DEVICE = dev
            log(f"模式: clientsocket（子进程汇入 client.py，设备: {dev or '(无)'})")
        elif sub == 'auto':
            LOCAL_MODE = 'auto'
            LOCAL_DEVICE = None
            log("模式: auto（tun→tap→fake，自动选择）")
        else:
            log(f"未知 local 模式: {sub}，可用: fake / tun [设备名] / tap [设备名] / auto")
        return True
    elif cmd == 'p2pudp':
        if not arg:
            log("用法: p2pudp <对方用户名>")
            return True
        target = arg.strip()
        ws_send(ws_sock, {"type": "p2pudp", "target": target})
        log(f"P2P UDP 请求已发送给服务器，等待 {target} 确认...")
    elif cmd == 'p2ptcp':
        if not arg:
            log("用法: p2ptcp <对方用户名>")
            return True
        target = arg.strip()
        ws_send(ws_sock, {"type": "p2ptcp", "target": target})
        log(f"P2P TCP 请求已发送给服务器，等待 {target} 确认...")
    else:
        log(f"未知命令: {cmd}，输入 help")
    return True


# ====== 主循环 ======

def main():
    global connected, ws_sock, recv_buf, pending_auth, DEBUG, SERVER_IP, SERVER_PORT

    parser = argparse.ArgumentParser(description='p2pnet 命令行客户端')
    parser.add_argument('--server', default='127.0.0.1', help='服务器地址')
    parser.add_argument('--port', type=int, default=10000, help='服务器端口')
    parser.add_argument('--debug', action='store_true', help='打印所有消息')
    args = parser.parse_args()
    SERVER_IP = args.server
    SERVER_PORT = args.port
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
