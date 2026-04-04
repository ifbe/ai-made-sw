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
import subprocess

IS_WINDOWS = sys.platform == 'win32'


def launch_in_new_terminal(args, cwd=None, env=None, new_window=True, close_on_exit=False,
                   peer_name='', peer_ip='', peer_port=0, my_ip='', my_port=0, name=None,
                   _log_file=None):
    """
    启动子进程。
    new_window=True  且平台支持时：新开终端窗口运行
    new_window=False：后台直接运行，不开窗口，输出到日志
    close_on_exit=True：子进程结束时自动关闭窗口（仅 macOS/Windows；Linux 取决于终端）
    peer_name/ip/port, my_ip/port：记录到 children 列表，供运行时查看。
    返回存储条目 dict，失败返回 None。
    """
    import shlex
    import platform
    import time as _time
    cmd_str = ' '.join(shlex.quote(a) for a in args)
    cwd = cwd or os.getcwd()
    env = env or os.environ
    _name = name if name else os.path.basename(args[0])  # e.g. 'udp' or 'python3'
    system = platform.system()

    child_entry = {
        'pid': None, 'name': _name,
        'type': 'window' if new_window else 'bg',
        'popen': None, 'close_on_exit': close_on_exit,
        'peer_name': peer_name, 'peer_ip': peer_ip, 'peer_port': peer_port,
        'my_ip': my_ip, 'my_port': my_port,
    }

    if not new_window:
        # 后台直接跑
        if _log_file:
            stdout_redirect = open(_log_file, 'a')
        else:
            stdout_redirect = None
        p = subprocess.Popen(
            args, cwd=cwd, env=env,
            stdout=stdout_redirect,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        child_entry['pid'] = p.pid
        child_entry['popen'] = p
        children.append(child_entry)
        return child_entry

    if system == 'Darwin':
        if new_window:
            exit_suffix = '; exit' if close_on_exit else ''
            if _log_file:
                # 写日志文件，并在窗口显示 tail
                show_tail = f'; echo "--- log: {_log_file} ---"; tail -f {_log_file} {exit_suffix}'
                script = (
                    f'tell application "Terminal"\n'
                    f'  activate\n'
                    f'  do script "cd {shlex.quote(cwd)} && ({cmd_str} >> {_log_file} 2>&1) {show_tail}"\n'
                    f'end tell'
                )
            else:
                # 无日志文件，stdout 继承终端
                script = (
                    f'tell application "Terminal"\n'
                    f'  activate\n'
                    f'  do script "cd {shlex.quote(cwd)} && {cmd_str}{exit_suffix}"\n'
                    f'end tell'
                )
        else:
            script = None
        r = subprocess.run(
            ['osascript', '-e', script] if script else ['true'],
            cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # osascript 新版可返回窗口 shell 的 PID；尝试解析
        pid = None
        if r.returncode == 0 and r.stdout:
            try:
                pid = int(r.stdout.strip().split()[-1])
            except (ValueError, IndexError):
                pass
        if pid is None:
            # fallback：用 pgrep 找（窗口刚弹，python 进程在运行）
            _time.sleep(0.2)
            try:
                r2 = subprocess.run(
                    ['pgrep', '-f', f'python.*remote/{_name}'],
                    capture_output=True, text=True,
                )
                if r2.returncode == 0:
                    pid = int(r2.stdout.strip().split()[0])
            except (ValueError, IndexError):
                pass
        child_entry['pid'] = pid
        children.append(child_entry)
        return child_entry

    elif system == 'Windows':
        # /c = 结束后关闭窗口，/k = 保持窗口
        flag = '/c' if close_on_exit else '/k'
        p = subprocess.Popen(
            ['cmd', '/c', 'start', 'cmd', flag, f'cd /d {cwd} && {cmd_str}'],
            cwd=cwd, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        child_entry['pid'] = p.pid
        child_entry['popen'] = p
        children.append(child_entry)
        return child_entry

    else:
        # Linux
        close_flag = ''
        for term in ['gnome-terminal', 'konsole', 'xfce4-terminal']:
            if subprocess.call(['which', term], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                if term == 'gnome-terminal':
                    close_flag = ' --close-session' if close_on_exit else ''
                    cmd_shell = f'cd {shlex.quote(cwd)} && ({cmd_str}' + (f' >> {_log_file} 2>&1)' if _log_file else ')')
                    p = subprocess.Popen(
                        [term + close_flag, '--', 'bash', '-c', cmd_shell],
                        cwd=cwd, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                elif term == 'konsole':
                    close_flag = ' --close' if close_on_exit else ''
                    cmd_shell = f'cd {shlex.quote(cwd)} && ({cmd_str}' + (f' >> {_log_file} 2>&1)' if _log_file else ')')
                    p = subprocess.Popen(
                        [term + close_flag, '-e', 'bash', '-c', cmd_shell],
                        cwd=cwd, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                elif term == 'xfce4-terminal':
                    close_flag = ' -H' if close_on_exit else ''
                    cmd_shell = f'cd {shlex.quote(cwd)} && ({cmd_str}' + (f' >> {_log_file} 2>&1)' if _log_file else ')')
                    p = subprocess.Popen(
                        [term + close_flag, '-e', cmd_shell],
                        cwd=cwd, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                child_entry['pid'] = p.pid
                child_entry['popen'] = p
                children.append(child_entry)
                return child_entry
            # next term
        # fallback: 找不到终端，后台跑
        p = subprocess.Popen(
            args, cwd=cwd, env=env,
            stdout=stdout_redirect,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        child_entry['pid'] = p.pid
        child_entry['popen'] = p
        children.append(child_entry)
        return child_entry


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

# 子进程/子窗口列表，每个元素 {pid, name, type, popen, close_on_exit}
children = []
# 运行参数（由 argparse 设置）
NEW_WINDOW = False  # 默认当前窗口（后台运行写日志）；--new-window 开启新窗口
CLOSE_WINDOW = False  # 默认窗口保留（子进程结束后不自动关窗口）
ARGS_USER = None  # --user 自动登录
ARGS_PASS = None  # --pass 密码
REMOTELOG = False  # --remotelog

# 等待 challenge 的登录上下文
pending_auth = None
logged_in_user = None
pending_salt = None
pending_challenge = None
pending_pw_hash = None
session_key = None  # login_ok 后派生，HKDF(pw_hash, info=challenge)


def hkdf_sha256(ikm, salt, info=b''):
    """HKDF-SHA256(IKM, salt, info) -> 32-byte key"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''
    okm = b''
    i = 1
    while len(okm) < 32:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:32]


def sign_with_session_key(message=b'ping'):
    """用 session_key 对消息签名：HMAC-SHA256(session_key, message) -> hex"""
    if not session_key:
        return None
    return hmac.new(session_key, message, hashlib.sha256).hexdigest()

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

    # 保持 IPv4（服务器是 IPv4 0.0.0.0），避免 IPv6 socket 发到 IPv4 服务器失败
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
            sig = sign_with_session_key(b'ping') if session_key else None
            payload = {'type': 'p2pudp_hello', 'username': username}
            if sig:
                payload['signature'] = sig
            msg = json.dumps(payload).encode()
            if DEBUG:
                sk_hex = binascii.hexlify(session_key).decode() if session_key else 'None'
                print(f"[DEBUG] UDP hello -> {server_ip}:{server_udp_port}: {payload}")
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
    log("  appmode            - 显示当前模式")
    log("  appmode fake       - 模式: fake（子进程独立 tun，不汇入 client.py）")
    log("  appmode tun [dev] - 模式: clientsocket（子进程汇入 client.py）")
    log("  appmode tap [dev] - 模式: clientsocket（子进程汇入 client.py）")
    log("  appmode auto      - 模式: auto（tun→tap→fake）")
    log("  help              - 显示帮助")
    log("  quit             - 退出")
    log("  children           - 列出所有子进程/子窗口")
    log("  kill <pid>         - 杀掉指定 PID 的子进程/子窗口")


# ====== 处理消息 ======

def handle_server_message(obj):
    global pending_auth, logged_in_user, session_key, ARGS_USER, ARGS_PASS

    if obj.get('type') == 'challenge':
        if pending_auth is None:
            log("收到 challenge，但没有待完成的登录，请先输入 login <username>")
            return
        username, = pending_auth  # pending_auth 现在是 (username,)
        challenge = obj.get('challenge', '')
        salt = obj.get('salt', '')
        if ARGS_PASS:
            password = ARGS_PASS
            # 一次性，用完即清
            ARGS_USER = None
            ARGS_PASS = None
        else:
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
        # 存储，供 login_ok 后派生 session_key
        global pending_salt, pending_challenge, pending_pw_hash
        pending_salt = salt
        pending_challenge = challenge
        pending_pw_hash = pw_hash
        ws_send(ws_sock, {
            "type": "login",
            "username": username,
            "response": response
        })
        pending_auth = None

    elif obj.get('type') == 'login_ok':
        logged_in_user = obj.get('username', '')
        # session_key = HKDF(pw_hash, info=challenge)，从不在网络传输
        if pending_pw_hash and pending_challenge:
            sk_ikm = binascii.unhexlify(pending_pw_hash)
            session_key = hkdf_sha256(sk_ikm, sk_ikm, binascii.unhexlify(pending_challenge))
            log(f"登录成功: {logged_in_user}，session_key 已派生: {binascii.hexlify(session_key).decode()}")
        else:
            session_key = None
            log(f"登录成功: {logged_in_user}（无 session_key，请重新登录）")
        pending_salt = pending_challenge = pending_pw_hash = None
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
        session_key = None
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
        env = {**os.environ, 'PYTHONUNBUFFERED': '1'}

        # clientsocket 需传 socketpath；其他模式不传 --appmode（默认 fake）
        _log = REMOTELOG
        if _log:
            import time as _t
            _log_file = f"/tmp/p2pnet_udp_{logged_in_user}_{peer_name}_{int(_t.time())}.log"
        else:
            _log_file = None

        remote_args = [sys.executable, 'remote/udp.py',
                       '--peeraddr', peer_ip,
                       '--peerport', str(peer_port),
                       '--localport', str(hello_port)]
        if LOCAL_MODE == 'clientsocket':
            sock_path = f'/tmp/p2p/{logged_in_user}-{peer_name}.sock'
            remote_args += ['--socketpath', sock_path]
            log(f"[P2P] clientsocket 模式，socket={sock_path}")
        if _log_file:
            remote_args += ['--remotelog', _log_file]

        try:
            entry = launch_in_new_terminal(
                remote_args,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
                new_window=NEW_WINDOW,
                close_on_exit=CLOSE_WINDOW,
                peer_name=peer_name, peer_ip=peer_ip, peer_port=peer_port,
                my_ip='0.0.0.0', my_port=hello_port,
                name='udp',
                _log_file=_log_file,
            )
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
            server_info = _socket.getaddrinfo(SERVER_IP, tcpport, _socket.AF_UNSPEC, _socket.SOCK_STREAM)
            family, socktype, proto, _, sockaddr = server_info[0]
            tcp_sock = _socket.socket(family, socktype, proto)
            tcp_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            tcp_sock.connect(sockaddr)
            sig = sign_with_session_key(b'ping') if session_key else None
            payload = {'username': logged_in_user}
            if sig:
                payload['signature'] = sig
            if DEBUG:
                sk_hex = binascii.hexlify(session_key).decode() if session_key else 'None'
                print(f"[DEBUG] TCP registration -> {SERVER_IP}:{tcpport}: {payload}")
            tcp_sock.sendall((json.dumps(payload) + '\n').encode())
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
        env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'P2P_USER': logged_in_user or ''}

        # clientsocket 需传 socketpath；其他模式不传 --appmode（默认 fake）
        _log = REMOTELOG
        if _log:
            import time as _t
            _log_file = f"/tmp/p2pnet_tcp_{logged_in_user}_{peer_name}_{int(_t.time())}.log"
        else:
            _log_file = None

        remote_args = [sys.executable, 'remote/tcp.py',
                       '--peeraddr', peer_ip, '--peerport', str(peer_port),
                       '--localport', str(my_port), '--peername', peer_name]
        if LOCAL_MODE == 'clientsocket':
            sock_path = f'/tmp/p2p/{logged_in_user}-{peer_name}.sock'
            remote_args += ['--socketpath', sock_path]
            log(f"[P2P] clientsocket 模式，socket={sock_path}")
        if _log_file:
            remote_args += ['--remotelog', _log_file]

        try:
            entry = launch_in_new_terminal(
                remote_args,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
                new_window=NEW_WINDOW,
                close_on_exit=CLOSE_WINDOW,
                peer_name=peer_name, peer_ip=peer_ip, peer_port=peer_port,
                my_ip=my_ip, my_port=my_port,
                name='tcp',
                _log_file=_log_file,
            )
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
    elif cmd == 'appmode':
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
            log(f"未知 appmode: {sub}，可用: fake / tun [设备名] / tap [设备名] / auto")
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
    elif cmd == 'children':
        if not children:
            log("没有运行的子进程")
        else:
            for i, c in enumerate(children):
                winfo = ''
                if c['type'] == 'window':
                    winfo = '  [窗口]' if c['close_on_exit'] else '  [窗口·保留]'
                else:
                    winfo = '  [后台]'
                pn = c['peer_name']
                pi = c['peer_ip']
                pp = c['peer_port']
                mi = c['my_ip']
                mp = c['my_port']
                log(f"  [{i}] pid={c['pid']}  name={c['name']}{winfo}")
                log(f"       对端: {pn}  {pi}:{pp}  本端: {mi}:{mp}")
        return True
    elif cmd == 'kill':
        if not arg:
            log("用法: kill <pid>")
            return True
        try:
            target_pid = int(arg.strip())
        except ValueError:
            log(f"无效 PID: {arg}")
            return True
        killed = False
        for c in children:
            if c['pid'] == target_pid:
                try:
                    p = c.get('popen')
                    if p is not None:
                        p.terminate()
                        log(f"已 terminate pid={target_pid} ({c['name']})")
                    else:
                        import signal as _sig
                        if IS_WINDOWS:
                            os.kill(target_pid, _sig.CTRL_C_EVENT)
                        else:
                            os.kill(target_pid, _sig.SIGINT)
                        log(f"已发送 SIGINT 到 pid={target_pid} ({c['name']})")
                except (ProcessLookupError, OSError):
                    log(f"进程已不存在: pid={target_pid}")
                except PermissionError:
                    log(f"权限不足，无法 kill pid={target_pid}")
                try:
                    children.remove(c)
                except ValueError:
                    pass
                killed = True
                break
        if not killed:
            log(f"未找到 pid={target_pid} 的子进程")
        return True
    else:
        log(f"未知命令: {cmd}，输入 help")
    return True


# ====== 主循环 ======

def main():
    global connected, ws_sock, recv_buf, pending_auth, DEBUG, SERVER_IP, SERVER_PORT

    parser = argparse.ArgumentParser(description='p2pnet 命令行客户端')
    parser.add_argument('--server', default='127.0.0.1', help='服务器地址（IPv4/IPv6/域名，自动识别）')
    parser.add_argument('--port', type=int, default=10000, help='服务器端口')
    parser.add_argument('--debug', action='store_true', help='打印所有消息')
    parser.add_argument('--new-window', dest='new_window', action='store_true', default=False, help='在新窗口运行子进程（默认当前窗口后台）')
    parser.add_argument('--close-window', dest='close_window', action='store_true', default=False, help='子进程结束时自动关闭新窗口（默认不关闭）')
    parser.add_argument('--user', dest='user', default=None, help='登录用户名（需配合 --pass 使用）')
    parser.add_argument('--pass', dest='pass_', default=None, help='登录密码（需配合 --user 使用，连上服务器后自动登录）')
    parser.add_argument('--remotelog', dest='remotelog', nargs='?', const=True, default=False,
                        help='子进程日志：默认 False（stdout），True 时写入 /tmp/p2pnet_{udp|tcp}_{user}_{peer}_{time}.log）')
    args = parser.parse_args()
    SERVER_IP = args.server
    SERVER_PORT = args.port
    DEBUG = args.debug
    NEW_WINDOW = args.new_window
    CLOSE_WINDOW = args.close_window
    global ARGS_USER, ARGS_PASS, REMOTELOG
    ARGS_USER = args.user
    ARGS_PASS = args.pass_
    REMOTELOG = args.remotelog

    # 自动判断 IPv4/IPv6，同时支持域名解析
    server_info = socket.getaddrinfo(args.server, args.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = server_info[0]
    ws_sock = socket.socket(family, socktype, proto)
    ws_sock.settimeout(10)
    try:
        ws_sock.connect(sockaddr)
    except Exception as e:
        log(f"连接失败: {e}")
        sys.exit(1)

    # WebSocket 握手（host 传原始域名，sockaddr 已解析）
    if not ws_handshake(ws_sock, args.server, args.port):
        log("WebSocket 握手失败")
        ws_sock.close()
        sys.exit(1)

    ws_sock.setblocking(False)
    connected = True
    log(f"已连接至 {args.server}:{args.port}（输入 help 查看命令）")

    # --user --pass 自动登录
    if ARGS_USER:
        pending_auth = (ARGS_USER,)
        ws_send(ws_sock, {"type": "login", "username": ARGS_USER})
        log(f"自动登录: {ARGS_USER}（等待 challenge...）")

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
    # 清理所有子进程
    for c in list(children):
        p = c.get('popen')
        pid = c.get('pid')
        if p is not None:
            try:
                p.terminate()
            except (ProcessLookupError, OSError):
                pass
        elif pid is not None:
            try:
                import signal as _sig
                if IS_WINDOWS:
                    os.kill(pid, _sig.CTRL_C_EVENT)
                else:
                    os.kill(pid, _sig.SIGINT)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            children.remove(c)
        except ValueError:
            pass
    children.clear()
    try:
        ws_sock.close()
    except:
        pass
    log("已退出")


if __name__ == '__main__':
    main()
