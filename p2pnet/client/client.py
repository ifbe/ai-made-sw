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
    peer_name/ip/port, my_ip/port：记录到 peers 列表，供运行时查看。
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
        peers.append(child_entry)
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
        peers.append(child_entry)
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
        peers.append(child_entry)
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
                peers.append(child_entry)
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
        peers.append(child_entry)
        return child_entry


# 后台 UDP hello 线程
udp_hello_running = False
_hello_stop_event = threading.Event()  # 信号线程退出（替代 _udp_hello_running 轮询）
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
peers = []

# WireGuard 共享进程（单实例）
WG_ADMIN_PATH = None  # wireguard.py 的 admin socket 路径
WG_PROC = None        # wireguard.py 进程

# Switch 共享进程（单实例）
SWITCH_PROC = None    # switch.py 进程
SWITCH_SOCK_PATH = None  # switch 的 Unix socket 路径（供 udp.py/tcp.py 连接）
WG_NATIVE_MODE = False  # True = 使用原生 WireGuard（wghelp），不用 wireguard.py
WG_NATIVE_MY_KEY = ''   # wghelp 命令时存储我的私钥
WG_NATIVE_MY_IP = ''    # wghelp 命令时存储我的 mesh IP
FFMPEG_MODE = False     # True = 收到 thisisyourpeer_udp 时拉起 ffmpeg.sh（不用 udp.py）
STARTUP_FFMPEG = []     # 启动时自动 ffmpeg 视频连接（每个元素: peer_name）
# 启动命令（login 成功后自动执行）
STARTUP_APPMODE = None
STARTUP_UDP = []
STARTUP_TCP = []
STARTUP_WG = []
STARTUP_WGHELP = []  # 每个元素: (user, key, mesh_ip)
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
    _hello_stop_event.clear()  # 重置事件，表示线程正在运行
    log(f"[UDP hello] 开始，往 {server_ip}:{server_udp_port} 发送 hello (本地端口 {local_bound_port})")

    def _send_hello():
        sig = sign_with_session_key(b'ping') if session_key else None
        payload = {'type': 'p2pudp_hello', 'username': username}
        if sig:
            payload['signature'] = sig
        msg = json.dumps(payload).encode()
        if DEBUG:
            print(f"[DEBUG] UDP hello -> {server_ip}:{server_udp_port}: {payload}")
        sock.sendto(msg, (server_ip, server_udp_port))

    while udp_hello_running:
        try:
            # 启动时发 burst 建立 NAT 映射（15个，30ms间隔，0.45s 发完）
            # burst 期间不响应 stop，必须发满 15 个
            for _ in range(15):
                _send_hello()
                time.sleep(0.03)
            # burst 发完了，再检查是否要退出
            if not udp_hello_running:
                break
            # 之后每秒发 1 个维持映射
            while udp_hello_running:
                # 每 1 秒醒一次，配合 stop event 快速退出
                if _hello_stop_event.wait(timeout=1):
                    break  # 收到停止信号
                if udp_hello_running:
                    _send_hello()
        except Exception as e:
            # socket 已被关闭，不用再关，直接 break 退出
            break

    sock.close()
    _hello_stop_event.set()  # 通知 stop_udp_hello() 线程已完全退出
    log("[UDP hello] 已停止")

    def _send_hello():
        sig = sign_with_session_key(b'ping') if session_key else None
        payload = {'type': 'p2pudp_hello', 'username': username}
        if sig:
            payload['signature'] = sig
        msg = json.dumps(payload).encode()
        if DEBUG:
            print(f"[DEBUG] UDP hello -> {server_ip}:{server_udp_port}: {payload}")
        sock.sendto(msg, (server_ip, server_udp_port))

    while udp_hello_running:
        try:
            # 启动时发 burst 建立 NAT 映射（15个，30ms间隔，0.45s 发完）
            for _ in range(15):
                if not udp_hello_running:
                    break
                _send_hello()
                time.sleep(0.03)
            # 之后每秒发 1 个维持映射
            while udp_hello_running:
                time.sleep(1)
                if udp_hello_running:
                    _send_hello()
        except Exception as e:
            # socket 被 stop_udp_hello() 关闭了，线程应该退出
            break

    sock.close()
    _hello_stop_event.set()  # 通知 stop_udp_hello() 线程已完全退出
    log("[UDP hello] 已停止")


def stop_udp_hello():
    """发送停止信号给 hello 线程，不阻塞"""
    global udp_hello_running, udp_hello_sock, udp_hello_thread
    udp_hello_running = False
    _hello_stop_event.set()  # 通知线程退出
    # 不关闭 socket，让 burst 发完再自然退出
    if udp_hello_thread:
        # 最多等 2 秒让线程自然退出（burst 最多 0.45s）
        try:
            udp_hello_thread.join(timeout=2)
        except Exception:
            pass
        udp_hello_thread = None
    # 清理 socket
    if udp_hello_sock:
        try:
            udp_hello_sock.close()
        except:
            pass
        udp_hello_sock = None


def start_udp_hello_thread(server_ip, server_udp_port, username):
    """启动 UDP hello 线程，使用随机可用端口"""
    global udp_hello_running, udp_hello_thread
    # 防止重复启动：如果线程已经在运行，不启动新的
    if udp_hello_running and udp_hello_thread and udp_hello_thread.is_alive():
        return
    import random
    local_port = random.randint(50000, 65000)
    t = threading.Thread(target=start_udp_hello, args=(server_ip, server_udp_port, username, local_port), daemon=True)
    t.start()
    udp_hello_thread = t
    return t

def print_help():
    log("=== p2pnet 客户端 ===")
    log("  help              - 显示帮助")
    log("  quit             - 退出")

    log("  login            - 交互式登录（提示输入用户名和密码）")
    log("  login <username> - 登录，随后提示输入密码")
    log("  list             - 发送 list")

    log("  appmode            - 显示当前模式")
    log("  appmode fake       - 模式: fake（测试用，无网络）")
    log("  appmode tun [dev] - 模式: tun（tun 设备汇入 p2p 网络）")
    log("  appmode tap [dev] - 模式: tap（tap 设备汇入 p2p 网络）")
    log("  appmode auto      - 模式: auto（tun→tap→fake，自动选择）")
    log("  appmode switch   - 模式: switch（拉起 switch.py 做 P2P 交换中心）")
    log("  appmode video    - 模式: video（拉起 video.py 做 P2P 视频通话，TODO）")
    log("  appmode file     - 模式: file（拉起 file.py 做 P2P 文件传输，TODO）")

    log("  peer              - 列出所有 P2P 连接")
    log("  kill <pid>|all  - 杀掉指定 PID 的 peer，或 kill all 杀掉全部")
    log("  udp <user>   - 请求与对方建立 UDP P2P 连接")
    log("  tcp <user>   - 请求与对方建立 TCP P2P 连接")
    log("  wg  <user>   - 请求与对方建立 WireGuard P2P 连接（单进程多 peer）")
    log("  wghelp <user> <私钥> <mesh_ip>  - WireGuard NAT 穿透（原生 WG）")
    log("  ffmpeg <user> - P2P 视频通话（打完洞后拉起 ffmpeg）")

# ====== Switch 进程管理 ======

def _do_start_switch():
    """拉起 switch.py 作为子进程，stdin/stdout 做控制通道"""
    global SWITCH_PROC, SWITCH_SOCK_PATH, LOCAL_MODE
    if SWITCH_PROC is not None:
        log("switch 已在运行")
        return
    import time as _t
    sock_path = f'/tmp/p2pnet/switch-{os.getpid()}.sock'
    SWITCH_SOCK_PATH = sock_path
    # 清理旧 socket 文件
    if os.path.exists(sock_path):
        os.remove(sock_path)
    switch_args = [sys.executable, 'app/switch.py',
                   '--type', 'unixsocket',
                   '--socketpath', sock_path]
    try:
        entry = launch_in_new_terminal(
            switch_args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={**os.environ, 'PYTHONUNBUFFERED': '1'},
            new_window=False,  # 后台运行，stdout 给 client.py 读
            name='switch',
        )
        SWITCH_PROC = entry
        # 等 switch 启动并开始接受连接
        _t.sleep(0.5)
        log(f"switch.py 已启动（{sock_path}），peer 连接请用 --udp/--tcp/--wg")
        LOCAL_MODE = 'switch'
    except Exception as e:
        log(f"switch.py 启动失败: {e}")


# ====== 启动时自动执行的命令 ======

def _do_startup_commands():
    """登录成功后自动执行启动命令（--appmode/--udp/--tcp/--wg/--wghelp）"""
    global STARTUP_APPMODE, STARTUP_UDP, STARTUP_TCP, STARTUP_WG, STARTUP_WGHELP, STARTUP_FFMPEG
    global WG_NATIVE_MODE, WG_NATIVE_MY_KEY, WG_NATIVE_MY_IP

    if STARTUP_APPMODE:
        log(f"[启动] 设置 appmode = {STARTUP_APPMODE}")
        process_input_line(f'appmode {STARTUP_APPMODE}')

    for target in STARTUP_UDP:
        log(f"[启动] UDP 连接 {target}...")
        process_input_line(f'udp {target}')

    for target in STARTUP_TCP:
        log(f"[启动] TCP 连接 {target}...")
        process_input_line(f'tcp {target}')

    for target in STARTUP_WG:
        log(f"[启动] WireGuard 连接 {target}...")
        process_input_line(f'wg {target}')

    for user, key, mesh_ip in STARTUP_WGHELP:
        log(f"[启动] WireGuard NAT穿透连接 {user}...")
        WG_NATIVE_MODE = True
        WG_NATIVE_MY_KEY = key
        WG_NATIVE_MY_IP = mesh_ip
        process_input_line(f'wg {user}')  # 发 p2pwg 握手

    for target in STARTUP_FFMPEG:
        log(f"[启动] ffmpeg 视频连接 {target}...")
        process_input_line(f'ffmpeg {target}')

    STARTUP_UDP = STARTUP_TCP = STARTUP_WG = []
    STARTUP_WGHELP = []
    STARTUP_FFMPEG = []


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

        # 登录成功后自动执行启动命令
        _do_startup_commands()
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
        log(f"⚠️  {from_user} 请求和你建立 UDP P2P 连接，输入 udp {from_user} 回应")
    elif obj.get('type') == 'send_udp_to_server':
        udpport = obj.get('udpport', 9999)
        log(f"[P2P] 服务器要求往 UDP {udpport} 发包，开始 UDP hello...")
        # 启动 UDP hello 线程
        start_udp_hello_thread(SERVER_IP, udpport, logged_in_user)
    elif obj.get('type') == 'thisisyourpeer_udp':
        peer_name = obj.get('name', '')
        peer_ip = obj.get('ip', '')
        peer_port = obj.get('port', 0)
        log(f"[P2P] 收到对端 {peer_name} 地址: {peer_ip}:{peer_port}，停止 UDP hello...")
        hello_port = udp_hello_sock.getsockname()[1] if udp_hello_sock else 0
        stop_udp_hello()

        # FFMPEG_MODE：拉起 ffmpeg.sh 做 P2P 视频，不走 udp.py
        global FFMPEG_MODE
        if FFMPEG_MODE:
            FFMPEG_MODE = False
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ffmpeg.sh')
            # 对方接收端口 = 对方 hello_port（打洞时的本地端口）
            peer_recv_port = obj.get('peer_hello_port', peer_port)
            my_ip_addr = obj.get('my_ip', '0.0.0.0')
            log(f"[P2P] ffmpeg 双向通话: 本机端口={hello_port} -> 对方端口={peer_recv_port}")
            try:
                call_args = ['bash', script_path,
                             my_ip_addr, str(hello_port),
                             peer_ip, str(peer_recv_port)]
                entry = launch_in_new_terminal(
                    call_args,
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                    new_window=True, close_on_exit=False,
                    peer_name=peer_name, name='ffmpeg',
                )
                peers.append(entry)
                log(f"[P2P] ffmpeg 已启动（新窗口），持续 1 小时")
            except Exception as e:
                log(f"[P2P] ffmpeg 启动失败: {e}")
            return True

        env = {**os.environ, 'PYTHONUNBUFFERED': '1'}

        _log = REMOTELOG
        if _log:
            import time as _t
            _log_file = f"/tmp/p2pnet/udp-{logged_in_user}_{peer_name}_{int(_t.time())}.log"
        else:
            _log_file = None

        remote_args = [sys.executable, 'remote/udp.py',
                       '--peeraddr', peer_ip,
                       '--peerport', str(peer_port),
                       '--localport', str(hello_port)]
        if LOCAL_MODE in ('tun', 'tap'):
            sock_path = f'/tmp/p2p/{logged_in_user}-{peer_name}.sock'
            remote_args += ['--socketpath', sock_path]
            log(f"[P2P] {LOCAL_MODE} 模式，socket={sock_path}")
        elif LOCAL_MODE == 'switch' and SWITCH_SOCK_PATH:
            remote_args += ['--socketpath', SWITCH_SOCK_PATH]
            log(f"[P2P] switch 模式，socket={SWITCH_SOCK_PATH}")
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

        _log = REMOTELOG
        if _log:
            import time as _t
            _log_file = f"/tmp/p2pnet/tcp-{logged_in_user}_{peer_name}_{int(_t.time())}.log"
        else:
            _log_file = None

        remote_args = [sys.executable, 'remote/tcp.py',
                       '--peeraddr', peer_ip, '--peerport', str(peer_port),
                       '--localport', str(my_port), '--peername', peer_name]
        if LOCAL_MODE in ('tun', 'tap'):
            sock_path = f'/tmp/p2p/{logged_in_user}-{peer_name}.sock'
            remote_args += ['--socketpath', sock_path]
            log(f"[P2P] {LOCAL_MODE} 模式，socket={sock_path}")
        elif LOCAL_MODE == 'switch' and SWITCH_SOCK_PATH:
            remote_args += ['--socketpath', SWITCH_SOCK_PATH]
            log(f"[P2P] switch 模式，socket={SWITCH_SOCK_PATH}")
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
    elif obj.get('type') == 'incoming_p2pwg':
        from_user = obj.get('from_username', '')
        log(f"⚠️  {from_user} 请求和你建立 WireGuard P2P 连接，输入 wg {from_user} 回应")
    elif obj.get('type') == 'thisisyourpeer_wg':
        global WG_ADMIN_PATH, WG_PROC, WG_NATIVE_MODE, WG_NATIVE_MY_KEY, WG_NATIVE_MY_IP
        peer_name = obj.get('name', '')
        peer_ip = obj.get('ip', '')       # peer's mesh IP (e.g. 192.168.250.3)
        peer_port = obj.get('port', 0)     # peer's WireGuard ListenPort
        peer_pubkey = obj.get('peer_pubkey', '')
        peer_public_addr = obj.get('peer_public_addr', '')  # peer's public ip:port (hole-punched)
        import time as _t

        # -------- wghelp 模式：拉起 wghelp.sh 配置原生 WireGuard --------
        if WG_NATIVE_MODE:
            my_privkey = WG_NATIVE_MY_KEY
            my_ip = WG_NATIVE_MY_IP
            # peer_public_addr 优先，否则 fallback 到 peer_ip:peer_port
            if peer_public_addr:
                endpoint = peer_public_addr
            else:
                endpoint = f"{peer_ip}:{peer_port}"
            log(f"[P2P] wghelp: 配置原生 WireGuard...")
            log(f"  我的 mesh IP: {my_ip}")
            log(f"  对方 mesh IP: {peer_ip}")
            log(f"  对方公钥: {peer_pubkey[:16]}...")
            log(f"  对方 Endpoint: {endpoint}")

            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wghelp.sh')
            if not os.path.exists(script_path):
                log(f"[P2P] 错误: wghelp.sh 不在当前目录: {script_path}")
                WG_NATIVE_MODE = False
                return True

            # wghelp.sh: <私钥> <我meshIP> <对方公钥> <对方meshIP> <对方公网地址:端口>
            wg_args = ['sudo', 'bash', script_path, my_privkey, my_ip, peer_pubkey, peer_ip, endpoint]
            try:
                entry = launch_in_new_terminal(
                    wg_args,
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                    new_window=True,
                    close_on_exit=False,
                    peer_name=peer_name, peer_ip=peer_ip, peer_port=peer_port,
                    name='wghelp',
                )
                if entry:
                    peers.append(entry)
                log(f"[P2P] wghelp.sh 已在新窗口启动（可能需要输入 sudo 密码）")
                log(f"[P2P] 运行后检查: ping {peer_ip} && wg show")
            except Exception as e:
                log(f"[P2P] wghelp.sh 启动失败: {e}")
            WG_NATIVE_MODE = False
            return True

        def _do_add_peer():
            """通过 admin socket 添加 peer（闭包捕获 peer_name 等）"""
            if not WG_ADMIN_PATH or not os.path.exists(WG_ADMIN_PATH):
                log(f"[P2P] wireguard.py 未运行，无法添加 peer {peer_name}")
                return False
            import json as _json
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(WG_ADMIN_PATH)
                cmd = _json.dumps({'cmd': 'add_peer', 'name': peer_name,
                                   'ip': peer_ip, 'port': peer_port,
                                   'pubkey': peer_pubkey})
                sock.sendall((cmd + '\n').encode())
                data = b''
                while b'\n' not in data:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                sock.close()
                if data:
                    resp = _json.loads(data.decode('utf-8').strip())
                    if resp.get('ok'):
                        log(f"[P2P] peer {peer_name} 已添加，公钥: {resp.get('pubkey', '')[:16]}...")
                        return True
                    else:
                        log(f"[P2P] 添加 peer 失败: {resp.get('error')}")
                return False
            except Exception as e:
                log(f"[P2P] admin socket 错误: {e}")
                return False

        if WG_ADMIN_PATH and os.path.exists(WG_ADMIN_PATH):
            log(f"[P2P] wireguard.py 已运行，添加 peer {peer_name}...")
            _do_add_peer()
        else:
            log(f"[P2P] 启动 wireguard.py（第一个 peer: {peer_name}）...")
            env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'P2P_USER': logged_in_user or ''}
            admin_path = f'/tmp/p2pnet/wg-admin-{os.getpid()}.sock'
            _log = REMOTELOG
            _log_file = f"/tmp/p2pnet/wg-{logged_in_user}_main_{int(_t.time())}.log" if _log else None

            remote_args = [sys.executable, 'remote/wireguard.py',
                           '--socketpath', SWITCH_SOCK_PATH or f'/tmp/p2pnet/switch-{os.getpid()}.sock',
                           '--adminpath', admin_path]
            if _log_file:
                remote_args += ['--log', _log_file]

            try:
                entry = launch_in_new_terminal(
                    remote_args,
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                    env=env,
                    new_window=NEW_WINDOW,
                    close_on_exit=CLOSE_WINDOW,
                    peer_name=peer_name, peer_ip=peer_ip, peer_port=peer_port,
                    name='wg',
                    _log_file=_log_file,
                )
                WG_ADMIN_PATH = admin_path
                WG_PROC = entry
                _t.sleep(0.5)  # 等 wireguard.py 启动
                _do_add_peer()
            except Exception as e:
                log(f"[P2P] 启动 wireguard.py 失败: {e}")
    else:
        log(f"[消息] {json.dumps(obj)}")


def process_input_line(line):
    global pending_auth, WG_NATIVE_MODE, WG_NATIVE_MY_KEY, WG_NATIVE_MY_IP
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
            log("模式: fake（测试用，无网络）")
        elif sub in ('tun', 'tap'):
            LOCAL_MODE = sub
            LOCAL_DEVICE = dev
            log(f"模式: {sub}（tun 设备汇入 p2p 网络，设备: {dev or '(无)'}）")
        elif sub == 'auto':
            LOCAL_MODE = 'auto'
            LOCAL_DEVICE = None
            log("模式: auto（tun→tap→fake，自动选择）")
        elif sub == 'switch':
            _do_start_switch()
        elif sub == 'video':
            LOCAL_MODE = 'video'
            LOCAL_DEVICE = None
            log("模式: video（拉起 video.py 做 P2P 视频通话，TODO）")
        elif sub == 'file':
            LOCAL_MODE = 'file'
            LOCAL_DEVICE = None
            log("模式: file（拉起 file.py 做 P2P 文件传输，TODO）")
        else:
            log(f"未知 appmode: {sub}，可用: fake / tun [设备名] / tap [设备名] / auto / switch / video / file")
        return True
    elif cmd == 'udp':
        if not arg:
            log("用法: udp <对方用户名>")
            return True
        target = arg.strip()
        ws_send(ws_sock, {"type": "p2pudp", "target": target})
        log(f"P2P UDP 请求已发送给服务器，等待 {target} 确认...")
    elif cmd == 'tcp':
        if not arg:
            log("用法: tcp <对方用户名>")
            return True
        target = arg.strip()
        ws_send(ws_sock, {"type": "p2ptcp", "target": target})
        log(f"P2P TCP 请求已发送给服务器，等待 {target} 确认...")
    elif cmd == 'wg':
        if not arg:
            log("用法: wg <对方用户名>")
            return True
        target = arg.strip()
        WG_NATIVE_MODE = False
        ws_send(ws_sock, {"type": "p2pwg", "target": target})
        log(f"P2P WireGuard 请求已发送给服务器，等待 {target} 确认...")
    elif cmd == 'wghelp':
        # wghelp: 前半段同 wg，后半段拉起 wghelp.sh 配置原生 WireGuard
        if not arg:
            log("用法: wghelp <对方用户名> <我的私钥> <我的mesh IP>")
            log("  例: wghelp bob YGzbJJ8... 192.168.250.2")
            log("  注意: 私钥会传入 wghelp.sh（当前目录），不要在共享环境使用")
            return True
        parts = arg.strip().split()
        if len(parts) < 3:
            log("用法: wghelp <对方用户名> <我的私钥> <我的mesh IP>")
            return True
        target = parts[0]
        my_privkey = parts[1]
        my_ip = parts[2]
        WG_NATIVE_MODE = True
        WG_NATIVE_MY_KEY = my_privkey
        WG_NATIVE_MY_IP = my_ip
        ws_send(ws_sock, {"type": "p2pwg", "target": target})
        log(f"P2P WireGuard NAT穿透请求已发送，等待 {target} 确认...")
    elif cmd == 'ffmpeg':
        # ffmpeg: 前半段同 udp（p2pudp 握手），后半段拉起 ffmpeg.sh 做视频流
        if not arg:
            log("用法: ffmpeg <对方用户名>")
            log("  打洞成功后自动拉起 ffplay/ffmpeg 进行 P2P 视频通话")
            return True
        target = arg.strip()
        global FFMPEG_MODE
        FFMPEG_MODE = True
        ws_send(ws_sock, {"type": "p2pudp", "target": target})
        log(f"P2P ffmpeg 视频请求已发送，等待 {target} 确认...")
    elif cmd == 'peer':
        if not peers:
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
        if not arg or arg.strip() == 'all':
            # kill all peers
            if not peers:
                log("没有运行的 peer")
            else:
                for c in list(peers):
                    p = c.get('popen')
                    pid = c.get('pid')
                    if p is not None:
                        p.terminate()
                        log(f"已 terminate pid={pid} ({c['name']})")
                    elif pid is not None:
                        try:
                            import signal as _sig
                            if IS_WINDOWS:
                                os.kill(pid, _sig.CTRL_C_EVENT)
                            else:
                                os.kill(pid, _sig.SIGINT)
                            log(f"已发送 SIGINT pid={pid} ({c['name']})")
                        except (ProcessLookupError, OSError):
                            log(f"进程已不存在: pid={pid}")
                        except PermissionError:
                            log(f"权限不足: pid={pid}")
                    peers.remove(c)
            return True

        try:
            target_pid = int(arg.strip())
        except ValueError:
            log(f"无效 PID: {arg}")
            return True
        killed = False
        for c in peers:
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
                        log(f"已发送 SIGINT pid={target_pid} ({c['name']})")
                except (ProcessLookupError, OSError):
                    log(f"进程已不存在: pid={target_pid}")
                except PermissionError:
                    log(f"权限不足: pid={target_pid}")
                try:
                    peers.remove(c)
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
                        help='子进程日志：默认 False（stdout），True 时写入 /tmp/p2pnet/{udp|tcp}-{user}_{peer}_{time}.log）')
    parser.add_argument('--appmode', dest='appmode', default=None,
                        help='启动后自动设置的 appmode（fake/tun/tap/auto）')
    parser.add_argument('--udp', dest='udp_targets', action='append', default=[],
                        help='启动后自动连接的 UDP 用户（可多次指定）')
    parser.add_argument('--tcp', dest='tcp_targets', action='append', default=[],
                        help='启动后自动连接的 TCP 用户（可多次指定）')
    parser.add_argument('--wg', dest='wg_targets', action='append', default=[],
                        help='启动后自动连接的 WireGuard 用户（可多次指定）')
    parser.add_argument('--wghelp', dest='wghelp_targets', action='append', default=[],
                        help='启动后自动连接的 WireGuard 用户（原生 WG），格式: "user key=xxx mesh_ip=yyy"（可多次指定）')
    parser.add_argument('--ffmpeg', dest='ffmpeg_targets', action='append', default=[],
                        help='启动后自动视频连接的用户（可多次指定）')
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
    global STARTUP_UDP, STARTUP_TCP, STARTUP_WG, STARTUP_WGHELP, STARTUP_APPMODE, STARTUP_FFMPEG
    STARTUP_APPMODE = args.appmode
    STARTUP_UDP = args.udp_targets
    STARTUP_TCP = args.tcp_targets
    STARTUP_WG = args.wg_targets
    STARTUP_WGHELP = []
    for wg_arg in (args.wghelp_targets or []):
        # 格式: "user key=xxx mesh_ip=yyy"
        parts = wg_arg.split()
        if not parts:
            continue
        user = parts[0]
        key = ''
        mesh_ip = ''
        for p in parts[1:]:
            if p.startswith('key='):
                key = p[4:]
            elif p.startswith('mesh_ip='):
                mesh_ip = p[8:]
        STARTUP_WGHELP.append((user, key, mesh_ip))
    STARTUP_FFMPEG = args.ffmpeg_targets

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
    for c in list(peers):
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
            peers.remove(c)
        except ValueError:
            pass
    peers.clear()
    try:
        ws_sock.close()
    except:
        pass
    log("已退出")


if __name__ == '__main__':
    main()
