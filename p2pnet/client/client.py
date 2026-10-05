#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet 命令行客户端
python3 client.py --server 127.0.0.1 --port 10000

命令分四段：
  1. 基础      : help / quit / login / logout / list / del
  2. p2p       : direct / upnp / udp / tcp
  3. 打完洞以后的协议: udptest <洞> / proxy <洞> <host:port> / ffmpeg <洞> / wg-py <洞> / wg-sh <洞>
  4. 被调时的自动操作: onholefrompeer / onholefromself / onpeerwant{udp,tcp,direct,upnp}

这个文件只负责：连服务器 / 收 WS 消息 / CLI 命令 / 维护洞的**总表格** /
把打好的洞交给 app/ 下的协议（拉子进程）。
**每个洞的打洞步骤在 hole/ 里**（hole/udp.py 6 步、hole/tcp.py 5 步、direct/upnp 占位），
通过 hole/core.py 注入的钩子回调回来。
洞标识可以是 fd=<fd> / port=<本端端口> / #<编号> / <用户名>。
"""

import os
import sys
import json
import time
import argparse
import socket
import hashlib
import hmac
import binascii
import base64
import struct
import secrets
import errno
import array
import select
import threading
import subprocess

# 打洞步骤（每个洞怎么打）都在 hole/ 里；这里的 client.py 管总表格 + CLI + 拉起子进程
from hole import core as hole_core
from hole import udp as hole_udp
from hole import tcp as hole_tcp
from hole import direct as hole_direct
from hole import upnp as hole_upnp
from hole import stop_hole as hole_stop_hole

IS_WINDOWS = sys.platform == 'win32'


def launch_in_new_terminal(args, cwd=None, env=None, new_window=True, close_on_exit=False,
                   peer_name='', peer_ip='', peer_port=0, my_ip='', my_port=0, name=None,
                   _log_file=None, stdin_pipe=False, stdout_pipe=False, pass_fds=()):
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
        'hole_id': None,   # 这个子进程是为哪条洞拉起来的（list 里要按洞列出来）
    }

    if not new_window:
        # 后台直接跑
        if stdout_pipe:
            # 要读子进程的 stdout（switch 的 console 走 stdin/stdout JSON），日志留给 stderr
            stdout_arg, stderr_arg = subprocess.PIPE, None
        else:
            stdout_arg = open(_log_file, 'a') if _log_file else None
            stderr_arg = subprocess.STDOUT
        extra = {}
        if pass_fds:
            # 把已经建立的内核 socket（TCP 洞）继承给子进程，它直接用，不重做握手
            if os.name == 'posix':
                extra['pass_fds'] = tuple(pass_fds)
            else:
                # Windows：没有 pass_fds，只能把句柄标成可继承 + close_fds=False
                # ⚠️ 这条分支没有环境验证过（开发机是 Linux）
                import msvcrt
                for _fd in pass_fds:
                    os.set_handle_inheritable(msvcrt.get_osfhandle(_fd), True)
                extra['close_fds'] = False
        p = subprocess.Popen(
            args, cwd=cwd, env=env,
            stdin=(subprocess.PIPE if stdin_pipe else None),
            stdout=stdout_arg,
            stderr=stderr_arg,
            start_new_session=True,
            **extra
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
                    ['pgrep', '-f', f'python.*app/{_name}'],
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


# ====== 打洞表（洞）======
#
# 每条洞:
#   proto           : 'udp' / 'tcp'
#   id              : 编号（#1, #2 ...）
#   fd              : 主进程 socket 的真实 OS fd（udp 有；tcp 为 None）
#   peer            : 对方用户名
#   my_ip/my_port   : 本端（my_ip = 服务器看到的公网地址，my_port = 本地监听端口）
#   peer_ip/peer_port : 对端（服务器看到的公网地址）
#   status          : 打洞中 / 已打通 / 已交给 X / 地址已交换 / 拉起失败
#   handed_to       : None 或已移交给的用法（udptest / tun / ffmpeg / wg / tcp.py ...）
#   sock            : 未移交时主进程持有的 UDP socket（移交后置 None）
#   stop            : 通知该洞的 ping/pong 线程退出
#   thread          : 该洞的 ping/pong 线程
#
# 打洞的**步骤**在 hole/ 里（hole/udp.py 6 步、hole/tcp.py 5 步），
# 这里只放"总表格"和跟它配套的查/删/显示。
holes = []
_holes_lock = threading.Lock()
_hole_seq = 0

# 打洞成功后要自动拉起的用法（None = 只记录，等用户自己用 udptest fd=N 等拉起）
_pending_usage = None
# wg 用：对方 WireGuard 公钥（服务端未实现 thisisyourpeer_wg，只能命令行给）
_pending_wg_pubkey = None

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
WG_ADMIN_PATH = None  # wg-python.py 的 admin socket 路径
WG_PROC = None        # wg-python.py 进程

# Switch 共享进程（单实例）
SWITCH_PROC = None    # switch.py 进程
SWITCH_SOCK_PATH = None  # switch 的 Unix socket 路径（供 udptest.py/tcp.py 连接）
SWITCH_CTL_PATH = None   # switch 的控制通道（用 SCM_RIGHTS 把 TCP 洞的 fd 送进去）
# wg-sh（系统 wg 版，app/wg-calltool.py + app/wghelp.sh）需要的参数：
# 服务端没实现 thisisyourpeer_wg，对方公钥/mesh IP 拿不到，只能命令行给
WG_SH_MY_KEY = ''       # 我的私钥
WG_SH_MY_IP = ''        # 我的 mesh IP
WG_SH_PEER_PUBKEY = ''  # 对方公钥
WG_SH_PEER_IP = ''      # 对方 mesh IP
WG_SH_IFACE = 'wghelp0' # WireGuard 接口名
STARTUP_FFMPEG = []     # 启动时自动 ffmpeg 视频连接（每个元素: peer_name）
# 启动命令（login 成功后自动执行）
STARTUP_ON_SELF = None  # --onholefromself
STARTUP_ON_PEER = None  # --onholefrompeer
STARTUP_UDP = []
STARTUP_TCP = []
STARTUP_WG = []
STARTUP_WGSH = []    # 每个元素: (user, 我的私钥, 我的meshIP, 对方公钥, 对方meshIP, 接口名)
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

# ====== WS 协议级心跳（保活）======
# 服务端支持 RFC 6455 ping/pong：客户端发 0x9 ping 帧（**必须掩码**）→ 服务器原样回 0xA pong。
# 设计要点（GUI 是 in-process 驱动 client.py、自己跑收循环，所以心跳**不能**写在 main() 的
# select 循环里 —— 那样只有命令行跑才生效）：
#   · 随连接起：ws_handshake() 成功后自动 start_ws_heartbeat()（两种模式都自动生效）；
#   · 判活信号只能来自**读方**：谁在读 socket（main() 或 GUI 的引擎循环）谁负责在收到**任何字节**时
#     调一次 note_ws_rx()；心跳线程只发不读，绝不和读方抢 socket；
#   · 成功的心跳不打日志，失败只打一行。
WS_HEARTBEAT_INTERVAL = 20.0   # 每 20s 发一个 ping 帧（三端统一）
WS_HEARTBEAT_TIMEOUT = 10.0    # 发过 ping 之后这么久没收到任何字节 → 判定连接已死
WS_HEARTBEAT_PAYLOAD = b'p2pnet'      # payload 基名（下面带序号成 p2pnet#N）

_hb_lock = threading.Lock()
_hb_thread = None
_hb_stop = threading.Event()
_hb_last_rx = 0.0        # 最后一次"收到任何字节"的时刻（由读方 note_ws_rx() 更新）
_hb_last_tx = 0.0        # 最后一次"往这条 WS 上发东西"的时刻（含普通消息）
_hb_ping_sent_at = 0.0   # 最后一次发 ping 帧的时刻
_hb_count = 0            # 本次连接已经发过几次协议级 ping（日志里的"第 N 次"，随连接重置）

# ====== WS 自动重连（带熔断）======
# 触发：**连接已建立之后**，因 WS 协议级心跳判死、或异常断开（非用户主动断开）。
# 不触发：用户手动断开、首次连接就失败。
# 规则：退避 1s → 2s → 4s；**60 秒滑窗内最多 3 次**；到顶仍失败 → 放弃并打一行（文案三端一致）。
# 计数重置：① 用户手动连接；② 连接稳定存活 ≥60 秒。
WS_RECONNECT_BACKOFF = (1.0, 2.0, 4.0)   # 每次尝试前的等待（1s → 2s → 4s）
WS_RECONNECT_WINDOW = 60.0               # 60 秒滑窗
WS_RECONNECT_MAX = 3                     # 滑窗内最多 3 次


def ws_reconnect_delay(attempt):
    """第 attempt 次（从 1 开始）重连前的等待秒数；超出退避表 → None（= 该熔断了）"""
    if 1 <= attempt <= len(WS_RECONNECT_BACKOFF):
        return WS_RECONNECT_BACKOFF[attempt - 1]
    return None


def ws_reconnect_prune(attempts, now, window=WS_RECONNECT_WINDOW):
    """丢掉滑窗之外的尝试时刻（60 秒滑动窗口）"""
    return [t for t in attempts if (now - t) < window]


def ws_reconnect_allowed(attempts, now, window=WS_RECONNECT_WINDOW, limit=WS_RECONNECT_MAX):
    """滑窗内还能不能再自动重连一次"""
    return len(ws_reconnect_prune(attempts, now, window)) < limit


def ws_reconnect_log_attempt_text(n):
    """每次尝试前的日志正文（三端逐字一致）：WS 自动重连：第 N 次（60 秒窗口内）"""
    return f'WS 自动重连：第 {n} 次（{int(WS_RECONNECT_WINDOW)} 秒窗口内）'


def ws_reconnect_log_ok_text(n):
    """重连成功的日志正文（三端逐字一致）：WS 自动重连成功（第 N 次）"""
    return f'WS 自动重连成功（第 {n} 次）'


# 熔断放弃那一行（三端逐字一致）
WS_RECONNECT_GIVEUP_TEXT = (
    f'WS 自动重连已放弃：{int(WS_RECONNECT_WINDOW)} 秒内已重连 {WS_RECONNECT_MAX} 次仍失败'
    f'（不再自动重连，请手动连接）'
)

# ── 自动重连的运行时状态（client.py 自己持有：命令行和 GUI 都走这一份）──
_rc_attempts = []          # 60 秒滑窗内的重连尝试时刻
_last_connected_at = 0.0   # 本次连接建立时刻（稳定存活 ≥60s → 计数清零）
_saved_login_user = None   # 断线前登录用的凭据（重连后恢复登录）
_saved_login_pass = None
_was_logged_in = False     # 断开收尾时记下"断开前是否已登录"
_user_quit = False         # 用户输入 quit → 不自动重连

# "断开"的两种原因（四端统一口径）。
# ⚠️ "被踢"**不是**一种断开原因：它只把登录状态从"已登录"打回"已连接未登录"，
#    之后掉线自然落进"被动断开 + 断开前未登录"那一行 —— 所以不需要单独标记。
DISCONNECT_MANUAL = 'manual'     # ① 用户主动断开（quit / 点"断开"）
DISCONNECT_PASSIVE = 'passive'   # ② 其他被动断开（心跳判死 / 对端关闭 …）


def should_reconnect(reason):
    """四端统一：**只有 ③ 被动断开**才自动重连（① 主动断开不重连；② 被踢根本不是断开）。"""
    return reason == DISCONNECT_PASSIVE


def should_relogin(reason, was_logged_in):
    """
    四端统一：**被动断开** 且 **断开前最后状态是"已登录"** 才自动重新登录。

    没有单独的"被踢标记"：被踢只是把状态打回"已连接未登录"，于是这里自然是 False；
    用户被踢后手动 login 成功 → 状态又变"已登录" → 再掉线就又会自动重登（状态本身就是真相）。
    """
    return reason == DISCONNECT_PASSIVE and bool(was_logged_in)


def current_disconnect_reason():
    """当前这次**断开**属于哪种（被踢不是断开，所以不在这里）"""
    if _user_quit:
        return DISCONNECT_MANUAL
    return DISCONNECT_PASSIVE


def reconnect_allowed():
    """现在允许自动重连吗（用户主动断开 → False）。

    `ws_auto_reconnect()` 内部还会再查一次（保险）；GUI 起线程前也查这个。
    """
    return should_reconnect(current_disconnect_reason())


def relogin_allowed():
    """现在允许自动重新登录吗（判据 = 被动断开 + 断开前最后状态是已登录）"""
    return should_relogin(current_disconnect_reason(), _was_logged_in)


def mark_user_connect():
    """用户**手动**连接 / 手动登录时调：清掉"主动退出"标记并清零重连计数。"""
    global _user_quit
    _user_quit = False
    ws_reconnect_reset()


def ws_reconnect_reset():
    """重连计数清零（① 用户手动连接；② 连接稳定存活 ≥60 秒）"""
    global _rc_attempts, _last_connected_at
    _rc_attempts = []
    _last_connected_at = time.time()


def ws_reconnect_plan(now=None):
    """
    现在该不该重连、该等多久（**纯决策**，命令行与 GUI 共用；self-test 也直接测它）：
      返回 (第 N 次, 等待秒数)，或 None（= 熔断，放弃自动重连）
    """
    now = time.time() if now is None else now
    attempts = ws_reconnect_prune(_rc_attempts, now)
    if not ws_reconnect_allowed(attempts, now):
        return None
    n = len(attempts) + 1
    delay = ws_reconnect_delay(n)
    return None if delay is None else (n, delay)


def ws_reconnect_note_attempt(now=None):
    """记一次重连尝试（进 60 秒滑窗）"""
    global _rc_attempts
    now = time.time() if now is None else now
    _rc_attempts = ws_reconnect_prune(_rc_attempts, now) + [now]


def ws_reconnect_sleep(seconds, should_stop=None):
    """可打断的退避等待；返回 True = 被打断（用户断开/退出，别再重连了）"""
    end = time.time() + max(0.0, seconds)
    while time.time() < end:
        if should_stop is not None and should_stop():
            return True
        time.sleep(0.05)
    return bool(should_stop is not None and should_stop())


def _close_ws_socket():
    """关掉当前 WS socket（重连前必须关，别漏 fd）"""
    global ws_sock
    try:
        if ws_sock is not None:
            ws_sock.close()
    except Exception:
        pass
    ws_sock = None


def ws_connect_once(host=None, port=None):
    """
    建 socket + WS 握手（握手成功后**心跳自动起**，见 ws_handshake）。成功返回 True。

    命令行与 GUI 都用它，所以"连接"这件事只有一个实现。
    """
    global connected, ws_sock, recv_buf
    host = host or SERVER_IP
    port = int(port or SERVER_PORT)
    try:
        info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        family, socktype, proto, _, sockaddr = info[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(10)
        sock.connect(sockaddr)
    except Exception as e:
        log(f"连接失败: {e}")
        return False
    if not ws_handshake(sock, host, port):
        log("WebSocket 握手失败")
        try:
            sock.close()
        except Exception:
            pass
        return False
    sock.setblocking(False)
    ws_sock = sock
    recv_buf = b''
    connected = True
    return True


def mark_disconnected():
    """
    一次会话结束时的统一收尾（命令行与 GUI 都调）：

      · 记下"断开前是否已登录"，供重连后恢复登录；
      · 连接稳定存活 ≥60 秒 → 重连计数清零；
      · 清掉会话态（登录用户 / session_key / 半截登录），关掉旧 socket。
    """
    global _was_logged_in, logged_in_user, session_key, pending_auth, connected
    _was_logged_in = logged_in_user is not None
    if _last_connected_at and (time.time() - _last_connected_at) >= WS_RECONNECT_WINDOW:
        ws_reconnect_reset()          # 稳定存活 ≥60 秒 → 计数清零
    logged_in_user = None
    session_key = None
    pending_auth = None
    connected = False
    stop_ws_heartbeat()      # 会话真的结束了 → 心跳停
    _close_ws_socket()


def ws_auto_reconnect(host=None, port=None, *, on_connected=None, should_stop=None):
    """
    **连接已建立过**之后异常断开时调用：按策略自动重连（退避 1s→2s→4s，60 秒滑窗内最多 3 次）。

      返回 True  = 已重连上（socket/心跳都就绪，调用方接着跑自己的读循环）；
      返回 False = 放弃（熔断）/ 被 should_stop 打断（用户断开或退出）。

    命令行（main()）和 GUI（EngineBridge）都调这个 —— 重连只有这一份实现。
    """
    if not reconnect_allowed():
        # 用户主动断开（quit / 点"断开"）：连试都不试（调用方忘了判断也拦得住）。
        return False
    host = host or SERVER_IP
    port = int(port or SERVER_PORT)
    while True:
        if should_stop is not None and should_stop():
            return False
        plan = ws_reconnect_plan()
        if plan is None:
            log(WS_RECONNECT_GIVEUP_TEXT)
            return False
        n, delay = plan
        log(ws_reconnect_log_attempt_text(n))
        if ws_reconnect_sleep(delay, should_stop):
            return False
        ws_reconnect_note_attempt()
        if not ws_connect_once(host, port):
            continue                      # 失败 → 下一轮（计数已 +1，窗口满就熔断）
        log(ws_reconnect_log_ok_text(n))
        if on_connected is not None:
            on_connected()
        return True


def start_login(username):
    """发起一次登录（发 login 等 challenge）。命令行自动登录 / 重连后恢复登录都走这里。"""
    global pending_auth
    pending_auth = (username,)
    ws_send(ws_sock, {"type": "login", "username": username})
    log("等待服务器验证...")


def resume_login():
    """重连成功后：断开前若为已登录，用保存的凭据走现有登录流程重新登录；没凭据就如实说明。"""
    global ARGS_USER, ARGS_PASS
    if not relogin_allowed():
        # 断开前就是"已连接未登录"（含被服务器踢下线之后）→ 本来就不该自动重登（四端统一文案）
        if not _was_logged_in:
            log("WS 自动重连：连接已恢复，断开前未登录，不自动重新登录")
        return
    if not (_saved_login_user and _saved_login_pass):
        # 被动断开 + 断开前已登录，但拿不到凭据 → 只恢复连接，不假装已登录（四端统一文案）
        log("WS 自动重连：连接已恢复，但没有可用的凭据，需要手动重新登录")
        return
    # 断开前已登录且有凭据：**只发这一次**（登录失败也不循环重试，等用户手动）
    log("WS 自动重连：用保存的凭据重新登录")      # 四端统一文案
    ARGS_USER, ARGS_PASS = _saved_login_user, _saved_login_pass
    start_login(_saved_login_user)


# ====== 应用层 ping（服务端：{"type":"ping","seq":N} → {"type":"pong","seq":N}，不需要登录）======
# ⚠️ 和这两处是**不同**的东西，别混：
#   · hole/udp.py 的 UDP ping/pong（洞打通之后在洞上互发，用来探活 + 算 RTT）
#   · sign_with_session_key(b'ping') 那个 HMAC 签名（p2pudp_hello 的签名用的字面量）
_app_ping_seq = 0
_app_ping_sent = {}      # seq → 发出时刻，收到 pong 时算 RTT


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

# 被调时的自动操作：洞打通之后自动跑什么
#   本端发起打洞（我敲 udp/tcp <user>） → ON_SELF_HOLE
#   对方打进来（服务器通知我）        → ON_PEER_HOLE
# 每个变量是 None 或 (模式, 设备)；None = 当前行为（洞记下来，等用户自己 udptest fd=N 拉起）
ON_SELF_HOLE = None
ON_PEER_HOLE = None
# 对方来找我时怎么办（按协议分开；auto = 参与（默认，当前行为） / none = 静默拒绝）
#   udp/tcp : 收到 send_udp_to_server / send_tcp_to_server 时要不要参与打洞
#   direct  : 收到别人的 p2pdirect（对方要我的地址）时要不要回地址
#   upnp    : 暂时没有消费者（upnp 本身还没实现），先把状态位留着
ON_PEER_WANT = {'udp': 'auto', 'tcp': 'auto', 'direct': 'auto', 'upnp': 'auto'}

# list 命令在等服务器回谁：'all' = 三块都打 / 'peer' = 只打同服务器的人 / None = 没在等
_list_what = None

# 洞打通可以自动跑 / 手动拉起的用法
HOLE_USAGES = ('udptest', 'tun', 'tap', 'auto', 'switch', 'proxy', 'ffmpeg', 'wg-py', 'wg-sh')
# onholefromself / onholefrompeer 能设的值（video/file 还没实现，允许设，拉起时会提示 TODO）
ON_HOLE_MODES = ('udptest', 'tun', 'tap', 'auto', 'switch', 'proxy',
                 'ffmpeg', 'wg-py', 'wg-sh', 'video', 'file')

# 线程安全的消息队列
input_queue = []
queue_lock = threading.Lock()


def ts():
    import time as _time
    return _time.strftime("%H:%M:%S")

def log(msg):
    hole_core.finish_open()   # 别的输出来了，先把没定结果的步骤行收尾
    print(f"[{ts()}][client] {msg}")
    sys.stdout.flush()


def dbg(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


# ====== 打洞模块接线（打洞步骤在 hole/ 里）======
#
# hole/udp.py   UDP 打洞 6 步   hole/tcp.py  TCP 打洞 5 步
# hole/direct.py / hole/upnp.py 占位
#
# hole/ 不反向 import client：这里把日志、WS 发送、建洞记录（总表格）、
# 以及"洞通了怎么办"的钩子注入给它。

def _hole_configure():
    """把 client 这边的钩子注入 hole/（在 main() 里调一次）"""
    hole_core.log = log
    hole_core.ws_send = lambda obj: ws_send(ws_sock, obj)
    hole_core.record_hole = _record_hole
    hole_core.holes_lock = _holes_lock
    hole_core.sign_session = lambda: sign_with_session_key(b'ping')
    hole_core.on_udp_ready = _auto_handover
    hole_core.launch_tcp = _launch_tcp_on_hole
    hole_core.get_server = lambda: (SERVER_IP, SERVER_PORT)
    hole_core.get_username = lambda: logged_in_user
    hole_core.get_debug = lambda: DEBUG
    hole_core.get_onpeerwant = lambda kind: ON_PEER_WANT.get(kind, 'auto')

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
    ok = b"101 Switching Protocols" in resp
    if ok:
        # 连接建立 → 自动起 WS 心跳（main() 和 GUI 都走这里，所以两种模式都生效；
        # 不需要各调用方自己记着起）
        start_ws_heartbeat()
    return ok


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
        # 对端要关连接：停掉心跳（返回值仍然是 None，不改调用方看到的行为）
        stop_ws_heartbeat()
        return None
    if opcode == 0x9:
        # 服务端主动 ping：按 RFC 6455 回一个 pong（payload 原样带回）。
        # ⚠️ 只是"顺手回一下"，**返回值仍然是 None**（调用方只认 0x1 文本帧）。
        try:
            if ws_sock is not None:
                ws_sock.send(ws_pong_frame(payload))
        except Exception:
            pass
        return None
    if opcode == 0xA:
        # 协议级 pong：服务端把 payload 原样回（我们发的是 p2pnet#N），从这里解出序号，
        # 打出与"发出"配对的那一行。**只有真的读到 0xA 才打**（不是发的时候就预告）。
        # 判活仍靠 note_ws_rx()（读方的事）；返回值仍然是 None，契约不变。
        seq = ws_heartbeat_seq_from_payload(payload)
        if seq is not None:
            log(ws_heartbeat_pong_log_text(seq))
            # 应答到了 → 不再"等应答"。这是第二道防线：即便将来判死条件又被改坏，
            # 也不会拿着旧的等待状态去判死（语义最直白：还在等吗？不等了）。
            _hb_clear_pending()
        return None
    if opcode == 0x1:
        return payload.decode('utf-8', errors='replace')
    return None


def ws_send(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    framed = ws_encode(data)
    sock.send(framed)
    _hb_note_tx()
    dbg(f"[SEND] {json.dumps(obj)}")


def send_app_ping():
    """应用层 ping：`{"type":"ping","seq":N}` —— 先 log 出来（App 内日志面板能看到）再发。

    `N` 每次调用 +1，从 1 开始。命令入口：`process_input_line("ping")`。
    """
    global _app_ping_seq
    _app_ping_seq += 1
    payload = {"type": "ping", "seq": _app_ping_seq}
    log(f"发出应用层 ping：{json.dumps(payload, ensure_ascii=False)}")
    _app_ping_sent[_app_ping_seq] = time.time()
    if ws_sock is None:
        log("还没连上，发不出去")
        return
    try:
        ws_send(ws_sock, payload)
    except Exception as e:
        log(f"发送应用层 ping 失败：{e!r}")


# ====== WS 心跳：帧构造 + 判活 + 线程 ======

def ws_ping_frame(payload=WS_HEARTBEAT_PAYLOAD, mask=None):
    """构一个**带掩码**的 WebSocket ping 帧（RFC 6455：客户端 → 服务器必须掩码）

        byte0 = 0x89        FIN=1 + opcode=0x9
        byte1 = 0x80 | len  MASK 位 + 长度（payload ≤125 时一字节）
        然后 4 字节 mask key + 掩码后的 payload

    ⚠️ 不能用 ws_encode()：那只发 0x1 文本帧。
    `mask` 可注入，方便测试断言确定的字节序列。
    """
    if mask is None:
        mask = secrets.token_bytes(4)
    if len(mask) != 4:
        raise ValueError('mask 必须是 4 字节')
    n = len(payload)
    if n > 125:
        raise ValueError('心跳 payload 不该超过 125 字节（不实现扩展长度）')
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(n))
    return bytes([0x89, 0x80 | n]) + mask + masked


def ws_pong_frame(payload=b'', mask=None):
    """回一个 pong 帧（0x8A），payload 原样带回 —— 服务端若主动 ping，按规范要回这个"""
    if mask is None:
        mask = secrets.token_bytes(4)
    if len(mask) != 4:
        raise ValueError('mask 必须是 4 字节')
    n = len(payload)
    if n > 125:
        raise ValueError('pong payload 不该超过 125 字节（不实现扩展长度）')
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(n))
    return bytes([0x8A, 0x80 | n]) + mask + masked


def ws_heartbeat_log_text(n):
    """协议级心跳的日志正文（三端必须逐字一致）。

    前缀 `[时间][client]` 由 log() 自己加，这里只给正文：
        WS 心跳：发出协议级 ping（第 N 次，间隔 20s）
    """
    return f'WS 心跳：发出协议级 ping（第 {n} 次，间隔 {int(WS_HEARTBEAT_INTERVAL)}s）'


def ws_heartbeat_pong_log_text(n):
    """协议级心跳"收到 pong"的日志正文（三端逐字一致）：
        WS 心跳：收到协议级 pong（第 N 次）
    """
    return f'WS 心跳：收到协议级 pong（第 {n} 次）'


def ws_heartbeat_payload(n):
    """心跳 ping 的 payload：**带序号**（`p2pnet#3`）。

    为什么要带：服务端会把 payload **原样回**，所以收到 pong 时能从 payload 解出
    这是"第几次 ping 的回包"，做到**精确对应**（而不是靠"数收到过几次"去猜）。
    """
    return f'{WS_HEARTBEAT_PAYLOAD.decode()}#{n}'.encode()


def ws_heartbeat_seq_from_payload(payload):
    """从 pong 的 payload 解出对应的 ping 序号；不是我们的心跳 payload 就返回 None"""
    try:
        text = payload.decode('utf-8', errors='replace')
    except Exception:
        return None
    prefix = WS_HEARTBEAT_PAYLOAD.decode() + '#'
    if not text.startswith(prefix):
        return None
    tail = text[len(prefix):]
    return int(tail) if tail.isdigit() else None


def _hb_clear_pending():
    """清掉"正在等协议级 pong"的状态（收到应答时调）"""
    global _hb_ping_sent_at
    with _hb_lock:
        _hb_ping_sent_at = 0.0


def note_ws_rx():
    """**读方**每收到任何字节就喊一声（pong 帧也算"有字节"）。

    GUI 的引擎循环、main() 的 select 循环都要调；心跳线程据此判活。
    """
    global _hb_last_rx
    with _hb_lock:
        _hb_last_rx = time.time()


def _hb_note_tx():
    """往这条 WS 上发过东西了（普通消息也算）—— 免得刚发完就补一个心跳"""
    global _hb_last_tx
    with _hb_lock:
        _hb_last_tx = time.time()


def start_ws_heartbeat():
    """连接建立后自动调用（见 ws_handshake）。幂等：重复调不会起第二个线程。"""
    global _hb_thread, _hb_last_rx, _hb_last_tx, _hb_ping_sent_at, _hb_count
    stop_ws_heartbeat()
    now = time.time()
    with _hb_lock:
        _hb_last_rx = now
        _hb_last_tx = now
        _hb_ping_sent_at = 0.0
    _hb_count = 0        # 计数跟连接同生命周期：每次 start（= 每次握手成功）都从 1 重新数
    _hb_stop.clear()
    _hb_thread = threading.Thread(target=_ws_heartbeat_loop, name='ws-heartbeat', daemon=True)
    _hb_thread.start()


def stop_ws_heartbeat():
    """停掉心跳线程（断开/被踢/退出/收到 0x8 都要调）。可从心跳线程自己里调，不会自 join。"""
    global _hb_thread, _hb_ping_sent_at
    _hb_stop.set()
    t = _hb_thread
    if t is not None and t is not threading.current_thread() and t.is_alive():
        t.join(timeout=1.0)
    _hb_thread = None
    with _hb_lock:
        _hb_ping_sent_at = 0.0


def _ws_heartbeat_loop():
    """心跳线程：只发不读。判死 → 打一行日志 + connected=False + 自己停掉。

    ⚠️ 这里对 `_hb_last_tx/_hb_ping_sent_at` 有**赋值**，所以必须 global 声明 ——
    少了它 Python 会把它们当局部变量，线程一起来就 `UnboundLocalError` 静默死掉
    （这个 bug 是端到端真连服务器时才暴露的：self-test 不会真起线程）。
    """
    global connected, _hb_last_tx, _hb_ping_sent_at
    try:
        _ws_heartbeat_loop_inner()
    except Exception as e:
        # 兜底：心跳线程无论如何不该静默死掉，至少留一行
        log(f'WS 心跳线程异常退出：{e!r}')


def _ws_heartbeat_loop_inner():
    while not _hb_stop.wait(0.5):
        if _ws_heartbeat_tick(time.time()) == 'dead':
            return


def _ws_heartbeat_tick(now):
    """心跳的一轮（抽出来是为了 self-test 能不起真线程就测）：

        返回 'dead'（判死，已停线程）/ 'sent'（这一轮真发了帧）/ 'idle'（只检查，没到时机）

    **只有 'sent' 那一轮会打日志**（"检查但没发"或"跳过"都不打）—— 用户要求。
    日志打在 `sock.send()` **之前**（"发出协议级 ping 之前打一行"）。
    """
    global connected, _hb_last_tx, _hb_ping_sent_at, _hb_count
    with _hb_lock:
        last_rx, last_tx, ping_at = _hb_last_rx, _hb_last_tx, _hb_ping_sent_at
    # 发过 ping 之后，超时窗口内**一个字节都没收到** → 判定连接已死。
    # ⚠️ 必须写成"`last_rx < ping_at`（发 ping 之后没收到过任何字节）**且**距 ping 已超时"。
    # 只写 `now - last_rx >= TIMEOUT` 是错的：那看的是"距上次收字节多久"，
    # 于是 ping 发出去满 10s 就必然为真 —— 哪怕这期间 pong 早就到了、last_rx 刚被刷新，
    # 每个心跳周期都会在 ping+10s 稳定误判死（用户实机撞到过）。
    if ping_at and last_rx < ping_at and (now - ping_at) >= WS_HEARTBEAT_TIMEOUT:
        log('pong 超时：连接已断开（WS 心跳失败）')
        connected = False
        stop_ws_heartbeat()
        return 'dead'
    if (now - last_tx) < WS_HEARTBEAT_INTERVAL:
        return 'idle'          # 没到发送时机：不打日志
    sock = ws_sock
    if sock is None:
        stop_ws_heartbeat()
        return 'idle'          # 没 socket 可发：也不打
    _hb_count += 1
    log(ws_heartbeat_log_text(_hb_count))    # ← 发之前打一行（三端逐字一致）
    try:
        # payload 带序号：服务端原样回，收到 pong 时就能打出"第 N 次"，精确对应
        sock.send(ws_ping_frame(ws_heartbeat_payload(_hb_count)))
    except Exception as e:
        log(f'发送 WS 心跳失败：{e!r}')
        connected = False
        stop_ws_heartbeat()
        return 'dead'
    with _hb_lock:
        _hb_last_tx = now
        _hb_ping_sent_at = now
    return 'sent'


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


# ====== 打洞：主进程自己做第 5/6 步 ======

def _new_hole_id():
    global _hole_seq
    _hole_seq += 1
    return _hole_seq


def _record_hole(proto, peer, peer_ip, peer_port, my_ip, my_port,
                 fd=None, sock=None, status='打洞中'):
    """往洞表里加一条记录"""
    hole = {
        'proto': proto, 'id': _new_hole_id(), 'fd': fd, 'peer': peer,
        'my_ip': my_ip, 'my_port': my_port,
        'peer_ip': peer_ip, 'peer_port': peer_port,
        # 候选地址：服务器给的 srflx 是第一个；之后收到对方包的源地址（peer-reflexive）
        # 会往里追加。每轮往所有候选都发一份 ping。
        'candidates': ([{'ip': peer_ip, 'port': peer_port}]
                       if (peer_ip and peer_port) else []),
        'status': status, 'handed_to': None, 'sock': sock,
        'stop': threading.Event(), 'thread': None, 'rtt': None,
        'created': time.time(), 'local_init': False,
    }
    with _holes_lock:
        holes.append(hole)
    return hole


def _on_hole_cfg(hole):
    """按角色取"洞打通自动跑什么"，返回 (模式, 设备)；没设返回 (None, None)"""
    cfg = ON_SELF_HOLE if hole.get('local_init') else ON_PEER_HOLE
    if not cfg:
        return None, None
    return cfg


def _auto_handover(hole):
    """
    打洞成功后要不要"自动执行"，看两个状态变量（都在"被调时的自动操作"里）：

      ON_SELF_HOLE : 本端发起打洞（我敲 udp/tcp <user>）→ 打通后自动跑什么
      ON_PEER_HOLE : 对方打进来 → 打通后自动跑什么
      _pending_usage : ffmpeg/wg <user> 这类一次性用法，优先于上面两个

    没设 → 不自动执行，只把洞记下来，等用户自己 udptest fd=N 等拉起（= 当前行为）。
    """
    global _pending_usage
    usage = _pending_usage
    device = None
    if usage:
        _pending_usage = None
    else:
        usage, device = _on_hole_cfg(hole)

    local = bool(hole.get('local_init'))
    who = '本端发起' if local else '对方发起'
    var = 'onholefromself' if local else 'onholefrompeer'
    if usage:
        log(f"[洞 #{hole['id']}] {var} = {usage}"
            + (f" {device}" if device else '')
            + f"（{who}），打洞成功，自动拉起...")
        _handover_hole(hole, usage, device)
    else:
        log(f"[洞 #{hole['id']}] {var} 未设定（{who}），不自动拉起；"
            f"洞保持打通状态，用 udptest fd={hole['fd']} 等自己拉起")


def _looks_like_hole_selector(s):
    """fd=21 / port=50001 / #1 / 21 这种是洞标识，不是用户名"""
    s = (s or '').strip()
    return ('=' in s) or s.startswith('#') or s.isdigit()


def _resolve_hole(arg):
    """把 fd=N / port=N / #N / N / name=X / <用户名> 解析成一条洞记录。
    返回 (hole, errmsg)。"""
    s = (arg or '').strip()
    if not s:
        return None, "缺少洞标识（fd=<fd> / port=<本端端口> / #<编号> / <用户名>）"

    kind, val = 'auto', s
    if '=' in s:
        k, v = s.split('=', 1)
        kind, val = k.strip().lower(), v.strip()
    elif s.startswith('#'):
        kind, val = 'id', s[1:].strip()
    elif not s.isdigit():
        kind, val = 'name', s

    with _holes_lock:
        cands = list(holes)

    def _rank(h):
        if h['status'] == '已打通' and not h['handed_to']:
            return 0
        if h['status'] == '打洞中':
            return 1
        return 2
    cands.sort(key=_rank)

    def _match(pred):
        for h in cands:
            if pred(h):
                return h
        return None

    if kind in ('fd', 'id', 'port', 'auto'):
        try:
            n = int(val)
        except ValueError:
            return None, f"洞标识不是数字: {s}"
        if kind in ('fd', 'auto'):
            h = _match(lambda x: x.get('fd') == n)
            if h:
                return h, None
        if kind in ('id', 'auto'):
            h = _match(lambda x: x.get('id') == n)
            if h:
                return h, None
        if kind in ('port', 'auto'):
            h = _match(lambda x: x.get('my_port') == n)
            if h:
                return h, None
        return None, f"找不到洞 {s}（用 hole 看已有洞）"

    if kind in ('name', 'peer', 'user'):
        h = _match(lambda x: x.get('peer') == val)
        if h is None:
            h = _match(lambda x: str(x.get('peer', '')).startswith(val))
        if h is None:
            return None, f"找不到和 {val} 的洞（用 hole 看已有洞）"
        return h, None

    return None, f"不认识的洞标识: {s}"


def _split_pubkey(arg):
    """从 'bob pubkey=xxx' 里分出用户名和可选 pubkey=..."""
    pubkey = None
    rest = []
    for tok in (arg or '').split():
        if tok.startswith('pubkey='):
            pubkey = tok[len('pubkey='):]
        else:
            rest.append(tok)
    return ' '.join(rest), pubkey


# 打完洞之后的用法（HOLE_USAGES 见文件开头全局区）


def _handover_hole(hole, usage, device=None):
    """把打好的洞交给某个用法。

    主进程先 close 自己的 socket（让子进程能 bind 同一个本地端口，NAT 映射不废），
    再把 地址/端口 传给子进程 —— 不传 fd。
    洞记录不删，只把 status 改成 "已交给 X"。"""
    if not hole:
        log("没有可用的洞")
        return False
    if hole.get('handed_to'):
        log(f"[洞 #{hole['id']}] 已经交给 {hole['handed_to']}，不能重复拉起")
        return False
    if hole['proto'] != 'udp':
        log(f"[洞 #{hole['id']}] 是 {hole['proto']} 洞，不能这样拉起")
        return False
    if hole['status'] != '已打通':
        log(f"[洞 #{hole['id']}] 还没打通（{hole['status']}），不能拉起 {usage}")
        return False

    # ---- 先校验，避免关了 socket 才发现拉不起来（洞就废了）----
    if usage not in HOLE_USAGES:
        log(f"[洞 #{hole['id']}] 用法 {usage} 还没实现（TODO），洞保持打通状态")
        return False
    if usage == 'wg-py' and not _pending_wg_pubkey:
        log("[P2P] wg-py 需要对方的 WireGuard 公钥（服务端暂未实现 thisisyourpeer_wg，拿不到）")
        log("      请用: wg-py <洞> pubkey=<对方公钥base64>")
        return False
    if usage == 'wg-sh' and not (WG_SH_MY_KEY and WG_SH_MY_IP and WG_SH_PEER_PUBKEY):
        log("[P2P] wg-sh 需要: 我的私钥 / 我的 mesh IP / 对方公钥 / 对方 mesh IP")
        log("      请用: wg-sh <洞> <我的私钥> <我的meshIP> <对方公钥> <对方meshIP> [接口名]")
        return False

    # ---- 关掉主进程 socket，等 ping 线程退出，释放本地端口 ----
    hole['stop'].set()
    sock = hole.get('sock')
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
        hole['sock'] = None
    t = hole.get('thread')
    if t and t.is_alive() and t is not threading.current_thread():
        t.join(timeout=2.0)

    if usage == 'udptest':
        ok = _launch_udptest(hole)                     # 纯互发测试
    elif usage in ('tun', 'tap', 'auto'):
        ok = _launch_vpn(hole, usage, device)          # 单人单 tun/tap
    elif usage == 'switch':
        ok = _switch_plug(hole)                        # 插到已在跑的虚拟交换机上（多人多洞）
    elif usage == 'proxy':
        ok = _launch_proxy(hole, device)               # device 这一格放目标 host:port
    elif usage == 'ffmpeg':
        ok = _launch_ffmpeg(hole)
    elif usage == 'wg-py':
        ok = _launch_wg_python(hole)
    elif usage == 'wg-sh':
        ok = _launch_wg_calltool(hole)
    else:
        log(f"[洞 #{hole['id']}] 不认识的用法: {usage}")
        return False

    if ok:
        hole['handed_to'] = usage
        hole['status'] = f'已交给 {usage}'
        # 具体交给谁（switch 会写成"switch 的 port1 端口"，其余就是 usage 本身）
        detail = hole.get('handed_detail') or usage
        log(f"[洞 #{hole['id']}] {hole['peer']} 已交给 {detail}"
            f"（本端端口 {hole['my_port']} ↔ 对端 {hole['peer_ip']}:{hole['peer_port']}）")
    else:
        hole['status'] = '拉起失败'
    return ok


def _launch_hole_program(base_args, hole, name):
    """把一条打好的 UDP 洞交给 app/ 下的某个"使用者程序"

    只传地址/端口（不传 fd）：使用者程序自己 bind 同一个本地端口，NAT 映射才不废。
    打洞阶段学到的额外候选（peer-reflexive）一并带过去，
    不然使用者程序又会只往服务器给的那个地址发。
    """
    remote_args = list(base_args) + [
        '--peeraddr', str(hole['peer_ip']),
        '--peerport', str(hole['peer_port']),
        '--localport', str(hole['my_port']),
    ]
    extra = [c for c in hole.get('candidates', [])
             if (c['ip'], c['port']) != (hole['peer_ip'], hole['peer_port'])]
    if extra:
        remote_args += ['--peercandidates',
                        ','.join(f"{c['ip']}:{c['port']}" for c in extra)]
        log(f"[P2P] 额外候选地址: " + ', '.join(f"{c['ip']}:{c['port']}" for c in extra))

    _log_file = None
    if REMOTELOG:
        try:
            os.makedirs('/tmp/p2pnet', exist_ok=True)
        except OSError:
            pass
        _log_file = f"/tmp/p2pnet/{name}-{logged_in_user}_{hole['peer']}_{int(time.time())}.log"
        remote_args += ['--remotelog', _log_file]

    try:
        entry = launch_in_new_terminal(
            remote_args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={**os.environ, 'PYTHONUNBUFFERED': '1', 'P2P_USER': logged_in_user or ''},
            new_window=NEW_WINDOW, close_on_exit=CLOSE_WINDOW,
            peer_name=hole['peer'], peer_ip=hole['peer_ip'], peer_port=hole['peer_port'],
            my_ip=hole['my_ip'], my_port=hole['my_port'],
            name=name, _log_file=_log_file,
        )
        if entry:
            entry['hole_id'] = hole['id']
    except Exception as e:
        log(f"[P2P] 拉起 {name} 失败: {e}")
        return False
    log(f"[P2P] {name} 已拉起（本端端口 {hole['my_port']}）")
    return True


def _launch_udptest(hole):
    """交给 app/udptest.py：只做互发 ping/pong 测试"""
    return _launch_hole_program([sys.executable, 'app/udptest.py'], hole, 'udptest')


def _launch_vpn(hole, dev, devname=None):
    """交给 app/vpn.py：一个洞 ↔ 一个 tun/tap（单人单 tun）"""
    args = [sys.executable, 'app/vpn.py', '--dev', dev]
    if devname:
        args += ['--devname', str(devname)]
    return _launch_hole_program(args, hole, 'vpn')


def _launch_proxy(hole, target):
    """交给 app/proxy.py：把洞里的数据转发到 target（host:port）"""
    if not target:
        log("[P2P] proxy 需要目标地址（用法: proxy <洞> <host:port>，"
            "或 onholefrompeer proxy <host:port>）")
        return False
    return _launch_hole_program([sys.executable, 'app/proxy.py', '--target', str(target)],
                                hole, 'proxy')


def _ffmpeg_script_path():
    """
    ffmpeg.sh 的真实路径：`client/app/ffmpeg.sh`。

    ⚠️ 原来这里拼的是 `dirname(client.py)/ffmpeg.sh` = `client/ffmpeg.sh`（不存在）
    → `ffmpeg <洞>` / `--ffmpeg <user>` / `onholefrom* ffmpeg` 永远失败，只打一行
    "ffmpeg.sh 不在当前目录"。抽成函数是为了让 self-test 能直接断言它存在。
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app', 'ffmpeg.sh')


def _launch_ffmpeg(hole):
    """在打好的洞上跑 ffmpeg.sh <my_ip> <my_port> <peer_ip> <peer_port>"""
    script_path = _ffmpeg_script_path()
    if not os.path.exists(script_path):
        log(f"[P2P] 错误: 找不到 ffmpeg.sh: {script_path}")     # 明确错误（不是"不在当前目录"）
        return False
    call_args = ['bash', script_path,
                 hole['my_ip'] or '0.0.0.0', str(hole['my_port']),
                 str(hole['peer_ip']), str(hole['peer_port'])]
    try:
        entry = launch_in_new_terminal(
            call_args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            new_window=True, close_on_exit=False,
            peer_name=hole['peer'], peer_ip=hole['peer_ip'], peer_port=hole['peer_port'],
            my_ip=hole['my_ip'], my_port=hole['my_port'], name='ffmpeg',
        )
        if entry:
            entry['hole_id'] = hole['id']
    except Exception as e:
        log(f"[P2P] ffmpeg 拉起失败: {e}")
        return False
    log("[P2P] ffmpeg 已在新窗口启动")
    return True


def _launch_tcp_on_hole(hole, sock, peer_name, peer_ip, peer_port, my_ip, my_port):
    """TCP 打洞第 5 步：把**已建立连接的内核 socket** 继承给 app/tcptest.py

    和 UDP 完全不同：UDP 可以"主进程关掉 socket、子进程 bind 同一端口"接着用；
    TCP 一关连接就没了，子进程重建会**重新 SYN/ACK**，NAT 那边对不上。
    所以这里把 fd 直接继承过去（pass_fds），子进程拿它就用，不重建、不重连。

    代价：必须后台拉起（新终端窗口没法继承 fd），所以看不到窗口，只能靠日志。
    """
    # 本地这头挂什么，按角色取 onholefromself / onholefrompeer
    mode, _device = _on_hole_cfg(hole)
    if mode == 'switch':
        return _switch_plug_fd(hole, sock, peer_name)

    fd = sock.fileno()
    try:
        os.set_inheritable(fd, True)
    except (AttributeError, OSError):
        pass
    remote_args = [sys.executable, 'app/tcptest.py',
                   '--hole-fd', str(fd),
                   '--peername', peer_name or '']
    _log_file = None
    if REMOTELOG:
        try:
            os.makedirs('/tmp/p2pnet', exist_ok=True)
        except OSError:
            pass
        _log_file = f"/tmp/p2pnet/tcptest-{logged_in_user}_{peer_name}_{int(time.time())}.log"
        remote_args += ['--remotelog', _log_file]
    hole['tcp_fd'] = fd
    log(f"[P2P] 把已建立的连接（内核 fd={fd}）继承给 app/tcptest.py"
        f"（对端 {peer_ip}:{peer_port}）")
    try:
        entry = launch_in_new_terminal(
            remote_args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={**os.environ, 'PYTHONUNBUFFERED': '1', 'P2P_USER': logged_in_user or ''},
            new_window=False,          # 继承 fd 只能后台拉起（新窗口没法继承）
            close_on_exit=CLOSE_WINDOW,
            peer_name=peer_name, peer_ip=peer_ip, peer_port=peer_port,
            my_ip=my_ip, my_port=my_port,
            name='tcptest', _log_file=_log_file, pass_fds=(fd,),
        )
        if entry:
            entry['hole_id'] = hole['id']
    except Exception as e:
        log(f"[P2P] 拉起 tcptest.py 失败: {e}")
        return False
    # 子进程已经拿到这个 fd 了，父进程这份可以关掉（连接由子进程那份撑着，不是"关连接"）
    try:
        sock.close()
    except OSError:
        pass
    log(f"[P2P] tcptest.py 已拉起（fd={fd}）")
    return True


def _launch_wg_python(hole):
    """在打好的洞上跑自己实现的 WireGuard（app/wg-python.py），
    本端监听端口 = 洞的本地端口（映射不废），对端 endpoint = 洞里的对端公网地址。
    服务端没实现 thisisyourpeer_wg，对方公钥只能命令行给。"""
    global WG_ADMIN_PATH, WG_PROC
    pubkey = _pending_wg_pubkey
    if not pubkey:
        log("[P2P] wg-py 需要对方公钥: wg-py <洞> pubkey=<base64>")
        return False

    if WG_ADMIN_PATH and os.path.exists(WG_ADMIN_PATH):
        log(f"[P2P] wg-python.py 已运行，添加 peer {hole['peer']}...")
        return _wg_admin_add_peer(hole, pubkey)

    log(f"[P2P] 启动 wg-python.py（第一个 peer: {hole['peer']}）...")
    env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'P2P_USER': logged_in_user or ''}
    admin_path = f'/tmp/p2pnet/wg-admin-{os.getpid()}.sock'
    remote_args = [sys.executable, 'app/wg-python.py',
                   '--socketpath', SWITCH_SOCK_PATH or f'/tmp/p2pnet/switch-{os.getpid()}.sock',
                   '--adminpath', admin_path]
    if REMOTELOG:
        try:
            os.makedirs('/tmp/p2pnet', exist_ok=True)
        except OSError:
            pass
        remote_args += ['--log', f"/tmp/p2pnet/wg-{logged_in_user}_main_{int(time.time())}.log"]
    try:
        entry = launch_in_new_terminal(
            remote_args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env, new_window=NEW_WINDOW, close_on_exit=CLOSE_WINDOW,
            peer_name=hole['peer'], peer_ip=hole['peer_ip'], peer_port=hole['peer_port'],
            my_ip=hole['my_ip'], my_port=hole['my_port'], name='wg',
        )
        WG_ADMIN_PATH = admin_path
        WG_PROC = entry
        if entry:
            entry['hole_id'] = hole['id']
        time.sleep(0.5)
        return _wg_admin_add_peer(hole, pubkey)
    except Exception as e:
        log(f"[P2P] 启动 wg-python.py 失败: {e}")
    return False


def _launch_wg_calltool(hole):
    """把洞交给 app/wg-calltool.py（调系统 wg：ip link add type wireguard + wg set）

    它自己不碰数据面，只把洞的本端端口当成内核 WireGuard 的 listen-port，
    这样打洞时建立的 NAT 映射才不废；对端 endpoint 就是洞里的对端公网地址。
    """
    remote_args = [sys.executable, 'app/wg-calltool.py',
                   '--my-privkey', WG_SH_MY_KEY,
                   '--my-ip', WG_SH_MY_IP,
                   '--peer-pubkey', WG_SH_PEER_PUBKEY,
                   '--peer-ip', WG_SH_PEER_IP,
                   '--iface', WG_SH_IFACE]
    log(f"[P2P] 交给 wg-calltool.py（系统 wg）: "
        f"listen-port={hole['my_port']} endpoint={hole['peer_ip']}:{hole['peer_port']}")
    log(f"[P2P]   需要 root + wireguard-tools + 内核模块；mesh {WG_SH_MY_IP} ↔ {WG_SH_PEER_IP}")
    return _launch_hole_program(remote_args, hole, 'wg-sh')


def _wg_admin_add_peer(hole, pubkey_b64):
    """通过 admin socket 给 wg-python.py 加 peer"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(WG_ADMIN_PATH)
        cmd = json.dumps({'cmd': 'add_peer', 'name': hole['peer'],
                          'ip': hole['peer_ip'], 'port': hole['peer_port'],
                          'pubkey': pubkey_b64, 'localport': hole['my_port']})
        sock.sendall((cmd + '\n').encode())
        data = b''
        while b'\n' not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        if data:
            resp = json.loads(data.decode('utf-8').strip())
            if resp.get('ok'):
                log(f"[P2P] WG peer {hole['peer']} 已添加"
                    f"（endpoint {hole['peer_ip']}:{hole['peer_port']}，"
                    f"本端端口 {hole['my_port']}）")
                return True
            log(f"[P2P] 添加 WG peer 失败: {resp.get('error')}")
    except Exception as e:
        log(f"[P2P] WG admin socket 错误: {e}")
    return False


def close_all_holes(reason=''):
    """关掉所有洞的 socket（退出/被踢/登出）

    ⚠️ 这里**不停 WS 心跳**：登出与被踢都"只是登录态变了"，连接还在（还得靠心跳保活/判活）。
    心跳在**会话真的结束**时停 —— 见 `mark_disconnected()`（以及 main() 最后的收尾）。
    """
    # 注意：以前这里有一行 stop_ws_heartbeat()，被踢时会把还活着的连接的心跳停掉（已修）
    with _holes_lock:
        hs = list(holes)
    for h in hs:
        hole_stop_hole(h)
        if h['status'] == '打洞中':
            h['status'] = f'已断开({reason})' if reason else '已断开'


def _fmt_addr(ip, port):
    if not ip and not port:
        return '-'
    return f'{ip or "?"}:{port}'


def _print_people(users):
    """同服务器的人（list peer / list 的第一块）"""
    log(f"--- 同服务器的人（{len(users)}）---")
    if not users:
        log("  (无在线用户)")
        return
    for u in users:
        udp_port = u.get('udp_port')
        udp_s = f"  udp={udp_port}" if udp_port else ""
        log(f"  {u.get('username',''):<16} {u.get('ip','')}:{u.get('port','')}{udp_s}")


def _print_procs():
    """所有子进程（peer 命令 / list proc）"""
    if not peers:
        log("  (没有运行的子进程)")
        return
    for i, c in enumerate(peers):
        winfo = ''
        if c['type'] == 'window':
            winfo = '  [窗口]' if c['close_on_exit'] else '  [窗口·保留]'
        else:
            winfo = '  [后台]'
        hid = c.get('hole_id')
        htag = f"  [洞 #{hid}]" if hid is not None else ''
        log(f"  [{i}] pid={c['pid']}  name={c['name']}{winfo}{htag}")
        log(f"       对端: {c['peer_name']}  {c['peer_ip']}:{c['peer_port']}  "
            f"本端: {c['my_ip']}:{c['my_port']}")


def _print_holes():
    """打印洞表（list hole / list 的第二块）"""
    with _holes_lock:
        hs = list(holes)
    if not hs:
        log("  (没有洞)")
        return
    for h in hs:
        fd_s = str(h['fd']) if h['fd'] is not None else '-'
        extra = ''
        if h['proto'] == 'udp' and h.get('rtt'):
            extra = f"RTT={h['rtt']:.0f}ms"
        ncand = len(h.get('candidates') or [])
        cand_s = f"候选={ncand} " if ncand > 1 else ''
        reach = h.get('reachable')
        if reach is not None:
            cand_s = f"可达={len(reach)}/{len(h.get('peer_addrs') or [])} " 
        log(f"  #{h['id']:<3} {h['proto']:<4} {h['status']:<14} {h['peer'] or '?':<14} "
            f"fd={fd_s:<6} 本端 {_fmt_addr(h['my_ip'], h['my_port'])}  "
            f"对端 {_fmt_addr(h['peer_ip'], h['peer_port'])}  {cand_s}{extra}")
        if reach:
            log(f"       可达地址: " + ', '.join(reach))
    ready = [h for h in hs if h['status'] == '已打通']
    if ready:
        log("  已打通，可拉起: " + " / ".join(f"udptest fd={h['fd']}" for h in ready))


def _print_serving_procs():
    """打印"正在为这些洞服务的子进程"（list 的第三块）"""
    serving = [c for c in peers if c.get('hole_id') is not None]
    if not serving:
        log("  (没有为洞服务的子进程)")
        return
    for c in serving:
        winfo = ''
        if c['type'] == 'window':
            winfo = '  [窗口]' if c['close_on_exit'] else '  [窗口·保留]'
        else:
            winfo = '  [后台]'
        log(f"  [洞 #{c['hole_id']}] pid={c['pid']}  name={c['name']}{winfo}")
        log(f"       对端: {c['peer_name']}  {c['peer_ip']}:{c['peer_port']}  "
            f"本端: {c['my_ip']}:{c['my_port']}")


def _print_list_result(users):
    """list 不带参数：三块都打"""
    log("=== list ===")
    _print_people(users)
    log("--- 洞 ---")
    _print_holes()
    log("--- 为这些洞服务的子进程 ---")
    _print_serving_procs()


# ====== del：一个命令管所有删除 ======

def _kill_child(c):
    """停掉一个子进程"""
    p = c.get('popen')
    pid = c.get('pid')
    if p is not None:
        p.terminate()
        log(f"已 terminate pid={pid} ({c['name']})")
        return
    if pid is None:
        return
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


def _delete_procs(val):
    """del proc=<pid|名字|all>"""
    v = (val or '').strip()
    if not v:
        log("用法: del proc=<pid|名字|all>（用 list proc 看有哪些）")
        return
    if v.lower() == 'all':
        targets = list(peers)
    elif v.isdigit():
        targets = [c for c in peers if str(c.get('pid')) == v]
    else:
        targets = [c for c in peers if c.get('name') == v]
    if not targets:
        log(f"没有匹配的子进程: {v}（用 list proc 看有哪些）")
        return
    for c in list(targets):
        _kill_child(c)
        try:
            peers.remove(c)
        except ValueError:
            pass
    log(f"已停掉 {len(targets)} 个子进程")


def _delete_holes(val):
    """del hole=<洞标识|all>"""
    v = (val or '').strip()
    if not v:
        log("用法: del hole=<洞标识|all>（洞标识: #1 / fd=21 / port=50001 / <用户名>）")
        return
    if v.lower() == 'all':
        with _holes_lock:
            hs = list(holes)
            holes.clear()
        for h in hs:
            hole_stop_hole(h)
            if h.get('switch_port'):
                _switch_cmd({'cmd': 'unplug', 'name': h['switch_port']})
        log(f"已删除 {len(hs)} 条洞")
        return
    hole, err = _resolve_hole(v)
    if hole is None:
        log(err)
        return
    with _holes_lock:
        if hole in holes:
            holes.remove(hole)
    hole_stop_hole(hole)
    if hole.get('switch_port'):
        _switch_cmd({'cmd': 'unplug', 'name': hole['switch_port']})
    extra = ''
    if hole.get('handed_to'):
        extra = (f"（原来交给 {hole['handed_to']} 的子进程没动，"
                 f"要停掉用 del proc=<pid>）")
    log(f"已删除 [洞 #{hole['id']}] {hole['peer'] or '?'}{extra}")


def _set_onpeerwant(cmd, arg):
    """onpeerwantudp / onpeerwanttcp / onpeerwantdirect / onpeerwantupnp [auto|none]

    对方来找我时怎么办：auto = 参与（默认，当前行为）/ none = 静默拒绝（不参与，本地留一行提示）。
    """
    kind = cmd[len('onpeerwant'):]        # udp / tcp / direct / upnp
    if not arg:
        log(f"{cmd} = {ON_PEER_WANT.get(kind, 'auto')}")
        log("  auto  - 参与（默认，当前行为）")
        log("  none  - 静默拒绝：不参与，本地留一行提示")
        if kind == 'upnp':
            log("  注意: upnp 本身还没实现，这一项目前没有消费者，只是先把状态位留着")
        return
    val = arg.split()[0].lower()
    if val in ('auto', 'none'):
        ON_PEER_WANT[kind] = val
        log(f"{cmd} = {val}")
    else:
        log(f"未知取值: {val}，可用: auto / none")


def _set_on_hole_cmd(cmd, arg):
    """onholefromself / onholefrompeer [模式] [设备] [洞标识]

    不带洞标识 → 只改状态变量（该角色的洞打通后自动跑什么）
    带洞标识   → 同时立刻把这个洞交给该模式拉起
    """
    global ON_SELF_HOLE, ON_PEER_HOLE
    name = 'onholefromself' if cmd == 'onholefromself' else 'onholefrompeer'
    cur = ON_SELF_HOLE if cmd == 'onholefromself' else ON_PEER_HOLE
    who = '本端发起打洞' if cmd == 'onholefromself' else '对方打进来'

    if not arg:
        shown = (f"{cur[0]}" + (f" {cur[1]}" if cur[1] else '')) if cur else 'none（不自动跑）'
        log(f"{name} = {shown}   （{who}、洞打通后自动跑）")
        log(f"  用法: {name} <模式> [设备] [洞标识]")
        log("  模式: " + ' / '.join(ON_HOLE_MODES) + " / none")
        log(f"  带洞标识 = 同时立刻在这个洞上拉起，如 {name} tun fd=21")
        return

    toks = arg.strip().split()
    sub = toks[0].lower()
    rest = toks[1:]

    if sub == 'none':
        if cmd == 'onholefromself':
            ON_SELF_HOLE = None
        else:
            ON_PEER_HOLE = None
        log(f"{name} = none（洞打通后不自动跑）")
        return

    if sub not in ON_HOLE_MODES:
        log(f"未知模式: {sub}，可用: " + ' / '.join(ON_HOLE_MODES) + " / none")
        return

    dev = None
    if sub in ('tun', 'tap') and rest and not _looks_like_hole_selector(rest[0]):
        dev = rest.pop(0)
    hole_arg = ' '.join(rest).strip()

    if cmd == 'onholefromself':
        ON_SELF_HOLE = (sub, dev)
    else:
        ON_PEER_HOLE = (sub, dev)
    log(f"{name} = {sub}" + (f" {dev}" if dev else '') + "（洞打通后自动跑）")

    if sub == 'switch':
        _do_start_switch()
    if sub in ('video', 'file'):
        log(f"  注意: {sub} 还没实现（TODO），真拉起时会提示")

    if hole_arg:
        hole, err = _resolve_hole(hole_arg)
        if hole is None:
            log(err)
        else:
            _handover_hole(hole, sub, dev)


def print_help():
    log("=== p2pnet 客户端 ===")

    # ---------- 第一段：基础 ----------
    log("── 基础 ──")
    log("  help              - 显示帮助")
    log("  ping              - 发一条应用层 ping（服务端回 pong，日志里能看到报文和 RTT）")
    log("  quit              - 退出")
    log("  login [<username>] - 登录（不写用户名就交互式问；随后提示输入密码）")
    log("  logout            - 登出（连接不断，可以再 login）")
    log("  list [peer|hole|proc] - 不带参数列出三样；peer=同服务器的人 / hole=所有洞 / proc=所有子进程")
    log("  del hole=<洞标识|all>   - 删洞（关掉它的 socket）")
    log("  del proc=<pid|名字|all> - 杀掉子进程")
    log("  洞标识: fd=<fd> | port=<本端端口> | #<编号> | <用户名>")
    log("  ----------------------------------------")

    # ---------- 第二段：p2p ----------
    log("── p2p ──")
    log("  direct <user>     - 不用打洞，看对方哪些地址 ICMP 可达（枚举 v4/v6 + 并发 ping）")
    log("  upnp              - 和路由器协商直接开端口映射（不用打洞）            [协议待定]")
    log("  udp <user>        - 和对方打 UDP 洞（只做打洞 1~6 步，不自动拉起协议）")
    log("  tcp <user>        - 和对方打 TCP 洞（地址交换后由 tcp.py 完成连接）")
    log("  打洞过程每步一行: [洞 #N 对端] [第几步/共几步] 正在干嘛 然后接 （✓）/（✗）")
    log("  ----------------------------------------")

    # ---------- 第三段：打完洞以后的协议 ----------
    log("── 打完洞以后的协议（udptest/ffmpeg/wireguard 等等）──")
    log("  udptest <洞>      - 在这个洞上跑 app/udptest.py（只做互发 ping/pong 测试）")
    log("  proxy <洞> <host:port> - 把洞里的数据转发到这个地址（app/proxy.py）")
    log("  ffmpeg <洞>       - 在这个洞上跑 ffmpeg 视频")
    log("  wg-py <洞> [pubkey=<对方公钥>]  - 自己实现的 WireGuard（app/wg-python.py，不用 root）")
    log("  wg-sh <洞> <我的私钥> <我的meshIP> <对方公钥> <对方meshIP> [接口名]")
    log("                                - 调系统 wg（app/wg-calltool.py → wghelp.sh，需 root）")
    log("  ----------------------------------------")

    # ---------- 第四段：被调时的自动操作 ----------
    log("── 被调时的自动操作（对方来找我 / 洞打通时自动做什么）──")
    log("  onpeerwantdirect [auto|none] - 别人 direct 来要我的地址时回不回")
    log("  onpeerwantupnp [auto|none]   - 别人想让我开端口映射时（upnp 还没实现，暂无消费者）")
    log("  onpeerwantudp [auto|none]    - 别人找我打 UDP 洞时参不参与")
    log("  onpeerwanttcp [auto|none]    - 别人找我打 TCP 洞时参不参与")
    log("      auto = 参与（默认） / none = 静默拒绝，本地留一行提示")
    log("  onholefromself [模式] [设备] [洞] - 本端发起的洞打通后自动跑什么")
    log("  onholefrompeer [模式] [设备] [洞] - 对方发起的洞打通后自动跑什么")
    log("      none(默认) / udptest / tun [设备] / tap [设备] / auto / switch / proxy <host:port> / ffmpeg / wg")
    log("      tun/tap/auto 交给 app/vpn.py（单人单 tun）；switch 交给 app/switch.py（多人多洞）")
    log("      带洞标识 = 同时立刻在该洞上拉起（如 onholefrompeer tun fd=21）")
    log("========================================")
    log("  也可先打洞再拉起: udp <user> → list → udptest <洞>")
    log("  ffmpeg/wg 也支持先打洞: ffmpeg <user> / wg <user> [pubkey=...]")

# ====== Switch 进程管理 ======

def _switch_text_of(obj):
    """把内部的命令 dict 拼成 switch console 需要的**文本命令**（switch 的 stdin 是文本）

      {'cmd':'plug', ...}   → plug localport=50001 peer=1.2.3.4:30001 [candidates=a:1]
      {'cmd':'unplug', ...} → unplug port1
      其他（status 等）      → 直接是动词
    """
    c = obj.get('cmd', '')
    if c == 'plug':
        parts = [f"plug localport={obj.get('localport')}",
                 f"peer={obj.get('peer_ip')}:{obj.get('peer_port')}"]
        if obj.get('peercandidates'):
            parts.append(f"candidates={obj['peercandidates']}")
        return ' '.join(parts)
    if c == 'unplug':
        return f"unplug {obj.get('name')}"
    return c


def _parse_switch_reply(line):
    """switch 的文本回复 → dict：'ok k=v k=v' / 'err 消息'"""
    line = (line or '').strip()
    if line.startswith('err'):
        return {'ok': False, 'error': line[3:].strip()}
    if not line.startswith('ok'):
        return None
    out = {'ok': True}
    for tok in line[2:].split():
        k, sep, v = tok.partition('=')
        if sep:
            out[k] = v
    return out


def _switch_cmd(obj, timeout=5.0):
    """给 switch.py 的 console 发一条**文本命令**，返回它回复解析成的 dict（失败/超时 None）

    switch.py 的 console 就是它的 stdin/stdout：stdin 收文本命令、stdout 回文本
    （ok ... / err ...），日志走 stderr（不污染协议）。
    ctl socket（传 fd 那条）仍然是 JSON —— 见 _switch_plug_fd。
    """
    if SWITCH_PROC is None or not SWITCH_PROC.get('popen'):
        return None
    p = SWITCH_PROC['popen']
    if p.stdin is None or p.stdout is None or p.poll() is not None:
        log("[switch] 控制通道不可用（switch 没起来或已退出）")
        return None
    line = _switch_text_of(obj)
    try:
        p.stdin.write((line + '\n').encode('utf-8'))
        p.stdin.flush()
    except Exception as e:
        log(f"[switch] 写命令失败: {e}")
        return None
    try:
        r, _, _ = select.select([p.stdout], [], [], timeout)
        if not r:
            log(f"[switch] 命令 {line.split()[0]} 没有回应（{timeout:.0f}s）")
            return None
        raw = p.stdout.readline()
        if not raw:
            return None
        return _parse_switch_reply(raw.decode('utf-8', 'replace'))
    except Exception as e:
        log(f"[switch] 读回复失败: {e}")
        return None


def _switch_plug(hole):
    """把一条打好的洞"插到" switch 上（console plug）

    switch 自己 bind 这个本地端口、自己保活，把这条洞当成一个交换机端口接进 L2/L3 转发。
    多人多洞 = 插多根线。
    """
    if SWITCH_PROC is None:
        _do_start_switch()
    if SWITCH_PROC is None:
        log(f"[洞 #{hole['id']}] switch 没起来，无法接洞")
        return False
    extra = [c for c in hole.get('candidates', [])
             if (c['ip'], c['port']) != (hole['peer_ip'], hole['peer_port'])]
    resp = _switch_cmd({
        'cmd': 'plug',
        'localport': hole['my_port'],
        'localaddr': '0.0.0.0',
        'peer_ip': hole['peer_ip'],
        'peer_port': hole['peer_port'],
        'peercandidates': ','.join(f"{c['ip']}:{c['port']}" for c in extra),
    })
    if not resp or not resp.get('ok'):
        log(f"[洞 #{hole['id']}] 给 switch 插线失败: {(resp or {}).get('error', '没回应')}")
        return False
    hole['switch_port'] = resp.get('name')
    hole['handed_detail'] = f"switch 的 {resp.get('name')} 端口"
    return True


def _switch_plug_fd(hole, sock, peer_name=''):
    """把一条**已建立连接的 TCP socket** 用 **SCM_RIGHTS** 送进常驻的 switch

    switch 一直在跑，没法用 pass_fds（那是拉起新进程时用的）。所以走 Unix socket
    的辅助数据（SCM_RIGHTS）把 fd 复制进 switch 的进程，让它当成一个 port 用。
    送完这边就可以关掉自己那份了（内核里 switch 那份撑着，不是"关连接"）。

    Windows 没有 SCM_RIGHTS，得换 DuplicateHandle + 控制通道 —— TODO，没实现。
    """
    if os.name != 'posix':
        log("[P2P] 常驻进程接 TCP 洞目前只支持 POSIX（SCM_RIGHTS）；Windows 要用 "
            "DuplicateHandle，还没实现")
        return False
    if SWITCH_PROC is None:
        _do_start_switch()
    if not SWITCH_CTL_PATH or not os.path.exists(SWITCH_CTL_PATH):
        log(f"[P2P] switch 控制通道不可用（{SWITCH_CTL_PATH}）")
        return False
    fd = sock.fileno()
    try:
        os.set_inheritable(fd, False)      # 走 SCM_RIGHTS，不需要可继承
    except OSError:
        pass
    msg = (json.dumps({'cmd': 'plug_fd', 'peer': peer_name or hole.get('peer') or ''}) + '\n').encode()
    fds = array.array('i', [fd])
    try:
        ctl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ctl.settimeout(5.0)
        ctl.connect(SWITCH_CTL_PATH)
        ctl.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
        r, _, _ = select.select([ctl], [], [], 5.0)
        line = ctl.recv(4096) if r else b''
        ctl.close()
    except OSError as e:
        log(f"[P2P] 用 SCM_RIGHTS 把 fd 送进 switch 失败: {e}")
        return False
    try:
        resp = json.loads(line.decode('utf-8').split('\n')[0])
    except Exception:
        log("[P2P] switch 没给有效回复")
        return False
    if not resp.get('ok'):
        log(f"[P2P] switch 插 fd 失败: {resp.get('error')}")
        return False
    hole['switch_port'] = resp.get('name')
    hole['handed_detail'] = f"switch 的 {resp.get('name')} 端口（SCM_RIGHTS 送的 fd={fd}）"
    log(f"[P2P] 已把 fd={fd}（对端 {resp.get('peer')}）送进 switch，插成 {resp.get('name')}")
    try:
        sock.close()                        # switch 那份已经拿到，父进程这份可以关
    except OSError:
        pass
    return True


def _do_start_switch():
    """拉起 switch.py 作为子进程，stdin/stdout 做控制通道（JSON 行）"""
    global SWITCH_PROC, SWITCH_SOCK_PATH, SWITCH_CTL_PATH
    if SWITCH_PROC is not None:
        log("switch 已在运行")
        return
    import time as _t
    sock_path = f'/tmp/p2pnet/switch-{os.getpid()}.sock'
    ctl_path = f'/tmp/p2pnet/switch-{os.getpid()}.ctl.sock'
    SWITCH_SOCK_PATH = sock_path
    SWITCH_CTL_PATH = ctl_path
    # 清理旧 socket 文件
    for _p in (sock_path, ctl_path):
        if os.path.exists(_p):
            os.remove(_p)
    switch_args = [sys.executable, 'app/switch.py',
                   '--type', 'unixsocket',
                   '--socketpath', sock_path,
                   '--ctlpath', ctl_path]
    try:
        entry = launch_in_new_terminal(
            switch_args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={**os.environ, 'PYTHONUNBUFFERED': '1'},
            new_window=False,     # 后台运行
            name='switch',
            stdin_pipe=True,      # console 命令从这里进
            stdout_pipe=True,     # JSON 回复从这里出（日志走 stderr）
        )
        SWITCH_PROC = entry
        # 等 switch 启动并开始接受连接
        _t.sleep(0.5)
        log(f"switch.py 已启动（unix socket {sock_path}）")
        log("        UDP 洞打通后会自动插上去；--tcp/--wg 仍走这个 socket")
    except Exception as e:
        log(f"switch.py 启动失败: {e}")


# ====== 启动时自动执行的命令 ======

def _do_startup_commands():
    """登录成功后自动执行启动命令（--onholefromself/--onholefrompeer/--udp/--tcp/--wg-py/--wg-sh）"""
    global STARTUP_ON_SELF, STARTUP_ON_PEER
    global STARTUP_UDP, STARTUP_TCP, STARTUP_WG, STARTUP_WGSH, STARTUP_FFMPEG
    global WG_SH_MY_KEY, WG_SH_MY_IP, WG_SH_PEER_PUBKEY, WG_SH_PEER_IP, WG_SH_IFACE

    if STARTUP_ON_SELF:
        log(f"[启动] 设置 onholefromself = {STARTUP_ON_SELF}")
        process_input_line(f'onholefromself {STARTUP_ON_SELF}')

    if STARTUP_ON_PEER:
        log(f"[启动] 设置 onholefrompeer = {STARTUP_ON_PEER}")
        process_input_line(f'onholefrompeer {STARTUP_ON_PEER}')

    for target in STARTUP_UDP:
        log(f"[启动] UDP 连接 {target}...")
        process_input_line(f'udp {target}')

    for target in STARTUP_TCP:
        log(f"[启动] TCP 连接 {target}...")
        process_input_line(f'tcp {target}')

    for target in STARTUP_WG:
        log(f"[启动] WireGuard（自己实现）连接 {target}...")
        process_input_line(f'wg-py {target}')

    for user, mykey, myip, peerpub, peerip, iface in STARTUP_WGSH:
        log(f"[启动] WireGuard（系统 wg）连接 {user}...")
        WG_SH_MY_KEY, WG_SH_MY_IP = mykey, myip
        WG_SH_PEER_PUBKEY, WG_SH_PEER_IP, WG_SH_IFACE = peerpub, peerip, iface
        process_input_line(f'wg-sh {user} {mykey} {myip} {peerpub} {peerip} {iface}')

    for target in STARTUP_FFMPEG:
        log(f"[启动] ffmpeg 视频连接 {target}...")
        process_input_line(f'ffmpeg {target}')

    STARTUP_UDP = STARTUP_TCP = STARTUP_WG = []
    STARTUP_WGSH = []
    STARTUP_FFMPEG = []


# ====== 处理消息 ======

def handle_server_message(obj):
    global pending_auth, logged_in_user, session_key, ARGS_USER, ARGS_PASS
    global _list_what

    if obj.get('type') == 'pong':
        # 应用层 ping 的回包（不是 UDP 那套 ping/pong）
        seq = obj.get('seq')
        sent = _app_ping_sent.pop(seq, None)
        rtt = f"（RTT {(time.time() - sent) * 1000:.1f}ms）" if sent else ""
        log(f"收到应用层 pong：{json.dumps(obj, ensure_ascii=False)}{rtt}")
        return

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
        # 留一份凭据在内存里：断线自动重连后用同一套流程恢复登录（命令行与 GUI 共用）
        global _saved_login_user, _saved_login_pass
        _saved_login_user, _saved_login_pass = username, password
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
        what = _list_what or 'all'
        _list_what = None
        if what == 'peer':
            log("=== list peer ===")
            _print_people(users)
        else:
            _print_list_result(users)
    elif obj.get('type') == 'user_joined':
        log(f"+ 用户上线: {obj.get('username','')}")
    elif obj.get('type') == 'user_left':
        log(f"- 用户下线: {obj.get('username','')}")
    elif obj.get('type') == 'error':
        msg = obj.get('message', '')
        _list_what = None      # list 请求被拒（比如没登录），别再等 list_result
        # 打洞被服务器拒绝（比如目标不存在）→ 原因直接写进那一步的 （✗）
        if not (hole_udp.on_error(msg) or hole_tcp.on_error(msg)):
            log(f"错误: {msg}")
    elif obj.get('type') == 'logout_ok':
        hole_udp.stop_all_hellos()
        close_all_holes('登出')
        pending_auth = None
        logged_in_user = None
        session_key = None
        log("已登出（连接还在，可以再 login）")
    elif obj.get('type') == 'kicked':
        # ② 被踢 = **登录状态被取消，连接没断**（服务端只发 kicked + 清 username，不关 socket）。
        #    所以这里**不许**停心跳、**不许**关连接 —— 连接还活着，心跳继续保活；
        #    只做两件事：取消登录态 + 置"不许自动重新登录"的标记（标记留到用户手动 login）。
        #    ⚠️ 不需要额外的"被踢标记"：登录状态被清成"未登录"本身就是判据 ——
        #    之后这条连接若自己被动断开，传输层照常重连，而"断开前未登录" → 不自动重登；
        #    用户再手动 login 成功（状态回到已登录）后掉线，又会正常自动重登。
        logged_in_user = None
        session_key = None
        hole_udp.stop_all_hellos()
        close_all_holes('被踢')
        log(f"被服务器踢下线（{obj.get('message','')}）：登录已取消，不会自动重新登录")   # 四端统一文案
    elif obj.get('type') == 'incoming_p2pudp':
        from_user = obj.get('from_username', '')
        log(f"⚠️  {from_user} 请求和你建立 UDP P2P 连接，输入 udp {from_user} 回应")
    elif obj.get('type') == 'send_udp_to_server':
        hole_udp.on_send_udp_to_server(obj.get('udpport', SERVER_PORT or 10000))
    elif obj.get('type') == 'thisisyourpeer_udp':
        hole_udp.on_thisisyourpeer(obj)
    elif obj.get('type') == 'p2pudp_pending':
        target = obj.get('target', '')
        log(f"P2P UDP 等待 {target} 确认...")
    elif obj.get('type') == 'send_tcp_to_server':
        # 改用 TCP 了，停掉还在发 hello 的 UDP socket
        hole_udp.stop_all_hellos()
        hole_tcp.on_send_tcp_to_server(obj.get('tcpport', SERVER_PORT))
    elif obj.get('type') == 'thisisyourpeer_tcp':
        hole_tcp.on_thisisyourpeer(obj)
    elif obj.get('type') in ('p2pdirect', 'p2pdirect_reply'):
        hole_direct.on_peer(obj)
    elif obj.get('type') == 'incoming_p2pwg':
        from_user = obj.get('from_username', '')
        log(f"⚠️  {from_user} 请求和你建立 WireGuard P2P 连接，输入 wg-py {from_user} 回应")
    elif obj.get('type') == 'thisisyourpeer_wg':
        # 服务端从未实现这个 type（wg-python.py / wg-calltool.py 的公钥都得命令行给），
        # 这里只留个说明，别再指望它。两条 wg 路现在都是"洞打通 → 移交"：
        #   wg-py <洞> [pubkey=...]                      → app/wg-python.py（自己实现）
        #   wg-sh <洞> <私钥> <我的meshIP> <对方公钥> <对方meshIP> → app/wg-calltool.py（系统 wg）
        log("[P2P] 服务端未实现 thisisyourpeer_wg：对方公钥/mesh IP 请用命令行给"
            "（wg-py ... pubkey=<公钥> / wg-sh <洞> <私钥> <我的meshIP> <对方公钥> <对方meshIP>）")
        return True

        def _do_add_peer():
            """通过 admin socket 添加 peer（闭包捕获 peer_name 等）"""
            if not WG_ADMIN_PATH or not os.path.exists(WG_ADMIN_PATH):
                log(f"[P2P] wg-python.py 未运行，无法添加 peer {peer_name}")
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

            remote_args = [sys.executable, 'app/wg-python.py',
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
                log(f"[P2P] 启动 wg-python.py 失败: {e}")
    else:
        log(f"[消息] {json.dumps(obj)}")


def process_input_line(line):
    global pending_auth
    global WG_SH_MY_KEY, WG_SH_MY_IP, WG_SH_PEER_PUBKEY, WG_SH_PEER_IP, WG_SH_IFACE
    global _pending_usage, _pending_wg_pubkey
    global _list_what
    parts = line.split(maxsplit=1)
    cmd = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else ''

    if cmd == 'quit':
        global _user_quit
        _user_quit = True          # 用户主动退出 → 不自动重连
        return False
    elif cmd == 'help':
        print_help()
    elif cmd == 'ping':
        # 应用层 ping（服务端会回 {"type":"pong","seq":N}，见 handle_server_message）
        send_app_ping()
    elif cmd == 'login':
        if not arg:
            username = input("用户名: ").strip()
            if not username:
                return True
        else:
            username = arg
        # 用户**手动**登录 → 清掉"被踢/主动退出"状态（以后掉线还能自动重连重登）
        mark_user_connect()
        # 先发 login username，等收到 challenge 后再要密码
        pending_auth = (username,)
        ws_send(ws_sock, {"type": "login", "username": username})
        log(f"等待服务器验证...")
    elif cmd == 'logout':
        ws_send(ws_sock, {"type": "logout"})
        return True
    elif cmd == 'del':
        # del hole=<洞标识|all>   /   del proc=<pid|名字|all>
        if '=' not in arg:
            log("用法: del hole=<洞标识|all>   /   del proc=<pid|名字|all>")
            log("  洞标识: #1 / fd=21 / port=50001 / <用户名>")
            return True
        kind, _, val = arg.partition('=')
        kind = kind.strip().lower()
        if kind == 'hole':
            _delete_holes(val)
        elif kind == 'proc':
            _delete_procs(val)
        else:
            log(f"未知类别: {kind}，可用: hole / proc")
        return True
    elif cmd == 'list':
        # list [peer|hole|proc]
        #   不带参数 = 三块都打；peer = 同服务器的人；hole = 所有洞；proc = 所有子进程
        sub = arg.split()[0].lower() if arg.strip() else ''
        if sub in ('', 'all'):
            _list_what = 'all'
            ws_send(ws_sock, {"type": "list"})
        elif sub == 'peer':
            _list_what = 'peer'
            ws_send(ws_sock, {"type": "list"})
        elif sub == 'hole':
            log("=== 洞 ===")
            _print_holes()
        elif sub == 'proc':
            log("=== 子进程 ===")
            _print_procs()
        else:
            log(f"未知参数: {sub}，可用: (空) / peer / hole / proc")
        return True
    elif cmd in ('onholefrompeer', 'onholefromself'):
        # onholefrompeer / onholefromself [模式] [设备] [洞标识]
        #   不带洞标识: 只改状态变量（该角色洞打通后自动跑什么）
        #   带洞标识  : 同时立刻把这个洞交给该模式拉起
        _set_on_hole_cmd(cmd, arg)
        return True
    elif cmd in ('onpeerwantudp', 'onpeerwanttcp', 'onpeerwantdirect', 'onpeerwantupnp'):
        _set_onpeerwant(cmd, arg)
        return True
    elif cmd == 'direct':
        # 请求对方全部地址（v4+v6），逐个 ping 看能不能直连 —— 协议待定
        hole_direct.run(arg)
        return True
    elif cmd == 'upnp':
        # 和路由器协商直接开端口映射 —— 协议待定
        hole_upnp.run()
        return True
    elif cmd == 'udp':
        if not arg:
            log("用法: udp <对方用户名>")
            log("  只做打洞 1~6 步；打完洞用 hole 看洞，再 udptest <洞> 等拉起")
            return True
        target = arg.split()[0]
        hole_udp.start(target)
    elif cmd == 'tcp':
        if not arg:
            log("用法: tcp <对方用户名>")
            return True
        target = arg.split()[0]
        hole_tcp.start(target)
    elif cmd == 'proxy':
        parts = arg.split()
        if len(parts) < 2:
            log("用法: proxy <洞标识> <host:port>   （洞标识: fd=21 / port=50001 / #1 / bob）")
            log("      把这条洞里的数据转发到 host:port（app/proxy.py）")
            return True
        hole, err = _resolve_hole(parts[0])
        if hole is None:
            log(err)
            return True
        _handover_hole(hole, 'proxy', parts[1])
        return True
    elif cmd == 'udptest':
        if not arg:
            log("用法: udptest <洞标识>   （洞标识: fd=21 / port=50001 / #1 / bob）")
            return True
        hole, err = _resolve_hole(arg)
        if hole is None:
            log(err)
            return True
        _handover_hole(hole, 'udptest')
        return True
    elif cmd == 'wg-py':
        if not arg:
            log("用法: wg-py <对方用户名> [pubkey=<对方WireGuard公钥base64>]")
            log("      wg-py <洞标识> [pubkey=<...>]   # 在已打通的洞上跑自己实现的 WireGuard")
            log("  app/wg-python.py: 纯用户态实现，不需要 root / 内核模块 / wireguard-tools")
            log("  注意: 服务端未实现 thisisyourpeer_wg，对方公钥只能自己给")
            return True
        target, pubkey = _split_pubkey(arg)
        hole, err = _resolve_hole(target)
        if hole is not None:
            _pending_wg_pubkey = pubkey
            _handover_hole(hole, 'wg-py')
            return True
        if _looks_like_hole_selector(target):
            log(err)
            return True
        # 不是洞 → 当成用户名：先打 UDP 洞，成功后自动拉起
        _pending_usage = 'wg-py'
        _pending_wg_pubkey = pubkey
        hole_udp.start(target)
    elif cmd == 'wg-sh':
        # 调系统 wg（app/wg-calltool.py → app/wghelp.sh）：需要 root + wireguard-tools + 内核模块
        usage_txt = ("用法: wg-sh <对方用户名|洞标识> <我的私钥> <我的meshIP> "
                     "<对方公钥> <对方meshIP> [接口名]")
        if not arg:
            log(usage_txt)
            log("  例: wg-sh bob YGzbJJ8... 192.168.250.2 BDDBwN2... 192.168.250.3 wghelp0")
            log("  app/wg-calltool.py: 调系统的 wg / ip 命令（内核 WireGuard）")
            log("  注意: 私钥会传给 wghelp.sh，不要在共享环境使用")
            return True
        toks = arg.strip().split()
        if len(toks) < 5:
            log(usage_txt)
            return True
        target = toks[0]
        globals()['WG_SH_MY_KEY'] = toks[1]
        globals()['WG_SH_MY_IP'] = toks[2]
        globals()['WG_SH_PEER_PUBKEY'] = toks[3]
        globals()['WG_SH_PEER_IP'] = toks[4]
        if len(toks) >= 6:
            globals()['WG_SH_IFACE'] = toks[5]
        hole, err = _resolve_hole(target)
        if hole is not None:
            _handover_hole(hole, 'wg-sh')
            return True
        if _looks_like_hole_selector(target):
            log(err)
            return True
        _pending_usage = 'wg-sh'
        hole_udp.start(target)
    elif cmd == 'ffmpeg':
        # 带洞标识 = 在已打通的洞上拉 ffmpeg；否则当用户名，先打洞再自动拉 ffmpeg
        if not arg:
            log("用法: ffmpeg <对方用户名>   或   ffmpeg <洞标识>")
            return True
        hole, err = _resolve_hole(arg)
        if hole is not None:
            _handover_hole(hole, 'ffmpeg')
            return True
        if _looks_like_hole_selector(arg):
            log(err)
            return True
        target = arg.split()[0]
        _pending_usage = 'ffmpeg'
        hole_udp.start(target)
    else:
        log(f"未知命令: {cmd}，输入 help")
    return True


# ====== 主循环 ======

def _run_session():
    """
    跑**一次** WebSocket 会话：读到断开 / 心跳判死 / 用户 quit 为止。

    main() 会把"首次连接 → 本函数 → mark_disconnected() → ws_auto_reconnect()"串成一个外层循环，
    所以断线后命令行模式也会自动重连（和 GUI 走同一套 client.py 实现）。
    """
    global running, connected, recv_buf, _user_quit
    running = True
    while running:
        # 心跳线程判定连接已死（connected=False）→ 退出循环，走下面的收尾
        if not connected:
            break
        # ---- 接收网络数据 ----
        # 注意区分两种情况（原来混在一起，导致对端关闭后只能干等心跳判死）：
        #   data is None → 只是暂时没数据（EWOULDBLOCK）→ 继续转
        #   data == b''  → 对端真的关了 / 出错 → **立刻 break**，好让外层自动重连马上接手
        try:
            data = ws_sock.recv(4096)
        except socket.error as e:
            if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN) or e.args[0] == 10035:
                data = None
            else:
                data = b''
        except Exception:
            data = b''

        if data is None:
            import time; time.sleep(0.05)
        elif not data:
            log("连接已被对端/服务器关闭")
            break
        else:
            note_ws_rx()      # 读方通知心跳线程："还有字节进来"（pong 帧也算）
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
            try:
                handle_server_message(obj)
            except Exception as e:
                # 单条消息的处理出错**不该**打死会话：否则客户端会崩掉，
                # 或者（GUI 那种长驻线程）静默死掉、UI 一直显示"已连接"。跳过这条继续读。
                log(f"处理服务器消息出错（已跳过这条）：{e!r}")

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
            try:
                keep = process_input_line(line)
            except Exception as e:
                log(f"处理本地命令出错（已跳过）：{e!r}")     # 本地命令出错不该断开连接
                keep = True
            if not keep:
                running = False
                break



def main():
    global connected, ws_sock, recv_buf, pending_auth, DEBUG, SERVER_IP, SERVER_PORT

    global _user_quit
    _user_quit = False            # 每次启动复位（用户 quit 才会置 True）

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
    parser.add_argument('--onholefromself', dest='onholefromself', default=None,
                        help='本端发起打洞、洞打通后自动跑什么（none 默认 / udptest / tun [设备] / '
                             'tap [设备] / auto / switch / proxy <host:port> / ffmpeg / wg-py / wg-sh）')
    parser.add_argument('--onholefrompeer', dest='onholefrompeer', default=None,
                        help='对方打进来、洞打通后自动跑什么（同上）')
    parser.add_argument('--udp', dest='udp_targets', action='append', default=[],
                        help='启动后自动连接的 UDP 用户（可多次指定）')
    parser.add_argument('--tcp', dest='tcp_targets', action='append', default=[],
                        help='启动后自动连接的 TCP 用户（可多次指定）')
    parser.add_argument('--wg-py', dest='wg_targets', action='append', default=[],
                        help='启动后自动连接的 WireGuard 用户（自己实现版，可多次指定）')
    parser.add_argument('--wg-sh', dest='wgsh_targets', action='append', default=[],
                        help='启动后自动连接的 WireGuard 用户（系统 wg 版），格式: '
                             '"user privkey=xxx myip=yyy pubkey=zzz peerip=www [iface=...]"（可多次指定）')
    parser.add_argument('--ffmpeg', dest='ffmpeg_targets', action='append', default=[],
                        help='启动后自动视频连接的用户（可多次指定）')
    args = parser.parse_args()
    SERVER_IP = args.server
    SERVER_PORT = args.port
    DEBUG = args.debug
    NEW_WINDOW = args.new_window
    CLOSE_WINDOW = args.close_window
    _hole_configure()   # 把日志/WS/建洞记录/回调注入 hole/
    global ARGS_USER, ARGS_PASS, REMOTELOG
    ARGS_USER = args.user
    ARGS_PASS = args.pass_
    REMOTELOG = args.remotelog
    global STARTUP_UDP, STARTUP_TCP, STARTUP_WG, STARTUP_WGSH, STARTUP_FFMPEG
    global STARTUP_ON_SELF, STARTUP_ON_PEER
    STARTUP_ON_SELF = args.onholefromself
    STARTUP_ON_PEER = args.onholefrompeer
    STARTUP_UDP = args.udp_targets
    STARTUP_TCP = args.tcp_targets
    STARTUP_WG = args.wg_targets
    STARTUP_WGSH = []
    for wg_arg in (args.wgsh_targets or []):
        # 格式: "user privkey=xxx myip=yyy pubkey=zzz peerip=www [iface=...]"
        parts = wg_arg.split()
        if not parts:
            continue
        kv = {}
        for p in parts[1:]:
            k, _sep, v = p.partition('=')
            if k and v:
                kv[k] = v
        STARTUP_WGSH.append((parts[0], kv.get('privkey', ''), kv.get('myip', ''),
                             kv.get('pubkey', ''), kv.get('peerip', ''),
                             kv.get('iface', 'wghelp0')))
    STARTUP_FFMPEG = args.ffmpeg_targets

    # ── 首次连接（唯一入口：ws_connect_once 内部就是 getaddrinfo + connect + ws_handshake）
    #    ⚠️ 这里曾经**残留过一段旧的连接代码**（本函数重构时没删干净）→ 每次启动连两次：
    #    第一个 socket 泄漏、服务端多挂一条永不登录的连接、`--user/--pass` 时 challenge 对不上。
    #    现在连接只有这一个入口（见 E2E 里"服务端 [连接] 条数 == 1"的常驻断言）。
    #    首次失败仍 sys.exit(1)：**首次连不上不自动重连**。──
    if not ws_connect_once(args.server, args.port):
        sys.exit(1)
    mark_user_connect()           # 手动/首次连接 → 清"被踢/主动退出"状态 + 重连计数清零
    log(f"已连接至 {args.server}:{args.port}（输入 help 查看命令）")

    # --user --pass 自动登录
    if ARGS_USER:
        log(f"自动登录: {ARGS_USER}（等待 challenge...）")
        start_login(ARGS_USER)

    # Windows 启动输入线程
    input_t = None
    if IS_WINDOWS:
        input_t = threading.Thread(target=windows_input_thread, daemon=True)
        input_t.start()

    # ── 会话外层：断开（异常/心跳判死）后按策略自动重连；用户 quit 就结束 ──
    while True:
        try:
            _run_session()
        except Exception as e:
            # 会话循环里任何未预期异常都按"断开"处理，走下面的 mark_disconnected + 自动重连，
            # 而不是让整个客户端带着 traceback 退出。
            log(f"会话循环异常（按断开处理）：{e!r}")
        mark_disconnected()
        if _user_quit:
            break
        log("连接已断开，尝试自动重连…")
        if not ws_auto_reconnect(args.server, args.port, should_stop=lambda: _user_quit):
            break
        log(f"已重新连接至 {args.server}:{args.port}（输入 help 查看命令）")
        resume_login()

    connected = False
    # 关掉所有洞 / 还在发 hello 的 socket
    hole_udp.stop_all_hellos()
    close_all_holes('退出')
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
    stop_ws_heartbeat()
    try:
        ws_sock.close()
    except:
        pass
    log("已退出")


if __name__ == '__main__':
    main()
