# -*- coding: utf-8 -*-
"""hole/ 的公共部分：client.py 注入的钩子 + 打洞步骤的实时显示。

这个文件是 hole/ 和 client.py 之间唯一的接口层：
  * 上半部分是**钩子**——client.py 启动时填上（日志、WS 发送、建洞记录、回调…），
    hole/ 里的模块在调用时才取，所以填充顺序无所谓。洞的"总表格"（洞记录列表
    和它的锁）在 client.py，这里只是引用。
  * 下半部分是**步骤显示**——UDP 6 步 / TCP 5 步共用：每一步只占一行，先打出
    "正在干嘛"（行尾不换行），结果出来后在行尾接上（✓）/（✗）：

      [12:00:00][client] [洞 #1 bob] [2/6] 正在等服务器要求发给 udp  （✓）127.0.0.1:10000

    行还没收尾时如果来了别的输出（用户上下线、错误、用户敲的命令），会先把这行
    换行收尾，那一步的结果就只能另起一行（少数情况会是两行）。等待超过
    STEP_INPLACE_MAX 的步骤，结果会整行重写一遍，防止后台子进程（app/udptest.py 等）
    的输出顶串了这一行。
"""

import sys
import time
import threading

# ==================== 一、client.py 注入的钩子 ====================

log = print              # def log(msg)                        —— client 的日志
ws_send = None           # def ws_send(obj)                     —— 给服务器发 WS 消息
record_hole = None       # def record_hole(proto, peer, ...) -> hole  —— 往总表格里加一条
holes_lock = None        # threading.Lock                       —— 保护总表格
sign_session = None      # def sign_session() -> hex/None        —— 用 session_key 签 'ping'
on_udp_ready = None      # def on_udp_ready(hole)               —— UDP 洞打通 → client 决定拉起谁
launch_tcp = None        # def launch_tcp(hole, peer_name, peer_ip, peer_port, my_ip, my_port)
get_server = None        # def get_server() -> (ip, port)
get_username = None      # def get_username() -> str
get_debug = None         # def get_debug() -> bool
get_onpeerwant = None    # def get_onpeerwant(kind) -> 'auto'/'none'（kind: udp/tcp/direct/upnp）


# ==================== 二、打洞步骤的实时显示 ====================

UDP_STEPS = 6
TCP_STEPS = 5
DIRECT_STEPS = 3

STEP_INPLACE_MAX = 1.0         # 等待超过这么久就整行重写（防后台子进程输出顶串这一行）

UDP_STEP_DESC = {
    1: '正在通知服务器',
    2: '正在等服务器要求发给 udp',
    3: '正在往服务器发 hello',
    4: '正在等服务器告知双方地址',
    5: '正在往对方发消息',
    6: '正在等对方消息',
}
TCP_STEP_DESC = {
    1: '正在通知服务器',
    2: '正在等服务器要求连 TCP',
    3: '正在向服务器注册',
    4: '正在等服务器告知双方地址',
    5: '正在同时 listen/connect 打洞，再把内核 socket 交出去',
}
DIRECT_STEP_DESC = {
    1: '正在枚举本机地址',
    2: '正在和服务器交换地址',
    3: '正在 ping 对方地址',
}
STEP_DESC = {'udp': UDP_STEP_DESC, 'tcp': TCP_STEP_DESC, 'direct': DIRECT_STEP_DESC}

# 当前"开着"的那条步骤行（可以在行尾接结果的那种）
_step_open = None
# 还没出结果的那一步（行可能已经被别的输出收尾了，但这一步依然该等/该超时）
_step_pending = None
_step_watch_started = False


def ts():
    return time.strftime("%H:%M:%S")


def hole_tag(hole):
    """[洞 #1 bob] 这样的标签（对端还不知道时用 ?）"""
    return f"洞 #{hole['id']} {hole.get('peer') or '?'}"


def step_desc(hole, n):
    return STEP_DESC.get(hole['proto'], {}).get(n, '')


def finish_open():
    """把还没定结果的步骤行换行收尾（避免别的输出接在它后面）

    注意只收尾"这一行"，不影响 `_step_pending` —— 那一步还没出结果，
    watchdog 还盯着它（别的日志插进来不能让这一步的超时 ✗ 丢掉）。
    """
    global _step_open
    if _step_open is not None:
        sys.stdout.write('\n')
        sys.stdout.flush()
        _step_open = None


def begin(hole, n, total, desc=None, timeout=None, timeout_msg='服务器没回应'):
    """打出"正在做这一步"，行尾不换行，等结果接在后面"""
    global _step_open, _step_pending, _step_watch_started
    finish_open()
    desc = desc or step_desc(hole, n)
    text = f"[{ts()}][client] [{hole_tag(hole)}] [{n}/{total}] {desc}"
    sys.stdout.write(text)
    sys.stdout.flush()
    _step_open = {
        'key': (hole['id'], n), 'hole': hole, 'n': n, 'total': total,
        'desc': desc, 'timeout': timeout, 'start': time.time(),
        'deadline': (time.time() + timeout) if timeout else None,
        'timeout_msg': timeout_msg,
    }
    _step_pending = dict(_step_open)
    if timeout and not _step_watch_started:
        _step_watch_started = True
        threading.Thread(target=_watchdog, daemon=True, name='step-watchdog').start()


def result(hole, n, total, ok, detail=''):
    """结果出来：这一行还开着就接在行尾，否则另起一行"""
    global _step_open, _step_pending
    mark = '✓' if ok else '✗'
    tail = f"  （{mark}）"
    if detail:
        tail += f" {detail}"

    if _step_pending is not None and _step_pending['key'] == (hole['id'], n):
        _step_pending = None

    op = _step_open
    if op is not None and op['key'] == (hole['id'], n):
        if time.time() - op.get('start', 0) <= STEP_INPLACE_MAX:
            # 短等待：结果直接接在这一行行尾 —— 这一步就一行
            sys.stdout.write(tail + '\n')
        else:
            # 长等待：后台子进程（app/udptest.py 等）可能已经往这一行里写过东西了，
            # 整行重写一遍，保证这一行还是完整、看得懂的一步
            sys.stdout.write(
                f"\r[{ts()}][client] [{hole_tag(hole)}] [{n}/{total}] {op['desc']}{tail}\n")
        sys.stdout.flush()
        _step_open = None
    else:
        finish_open()
        # 行已经被别的输出收尾了（或者本来就是一步到位）→ 打一整行
        sys.stdout.write(f"[{ts()}][client] [{hole_tag(hole)}] [{n}/{total}] "
                         f"{step_desc(hole, n)}{tail}\n")
        sys.stdout.flush()


def once(hole, n, total, ok=True, detail=''):
    """一步做完（不需要等待的那种）：开始+结果连着打，还是一行"""
    begin(hole, n, total)
    result(hole, n, total, ok, detail)


def _watchdog():
    """盯着"还没出结果的那一步"：到点就打 ✗ 收尾（收不到回复就 (×)）

    注意盯的是 `_step_pending` 而不是 `_step_open`：别的输出（用户上下线、
    子进程日志、自己 core.log）会把那行收尾（`_step_open` 变 None），
    但那一步依然该超时。
    """
    global _step_pending
    while True:
        time.sleep(0.25)
        op = _step_pending
        if op is None or op.get('deadline') is None:
            continue
        if time.time() < op['deadline']:
            continue
        if _step_pending is not op:
            continue
        hole, n, total = op['hole'], op['n'], op['total']
        with holes_lock:
            if hole['status'] == '打洞中':
                hole['status'] = '打洞失败'
        result(hole, n, total, False, op.get('timeout_msg', '超时'))
