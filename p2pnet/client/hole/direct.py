# -*- coding: utf-8 -*-
"""direct <user>：不用打洞，看能不能直连（ICMP 可达性探测）。

流程（3 步）：
  1. 枚举本机所有网卡的 v4/v6 地址（过滤 loopback / link-local / 多播等）
  2. 和服务器交换地址：
       A 敲 direct bob → {"type":"p2pdirect","target":"bob","ipv4":[],"ipv6":[]}
       服务器校验 target 在线、填上 from、转发给 bob
       bob 收到 p2pdirect 且 onpeerwantdirect=auto → 枚举自己的地址回一份 p2pdirect_reply
  3. 拿到对方地址表后，**并发**对每个地址跑一次 ICMP ping，把能通的都列出来

用**两个 type**区分请求和应答（而不是一个 reply 字段），防止两边"收到就回"无限来回：
  {"type":"p2pdirect",       "target":"bob",   "ipv4":[],"ipv6":[]}   ← 请求，收到该回一份
  {"type":"p2pdirect_reply", "target":"alice", "ipv4":[],"ipv6":[]}   ← 应答，收到只 ping 不再回

探测方式用 ICMP（调系统 ping 命令，普通用户即可，不需要 root）：
  * Linux(iputils) : ping -c 1 -W <秒> <ip>      （-W 单位是秒）
  * macOS(BSD)     : ping6/ping -c 1 -W <毫秒>   （-W 单位是毫秒！）
  * Windows        : ping -n 1 -w <毫秒> <ip>    （-n 是 count，不是"不做 DNS"）
判定：stdout 里（不分大小写）出现 "ttl="，比退出码可靠
（Windows 收到路由器回的 "Destination host unreachable" 也会返回 0）。

注意：ICMP 只能证明"地址可达"，**不能证明端口能过**（有些机器 ping 得通但端口被过滤）。
所以 direct 只报告可达地址、记一条 proto='direct' 的洞，不建隧道、不拉子进程。
真要传数据还得有个端口（`upnp` 就是干这个的，还没实现）。
"""

import sys
import ipaddress
import socket
import subprocess
import threading

from concurrent.futures import ThreadPoolExecutor

from hole import core

DIRECT_STEPS = 3
STEP_RESPONSE_TIMEOUT = 10.0   # 第 2 步等对方回地址多久算失败
PING_TIMEOUT_S = 1             # Linux: ping -W 的秒数
PING_TIMEOUT_MS = 1000         # macOS/Windows: 毫秒
PING_WORKERS = 16              # 并发 ping 的线程数

IS_WINDOWS = sys.platform == 'win32'
IS_DARWIN = sys.platform == 'darwin'

# 当前正在走第 1~3 步的那个洞（和 udp/tcp 一样，服务器是串行的，一个指针就够）
_current = None


# ====== 本机地址枚举（三平台，纯 stdlib，无第三方依赖）======

def local_addresses():
    """返回 (ipv4_list, ipv6_list)，已过滤噪音并去重"""
    if IS_WINDOWS:
        v4, v6 = _addrs_windows()
    elif IS_DARWIN:
        v4, v6 = _addrs_darwin()
    else:
        v4, v6 = _addrs_linux()
    if not v4 and not v6:
        v4, v6 = _addrs_getaddrinfo()   # 兜底：所有平台都能用（可能拿不全）
    return _dedup_usable(v4), _dedup_usable(v6)


def _dedup_usable(lst):
    """去重 + 过滤 loopback / link-local / 多播 / 未指定 / 保留地址

    注意**不过滤** is_private：10/8、172.16/12、192.168/16、fc00::/7 正是同局域网直连要用的。
    """
    out = []
    for ip in lst:
        s = str(ip).strip()
        if not s or s in out:
            continue
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            continue
        if a.is_loopback or a.is_link_local or a.is_multicast \
                or a.is_unspecified or a.is_reserved:
            continue
        out.append(s)
    return out


def _addrs_linux():
    """Linux：v4 用 SIOCGIFADDR ioctl，v6 读 /proc/net/if_inet6（这台机器上验证过）"""
    v4, v6 = [], []
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _, name in socket.if_nameindex():
            try:
                req = struct.pack('256s', name.encode('utf-8')[:15])
                res = fcntl.ioctl(s.fileno(), 0x8915, req)   # SIOCGIFADDR
                v4.append(socket.inet_ntoa(res[20:24]))
            except OSError:
                continue
        s.close()
    except Exception:
        pass
    try:
        with open('/proc/net/if_inet6') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                try:
                    packed = bytes.fromhex(parts[0])
                except ValueError:
                    continue
                if len(packed) != 16:
                    continue
                v6.append(socket.inet_ntop(socket.AF_INET6, packed))
    except Exception:
        pass
    return v4, v6


def _addrs_darwin():
    """macOS：解析 ifconfig -a 的 inet / inet6 行（纯 stdlib 拿全地址最省事）

    ⚠️ 这一支没有环境验证过（开发机是 Linux）。
    """
    v4, v6 = [], []
    try:
        p = subprocess.run(['ifconfig', '-a'], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=5)
        out = (p.stdout or b'').decode('utf-8', 'replace')
    except Exception:
        return v4, v6
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == 'inet' and len(parts) >= 2:
            v4.append(parts[1])
        elif parts[0] == 'inet6' and len(parts) >= 2:
            v6.append(parts[1].split('%')[0])      # 去掉 fe80::1%en0 的 %en0
    return v4, v6


def _addrs_windows():
    """Windows：解析 ipconfig 输出（拿不到就用 getaddrinfo 兜底）

    ⚠️ 这一支没有环境验证过（开发机是 Linux）。
    """
    v4, v6 = [], []
    try:
        p = subprocess.run(['ipconfig'], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=5)
        out = (p.stdout or b'').decode('gbk', 'replace')
    except Exception:
        return v4, v6
    for line in out.splitlines():
        # 形如 "   IPv4 Address. . . . . . . . . . . : 192.168.1.5"
        if ':' not in line:
            continue
        key, _, val = line.partition(':')
        val = val.strip().split('%')[0].strip().strip('()')
        low = key.lower()
        if 'ipv4' in low and val:
            v4.append(val)
        elif 'ipv6' in low and val:
            v6.append(val)
    return v4, v6


def _addrs_getaddrinfo():
    """兜底：解析本机 hostname（跨平台可用，但可能拿不全，也没有接口信息）"""
    v4, v6 = [], []
    try:
        host = socket.gethostname()
        for fam, _, _, _, sa in socket.getaddrinfo(host, None, socket.AF_UNSPEC,
                                                   socket.SOCK_DGRAM):
            ip = sa[0]
            if fam == socket.AF_INET:
                v4.append(ip)
            elif fam == socket.AF_INET6:
                v6.append(ip)
    except Exception:
        pass
    return v4, v6


# ====== ICMP ping ======

def _ping_cmd(ip):
    """按平台拼 ping 命令（普通用户即可，不需要 root）"""
    v6 = ':' in ip
    if IS_WINDOWS:
        return ['ping', '-6' if v6 else '-4', '-n', '1', '-w', str(PING_TIMEOUT_MS), ip]
    if IS_DARWIN:
        # BSD ping：-W 单位是毫秒；IPv6 用 ping6
        return ['ping6' if v6 else 'ping', '-c', '1', '-W', str(PING_TIMEOUT_MS), ip]
    # Linux iputils：-W 单位是秒；-n 不做反向 DNS
    return ['ping', '-6' if v6 else '-4', '-c', '1', '-n', '-W', str(PING_TIMEOUT_S), ip]


def ping_once(ip):
    """ping 一次；通返回 True。以 stdout 里有没有 ttl= 为准（比退出码可靠）"""
    try:
        p = subprocess.run(_ping_cmd(ip), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=PING_TIMEOUT_S + 3)
    except Exception:
        return False
    out = (p.stdout or b'').decode('utf-8', 'replace').lower()
    return 'ttl=' in out


def ping_all(addrs):
    """并发 ping 一串地址，返回可达的那些（保持原顺序）"""
    if not addrs:
        return []
    workers = max(1, min(PING_WORKERS, len(addrs)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(ping_once, addrs))
    return [ip for ip, ok in zip(addrs, results) if ok]


# ====== 第 1、2 步：发起 / 应答地址交换 ======

def _print_addrs(v4, v6, who='本机'):
    """把枚举到的地址**全部**打出来（发给服务器之前先让人看见到底发了什么）"""
    core.log(f"[direct] {who} v4（{len(v4)}）: " + (', '.join(v4) if v4 else '(无)'))
    core.log(f"[direct] {who} v6（{len(v6)}）: " + (', '.join(v6) if v6 else '(无)'))


def run(target):
    """direct <user>：枚举本机地址（打印全部）→ 发 p2pdirect 给服务器 → 等对方回 p2pdirect_reply"""
    global _current
    if not target:
        core.log("用法: direct <对方用户名>")
        return None

    v4, v6 = local_addresses()
    hole = core.record_hole('direct', target, '', 0, '', 0, status='打洞中')
    hole['local_init'] = True
    _current = hole

    if not v4 and not v6:
        core.result(hole, 1, 1, False, '没枚举到可用的本机地址')
        return hole
    core.once(hole, 1, DIRECT_STEPS, True, f'本机 {len(v4)} 个 v4 / {len(v6)} 个 v6')
    _print_addrs(v4, v6)
    core.ws_send({'type': 'p2pdirect', 'target': target, 'ipv4': v4, 'ipv6': v6})
    core.begin(hole, 2, DIRECT_STEPS, timeout=STEP_RESPONSE_TIMEOUT,
               timeout_msg='对方一直没回地址')
    core.log(f"[direct] 已把上面的地址发给服务器，等 {target} 回地址...")
    return hole


def on_peer(msg):
    """收到服务器转来的 p2pdirect / p2pdirect_reply（对方 from 的地址列表）"""
    global _current
    peer = (msg.get('from') or '').strip()
    if not peer:
        return
    is_reply = (msg.get('type') == 'p2pdirect_reply')
    peer_addrs = _dedup_usable(list(msg.get('ipv4') or []) + list(msg.get('ipv6') or []))
    if not peer_addrs:
        core.log(f"[direct] {peer} 没给可用地址，跳过")
        return

    hole = _current if (_current is not None and _current.get('peer') == peer) else None
    if hole is not None and hole.get('pinged'):
        return      # 两边同时敲 direct 时会多收一条，已经处理过了

    # 对方来要地址（p2pdirect）→ 我回一份 p2pdirect_reply（受 onpeerwantdirect 管）
    if not is_reply:
        if core.get_onpeerwant('direct') == 'none':
            core.log(f"[onpeerwantdirect=none] 已忽略 {peer} 的 direct 请求（不回地址、不 ping）")
            return
        if hole is None:
            v4, v6 = local_addresses()
            hole = core.record_hole('direct', peer, '', 0, '', 0, status='打洞中')
            _current = hole
            if not v4 and not v6:
                core.result(hole, 1, 1, False, '没枚举到可用的本机地址')
            else:
                core.once(hole, 1, DIRECT_STEPS, True, f'本机 {len(v4)} 个 v4 / {len(v6)} 个 v6')
                _print_addrs(v4, v6, who=f'回给 {peer} 的')
                core.ws_send({'type': 'p2pdirect_reply', 'target': peer,
                              'ipv4': v4, 'ipv6': v6})
                core.once(hole, 2, DIRECT_STEPS, True, f'已把本机地址回给 {peer}')
        else:
            # 我自己也敲过 direct：地址已经发过了，不再回第二份
            core.result(hole, 2, DIRECT_STEPS, True, f'对方也在找我（地址已发过）')

    if hole is None:
        # 只收到应答、本端没有对应的洞（正常不会走到）→ 临时建一条
        hole = core.record_hole('direct', peer, '', 0, '', 0, status='打洞中')
        _current = hole

    if hole['local_init']:
        core.result(hole, 2, DIRECT_STEPS, True, f'收到对方 {len(peer_addrs)} 个地址')
    hole['peer_addrs'] = peer_addrs      # direct 洞没有端口，这里只记对方的 IP 列表
    hole['reachable'] = []
    hole['pinged'] = True
    _current = None
    t = threading.Thread(target=_ping_phase, args=(hole, peer_addrs),
                         daemon=True, name=f"direct-{hole['id']}")
    hole['thread'] = t
    t.start()


# ====== 第 3 步：并发 ping 对方所有地址 ======

def _ping_phase(hole, addrs):
    core.begin(hole, 3, DIRECT_STEPS, timeout=len(addrs) * 2 + 15,
               timeout_msg='ping 阶段超时')
    reach = ping_all(addrs)
    hole['reachable'] = reach
    if reach:
        hole['status'] = '直连可行'
        core.result(hole, 3, DIRECT_STEPS, True, f'{len(reach)}/{len(addrs)} 个地址可达')
        core.log(f"[direct] {hole['peer']} 可达地址: " + ', '.join(reach))
    else:
        hole['status'] = '不可直连'
        core.result(hole, 3, DIRECT_STEPS, False,
                    f'{len(addrs)} 个地址一个都不通（ICMP 被挡或地址不可达）')
