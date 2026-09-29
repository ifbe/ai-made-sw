#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app/switch.py - 虚拟交换机 / L3 Switch（mesh VPN）

定位：**多人多洞**。一堆对端（都在 192.168.x.0/24 这种网段里）把各自打好的洞交给
同一个 switch 进程，由它做 L2/L3 转发。单人单 tun 那条路是 `app/vpn.py`，别搞混。

进程关系（仅供理解，不代表拓扑层级）：
  switch.py（switch 进程，拥有 tun 设备 192.168.250.55/24）
  ├─ console：stdin/stdout（连 client.py，pipe 方式，JSON 行协议）
  ├─ card：   tun/tap（本地插口，本机 app 的 IP 包从这里进出）
  ├─ port1：  client.py 把一条打好的 UDP 洞 plug 进来（对端 Switch B）
  ├─ port2：  同上（对端 Switch C）
  └─ port3：  同上（对端 Switch C 的第二条路，洞不通时走 port2 中继）

对等理解（正确）：
  Switch A ↔ （UDP 洞） ↔ Switch B（alice 那边的网络）
  Switch A ↔ （UDP 洞） ↔ Switch C（bob）
  Switch A 眼里 Switch B/C/D 都是邻居，不是下属

client.py 交互（通过 pipe）：
  * stdin/stdout：**文本命令**，一行一条，回复也是文本（ok ... / err ...），人也能直接敲
  * 启动：client.py 用 stdin/stdout 管道 spawn(switch.py)
    例如：`plug localport=50001 peer=1.2.3.4:30001` / `status` / `routes` /
          `listenstart addr=0.0.0.0 port=15991` / `listenstop` /
          `connect [2001:db8::3]:15991` / `unplug port1` / `route add <ip> port1` / `quit`
  * connect：switch 自己主动 TCP 连对方（v4/v6/域名都行），连上自动接入成一个 port。
    只解决"能直达"的情况（如 v6 直通）；走 NAT 的还是要靠 client.py 打洞后 plug 进来。
  * listenstart/listenstop：运行时可开关监听；不带 addr 默认 0.0.0.0；
    accept 进来的连接自动接入；listenstop **不断已接入的 port**。
  * ctl socket（--ctlpath）：那份**仍然是 JSON**，因为要带 SCM_RIGHTS 传 fd：
      {"cmd":"plug_fd","peer":"bob"}   （fd 挂在辅助数据里）
      {"cmd":"status"} / {"cmd":"unplug","name":"port1"}
  * 注意 stdout 只写 JSON 回复，日志走 stderr

port 交互方式（--type 参数，给 **TCP 洞 / WireGuard** 用的老通道）：
  bindtcpsocket（默认）：switch bind TCP 127.0.0.1:15991+，对方通过 --socketpath 连上来
    例：switch --type bindtcpsocket --base-port 15991
  unixsocket：switch bind 单个 Unix socket 文件，多个连接各占一个 port
              （默认 /tmp/p2pnet/switch-<pid>.sock）

card 设备的地址 / MTU（启动时配一次）：
  --tun-ip 192.168.250.55[/24]  给 tun/tap 配地址（不带这个参数就不设地址）
  --tun-mtu 1400                MTU，默认 1400（0 = 不改）。洞是 IP over UDP，1500 会分片
  --route-ttl 300               学到的路由/MAC 多久没再出现就老化删除（0 = 不老化）

交换模式（--switch-mode 参数）：
  l2：纯 MAC 表转发，所有包 inject tun
  l3（默认）：纯 IP 表转发，所有包 inject tun
  auto：EtherType=IPv4/IPv6 时走 L3，其他走 L2
"""
import os
import sys
import json
import time
import array
import socket
import select
import struct
import subprocess
import threading
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ts():
    return time.strftime("%H:%M:%S")


# =============================================================================
# 全局状态
# =============================================================================

class SwitchState:
    def __init__(self):
        self.running = True
        self.tun_ip = None     # tun 网卡 IP（--tun-ip 参数，设为 None 则 tun 无 IP）
        self.tun_netmask = '255.255.255.0'
        self.card_mode = 'none'  # 'none' | 'tun' | 'tap'
        self.switch_mode = 'l3'  # 'l2' | 'l3' | 'auto'
        self.ports = {}        # port_name -> conn_socket
        self.routes = {}       # dest_ip -> port_name（L3 路由表）
        self.mac_table = {}    # mac -> port_name（L2 MAC 表）
        # 学到的路由会老化：记录"最后一次见到这个来源"的时间；静态路由（route_add）不老化
        self.route_ts = {}     # dest_ip -> 最后一次学到的时间
        self.mac_ts = {}       # mac -> 最后一次学到的时间
        self.static_routes = set()   # 手工 route_add 的，永不老化
        self.route_ttl = 300.0       # 学到的路由多久没再出现就删（--route-ttl）
        self.tun_mtu = 1400          # card 设备的 MTU（--tun-mtu，0=不改）
        self.tun_fd = None    # tun 设备 fd（TODO）
        self.iface = None     # tun 接口对象（TODO）
        self.listeners = []    # 关闭时需要清理的 socket
        self.port_seq = 0      # 已经插了几根网线（plug 用，给端口起名 port1/port2...）
        self.acceptors = {}    # port -> 正在监听的 srv socket（listenstart/listenstop）
        self.port_origin = {}  # 端口名 -> 它是怎么来的（plug / plug_fd / listen:15991 / connect:x:y）

state = SwitchState()
_log_fp = None


def log(*a, **kw):
    """日志输出到文件（默认 stderr），stdout 留给 JSON 协议"""
    msg = ' '.join(str(x) for x in a)
    line = f"[{ts()}][switch]  {msg}"
    if _log_fp:
        _log_fp.write(line + '\n')
        _log_fp.flush()
    else:
        print(line, file=sys.stderr, flush=True)


def send_json(obj):
    """通过 stdout 发 JSON 响应给 client.py"""
    sys.stdout.write(json.dumps(obj) + '\n')
    sys.stdout.flush()


def _recv_json_conn(conn, timeout=5.0):
    """从已连接 socket 接收一行 JSON，返回 dict 或 None"""
    conn.settimeout(timeout)
    try:
        data = b''
        while b'\n' not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8').strip())
    except Exception:
        return None
    finally:
        conn.settimeout(None)


# =============================================================================
# 路由
# =============================================================================

def _ip_src(data):
    """从 IP 包提取源 IP（IPv4/IPv6）"""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4 and len(data) >= 20:
        return '.'.join(str(b) for b in data[12:16])
    elif version == 6 and len(data) >= 40:
        return ':'.join(data[8:16].hex()[i:i+4] for i in range(0, 32, 4))
    return None


def _ip_dst(data):
    """从 IP 包提取目的 IP（IPv4/IPv6）"""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4 and len(data) >= 20:
        return '.'.join(str(b) for b in data[16:20])
    elif version == 6 and len(data) >= 40:
        return ':'.join(data[24:40].hex()[i:i+4] for i in range(0, 32, 4))
    return None


def _eth_src_mac(data):
    """从 Ethernet 帧提取源 MAC（6 bytes）"""
    if not data or len(data) < 14:
        return None
    return ':'.join(f'{b:02x}' for b in data[6:12])


def _eth_dst_mac(data):
    """从 Ethernet 帧提取目的 MAC（6 bytes）"""
    if not data or len(data) < 14:
        return None
    return ':'.join(f'{b:02x}' for b in data[0:6])


def _eth_type(data):
    """从 Ethernet 帧提取 EtherType（2 bytes，大端）"""
    if not data or len(data) < 14:
        return None
    return struct.unpack('>H', data[12:14])[0]


# EtherType 常量
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
ETH_P_UNKNOWN = None


# 假 Ethernet 头（用于 tun 模式伪装成 Ethernet 帧）
FAKE_SRC_MAC = b'\x00\x00\x00\x00\x00\x00'
FAKE_BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'


def _make_fake_eth_header(ip_data_len):
    """构造假 Ethernet 头：dst=broadcast, src=00:00:00:00:00:00, EtherType=IPv4"""
    ethertype = struct.pack('>H', ETH_P_IP)
    return FAKE_BROADCAST_MAC + FAKE_SRC_MAC + ethertype


def _open_card_device(card_mode):
    """按 --card 打开对应设备：tun → Tun，tap → Tap

    **以前的 bug**：不管 --card 写的是 tun 还是 tap，main() 里都 `from util.tun import Tun`
    → 选 tap 时开的其实是 TUN 设备，下面 card_listener / _inject_card 里那两条
    "tap 已经是 Ethernet 帧，原样收发"的分支永远走不到。

    Windows 走 wintun / tap-windows 那套驱动（需要先装驱动）。
    """
    import platform
    sysname = platform.system()
    if card_mode == 'tap':
        if sysname == 'Windows':
            from util.tap_windows import TapWindows
            return TapWindows()
        from util.tap import Tap          # Linux：/dev/net/tun + IFF_TAP
        return Tap()
    if sysname == 'Windows':
        from util.tun_windows import TunWintun
        return TunWintun()
    from util.tun import Tun
    return Tun()


def tun_ip_commands(dev_name, tun_ip, prefix=None):
    """把 --tun-ip 变成要执行的 ip 命令（抽出来是为了能单独测）

    tun_ip 可以是 "192.168.250.55" 或 "192.168.250.55/24"；不带前缀就用 prefix（默认 24）。
    /24 很重要：它顺带产生 "192.168.250.0/24 dev <dev>" 这条路由，
    否则发往同网段其它 mesh 地址的包不会走进 tun。
    """
    ip, _sep, pfx = str(tun_ip).strip().partition('/')
    pfx = pfx or str(prefix or 24)
    return [
        ['ip', 'addr', 'add', f'{ip}/{pfx}', 'dev', dev_name],
        ['ip', 'link', 'set', dev_name, 'up'],
    ]


def tun_mtu_commands(dev_name, mtu):
    """把 --tun-mtu 变成要执行的 ip 命令

    为什么默认要设小一点（1400）：洞是"**IP 包塞在 UDP 里**"跑过去的，
    1500 的 IP 包再套上 UDP/IP 头就超了网卡的 1500 MTU → 分片（甚至被中间设备丢）。
    降到 1400 让 TCP 自己按更小的 MSS 协商，就不会分片。
    """
    return [['ip', 'link', 'set', dev_name, 'mtu', str(int(mtu))]]


def _run_ip_cmds(cmds, label):
    """跑一串 ip 命令；失败只打日志不退出（没 root 时用户可以自己配）"""
    ok = True
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        except Exception as e:
            log(f"{label}: 执行 {' '.join(cmd)} 失败: {e}")
            ok = False
            continue
        out = (r.stdout or b'').decode('utf-8', 'replace').strip()
        if r.returncode != 0:
            # "File exists" 说明地址已经配过了，不算错
            if 'File exists' in out or 'file exists' in out:
                log(f"{label}: {' '.join(cmd)} → 已经配过了，跳过")
            else:
                log(f"{label}: {' '.join(cmd)} 失败（{out or r.returncode}）"
                    f"（八成是没 root；可以自己配）")
                ok = False
        else:
            log(f"{label}: {' '.join(cmd)} 成功")
    return ok


def apply_tun_mtu(dev_name):
    """启动时给 card 设备设 MTU（--tun-mtu，0 = 不设）"""
    if not state.tun_mtu:
        log("tun-mtu: --tun-mtu=0，不改设备 MTU")
        return False
    log(f"tun-mtu: 把 {dev_name} 的 MTU 设成 {state.tun_mtu}"
        f"（洞是 IP over UDP，默认 1400 是为了不分片）")
    return _run_ip_cmds(tun_mtu_commands(dev_name, state.tun_mtu), 'tun-mtu')


def assign_tun_ip(dev_name):
    """启动时把 --tun-ip 配到 card 设备上（没带这个参数就什么都不做）

    注意：需要 root/CAP_NET_ADMIN。失败只打日志、不退出 —— 用户可以自己 ifconfig。
    """
    if not state.tun_ip:
        log("tun-ip: 没指定 --tun-ip，不设地址（设备上是空的，要自己 ip addr add）")
        return False
    log(f"tun-ip: 给 {dev_name} 配地址 {state.tun_ip}"
        + ("" if '/' in str(state.tun_ip) else f"（默认前缀 24）"))
    return _run_ip_cmds(tun_ip_commands(dev_name, state.tun_ip), 'tun-ip')


def _inject_card(data, src_port=None):
    """
    把数据注入 card（tun 或 tap）。
    - card_mode=none：不做任何事
    - card_mode=tun：剥掉 eth 头（如果存在），把 raw IP 写入 tun
                   注意：peer 发来的帧格式是 eth_hdr(14B) + IP，tun 只认 raw IP
    - card_mode=tap：直接写 tap（已是 Ethernet 帧）

    src_port 用于避免 echo：来自 card 的包不再注回 card
    """
    if state.card_mode == 'none':
        return
    if src_port == 'card':
        return  # 来自 card 的包不再注回去，避免 echo

    if state.card_mode == 'tun':
        if state.iface is None:
            return
        # 剥掉 eth 头（peer 发来的是 Ethernet 帧），只留 raw IP 写 tun
        ip_data = data[14:] if len(data) > 14 else data
        try:
            state.iface.send(ip_data)
            log(f"  tun.inject: {len(ip_data)}B（剥掉 14B eth 头）")
        except Exception as e:
            log(f"  tun.inject 错误: {e}")

    elif state.card_mode == 'tap':
        if state.iface is None:
            return
        try:
            state.iface.send(data)  # tap 已是 Ethernet 帧
            log(f"  tap.inject: {len(data)}B")
        except Exception as e:
            log(f"  tap.inject 错误: {e}")


def lookup_route(dest_ip):
    """查路由表：dest_ip -> port_name"""
    return state.routes.get(dest_ip)


def add_route(dest_ip, via_port):
    """手工静态路由：不参与老化"""
    state.routes[dest_ip] = via_port
    state.static_routes.add(dest_ip)
    state.route_ts.pop(dest_ip, None)
    log(f"路由(静态): {dest_ip} via {via_port}")


def del_route(dest_ip):
    existed = state.routes.pop(dest_ip, None)
    state.route_ts.pop(dest_ip, None)
    state.static_routes.discard(dest_ip)
    return existed


def route_janitor():
    """老化线程：学到的路由/MAC 多久没再出现就删掉（静态路由不动）

    为什么要老化：`routes` 只增不减的话，对端换了地址、或者某条洞早断了，
    表里那条记录会一直把包往死路上引；泛洪能救回来，但得先学会"忘记"。

    老化是安全的：删掉之后下一个包查不到 → 泛洪 → 正确的那个对端回包 → 立刻重新学到。
    """
    log(f"route_janitor: 启动（学到的路由 {state.route_ttl:.0f}s 没再出现就删）")
    while state.running:
        time.sleep(5.0)
        now = time.time()
        ttl = state.route_ttl
        for ip, ts in list(state.route_ts.items()):
            if ip in state.static_routes or ip in state.routes and ip in state.static_routes:
                continue
            if now - ts <= ttl:
                continue
            via = state.routes.pop(ip, None)
            state.route_ts.pop(ip, None)
            if via is not None:
                log(f"route_janitor: 路由 {ip} via {via} 老化（{ttl:.0f}s 没再出现）")
        for mac, ts in list(state.mac_ts.items()):
            if now - ts <= ttl:
                continue
            via = state.mac_table.pop(mac, None)
            state.mac_ts.pop(mac, None)
            if via is not None:
                log(f"route_janitor: MAC {mac} via {via} 老化（{ttl:.0f}s 没再出现）")
    log("route_janitor: 结束")


# =============================================================================
# Port 处理（udpxxx.py 插"网线"）
# =============================================================================

def _flood(data, except_port):
    """泛洪：除源端口外发给所有 port"""
    count = 0
    for name, s in list(state.ports.items()):
        if name != except_port:
            try:
                s.sendall(data)
                count += 1
            except:
                pass
    return count


def _forward_frame(data, src_port):
    """
    通用转发入口（来自 card 或 peer port 的数据）。
    按 switch_mode 调用对应的 L2/L3 转发。
    src_port 用于泛洪时排除源端口，以及学习时记录来源。
    """
    if state.switch_mode == 'l2':
        _forward_l2(data, src_port)
    elif state.switch_mode == 'l3':
        _forward_l3(data, src_port)
    elif state.switch_mode == 'auto':
        _forward_auto(data, src_port)
    else:
        log(f"  未知 switch_mode {state.switch_mode}，丢弃")


def _forward_l2(data, port_name):
    """
    L2 转发：纯 MAC 表，查不到就泛洪。
    适用于：Ethernet 帧（如来自 tap/veth）
    """
    dst_mac = _eth_dst_mac(data)
    src_mac = _eth_src_mac(data)
    log(f"  [L2] src_mac={src_mac} dst_mac={dst_mac}")

    # 学习：来源 MAC → 这个 port（记时间戳，给老化用）
    if src_mac:
        state.mac_table[src_mac] = port_name
        state.mac_ts[src_mac] = time.time()

    # 查 MAC 表
    next_port = state.mac_table.get(dst_mac)
    if next_port and next_port in state.ports:
        state.ports[next_port].sendall(data)
        log(f"  -> {dst_mac} via {next_port}")
    else:
        count = _flood(data, port_name)
        log(f"  -> {dst_mac} 未知，泛洪到 {count} 个 port")


def _forward_l3(data, port_name=None):
    """
    L3 转发：纯 IP 路由表，查不到就泛洪。
    适用于：IP 包（如来自 udptest.py/tcp.py/wg-python.py）
    """
    src_ip = _ip_src(data)
    dst_ip = _ip_dst(data)
    log(f"  [L3] src={src_ip} dst={dst_ip}")

    # 学习：来源 IP → 这个 port（记时间戳，给老化用）
    if src_ip:
        state.routes[src_ip] = port_name
        if src_ip not in state.static_routes:
            state.route_ts[src_ip] = time.time()

    # inject card（tun 或 tap），但来自 card 的包不再注回去（避免 echo）
    if port_name != 'card':
        _inject_card(data, src_port=port_name)

    # 查 IP 路由表
    next_port = state.routes.get(dst_ip)
    if next_port and next_port in state.ports:
        state.ports[next_port].sendall(data)
        log(f"  -> {dst_ip} via {next_port}")
    else:
        count = _flood(data, port_name)
        log(f"  -> {dst_ip} 未知，泛洪到 {count} 个 port")


def _forward_auto(data, port_name=None):
    """
    Auto 模式：先按 EtherType 判断。
    EtherType = IPv4(0x0800) 或 IPv6(0x86DD) → L3 转发
    其他 EtherType → L2 转发
    """
    eth_t = _eth_type(data)
    if eth_t == ETH_P_IP or eth_t == ETH_P_IPV6:
        _forward_l3(data, port_name)
    else:
        _forward_l2(data, port_name)


class Cable:
    """一根"插到交换机端口上的网线"：底下是一条打好的 UDP 洞

    包装成"流式 conn"的样子，好塞进 state.ports

    port_handler 只要求 conn 有 recv(n) / send(data) / close()：
      * recv() 阻塞到有数据为止（空数据报=保活，忽略；socket 超时就继续等），
        这样 port_handler 的循环不会空转烧 CPU
      * send() 往这条洞的**所有候选地址**各发一份（对称 NAT 下服务器给的地址可能不对）
      * 关掉时 recv() 返回 b''，port_handler 就会把 port 摘掉

    和"多人多洞"的配合：每 plug 一条线就 new 一个 Cable，占用一个交换机端口（port1/port2...）
    """
    KEEPALIVE_INTERVAL = 20.0

    def __init__(self, local_addr, local_port, peer_ip, peer_port, peercandidates=None):
        res = socket.getaddrinfo(local_addr or '0.0.0.0', int(local_port),
                                 socket.AF_UNSPEC, socket.SOCK_DGRAM)
        family, socktype, proto, _, sockaddr = res[0]
        self.sock = socket.socket(family, socktype, proto)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.settimeout(0.5)
        self.sock.bind(sockaddr)                 # 沿用打洞时那个本地端口，NAT 映射才不废
        self.local_port = self.sock.getsockname()[1]
        self.peer_ip = peer_ip
        self.peer_port = int(peer_port)
        self._lock = threading.Lock()
        self.candidates = [{'ip': peer_ip, 'port': self.peer_port}]
        for item in (peercandidates or '').split(','):
            item = item.strip()
            if not item:
                continue
            ip, _sep, port = item.rpartition(':')
            try:
                port = int(port)
            except ValueError:
                continue
            if not ip or not (0 < port < 65536):
                continue
            if not any(c['ip'] == ip and c['port'] == port for c in self.candidates):
                self.candidates.append({'ip': ip, 'port': port})
        self.closed = False
        self.recv_count = 0
        self.send_count = 0
        self._ka_thread = None

    def _update_peer(self, addr):
        """收到包的源地址一定是对方真正在用的地址（对称 NAT 下和服务器给的不同）"""
        ip, port = addr[0], addr[1]
        with self._lock:
            if ip == self.peer_ip and port == self.peer_port:
                return
            known = any(c['ip'] == ip and c['port'] == port for c in self.candidates)
            if not known:
                self.candidates.append({'ip': ip, 'port': port})
                log(f"hole: 记下对端候选 {ip}:{port}（共 {len(self.candidates)} 个）")
            self.peer_ip, self.peer_port = ip, port

    def send(self, data):
        with self._lock:
            cands = list(self.candidates)
        for c in cands:
            try:
                self.sock.sendto(data, (c['ip'], c['port']))
            except OSError:
                pass                                  # 单个候选不可达不该影响其它候选
        self.send_count += 1

    def sendall(self, data):
        """switch 的转发 (`_flood` / `_forward_*`) 用的是流式 API，这里对齐一下"""
        self.send(data)

    def recv(self, bufsize=4096):
        while not self.closed:
            try:
                data, addr = self.sock.recvfrom(bufsize)
            except socket.timeout:
                continue
            except OSError:
                return b''
            if not data:
                continue                              # 空数据报 = 对端在保活
            self._update_peer(addr)
            self.recv_count += 1
            return data
        return b''

    def start_keepalive(self):
        """空闲时每 20s 发个空数据报，别让 NAT 映射过期"""
        def _loop():
            while not self.closed and state.running:
                time.sleep(self.KEEPALIVE_INTERVAL)
                if self.closed:
                    break
                self.send(b'')
        self._ka_thread = threading.Thread(target=_loop, daemon=True,
                                          name=f'hole-keepalive-{self.local_port}')
        self._ka_thread.start()

    def fileno(self):
        return self.sock.fileno()

    def setblocking(self, flag):
        self.sock.setblocking(flag)

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass

    def info(self):
        with self._lock:
            return {'localport': self.local_port, 'peer_ip': self.peer_ip,
                    'peer_port': self.peer_port, 'candidates': len(self.candidates),
                    'recv': self.recv_count, 'send': self.send_count}


def port_handler(port_name, conn):
    """
    处理单个 port 连接（对应一个 udpxxx.py "网线"插上）。
    udpxxx.py 直接发二进制包（可能是 IP 包或 Ethernet 帧）。
    第一个包的 src = 这个 peer 的标识（IP 或 MAC，取决于 mode）。

    转发模式由 --switch-mode 决定：
    - l2：纯 MAC 表转发（Ethernet 帧）
    - l3：纯 IP 表转发（IP 包），所有包 inject tun
    - auto：先看 EtherType，IPv4/IPv6 走 L3，其他走 L2
    """
    log(f"{port_name}: 插上网线（mode={state.switch_mode}）")
    state.ports[port_name] = conn

    while state.running:
        try:
            data = conn.recv(4096)
            if not data:
                break

            log(f"{port_name}: recv {len(data)}B")
            _forward_frame(data, port_name)

        except BlockingIOError:
            continue
        except Exception as e:
            log(f"{port_name}: 错误 {e}")
            break

    log(f"{port_name}: 网线拔出")
    conn.close()
    state.ports.pop(port_name, None)


# =============================================================================
# TCP port 模式（--type bindtcpsocket）
# =============================================================================

def tcp_port_listener(base_port=15991, max_ports=64):
    """
    TCP port 模式：每个 port 是 127.0.0.1:base_port+N 的 TCP socket。
    switch bind 这些端口，等待 udpxxx.py 连接（"插网线"）。
    """
    servers = []
    try:
        for i in range(max_ports):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.bind(('127.0.0.1', base_port + i))
                srv.listen(64)
                servers.append(srv)
                log(f"tcp_port_listener: 监听 127.0.0.1:{base_port + i} (port{i})")
            except OSError as e:
                log(f"tcp_port_listener: 端口 {base_port + i} 被占用，跳过: {e}")
                srv.close()
    finally:
        for srv in servers:
            state.listeners.append(srv)

    def acceptor():
        while state.running:
            try:
                r, _, _ = select.select(servers, [], [], 0.5)
                for srv in r:
                    try:
                        conn, addr = srv.accept()
                        port_name = f"port{addr[1] - base_port}"
                        t = threading.Thread(
                            target=port_handler,
                            args=(port_name, conn),
                            daemon=True
                        )
                        t.start()
                    except Exception as e:
                        log(f"tcp accept error: {e}")
            except Exception as e:
                if state.running:
                    log(f"tcp_port_listener select error: {e}")

    t = threading.Thread(target=acceptor, daemon=True, name='tcp_port_acceptor')
    t.start()
    return servers


# =============================================================================
# Unix socket port 模式（--type unixsocket）
# =============================================================================

def unix_port_listener(socket_path):
    """
    Unix socket 模式：单 socket 文件，多个 udpxxx.py 连上来，各是独立连接（"插网线"）。
    连接建立后直接开始双向收发二进制 IP 包，按 fd 编号标识端口。
    """
    os.makedirs(os.path.dirname(socket_path), exist_ok=True)
    if os.path.exists(socket_path):
        os.remove(socket_path)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(socket_path)
    srv.listen(64)
    state.listeners.append(srv)
    log(f"unix_port_listener: 监听 {socket_path}")

    def acceptor():
        while state.running:
            try:
                r, _, _ = select.select([srv], [], [], 0.5)
                if not r:
                    continue
                conn, addr = srv.accept()
                port_name = f"fd{conn.fileno()}"
                log(f"unix_port_listener: {port_name} 插上网线")
                t = threading.Thread(
                    target=port_handler,
                    args=(port_name, conn),
                    daemon=True
                )
                t.start()
            except Exception as e:
                if state.running:
                    log(f"unix accept error: {e}")

    t = threading.Thread(target=acceptor, daemon=True, name='unix_port_acceptor')
    t.start()
    return srv


# =============================================================================
# Console 处理（stdin/stdout JSON 行协议，client.py 通过 pipe 通信）
# =============================================================================

def _plug_socket(sock, origin, peer_name=None, name=None):
    """把一个**已经建立连接**的 socket 插成一个 port（三个来源共用）

      origin='plug_fd'       client.py 用 SCM_RIGHTS 送进来的 TCP 洞 fd
      origin='listen:...'    listenstart 监听端口上 accept 到的连接
      origin='connect:...'   connect 命令自己主动连上的
      （UDP 洞走 Cable 那条路，见 handle_console_cmd 的 plug）

    TCP 不能像 UDP 那样"关了再 bind 同一端口"——连接一关就没了，重连要重新
    SYN/ACK，NAT 那边对不上。所以洞必须把**内核对象**交进来，这里直接用。
    socket 自带的 recv/sendall/close 正好就是 port_handler / _flood 要的接口。
    """
    if name is None:
        state.port_seq += 1
        name = _next_port_name()
    if name in state.ports:
        return {'ok': False, 'error': f'端口 {name} 已被占用'}
    # 同一个底层 socket 只能挂一次
    for _n, _c in state.ports.items():
        try:
            if _c.fileno() == sock.fileno():
                return {'ok': False, 'error': f'这个 fd 已经插在 {_n} 上了'}
        except OSError:
            continue
    try:
        peer = sock.getpeername()
        peer_s = f"{peer[0]}:{peer[1]}"
    except OSError:
        peer_s = '?'
    sock.setblocking(True)          # 阻塞收，不要空转烧 CPU
    state.ports[name] = sock
    state.port_origin[name] = origin       # 记来源：plug / plug_fd / listen:x / connect:x
    log(f"plug: {name} 插上网线（{origin}，fd={sock.fileno()} ↔ {peer_s}"
        + (f"，对端 {peer_name}" if peer_name else '') + "）")
    threading.Thread(target=port_handler, args=(name, sock),
                     daemon=True, name=f'port-{name}').start()
    return {'ok': True, 'name': name, 'fileno': sock.fileno(), 'peer': peer_s}


def _next_port_name():
    """端口名统一 portN，跳过已被占用的（tcp_port_listener 也用 portN）"""
    while True:
        name = f'port{state.port_seq}'
        if name not in state.ports:
            return name
        state.port_seq += 1


def ctl_listener(ctl_path):
    """控制通道（Unix socket）：client.py 在这里用 **SCM_RIGHTS** 把已建立的 fd 送进来

    和 unix_port_listener 的区别：那个每条连接**本身**就是一根网线（收 IP 包）；
    这个只用来传"命令 + fd"，命令是 JSON 行，fd 在 sendmsg 的辅助数据里。
    协议：
      → {"cmd":"plug_fd","name":"port3","peer":"bob"}   （fd 随 sendmsg 一起）
      ← {"ok":true,"name":"port3",...}
      → {"cmd":"status"}                                （不带 fd）
      ← {"ok":true,"ports":[...],"plugged":{...}}
      → {"cmd":"unplug","name":"port3"}
      ← {"ok":true}
    Windows 没有 SCM_RIGHTS，得换 DuplicateHandle + 控制通道 —— TODO，没实现。
    """
    os.makedirs(os.path.dirname(ctl_path), exist_ok=True)
    if os.path.exists(ctl_path):
        os.remove(ctl_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(ctl_path)
    srv.listen(16)
    state.listeners.append(srv)
    log(f"ctl_listener: 监听 {ctl_path}（SCM_RIGHTS 传 fd 用）")

    def send_json(conn, obj):
        try:
            conn.sendall((json.dumps(obj) + '\n').encode('utf-8'))
        except OSError:
            pass

    def recv_fd_msg(conn):
        """收一条消息 + 可能随行的 fd

        注意：Python 3.6 **没有** socket.recv_fds / send_fds（那是 3.9+ 才加的），
        只能用底层的 recvmsg + SCM_RIGHTS 手工解辅助数据。
        """
        msg, ancdata, _flags, _addr = conn.recvmsg(4096, socket.CMSG_SPACE(4 * 4))
        fds = []
        for level, ctype, cdata in ancdata:
            if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                arr = array.array('i')
                usable = len(cdata) - (len(cdata) % arr.itemsize)
                arr.frombytes(cdata[:usable])
                fds.extend(arr.tolist())
        return msg, fds

    def handle(conn):
        try:
            msg, fds = recv_fd_msg(conn)
        except OSError as e:
            log(f"ctl: recvmsg 失败: {e}")
            conn.close()
            return
        line = msg.split(b'\n', 1)[0]
        try:
            cmd = json.loads(line.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            for fd in fds:
                os.close(fd)
            send_json(conn, {'ok': False, 'error': 'invalid json'})
            conn.close()
            return

        c = cmd.get('cmd', '')
        if c == 'plug_fd':
            if not fds:
                send_json(conn, {'ok': False, 'error': 'plug_fd 需要一个 fd（SCM_RIGHTS）'})
            else:
                fd = fds[0]
                for extra in fds[1:]:      # 多余的 fd 关掉
                    os.close(extra)
                try:
                    sock = socket.socket(fileno=fd)
                except OSError as e:
                    os.close(fd)
                    send_json(conn, {'ok': False, 'error': f'fd {fd} 不是 socket: {e}'})
                else:
                    send_json(conn, _plug_socket(sock, 'plug_fd',
                                                 cmd.get('peer'), cmd.get('name')))
        elif c == 'status':
            send_json(conn, {'ok': True, 'ports': list(state.ports.keys()),
                             'routes': dict(state.routes)})
            name = cmd.get('name')
            conn2 = state.ports.get(name)
            if conn2 is None:
                send_json(conn, {'ok': False, 'error': f'端口 {name} 上没插线'})
            else:
                try:
                    conn2.close()
                except OSError:
                    pass
                send_json(conn, {'ok': True})
        else:
            send_json(conn, {'ok': False, 'error': f'unknown cmd: {c}'})
        conn.close()

    def acceptor():
        while state.running:
            try:
                r, _, _ = select.select([srv], [], [], 0.5)
                if not r:
                    continue
                conn, _addr = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True,
                                 name='ctl-conn').start()
            except OSError as e:
                if state.running:
                    log(f"ctl_listener select/accept 错误: {e}")
                break
        log("ctl_listener: 结束")

    threading.Thread(target=acceptor, daemon=True, name='ctl').start()


def _kv(tokens):
    """把 ["addr=0.0.0.0","port=15991"] 解成 dict"""
    out = {}
    for t in tokens:
        k, sep, v = t.partition('=')
        if sep:
            out[k] = v
    return out


def parse_text_line(line):
    """stdin 的命令行 → 内部 cmd dict（和 ctl socket 的 JSON 命令走同一个 handle_console_cmd）

    支持的命令（一行一条）：
      status / routes / quit
      plug localport=50001 peer=1.2.3.4:30001 [candidates=a:1,b:2] [name=port9]
      unplug <port名>
      route add <ip|网段> <port名>
      route del <ip|网段>
      listenstart [addr=0.0.0.0] [port=15991]      ← 不带 addr 默认 0.0.0.0
      listenstop [port=15991]                      ← 不带 port = 全停；已接入的 port 不动
      connect <host:port> [name=port9] [timeout=5] ← 主动 TCP 连（v4/v6/域名，异步）
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    toks = line.split()
    verb = toks[0].lower()
    rest = toks[1:]
    kv = _kv(rest)
    pos = [t for t in rest if '=' not in t]

    if verb in ('status', 'routes', 'quit'):
        return {'cmd': verb}
    if verb == 'plug':
        peer = kv.get('peer') or (pos[0] if pos else '')
        host, _sep, port_s = peer.rpartition(':')
        try:
            peer_port = int(port_s)
        except ValueError:
            peer_port = 0
        return {'cmd': 'plug', 'localport': kv.get('localport'),
                'peer_ip': host.strip('[]'), 'peer_port': peer_port,
                'peercandidates': kv.get('candidates'), 'name': kv.get('name')}
    if verb == 'unplug':
        return {'cmd': 'unplug', 'name': kv.get('name') or (pos[0] if pos else None)}
    if verb == 'route':
        sub = (pos[0] if pos else '').lower()
        if sub == 'add' and len(pos) >= 3:
            return {'cmd': 'route_add', 'dest': pos[1], 'via': pos[2]}
        if sub == 'del' and len(pos) >= 2:
            return {'cmd': 'route_del', 'dest': pos[1]}
        return {'cmd': 'route'}
    if verb == 'listenstart':
        return {'cmd': 'listenstart', 'addr': kv.get('addr'), 'port': kv.get('port')}
    if verb == 'listenstop':
        return {'cmd': 'listenstop', 'port': kv.get('port')}
    if verb == 'connect':
        return {'cmd': 'connect', 'target': kv.get('target') or (pos[0] if pos else ''),
                'name': kv.get('name'), 'timeout': kv.get('timeout')}
    return {'cmd': verb}          # 未知动词 → 让 handle_console_cmd 回 unknown cmd


def fmt_reply(resp):
    """内部回复 dict → 一行文本：ok key=value ... / err 消息"""
    if not isinstance(resp, dict):
        return 'ok ' + str(resp)
    if not resp.get('ok'):
        return 'err ' + str(resp.get('error', 'unknown'))
    parts = []
    for k, v in resp.items():
        if k == 'ok':
            continue
        # 值里不能有空格，否则 'ok k=v k=v' 的分词就断了：
        #   列表 → 逗号连接（端口名/地址都不会有空格，好读）
        #   dict → 紧凑 JSON（repr 里带空格，会破坏分词）
        if isinstance(v, (list, tuple)):
            v = ','.join(str(x) for x in v)
        elif isinstance(v, dict):
            v = json.dumps(v, ensure_ascii=False, separators=(',', ':'))
        parts.append(f'{k}={v}')
    return 'ok' + (' ' + ' '.join(parts) if parts else '')


def handle_console_cmd(cmd):
    """处理来自 client.py 的控制命令"""
    c = cmd.get('cmd', '')

    if c == 'route':
        return {
            'ok': True,
            'routes': [{'dest': ip, 'via': port,
                        'static': ip in state.static_routes,
                        'age': (time.time() - state.route_ts[ip]) if ip in state.route_ts else None}
                       for ip, port in state.routes.items()],
            'neighbors': [{'name': name} for name in state.ports],
            'switch_ip': state.switch_ip,
        }

    elif c == 'route_add':
        dest = cmd.get('dest')
        via = cmd.get('via')
        if dest and via:
            add_route(dest, via)
            return {'ok': True}
        return {'ok': False, 'error': 'need dest and via'}

    elif c == 'route_del':
        dest = cmd.get('dest')
        del_route(dest)
        return {'ok': True}

    elif c == 'status':
        return {
            'ok': True,
            'switch_ip': state.switch_ip,
            'ports': list(state.ports.keys()),
            'port_origin': dict(state.port_origin),
            'listening': sorted(state.acceptors.keys()),
            # 插着网线的那些端口（底下是 UDP 洞），带本地/对端地址和收发计数
            'plugged': {n: conn.info() for n, conn in state.ports.items()
                        if isinstance(conn, Cable)},
            'routes': state.routes,
            'tun_fd': state.tun_fd,
        }

    elif c == 'routes':
        return {'ok': True, 'routes': dict(state.routes)}

    elif c == 'plug':
        # 插一根网线：client.py 打好一条 UDP 洞，交给 switch 当成一个端口用
        # （switch 自己 bind 那个本地端口、自己保活）
        localport = cmd.get('localport')
        peer_ip = (cmd.get('peer_ip') or '').strip()
        peer_port = cmd.get('peer_port')
        if not localport or not peer_ip or not peer_port:
            return {'ok': False, 'error': 'need localport / peer_ip / peer_port'}
        # 同一个本地端口只允许插一根线：Cable 开了 SO_REUSEPORT，两根线绑同一端口时
        # 内核会把收到的包**分流**给两边，两边都收不全 —— 直接拒掉
        for _n, _c in state.ports.items():
            if isinstance(_c, Cable) and _c.local_port == int(localport):
                return {'ok': False,
                        'error': f'本端端口 {localport} 已经插了一根线了（{_n}）'}
        if cmd.get('name'):
            name = cmd['name']
            if name in state.ports:
                return {'ok': False, 'error': f'端口 {name} 已被占用'}
        else:
            # 端口名统一是 portN；tcp_port_listener 也用 portN，所以往后找空位
            state.port_seq += 1
            name = f'port{state.port_seq}'
            while name in state.ports:
                state.port_seq += 1
                name = f'port{state.port_seq}'
        try:
            conn = Cable(cmd.get('localaddr') or '0.0.0.0', localport,
                         peer_ip, peer_port, cmd.get('peercandidates'))
        except Exception as e:
            return {'ok': False, 'error': f'bind {localport} 失败: {e}'}
        log(f"plug: {name} 插上网线（本端 :{conn.local_port} ↔ {peer_ip}:{peer_port}"
            f"，候选 {len(conn.candidates)} 个）")
        conn.start_keepalive()
        threading.Thread(target=port_handler, args=(name, conn),
                         daemon=True, name=f'port-{name}').start()
        return {'ok': True, 'name': name, 'localport': conn.local_port}

    elif c == 'listenstart':
        addr = cmd.get('addr') or '0.0.0.0'
        port = int(cmd.get('port') or 15991)
        if port in state.acceptors:
            return {'ok': False, 'error': f'已经在监听 {port}'}
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((addr, port))
            srv.listen(64)
        except OSError as e:
            return {'ok': False, 'error': f'bind {addr}:{port} 失败: {e}'}
        state.acceptors[port] = (addr, srv)
        state.listeners.append(srv)
        actual = srv.getsockname()[1]
        log(f"listenstart: 监听 {addr}:{actual}（accept 进来的都自动接入成一个 port）")

        def acceptor(srv=srv, port=actual, addr=addr):
            while state.running and state.acceptors.get(port, (None, None))[1] is srv:
                try:
                    r, _w, _x = select.select([srv], [], [], 0.5)
                    if not r:
                        continue
                    conn, peer = srv.accept()
                    _plug_socket(conn, f'listen:{addr}:{port}')
                except OSError as e:
                    if state.running and state.acceptors.get(port, (None, None))[1] is srv:
                        log(f"listenstart: accept 出错: {e}")
                    break
            log(f"listenstart: {addr}:{port} 停止 accept")

        threading.Thread(target=acceptor, daemon=True, name=f'accept-{actual}').start()
        return {'ok': True, 'addr': addr, 'port': actual}

    elif c == 'listenstop':
        port = cmd.get('port')
        targets = [int(port)] if port else list(state.acceptors.keys())
        if not targets:
            return {'ok': False, 'error': '没有在监听的端口'}
        stopped = []
        for pt in targets:
            item = state.acceptors.pop(pt, None)
            if not item:
                continue
            try:
                item[1].close()
            except OSError:
                pass
            stopped.append(pt)
            log(f"listenstop: 停止监听 {item[0]}:{pt}（已接入的 port 不动）")
        if not stopped:
            return {'ok': False, 'error': f'没在监听 {port}'}
        return {'ok': True, 'stopped': ','.join(str(x) for x in stopped),
                'ports_kept': len(state.ports)}

    elif c == 'connect':
        target = (cmd.get('target') or '').strip()
        if not target:
            return {'ok': False, 'error': 'need target，如 connect [2001:db8::3]:15991'}
        host, _sep, port_s = target.rpartition(':')
        host = host.strip('[]')
        try:
            port = int(port_s)
        except ValueError:
            return {'ok': False, 'error': f'目标端口不对: {target}'}
        timeout = float(cmd.get('timeout') or 5.0)
        name = cmd.get('name')

        def dial(host=host, port=port, timeout=timeout, name=name, target=target):
            """异步拨号：连上就自动接入成一个 port，失败只记日志（不卡住 console）"""
            try:
                infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except OSError as e:
                log(f"connect: 解析 {host} 失败: {e}")
                return
            for family, socktype, proto, _canon, sockaddr in infos:
                s2 = socket.socket(family, socktype, proto)
                s2.settimeout(timeout)
                try:
                    s2.connect(sockaddr)
                except OSError as e:
                    log(f"connect: {target}（family={family}）失败: {e}")
                    s2.close()
                    continue
                s2.settimeout(None)
                log(f"connect: ✅ 连上 {target}")
                _plug_socket(s2, f'connect:{target}', name=name)
                return
            log(f"connect: {target} 全部地址都连不上")

        threading.Thread(target=dial, daemon=True, name=f'connect-{port}').start()
        return {'ok': True, 'connecting': target}

    elif c == 'routes':
        return {'ok': True, 'routes': [{'dest': ip, 'via': via,
                                        'static': ip in state.static_routes}
                                       for ip, via in state.routes.items()]}

    elif c == 'unplug':
        name = cmd.get('name')
        conn = state.ports.get(name)
        if conn is None:
            return {'ok': False, 'error': f'端口 {name} 上没插线'}
        try:
            conn.close()          # recv() 返回 b''，port_handler 自己把 port 摘掉
        except OSError:
            pass
        state.port_origin.pop(name, None)
        log(f"unplug: {name} 拔掉网线")
        return {'ok': True}

    elif c == 'quit':
        state.running = False
        return {'ok': True}

    return {'ok': False, 'error': f'unknown cmd: {c}'}


def console_listener():
    """
    从 stdin 读取 JSON 行，处理命令，结果写到 stdout。
    client.py spawn 时 pipe=True，stdin/stdout 就是和 client.py 的专属通道。
    """
    log(f"console_listener: 启动（stdin/stdout pipe）")
    buffer = b''

    while state.running:
        r, _, _ = select.select([sys.stdin], [], [], 0.5)
        if not r:
            continue
        try:
            chunk = os.read(sys.stdin.fileno(), 4096)
            if not chunk:
                break
            buffer += chunk
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                try:
                    # stdin 是**文本命令**（人也能敲）；ctl socket 那边才是 JSON
                    cmd = parse_text_line(line.decode('utf-8', 'replace'))
                    if cmd is None:
                        continue
                    resp = handle_console_cmd(cmd)
                except Exception as e:
                    log(f"console: 命令处理错误: {e}")
                    resp = {'ok': False, 'error': str(e)}
                try:
                    sys.stdout.write(fmt_reply(resp) + '\n')
                    sys.stdout.flush()
                except Exception as e:
                    log(f"console: 写回复失败: {e}")
        except Exception as e:
            if state.running:
                log(f"console read error: {e}")
            break

    log(f"console_listener: 结束")


# =============================================================================
# Tun/Tap 监听（card <-> ports 转发）
# =============================================================================

def card_listener():
    """
    从 tun/tap 设备收包，按 switch-mode 转发到 ports。
    - tun 模式：收到 raw IP 包，加 14B 假 eth 头，注入 switch 转发
    - tap 模式：收到 Ethernet 帧，直接注入 switch 转发
    """
    if state.iface is None:
        log(f"card_listener: card 未初始化，跳过")
        return

    log(f"card_listener: 启动（card_mode={state.card_mode}）")

    while state.running:
        try:
            # 从 tun/tap 收数据
            data = state.iface.recv(65535)
            if not data:
                time.sleep(0.01)
                continue

            log(f"tun: recv {len(data)}B")

            if state.card_mode == 'tun':
                # raw IP 包：加 14B 假 eth 头伪装成 Ethernet 帧
                if len(data) >= 20:  # 最小 IP 头
                    hdr = _make_fake_eth_header(len(data))
                    frame = hdr + data
                    log(f"  tun -> switch: +14B eth 头 = {len(frame)}B")
                    _forward_frame(frame, src_port='card')

            elif state.card_mode == 'tap':
                # 已经是 Ethernet 帧，直接转发
                _forward_frame(data, src_port='card')

        except BlockingIOError:
            time.sleep(0.01)
        except Exception as e:
            if state.running:
                log(f"card_listener: 错误 {e}")
            break

    log(f"card_listener: 结束")


# =============================================================================
# main
# =============================================================================

def main():
    global _log_fp

    parser = argparse.ArgumentParser(description='p2pnet L3 Switch')
    parser.add_argument('--tun-ip', default=None,
                        help='启动时配到 tun 上的 IPv4 地址，可写 "192.168.250.55" 或 '
                             '"192.168.250.55/24"（不带的默认 /24）。**不带这个参数就不设地址**，'
                             '设备上是空的，需要自己 ip addr add')
    parser.add_argument('--tun-mtu', type=int, default=1400,
                        help='card（tun/tap）设备的 MTU，默认 1400。洞是"IP over UDP"，'
                             '1500 的包套上 UDP/IP 头会超网卡 MTU 分片，所以默认降到 1400；'
                             '写 0 = 不改设备 MTU')
    parser.add_argument('--route-ttl', type=float, default=300.0,
                        help='学到的路由/MAC 多久没再出现就老化删除（秒，默认 300；0=不老化；'
                             '手工 route_add 的静态路由永不老化）')
    parser.add_argument('--switch-mode', choices=['l2', 'l3', 'auto'],
                        default=None,
                        help='交换模式：l2=MAC 表转发，l3=IP 表转发，'
                             'auto=EtherType 为 IPv4/IPv6 时走 L3、其它走 L2。'
                             '不指定时：--card tap 默认 auto（tap 里是 Ethernet 帧，'
                             '按 l3 解析 IP 头会读出垃圾），其余默认 l3')
    parser.add_argument('--card', choices=['none', 'tun', 'tap'],
                        default='none',
                        help='card 设备：none=不开（默认），tun=开 TUN 加/剥假 eth 头，tap=开 TAP 直接透传')
    parser.add_argument('--type', choices=['bindtcpsocket', 'unixsocket'],
                        default='bindtcpsocket',
                        help='与 udpxxx.py 的交互方式：bindtcpsocket=TCP 127.0.0.1 端口，unixsocket=Unix socket 文件')
    parser.add_argument('--base-port', type=int, default=15991,
                        help='TCP port 起始端口（--type bindtcpsocket 时，默认 15991）')
    parser.add_argument('--socketpath',
                        default=None,
                        help='Unix socket 路径（--type unixsocket 时）')
    parser.add_argument('--ctlpath', default=None,
                        help='控制通道 Unix socket 路径（client.py 用 SCM_RIGHTS 把已建立的 '
                             'TCP fd 传进来插网线；不设则不开）')
    parser.add_argument('--log',
                        default=None,
                        help='日志文件路径（默认 stderr）')
    args = parser.parse_args()

    state.tun_ip = args.tun_ip
    state.switch_ip = args.tun_ip  # backward compat alias
    state.route_ttl = args.route_ttl
    state.tun_mtu = args.tun_mtu
    state.card_mode = args.card          # 先定 card，switch_mode 的默认值要看它
    # tap 里跑的是 Ethernet 帧，默认用 auto（看 EtherType 决定走 l2 还是 l3）
    state.switch_mode = args.switch_mode or ('auto' if state.card_mode == 'tap' else 'l3')

    if args.log:
        os.makedirs(os.path.dirname(args.log), exist_ok=True)
        _log_fp = open(args.log, 'a', encoding='utf-8')

    log(f"Switch 启动，card={state.card_mode}，switch_mode={state.switch_mode}，type={args.type}")

    # 初始化 card（tun 或 tap）
    if state.card_mode != 'none':
        try:
            dev = _open_card_device(state.card_mode)
            state.iface = dev
            tun_name = dev.name
            log(f"card: {state.card_mode} 设备 {tun_name} 已打开")
            # 先设 MTU（默认 1400），再把 --tun-ip 配上去（不带 --tun-ip 就不设地址）
            apply_tun_mtu(tun_name)
            assign_tun_ip(tun_name)
            # 启动 card_listener 线程
            t_card = threading.Thread(target=card_listener, daemon=True, name='card')
            t_card.start()
        except Exception as e:
            log(f"card: 打开 {state.card_mode} 设备失败: {e}")
            state.card_mode = 'none'

    # 三个线程：
    # 1. console_listener：stdin/stdout（client.py 专属通道，防干扰）
    # 2. port_listener：TCP 或 Unix socket（udpxxx.py 插网线的地方）
    # 3. card_listener：card <-> ports 转发
    t_console = threading.Thread(target=console_listener, daemon=True, name='console')
    t_console.start()

    if args.type == 'bindtcpsocket':
        tcp_port_listener(base_port=args.base_port, max_ports=64)
        log(f"TCP port 模式：udpxxx.py 用 --socketpath 127.0.0.1:<port> 连接")
    else:
        if args.socketpath is None:
            args.socketpath = f'/tmp/p2pnet/switch-{os.getpid()}.sock'
        unix_port_listener(args.socketpath)
        log(f"Unix socket 模式：udpxxx.py 用 --socketpath {args.socketpath} 连接")

    # 控制通道：client.py 用 SCM_RIGHTS 把**已建立的 TCP 洞 fd** 送进来插网线
    if args.ctlpath:
        ctl_listener(args.ctlpath)

    # 学到的路由老化
    if args.route_ttl and args.route_ttl > 0:
        threading.Thread(target=route_janitor, daemon=True, name='route-janitor').start()
    else:
        log("route_janitor: --route-ttl=0，学到的路由不老化")

    t_console.join()
    if state.card_mode != 'none':
        t_card.join()

    # 清理所有 listener socket
    for srv in state.listeners:
        try:
            srv.close()
        except:
            pass
    log(f"Switch 结束")


if __name__ == '__main__':
    main()
