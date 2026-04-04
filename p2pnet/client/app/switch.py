#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app/switch.py - L3 Switch（mesh VPN）

进程关系（仅供理解，不代表拓扑层级）：
  switch.py（switch 进程，拥有 tun 设备 192.168.250.55/24）
  ├─ console：stdin/stdout（连 client.py，pipe 方式，防干扰）
  ├─ card：   tun/tap（本地插口，本机 app 的 IP 包从这里进出）
  ├─ port1：  TCP 127.0.0.1:15991（udpxxx.py 连接这里，插上"网线" ↔ Switch B）
  ├─ port2：  TCP 127.0.0.1:15992（udpxxx.py 连接这里 ↔ Switch C）
  └─ port3：  TCP 127.0.0.1:15993（udpxxx.py 连接这里 ↔ Switch C，洞不通走 port2 中继）

对等理解（正确）：
  Switch A ↔ udpxxx.py ↔ Switch B（alice 那边的网络）
  Switch A ↔ udpxxx.py ↔ Switch C（bob）
  Switch A 眼里 Switch B/C/D 都是邻居，不是下属

client.py 交互（通过 pipe）：
  启动时 client.py spawn(switch.py, pipe=True)
  双方通过 stdin/stdout 的 JSON 行协议通信
  不暴露额外的 socket，避免其他进程干扰

port 交互方式（--type 参数）：
  bindtcpsocket（默认）：switch bind TCP 127.0.0.1:15991+，udpxxx.py 通过 --socketpath 收到连接地址

交换模式（--switch-mode 参数）：
  l2：纯 MAC 表转发，所有包 inject tun
  l3（默认）：纯 IP 表转发，所有包 inject tun
  auto：EtherType=IPv4/IPv6 时走 L3，其他走 L2
  bindtcpsocket（默认）：switch bind TCP 127.0.0.1:15991+，udpxxx.py 通过 --socketpath 收到连接地址
    例：switch --type bindtcpsocket --base-port 15991
        udpxxx.py --appmode switch --socketpath 127.0.0.1:15991
  unixsocket：switch bind 单个 Unix socket 文件，多个 udpxxx.py 各用独立连接，
              直接双向收发二进制 IP 包（默认 /tmp/p2pnet/switch-<pid>.sock）
    例：switch --type unixsocket
        udpxxx.py --appmode switch --socketpath /tmp/p2pnet/switch-<pid>.sock
"""

import os
import sys
import json
import time
import socket
import select
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
        self.tun_fd = None    # tun 设备 fd（TODO）
        self.iface = None     # tun 接口对象（TODO）
        self.listeners = []    # 关闭时需要清理的 socket

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
    state.routes[dest_ip] = via_port
    log(f"路由: {dest_ip} via {via_port}")


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

    # 学习：来源 MAC → 这个 port
    if src_mac:
        state.mac_table[src_mac] = port_name

    # 查 MAC 表
    next_port = state.mac_table.get(dst_mac)
    if next_port and next_port in state.ports:
        state.ports[next_port].sendall(data)
        log(f"  -> {dst_mac} via port {next_port}")
    else:
        count = _flood(data, port_name)
        log(f"  -> {dst_mac} 未知，泛洪到 {count} 个 port")


def _forward_l3(data, port_name=None):
    """
    L3 转发：纯 IP 路由表，查不到就泛洪。
    适用于：IP 包（如来自 udp.py/tcp.py/wireguard.py）
    """
    src_ip = _ip_src(data)
    dst_ip = _ip_dst(data)
    log(f"  [L3] src={src_ip} dst={dst_ip}")

    # 学习：来源 IP → 这个 port
    if src_ip:
        state.routes[src_ip] = port_name

    # inject card（tun 或 tap），但来自 card 的包不再注回去（避免 echo）
    if port_name != 'card':
        _inject_card(data, src_port=port_name)

    # 查 IP 路由表
    next_port = state.routes.get(dst_ip)
    if next_port and next_port in state.ports:
        state.ports[next_port].sendall(data)
        log(f"  -> {dst_ip} via port {next_port}")
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
    log(f"port {port_name}: 插上网线（mode={state.switch_mode}）")
    state.ports[port_name] = conn

    while state.running:
        try:
            data = conn.recv(4096)
            if not data:
                break

            log(f"port {port_name}: recv {len(data)}B")
            _forward_frame(data, port_name)

        except BlockingIOError:
            continue
        except Exception as e:
            log(f"port {port_name}: 错误 {e}")
            break

    log(f"port {port_name}: 网线拔出")
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

def handle_console_cmd(cmd):
    """处理来自 client.py 的控制命令"""
    c = cmd.get('cmd', '')

    if c == 'route':
        return {
            'ok': True,
            'routes': [{'dest': ip, 'via': port} for ip, port in state.routes.items()],
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
        state.routes.pop(dest, None)
        return {'ok': True}

    elif c == 'status':
        return {
            'ok': True,
            'switch_ip': state.switch_ip,
            'ports': list(state.ports.keys()),
            'routes': state.routes,
            'tun_fd': state.tun_fd,
        }

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
                    cmd = json.loads(line.decode('utf-8'))
                    resp = handle_console_cmd(cmd)
                    send_json(resp)
                except json.JSONDecodeError as e:
                    log(f"console: JSON 解析错误: {e}")
                except Exception as e:
                    log(f"console: 命令处理错误: {e}")
                    send_json({'ok': False, 'error': str(e)})
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
                        help='tun 网卡 IP（不设则 tun 无 IP，用户 ifconfig 看不到地址）')
    parser.add_argument('--switch-mode', choices=['l2', 'l3', 'auto'],
                        default='l3',
                        help='交换模式：l2=MAC 表转发，l3=IP 表转发（默认），auto=EtherType 为 IPv4/IPv6 时走 L3')
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
    parser.add_argument('--log',
                        default=None,
                        help='日志文件路径（默认 stderr）')
    args = parser.parse_args()

    state.tun_ip = args.tun_ip
    state.switch_ip = args.tun_ip  # backward compat alias
    state.switch_mode = args.switch_mode
    state.card_mode = args.card

    if args.log:
        os.makedirs(os.path.dirname(args.log), exist_ok=True)
        _log_fp = open(args.log, 'a', encoding='utf-8')

    log(f"Switch 启动，card={state.card_mode}，switch_mode={state.switch_mode}，type={args.type}")

    # 初始化 card（tun 或 tap）
    if state.card_mode != 'none':
        try:
            from app.tun import Tun
            tun = Tun()
            state.iface = tun
            tun_name = tun.name
            log(f"card: {state.card_mode} 设备 {tun_name} 已打开")
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
