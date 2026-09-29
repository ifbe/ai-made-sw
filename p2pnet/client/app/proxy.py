#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet proxy：把打好的 UDP 洞当作一条裸通道，和指定目标 地址:端口 双向转发

洞由 client.py 的 hole/udp.py 打好后转交过来（关掉自己的 socket，
再用同一个本地端口拉起本程序），所以本程序必须 bind 同一个本地 UDP 端口，
否则 NAT 映射会失效。

用法:
  python3 proxy.py --peeraddr <ip> --peerport <port> --localport <port>
                   --target <host:port> [--proto tcp|udp]
                   [--peercandidates a:1,b:2] [--localaddr 0.0.0.0]
                   [--remotelog <文件>]

典型用法:
  - 远程桌面：--target 127.0.0.1:3389
  - SSH：    --target 127.0.0.1:22
  - 端口转发：把洞里的流量转发到任意 TCP/UDP 服务

架构:
  udp_listener:   recvfrom(洞) → 忽略空包 → 更新 active_peer → 写入目标
  target_reader:  读目标(TCP conn / 已 connect 的 UDP socket) → 发往所有候选
  keepalive:      每 20s 往所有候选各发一个空 UDP 数据报，保活 NAT 映射
"""

import os
import sys
import time
import socket
import argparse
import threading
import signal

# ---- 全局变量 ----
_log_fp = None  # 日志文件句柄（main() 里赋值）
_TAG = os.path.basename(__file__)  # 'proxy.py'（日志标签，别再写死）

KEEPALIVE_INTERVAL = 20.0  # NAT 保活间隔（秒）
RECV_BUFSIZE = 65535
HEX_DUMP_LEN = 32  # 日志里最多打印前 32 字节


def ts():
    return time.strftime("%H:%M:%S")


def log(func_name, *a, **kw):
    """模块级 log，main() 里会覆盖 _log_fp 来重定向日志"""
    msg = ' '.join(str(x) for x in a)
    line = f"[{ts()}][{_TAG} {func_name}]  {msg}"
    if _log_fp:
        _log_fp.write(line + '\n')
        _log_fp.flush()
    else:
        print(line)


def hex_dump(data, maxlen=HEX_DUMP_LEN):
    """只取前 maxlen 字节做 hex，避免把全部数据 dump 到日志"""
    return ' '.join(f'{b:02x}' for b in data[:maxlen])


def parse_target(text):
    """解析 --target，返回 (host, port)。格式：host:port，IPv6 用 [::1]:port"""
    s = (text or '').strip()
    if not s:
        raise ValueError('空字符串')
    if s.startswith('['):
        end = s.find(']')
        if end < 0:
            raise ValueError('IPv6 地址缺少 ]')
        host = s[1:end]
        rest = s[end + 1:]
        if not rest.startswith(':'):
            raise ValueError('缺少端口（应为 [IPv6]:port）')
        port_s = rest[1:]
    else:
        host, sep, port_s = s.rpartition(':')
        if not sep:
            raise ValueError('缺少端口（应为 host:port）')
    host = host.strip()
    if not host:
        raise ValueError('缺少主机名')
    try:
        port = int(port_s)
    except ValueError:
        raise ValueError(f'端口不是数字: {port_s}')
    if not (0 < port < 65536):
        raise ValueError(f'端口超出范围: {port}')
    return host, port


def build_candidates(peer_ip, peer_port, extra_text):
    """--peeraddr:--peerport 是第一个候选；--peercandidates 里的追加"""
    candidates = [{'ip': peer_ip, 'port': peer_port}]
    for item in (extra_text or '').split(','):
        item = item.strip()
        if not item:
            continue
        ip, sep, port_s = item.rpartition(':')
        if not sep or not ip:
            log("build_candidates", f"忽略非法候选: {item}")
            continue
        try:
            port = int(port_s)
        except ValueError:
            log("build_candidates", f"忽略非法候选（端口非数字）: {item}")
            continue
        if not (0 < port < 65536):
            log("build_candidates", f"忽略非法候选（端口越界）: {item}")
            continue
        if not any(c['ip'] == ip and c['port'] == port for c in candidates):
            candidates.append({'ip': ip, 'port': port})
    return candidates


def main():
    global _log_fp

    parser = argparse.ArgumentParser(
        description='p2pnet 洞内流量转发代理（把打好的 UDP 洞和 --target 双向转发）')
    parser.add_argument('--peeraddr', required=True,
                        help='对方 IP（IPv4/IPv6/域名，自动识别）')
    parser.add_argument('--peerport', type=int, required=True, help='对方端口')
    parser.add_argument('--localport', type=int, required=True, help='本地 UDP 端口（必须和洞的端口一致）')
    parser.add_argument('--peercandidates', default=None,
                        help='额外对端候选地址 ip:port,ip:port（打洞阶段学到的 peer-reflexive，可选）')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本地监听地址（默认 0.0.0.0）')
    parser.add_argument('--target', default=None,
                        help='目标地址 host:port（必填，洞里的流量转发到这里）')
    parser.add_argument('--proto', choices=['tcp', 'udp'], default='tcp',
                        help='转发协议：tcp=一条 TCP 连接（默认），udp=无连接数据报')
    parser.add_argument('--remotelog', default=None,
                        help='日志文件路径（默认 stdout）')
    args = parser.parse_args()

    # --target 必填：给用法提示后退出
    if not args.target:
        parser.error('--target 必填：请用 --target <host:port> 指定要转发到的目标地址，'
                     '例如 --target 127.0.0.1:3389')
    try:
        target_host, target_port = parse_target(args.target)
    except ValueError as e:
        parser.error(f'--target 格式错误({e})：应为 host:port，例如 127.0.0.1:3389')

    peer_ip = args.peeraddr
    peer_port = args.peerport
    local_addr = args.localaddr
    local_port = args.localport
    proto = args.proto

    _log_fp = None
    if args.remotelog:
        try:
            _log_fp = open(args.remotelog, 'a', encoding='utf-8')
        except OSError as e:
            print(f"[{ts()}][{_TAG} main]  打开日志文件失败: {e}", file=sys.stderr)
            _log_fp = None

    # ========== 接管洞：同一个本地 UDP 端口 ==========
    try:
        local_res = socket.getaddrinfo(local_addr, local_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except socket.gaierror as e:
        log("main", f"本地地址解析失败 {local_addr}:{local_port}: {e}")
        return 1
    family, socktype, proto_num, _, sockaddr = local_res[0]
    sock = socket.socket(family, socktype, proto_num)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.settimeout(0.5)  # 超时以便优雅退出
    try:
        sock.bind(sockaddr)
    except OSError as e:
        log("main", f"绑定本地端口失败 {local_addr}:{local_port}: {e}")
        sock.close()
        return 1
    actual_port = sock.getsockname()[1]
    local_family = 'IPv6' if family == socket.AF_INET6 else 'IPv4'
    log("main", f"本端(洞): {local_addr}:{actual_port} ({local_family})")
    log("main", f"对端: {peer_ip}:{peer_port}")
    log("main", f"目标: {target_host}:{target_port}  proto={proto}")
    log("main", f"remotelog={args.remotelog or ''}")

    stop_event = threading.Event()
    peer_lock = threading.Lock()
    target_lock = threading.Lock()
    active_peer = {'ip': peer_ip, 'port': peer_port}
    candidates = build_candidates(peer_ip, peer_port, args.peercandidates)
    if len(candidates) > 1:
        log("main", "对端候选: " + ', '.join(f"{c['ip']}:{c['port']}" for c in candidates))

    stats = {'sent': 0, 'recv': 0, 'sent_bytes': 0, 'recv_bytes': 0}

    def get_active():
        with peer_lock:
            return {'ip': active_peer['ip'], 'port': active_peer['port']}

    def get_candidates():
        with peer_lock:
            return list(candidates)

    def update_peer(addr_tuple):
        """收到包的源地址才是一定能回包的那个；是新地址就追加为 peer-reflexive 候选"""
        ip, port = addr_tuple[0], addr_tuple[1]
        with peer_lock:
            if ip == active_peer['ip'] and port == active_peer['port']:
                return
            for c in candidates:
                if c['ip'] == ip and c['port'] == port:
                    active_peer['ip'] = ip
                    active_peer['port'] = port
                    log("update_peer", f"🔄 active_peer → {ip}:{port}")
                    return
            candidates.append({'ip': ip, 'port': port})
            old_ip, old_port = active_peer['ip'], active_peer['port']
            active_peer['ip'] = ip
            active_peer['port'] = port
            log("update_peer", f"🆕 peer-reflexive {ip}:{port}（原 {old_ip}:{old_port} 加入候选）")

    def send_to_candidates(data, func_name, what='data'):
        """每个包都往所有候选各发一份"""
        targets = get_candidates()
        hex_str = hex_dump(data)
        for c in targets:
            try:
                sock.sendto(data, (c['ip'], c['port']))
            except OSError as e:
                log(func_name, f"发往候选 {c['ip']}:{c['port']} 失败: {e}")
                continue
        stats['sent'] += 1
        stats['sent_bytes'] += len(data)
        log(func_name, f"send {what}: len={len(data)} hex={hex_str} → {len(targets)} 个候选")

    # ========== 目标侧：TCP 建连 / UDP 懒解析 ==========
    tcp_sock = None
    udp_target_sock = None
    udp_target_addr = None  # connect 之后仅用于日志/校验来源

    def connect_tcp():
        """向 --target 建立一条 TCP 连接，失败返回 None"""
        try:
            res = socket.getaddrinfo(target_host, target_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            log("connect_tcp", f"目标解析失败 {target_host}:{target_port}: {e}")
            return None
        last_err = None
        for fam, stype, pnum, _, taddr in res:
            s = socket.socket(fam, stype, pnum)
            s.settimeout(5.0)
            try:
                s.connect(taddr)
            except OSError as e:
                last_err = e
                try:
                    s.close()
                except OSError:
                    pass
                continue
            s.settimeout(0.5)  # 收循环里靠超时检查 stop_event
            log("connect_tcp", f"✅ TCP 连接建立: {target_host}:{target_port} ({taddr})")
            return s
        log("connect_tcp", f"❌ TCP 连接失败 {target_host}:{target_port}: {last_err}")
        return None

    def ensure_udp_target():
        """UDP 模式懒解析/创建目标 socket；解析不了就返回 None（不崩）"""
        nonlocal udp_target_sock, udp_target_addr
        with target_lock:
            if udp_target_sock is not None:
                return udp_target_sock
            try:
                res = socket.getaddrinfo(target_host, target_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
            except socket.gaierror as e:
                log("ensure_udp_target", f"目标还没解析好 {target_host}:{target_port}: {e}（数据丢弃）")
                return None
            fam, stype, pnum, _, taddr = res[0]
            s = socket.socket(fam, stype, pnum)
            try:
                s.connect(taddr)  # connect 到目标：简化收发 + 内核过滤来源
            except OSError as e:
                log("ensure_udp_target", f"目标 UDP connect 失败 {taddr}: {e}")
                s.close()
                return None
            s.settimeout(0.5)
            udp_target_sock = s
            udp_target_addr = taddr
            log("ensure_udp_target", f"✅ UDP 目标就绪: {target_host}:{target_port} ({taddr})")
            return udp_target_sock

    if proto == 'tcp':
        tcp_sock = connect_tcp()
        if tcp_sock is None:
            stop_event.set()
    else:
        # 先试一次；失败也不退出，收到数据时再重试解析
        ensure_udp_target()

    # ========== udp_listener: 收洞里的包，转发给目标 ==========
    def udp_listener():
        log("udp_listener", "启动")
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(RECV_BUFSIZE)
            except socket.timeout:
                continue
            except OSError as e:
                if not stop_event.is_set():
                    log("udp_listener", f"recvfrom 出错: {e}")
                continue

            # 空数据报 = NAT 保活心跳，不算数据
            if not data:
                log("udp_listener", f"收到空包（保活心跳）from {addr[0]}:{addr[1]}，忽略")
                continue

            known = any(c['ip'] == addr[0] and c['port'] == addr[1] for c in get_candidates())
            if not known:
                log("udp_listener", f"收到非预期来源 {addr[0]}:{addr[1]}（按 peer-reflexive 处理）")
            update_peer(addr)

            stats['recv'] += 1
            stats['recv_bytes'] += len(data)
            log("udp_listener", f"recv data: len={len(data)} hex={hex_dump(data)} from {addr[0]}:{addr[1]}")

            if proto == 'tcp':
                if tcp_sock is None:
                    log("udp_listener", "TCP 未连接，丢弃")
                    continue
                try:
                    tcp_sock.sendall(data)
                except OSError as e:
                    log("udp_listener", f"写入 TCP 失败（目标可能已断开）: {e}")
                    stop_event.set()
                    break
            else:
                tsock = ensure_udp_target()
                if tsock is None:
                    log("udp_listener", "UDP 目标未就绪，丢弃本包")
                    continue
                try:
                    tsock.send(data)
                except OSError as e:
                    log("udp_listener", f"UDP 发往目标失败: {e}")
        log("udp_listener", "结束")

    # ========== target_reader: 收目标回来的数据，发回洞里 ==========
    def target_reader():
        log("target_reader", "启动")
        if proto == 'tcp':
            src = tcp_sock
            if src is None:
                log("target_reader", "TCP 未连接，退出")
                return
            while not stop_event.is_set():
                try:
                    data = src.recv(RECV_BUFSIZE)
                except socket.timeout:
                    continue
                except OSError as e:
                    if not stop_event.is_set():
                        log("target_reader", f"TCP recv 出错: {e}")
                    break
                if not data:
                    log("target_reader", "目标 TCP 已断开 → 退出")
                    stop_event.set()
                    break
                log("target_reader", f"target → hole: len={len(data)} hex={hex_dump(data)}")
                send_to_candidates(data, "target_reader", what='data')
        else:
            while not stop_event.is_set():
                tsock = ensure_udp_target()
                if tsock is None:
                    # 目标还没解析好，歇一会再试
                    stop_event.wait(1.0)
                    continue
                try:
                    data, addr = tsock.recvfrom(RECV_BUFSIZE)
                except socket.timeout:
                    continue
                except OSError as e:
                    if not stop_event.is_set():
                        log("target_reader", f"UDP 目标 recv 出错: {e}")
                    stop_event.wait(0.2)
                    continue
                if udp_target_addr is not None and addr != udp_target_addr:
                    log("target_reader", f"收到非预期来源 {addr}（期望 {udp_target_addr}），忽略")
                    continue
                if not data:
                    continue
                log("target_reader", f"target → hole: len={len(data)} hex={hex_dump(data)} from {addr}")
                send_to_candidates(data, "target_reader", what='data')
        log("target_reader", "结束")
        stop_event.set()

    # ========== keepalive: 每 20s 空包，防止 NAT 映射过期 ==========
    def keepalive_loop():
        log("keepalive_loop", f"启动（每 {KEEPALIVE_INTERVAL:.0f}s 空包保活）")
        while not stop_event.is_set():
            if stop_event.wait(KEEPALIVE_INTERVAL):
                break
            for c in get_candidates():
                try:
                    sock.sendto(b'', (c['ip'], c['port']))
                except OSError as e:
                    log("keepalive_loop", f"保活包发往 {c['ip']}:{c['port']} 失败: {e}")
            log("keepalive_loop", f"已发空包保活（{len(get_candidates())} 个候选）")
        log("keepalive_loop", "结束")

    # ========== 信号处理：优雅退出 ==========
    def _signal_handler(signum, frame):
        log("_signal_handler", f"收到信号 {signum}，准备退出...")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    t_udp = threading.Thread(target=udp_listener, daemon=True, name='udp_listener')
    t_target = threading.Thread(target=target_reader, daemon=True, name='target_reader')
    t_keep = threading.Thread(target=keepalive_loop, daemon=True, name='keepalive_loop')
    t_udp.start()
    t_target.start()
    t_keep.start()

    log("main", f"转发中: 洞 :{actual_port} ↔ {proto} {target_host}:{target_port}（Ctrl-C 退出）")
    stop_event.wait()
    log("main", "开始清理...")

    # 让阻塞在 recv 的线程尽快醒来
    try:
        sock.settimeout(0.2)
    except OSError:
        pass

    for t in [t_udp, t_target, t_keep]:
        t.join(timeout=2.0)

    if tcp_sock is not None:
        try:
            tcp_sock.close()
        except OSError:
            pass
    if udp_target_sock is not None:
        try:
            udp_target_sock.close()
        except OSError:
            pass
    try:
        sock.close()
    except OSError:
        pass
    if _log_fp:
        _log_fp.flush()
        _log_fp.close()
        _log_fp = None
    return 0


if __name__ == '__main__':
    sys.exit(main())
