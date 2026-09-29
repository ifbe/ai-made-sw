#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p2pnet TCP 打洞之后的互发测试（tcptest）

洞由 client.py 的 TCP 打洞打好后，把**内核里那条已经 connected 的 TCP socket**
的 fd 继承过来（父进程 subprocess.Popen(..., pass_fds=(fd,))，fd 号用
--hole-fd 告诉本程序）。本程序**只做互发测试**：
  * 直接用 socket.socket(fileno=args.hole_fd) 包住那个 fd
    —— **绝不再 bind/listen/connect**（那会重新 SYN/ACK，把洞弄坏），
       也不关掉它重建，就当它是一条已经建好的字节流通道
  * 每秒发一个 ping（一行 JSON），收到 pong 算 RTT，
    连续 READY_PONGS 个 pong → 打印「✅ TCP P2P 就绪！」
  * 一段时间收不到对方任何消息 → 认为断了，打日志退出

分帧：TCP 是字节流没有消息边界，所以本程序自己定一个**行分隔帧**：
每条消息一行 JSON + '\n'，和项目别处一致：
  {"type":"ping","seq":N,"ts":<time.time()>}
  {"type":"pong","seq":N,"ts":<time.time()>}

**不挂任何本地设备/端点**：要挂 tun/tap 用 `app/vpn.py`，要转发端口用
`app/proxy.py`，要接虚拟交换机用 `app/switch.py`。每个程序自己解析参数、
自己实现"接管洞"那套（不共用公共模块）。

用法:
  python3 tcptest.py --hole-fd <N> [--peername <名字>] [--remotelog <文件>]
                     [--interval <秒>] [--timeout <秒>] [--ready-count <N>]
"""

import os
import sys
import json
import stat
import time
import errno
import socket
import signal
import argparse
import threading

_TAG = os.path.basename(__file__)   # 'tcptest.py'（日志标签，别写死）
_log_fp = None                      # 日志文件句柄（main() 里赋值）

PING_INTERVAL = 1.0     # 每秒一个 ping
PING_TIMEOUT = 5.0      # 多久没收到对方消息算断开
READY_PONGS = 3         # 连续多少个 pong 算"就绪"
RECV_BUFSIZE = 65535    # 单次 recv 上限（也是行切分缓冲的增长粒度）
IO_TIMEOUT = 0.5        # socket 超时，便于及时响应 stop_event
MAX_LINE = 1024 * 1024  # 一行最长 1MiB，超了认为对方不是本程序


def ts():
    return time.strftime("%H:%M:%S")


def log(func_name, *a):
    msg = ' '.join(str(x) for x in a)
    line = f"[{ts()}][{_TAG} {func_name}]  {msg}"
    if _log_fp:
        _log_fp.write(line + '\n')
        _log_fp.flush()
    else:
        print(line)


def send_msg(sock, obj, func_name):
    """把一条消息按"一行 JSON + \\n"发出去（流式分帧）"""
    line = json.dumps(obj) + '\n'
    try:
        sock.sendall(line.encode('utf-8'))
    except OSError as e:
        log(func_name, f"发送失败（对端可能已断开）: {e}")
        return False
    log(func_name, f"send beat: {json.dumps(obj)}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='p2pnet TCP 打洞之后的互发测试（tcptest，用继承来的已连接 fd）')
    parser.add_argument('--hole-fd', type=int, required=True,
                        help='已建立连接的内核 TCP socket 的 fd 号（父进程用 pass_fds 继承过来）')
    parser.add_argument('--peername', default='', help='对端名字（只用于日志）')
    parser.add_argument('--remotelog', default=None, help='日志文件路径（默认 stdout）')
    parser.add_argument('--interval', type=float, default=PING_INTERVAL, help='心跳间隔秒（默认 1.0）')
    parser.add_argument('--timeout', type=float, default=PING_TIMEOUT, help='多久没收到对方消息算断（默认 5.0）')
    parser.add_argument('--ready-count', type=int, default=READY_PONGS,
                        help='连续收到几个 pong 算就绪（默认 3）')
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error('--interval 必须 > 0')
    if args.timeout <= 0:
        parser.error('--timeout 必须 > 0')
    if args.ready_count <= 0:
        parser.error('--ready-count 必须 > 0')

    global _log_fp
    if args.remotelog:
        try:
            _log_fp = open(args.remotelog, 'a', encoding='utf-8')
        except OSError as e:
            print(f"[{ts()}][{_TAG} main]  打开日志文件失败: {e}", file=sys.stderr)
            _log_fp = None

    # ========== 接管洞：包住继承来的 fd，不 bind/listen/connect ==========
    # 先自己校验 fd：socket.socket(fileno=...) 在部分 Python 上对坏 fd 不报错，
    # 错误会拖到后面才暴露，日志就不清楚了。
    try:
        fd_stat = os.fstat(args.hole_fd)
    except OSError as e:
        log("main", f"❌ --hole-fd {args.hole_fd} 无效：不是本进程已打开的文件描述符 ({e})")
        log("main", "   父进程需要 pass_fds=(fd,) 把已连接的 TCP socket 继承过来")
        if _log_fp:
            _log_fp.flush()
            _log_fp.close()
            _log_fp = None
        return 1
    if not stat.S_ISSOCK(fd_stat.st_mode):
        log("main", f"❌ --hole-fd {args.hole_fd} 无效：不是 socket"
                    f"（st_mode=0o{fd_stat.st_mode:o}）")
        if _log_fp:
            _log_fp.flush()
            _log_fp.close()
            _log_fp = None
        return 1

    try:
        sock = socket.socket(fileno=args.hole_fd)
    except OSError as e:
        log("main", f"❌ --hole-fd {args.hole_fd} 无效，无法接管已连接的 TCP socket: {e}")
        if _log_fp:
            _log_fp.flush()
            _log_fp.close()
            _log_fp = None
        return 1

    try:
        sock.settimeout(IO_TIMEOUT)
    except OSError as e:
        log("main", f"❌ 设置 socket 超时失败（fd {args.hole_fd} 可能不是 socket）: {e}")
        try:
            sock.close()
        except OSError:
            pass
        if _log_fp:
            _log_fp.flush()
            _log_fp.close()
            _log_fp = None
        return 1

    # 收缓冲区：自己按 '\n' 切行（TCP 是字节流，没有消息边界）。
    # 刻意**不用 sock.makefile('rb')**：它底层的 SocketIO 在第一次
    # socket.timeout 之后会记住超时状态（_timeout_occurred），之后每次读都
    # 直接抛 OSError("cannot read from timed out object")，即使数据已经到了——
    # 那样"超时后继续等"的循环就再也读不到东西了。裸 recv() 超时后可以安全重试。
    recv_buf = bytearray()

    def fmt_addr(addr):
        # TCP 的地址是 (ip, port[, flow, scope])；AF_UNIX 之类可能给字符串，别炸
        if isinstance(addr, tuple) and len(addr) >= 2:
            return f"{addr[0]}:{addr[1]}"
        return str(addr)

    try:
        log("main", f"接管洞: fd={args.hole_fd} 本端={fmt_addr(sock.getsockname())} "
                    f"对端={fmt_addr(sock.getpeername())}")
    except (OSError, IndexError, TypeError) as e:
        # 拿不到地址不算致命（比如 fd 是 socketpair / 已连接但信息不可用）
        log("main", f"接管洞: fd={args.hole_fd}（取 socket 地址失败: {e}）")
    log("main", f"对端名字: {args.peername or '(未指定)'}")
    log("main", f"心跳间隔 {args.interval}s，超时 {args.timeout}s，就绪需 {args.ready_count} 个 pong")

    stop_event = threading.Event()
    state = {
        'seq': 0,
        'sent_pings': {},        # seq -> 发送时刻
        'sent_order': [],        # 发送顺序，用来清理旧条目
        'pingsent': 0,
        'pongrecv': 0,
        'pong_streak': 0,
        'confirmed': False,
        'bad_lines': 0,
        'rtts': [],
        'last_msg_time': time.time(),
        'reason': '',            # 退出原因（函数名 + 消息）
    }

    def rtt_avg_ms():
        if not state['rtts']:
            return 0.0
        return sum(state['rtts']) / len(state['rtts']) * 1000.0

    def handle_line(line):
        """处理对方发来的一整行（已去掉行尾 \\n）"""
        try:
            text = line.decode('utf-8')
        except UnicodeDecodeError:
            state['bad_lines'] += 1
            log("handle_line", f"忽略非法 UTF-8 行（{len(line)}B，累计 {state['bad_lines']} 行）")
            return
        try:
            msg = json.loads(text)
        except ValueError:
            state['bad_lines'] += 1
            log("handle_line", f"忽略非法 JSON 行（累计 {state['bad_lines']} 行）: {text[:120]!r}")
            return
        if not isinstance(msg, dict):
            state['bad_lines'] += 1
            log("handle_line", f"忽略非对象 JSON（累计 {state['bad_lines']} 行）: {text[:120]!r}")
            return

        state['last_msg_time'] = time.time()
        t = msg.get('type', '')
        s = msg.get('seq', -1)
        log("handle_line", f"recv beat: {json.dumps(msg)}")

        if t == 'ping':
            # 对方 ping 我，立刻回 pong（seq/ts 原样带回，和 udptest 一致）
            pong = {'type': 'pong', 'seq': s, 'ts': msg.get('ts')}
            send_msg(sock, pong, "handle_line")
        elif t == 'pong':
            if s in state['sent_pings']:
                rtt = time.time() - state['sent_pings'].pop(s)
                state['pongrecv'] += 1
                state['pong_streak'] += 1
                state['rtts'].append(rtt)
            else:
                rtt = 0.0     # 重复的 pong / 不在发送窗口内
            log("handle_line",
                f"  RTT={rtt * 1000:.0f}ms streak={state['pong_streak']} "
                f"ping={state['pingsent']} pong={state['pongrecv']}")
            if not state['confirmed'] and state['pong_streak'] >= args.ready_count:
                state['confirmed'] = True
                log("handle_line", "✅ TCP P2P 就绪！")
        else:
            log("handle_line", f"未知消息类型 {t!r}，忽略")

    def tcp_listener():
        """收循环：裸 recv() 读字节流，自己按 '\n' 切成一条条消息（行分隔帧）"""
        log("tcp_listener", "启动")
        while not stop_event.is_set():
            try:
                chunk = sock.recv(RECV_BUFSIZE)
            except socket.timeout:
                # 超时没有数据：检查对方是不是哑了（超时后可以安全地继续 recv）
                elapsed = time.time() - state['last_msg_time']
                if elapsed > args.timeout:
                    if state['confirmed']:
                        state['reason'] = ('tcp_listener',
                                           f"⚠️  {elapsed:.1f}s 没收到对方任何消息，断开")
                    else:
                        state['reason'] = ('tcp_listener',
                                           f"⚠️  {elapsed:.1f}s 没收到对方任何消息，"
                                           f"仍未就绪，放弃")
                    break
                continue
            except OSError as e:
                if e.errno in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                    # 对方直接 RST 了（关连接时还有没读完的数据，内核就会发 RST）
                    state['reason'] = ('tcp_listener', f"对端断开连接（连接被重置: {e}），退出")
                elif not stop_event.is_set():
                    state['reason'] = ('tcp_listener', f"recv 出错: {e}")
                break

            if not chunk:
                if not stop_event.is_set():
                    # stop_event 已置位说明是我们自己在收尾，别误报"对端关了"
                    state['reason'] = ('tcp_listener', "对端关闭连接（recv 返回空），退出")
                break

            recv_buf.extend(chunk)
            # 缓冲区里可能一次到了好几行，也可能只有半行；按 '\n' 全部切出来
            while True:
                idx = recv_buf.find(b'\n')
                if idx < 0:
                    if len(recv_buf) > MAX_LINE:
                        # 一行超过上限还没换行：对方不是本程序，别把内存吃光
                        state['bad_lines'] += 1
                        log("tcp_listener",
                            f"⚠️  单行超过 {MAX_LINE}B 仍无换行，丢弃该行"
                            f"（累计 {state['bad_lines']} 行）")
                        del recv_buf[:]
                    break
                line = bytes(recv_buf[:idx])
                del recv_buf[:idx + 1]
                if not line.strip(b'\r'):
                    continue
                handle_line(line.rstrip(b'\r'))

        stop_event.set()
        log("tcp_listener", "结束")

    def _signal_handler(signum, frame):
        log("main", f"收到信号 {signum}，准备退出...")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    t_tcp = threading.Thread(target=tcp_listener, daemon=True, name='tcp_listener')
    t_tcp.start()

    # ========== 主线程：每 interval 秒发一个 ping ==========
    log("main", "主循环开始，等待 TCP P2P 就绪...")
    while not stop_event.is_set():
        now = time.time()
        ping = {'type': 'ping', 'seq': state['seq'], 'ts': now}
        if send_msg(sock, ping, "main"):
            state['sent_pings'][state['seq']] = now
            state['sent_order'].append(state['seq'])
            state['pingsent'] += 1
        state['seq'] += 1
        while len(state['sent_order']) > 100:
            state['sent_pings'].pop(state['sent_order'].pop(0), None)
        # 分片睡眠，信号/断开能及时响应
        deadline = time.time() + args.interval
        while not stop_event.is_set() and time.time() < deadline:
            time.sleep(min(0.1, max(0.0, deadline - time.time())))

    log("main", "开始清理...")
    stop_event.set()

    # 先缩短超时：让阻塞在 recv 的读线程尽快醒来（最短 0.2s 内）
    try:
        sock.settimeout(0.2)
    except OSError:
        pass
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    t_tcp.join(timeout=2.0)

    # 退出原因（读线程里记的，比如对端关连接/超时）在读线程收尾后打出来
    if state['reason']:
        log(state['reason'][0], state['reason'][1])

    # ========== 统计 ==========
    log("main",
        f"统计: 发送 ping={state['pingsent']} 收到 pong={state['pongrecv']} "
        f"未就绪={'是' if not state['confirmed'] else '否'} "
        f"非法行={state['bad_lines']} 平均 RTT={rtt_avg_ms():.1f}ms")

    try:
        sock.close()
    except OSError:
        pass
    if _log_fp:
        _log_fp.flush()
        _log_fp.close()
        _log_fp = None
    log("main", "进程退出")
    return 0


if __name__ == '__main__':
    sys.exit(main())
