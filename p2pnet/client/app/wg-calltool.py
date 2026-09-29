#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""app/wg-calltool.py - 调系统 wg 工具的 WireGuard（内核版）

和 `app/wg-python.py` 是同一件事的两种做法：
  * `wg-python.py`  ：自己跑 WireGuard 协议（用户态，Noise + ChaCha20-Poly1305），
                     **不需要 root、不需要内核模块、不需要 wireguard-tools**
  * `wg-calltool.py`：调系统的 `wg` / `ip` 命令，用**内核**的 wireguard 模块，
                     需要 **root + wireguard-tools + 内核模块**

本程序自己不碰加密、不碰数据面，只做三件事：
  1. 从 client.py 接过一条打好的洞（本地端口 + 对端公网 地址:端口）
  2. 把参数拼给 `app/wghelp.sh`（真正执行 `ip link add type wireguard` / `wg set` 的地方）
     —— 关键是 --listen-port：内核 WG 必须 listen 在**打洞时那个本地端口**上，
        已经建立的 NAT 映射才不废
  3. 起一个守护循环：定期检查接口还在不在，掉了就报错退出（洞也就没了）

对方公钥 / 双方 mesh IP / 我的私钥这些，服务端（还没实现 thisisyourpeer_wg）拿不到，
只能命令行给。

用法:
  python3 wg-calltool.py --localport <洞的本端端口> \\
        --peeraddr <对端公网IP> --peerport <对端端口> \\
        --my-privkey <base64> --my-ip <我的meshIP> \\
        --peer-pubkey <base64> --peer-ip <对方meshIP> \\
        [--iface wghelp0] [--keepalive 25] [--check-interval 30] [--dry-run]

  --dry-run：只把要执行的命令打出来（不真的跑 sudo / wg），方便在没有 root、
             没装 wireguard-tools 的机器上检查参数拼得对不对。
"""

import os
import sys
import time
import signal
import argparse
import subprocess

_TAG = os.path.basename(__file__)          # 'wg-calltool.py'
_log_fp = None

# wghelp.sh 在同一个目录（app/）里
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
WGHELP_SH = os.path.join(_APP_DIR, 'wghelp.sh')

CHECK_INTERVAL = 30.0      # 多久检查一次接口还在不在


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


def build_wghelp_cmd(args, endpoint):
    """拼出 wghelp.sh 的命令行（单独抽出来，方便 --dry-run 和测试）

    wghelp.sh: <我的私钥> <我的mesh IP> <对方公钥> <对方mesh IP>
               <对方公网地址:端口> [接口名] [监听端口] [keepalive]
    （用位置参数而不是环境变量：sudo 默认 env_reset 会把环境变量吃掉）
    """
    return ['sudo', 'bash', WGHELP_SH,
            args.my_privkey, args.my_ip, args.peer_pubkey, args.peer_ip,
            endpoint, args.iface,
            str(args.localport),             # 洞的本端端口 → 内核 WG 的 listen-port
            str(args.keepalive)]


def iface_exists(iface):
    """接口还在不在（没有 ip 命令就返回 None = 不知道）"""
    try:
        r = subprocess.run(['ip', 'link', 'show', iface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return r.returncode == 0
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description='用系统 wg 工具配置内核 WireGuard（调 wghelp.sh）')
    # ---- 洞的参数（client.py 移交时给的，和别的使用者程序一样）----
    parser.add_argument('--localport', type=int, required=True,
                        help='洞的本端 UDP 端口（内核 WG 会 listen 这个端口，复用打的洞）')
    parser.add_argument('--peeraddr', required=True, help='对端公网地址（洞打通时那个）')
    parser.add_argument('--peerport', type=int, required=True, help='对端端口')
    parser.add_argument('--peercandidates', default=None,
                        help='额外对端候选（内核 WG 只认一个 endpoint，这里只作日志参考）')
    parser.add_argument('--localaddr', default='0.0.0.0', help='本端地址（仅日志参考）')
    # ---- WireGuard 自己的参数（服务端拿不到，只能命令行给）----
    parser.add_argument('--my-privkey', required=True, help='本端私钥（base64）')
    parser.add_argument('--my-ip', required=True, help='本端 mesh IP（如 192.168.250.2）')
    parser.add_argument('--peer-pubkey', required=True, help='对端公钥（base64）')
    parser.add_argument('--peer-ip', required=True, help='对端 mesh IP（如 192.168.250.3）')
    parser.add_argument('--iface', default='wghelp0', help='WireGuard 接口名（默认 wghelp0）')
    parser.add_argument('--keepalive', type=int, default=25,
                        help='persistent-keepalive 秒数（默认 25，顺便维持 NAT 映射）')
    parser.add_argument('--check-interval', type=float, default=CHECK_INTERVAL,
                        help='多久检查一次接口（默认 30s）')
    parser.add_argument('--dry-run', action='store_true',
                        help='只打印要执行的命令，不真的跑（无 root / 没装 wg 时用来检查参数）')
    parser.add_argument('--remotelog', default=None, help='日志文件路径（默认 stdout）')
    args = parser.parse_args()

    global _log_fp
    if args.remotelog:
        _log_fp = open(args.remotelog, 'a', encoding='utf-8')

    endpoint = f"{args.peeraddr}:{args.peerport}"
    log("main", f"洞: 本端端口 {args.localport}（内核 WG 会 listen 它）↔ 对端 {endpoint}")
    log("main", f"mesh: 本端 {args.my_ip} ↔ 对端 {args.peer_ip}，接口 {args.iface}")
    if args.peercandidates:
        log("main", f"额外候选（内核 WG 不认多个 endpoint，只留日志）: {args.peercandidates}")

    if not os.path.exists(WGHELP_SH):
        log("main", f"❌ 找不到 {WGHELP_SH}")
        return 1

    cmd = build_wghelp_cmd(args, endpoint)
    # 日志里别把私钥打出来
    safe = list(cmd)
    for i, v in enumerate(safe):
        if v == args.my_privkey:
            safe[i] = '<my-privkey>'
    log("main", "将执行: " + ' '.join(safe))

    if args.dry_run:
        log("main", "（--dry-run，不真的执行）")
        return 0

    # ---- 真正跑 wghelp.sh ----
    try:
        p = subprocess.run(cmd, cwd=_APP_DIR, timeout=60)
    except FileNotFoundError as e:
        log("main", f"❌ 执行失败（sudo/bash 不在？）: {e}")
        return 1
    except subprocess.TimeoutExpired:
        log("main", "❌ wghelp.sh 超时（60s）")
        return 1
    if p.returncode != 0:
        log("main", f"❌ wghelp.sh 退出码 {p.returncode}"
                    + ("（八成是没 root / 没装 wireguard-tools / 没内核模块）"
                       if p.returncode in (1, 127) else ""))
        return p.returncode

    log("main", f"✅ 内核 WireGuard 已配置（接口 {args.iface}，listen-port {args.localport}）")
    log("main", f"   对端 endpoint {endpoint}，persistent-keepalive {args.keepalive}s 会自动维持 NAT 映射")

    # ---- 守护：接口掉了就退出（洞也就没了）----
    stop = {'v': False}

    def _on_signal(signum, frame):
        log("main", f"收到信号 {signum}，准备退出...")
        stop['v'] = True

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    while not stop['v']:
        time.sleep(0.5)
        # 用 Event 那种做法要额外线程，这里简单起见分段睡
        elapsed = 0.0
        while elapsed < args.check_interval and not stop['v']:
            time.sleep(0.5)
            elapsed += 0.5
        if stop['v']:
            break
        exists = iface_exists(args.iface)
        if exists is False:
            log("main", f"⚠️  接口 {args.iface} 不见了（wg-quick down？），退出")
            break
        log("main", f"接口 {args.iface} 还在（listen-port {args.localport}）")

    log("main", "退出（接口/peer 没动，要清理请: sudo wg-quick down %s 或 "
                "sudo ip link del %s）" % (args.iface, args.iface))
    if _log_fp:
        _log_fp.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
