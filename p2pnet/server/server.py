#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet 服务器 - 最小实现
支持: 登录/登出记录 + list 命令 + P2P UDP 打洞协调
"""

import os
import sys
import json
import time
import secrets
import hashlib
import hmac
import base64
import struct
import socket
import select
import argparse
import threading

# 导入密码管理（复用 secret.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret import PasswordManager

# WebSocket 握手用的魔数
WS_MAGIC = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

# 在线用户: username -> {conn, token, ip, port, udp_port}
online_users = {}

# 挑战码: username -> {challenge, timestamp}
challenges = {}

# 密码管理器
pm = PasswordManager('passwd.json')

# 配置
HOST = '0.0.0.0'
PORT = 9999
UDP_PORT = 9999
DEBUG = False

# P2P 请求: username -> {target, timestamp}
p2p_requests = {}

# 线程安全的 UDP 地址记录: username -> (ip, port, timestamp)
udp_addrs = {}

# UDP socket 用于接收 P2P 客户端的注册包
udp_sock = None
udp_sock_port = None

# ==================== 命令行参数 ====================

def parse_args():
    global HOST, PORT, UDP_PORT, DEBUG
    parser = argparse.ArgumentParser(description='p2pnet 服务器')
    parser.add_argument('--host', default='0.0.0.0', help='监听地址')
    parser.add_argument('--port', type=int, default=9999, help='TCP 端口')
    parser.add_argument('--udpport', type=int, default=None, help='UDP P2P 端口（默认同 port）')
    parser.add_argument('--debug', action='store_true', help='打印所有 WebSocket 消息')
    args = parser.parse_args()
    HOST = args.host
    PORT = args.port
    UDP_PORT = args.udpport if args.udpport else args.port
    DEBUG = args.debug

# ==================== WebSocket 编解码 ====================

def ws_handshake(sock, headers):
    """WebSocket 握手，成功返回 True"""
    key = None
    for h in headers:
        if h.lower().startswith('sec-websocket-key:'):
            key = h.split(':', 1)[1].strip()
            break
    if not key:
        return False

    accept = base64.b64encode(
        hashlib.sha1((key + WS_MAGIC.decode()).encode()).digest()
    ).decode()

    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    sock.send(resp.encode())
    return True


def ws_decode(data):
    if len(data) < 2:
        return None, data
    first, second = data[0], data[1]
    opcode = first & 0x0F
    masked = (second & 0x80) >> 7
    length = second & 0x7F
    offset = 2
    if length == 126:
        if len(data) < 4:
            return None, data
        length = struct.unpack('>H', data[2:4])[0]
        offset = 4
    elif length == 127:
        if len(data) < 10:
            return None, data
        length = struct.unpack('>Q', data[2:10])[0]
        offset = 10
    if masked:
        if len(data) < offset + 4:
            return None, data
        mask = data[offset:offset+4]
        offset += 4
    if len(data) < offset + length:
        return None, data
    payload = data[offset:offset+length]
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return {'opcode': opcode, 'payload': payload}, data[offset+length:]


def ws_encode(payload, opcode=0x1):
    data = bytearray()
    data.append(0x80 | (opcode & 0x0F))
    n = len(payload)
    if n < 126:
        data.append(n)
    elif n < 65536:
        data.append(126)
        data.extend(struct.pack('>H', n))
    else:
        data.append(127)
        data.extend(struct.pack('>Q', n))
    data.extend(payload)
    return bytes(data)


def ws_send(ws, text):
    """发送 WebSocket 文本帧"""
    if DEBUG:
        print(f"[WS] {ws.addr} <- {text}")
    frame = ws_encode(text.encode('utf-8'))
    ws.sock.send(frame)


# ==================== WebSocket 连接封装 ====================

class WSConn:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.username = None
        self.handshake_done = False
        self.ip = addr[0]
        self.port = addr[1]
        self.buffer = b''


# ==================== HTTP 部分 ====================

def guess_content_type(path):
    if path.endswith('.html'):
        return 'text/html'
    elif path.endswith('.css'):
        return 'text/css'
    elif path.endswith('.js'):
        return 'application/javascript'
    elif path.endswith('.png'):
        return 'image/png'
    elif path.endswith('.ico'):
        return 'image/x-icon'
    return 'text/plain'


def serve_file(sock, filepath):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        ct = guess_content_type(filepath)
        resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: {ct}\r\n"
            f"Content-Length: {len(content)}\r\n"
            "\r\n"
        ).encode('utf-8') + content
        sock.send(resp)
    except FileNotFoundError:
        body = b"404 Not Found"
        sock.send(
            f"HTTP/1.1 404 Not Found\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n".encode('utf-8') + body
        )


def handle_http(sock, data):
    try:
        lines = data.decode('utf-8', errors='ignore').split('\r\n')
        if not lines:
            return
        parts = lines[0].split(' ')
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1]
        if method == 'GET':
            if path == '/':
                serve_file(sock, 'static/index.html')
            else:
                serve_file(sock, 'static' + path)
        else:
            body = b"Method Not Allowed"
            sock.send(
                f"HTTP/1.1 405 Method Not Allowed\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n".encode('utf-8') + body
            )
    except Exception as e:
        print(f"[HTTP错误] {e}")


# ==================== 业务逻辑 ====================

def send_error(ws, msg):
    ws_send(ws, json.dumps({'type': 'error', 'message': msg}))


def handle_message(ws, raw):
    """处理 WebSocket 消息"""
    try:
        msg = json.loads(raw)
    except:
        send_error(ws, "invalid json")
        return

    if not isinstance(msg, dict):
        send_error(ws, "invalid json type")
        return

    msg_type = msg.get('type')

    if DEBUG:
        print(f"[WS] {ws.addr} -> {msg}")

    if msg_type == 'login':
        handle_login(ws, msg)
    elif msg_type == 'list':
        handle_list(ws, msg)
    elif msg_type == 'logout':
        handle_logout(ws)
    elif msg_type == 'p2pudp':
        handle_p2pudp(ws, msg)
    else:
        send_error(ws, f"unknown type: {msg_type}")


def handle_login(ws, msg):
    username = msg.get('username', '').strip()
    response = msg.get('response', '')

    # 情况1: 没有用户名
    if not username:
        send_error(ws, "who are you?")
        return

    # 查用户
    if username not in pm.users:
        send_error(ws, "user not found")
        return

    stored_hash = pm.users[username]['hash']
    salt, pw_hash = stored_hash.split(':', 1)

    # 情况2: 只有 username，发 challenge
    if not response:
        chal = secrets.token_hex(32)
        challenges[username] = {'challenge': chal, 'timestamp': time.time()}
        ws_send(ws, json.dumps({
            'type': 'challenge',
            'challenge': chal,
            'salt': salt,
        }))
        return

    # 情况3: 有 response，验证
    if username not in challenges:
        send_error(ws, "no challenge for user")
        return
    chal = challenges[username]
    if time.time() - chal['timestamp'] > 300:
        del challenges[username]
        send_error(ws, "challenge expired")
        return
    import binascii
    expected = hmac.new(
        binascii.unhexlify(pw_hash),
        binascii.unhexlify(chal['challenge']),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, response):
        send_error(ws, "auth failed")
        return
    del challenges[username]

    # 踢掉之前的同账号连接
    kicked = []
    for k, v in list(online_users.items()):
        if v['username'] == username:
            ws_send(v['ws'], json.dumps({'type': 'kicked', 'message': 're-login from another connection'}))
            v['ws'].username = None
            kicked.append(k)
    for k in kicked:
        del online_users[k]

    # 记录上线
    token = secrets.token_hex(16)
    online_users[username] = {
        'username': username,
        'ws': ws,
        'token': token,
        'ip': ws.ip,
        'port': ws.port,
        'udp_port': None,
        'login_time': time.time(),
    }
    ws.username = username

    print(f"[登录] {username} 从 {ws.ip}:{ws.port}，当前在线 {len(online_users)} 人")

    ws_send(ws, json.dumps({
        'type': 'login_ok',
        'username': username,
    }))

    broadcast({'type': 'user_joined', 'username': username, 'ip': ws.ip}, exclude=username)


def handle_list(ws, msg):
    username = ws.username
    if not username or username not in online_users:
        send_error(ws, "not logged in")
        return

    users = []
    for u, info in online_users.items():
        users.append({
            'username': u,
            'ip': info['ip'],
            'port': info['port'],
            'udp_port': info.get('udp_port'),
        })

    ws_send(ws, json.dumps({
        'type': 'list_result',
        'users': users,
    }))


def handle_logout(ws):
    if ws.username and ws.username in online_users:
        del online_users[ws.username]
        print(f"[登出] {ws.username}，当前在线 {len(online_users)} 人")
        broadcast({'type': 'user_left', 'username': ws.username})
    ws.username = None
    ws_send(ws, json.dumps({'type': 'logout_ok'}))


def handle_p2pudp(ws, msg):
    """处理 p2pudp 请求：直接同时告诉两边发 UDP hello 到服务器"""
    username = ws.username
    if not username or username not in online_users:
        send_error(ws, "not logged in")
        return

    target = msg.get('target', '').strip()
    if not target:
        send_error(ws, "target required")
        return
    if target not in online_users:
        send_error(ws, "user not found")
        return
    if target == username:
        send_error(ws, "cannot connect to yourself")
        return

    target_info = online_users[target]

    # 记录 P2P 请求（UDP 线程靠这个知道谁在等谁的 hello）
    p2p_requests[username] = {'target': target, 'timestamp': time.time()}

    # 同时告诉两边往服务器 UDP 端口发 hello
    ws_send(ws, json.dumps({
        'type': 'send_udp_to_server',
        'udpport': UDP_PORT,
    }))
    ws_send(target_info['ws'], json.dumps({
        'type': 'send_udp_to_server',
        'udpport': UDP_PORT,
    }))
    print(f"[P2P] {username} <-> {target}，已通知双方发 UDP hello 到服务器")


def broadcast(msg, exclude=None):
    data = json.dumps(msg).encode('utf-8')
    for info in online_users.values():
        if info['username'] != exclude:
            ws_send(info['ws'], json.dumps(msg))


def on_disconnect(ws):
    if ws.username and ws.username in online_users:
        del online_users[ws.username]
        print(f"[断开] {ws.username}，当前在线 {len(online_users)} 人")
        broadcast({'type': 'user_left', 'username': ws.username})


# ==================== UDP 服务器线程 ====================

def udp_server_thread(port):
    """接收客户端的 UDP 注册/打洞包，记录公网地址"""
    global udp_addrs
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(1.0)
    print(f"[UDP] P2P UDP 服务器监听 {port}/UDP")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[UDP] recvfrom 错误: {e}")
            continue

        try:
            msg = json.loads(data.decode('utf-8'))
        except:
            # 非 JSON 包（可能是打洞包），忽略
            continue

        msg_type = msg.get('type')

        # UDP 包内容: {"type": "p2pudp_hello", "username": "alice"}
        if msg_type == 'p2pudp_hello':
            username = msg.get('username', '').strip()
            if username not in online_users:
                continue

            # 记录/更新这个用户的 UDP 公网地址
            udp_addrs[username] = {
                'ip': addr[0],
                'port': addr[1],
                'timestamp': time.time(),
            }
            online_users[username]['udp_port'] = addr[1]
            print(f"[UDP] {username} UDP 来自: {addr[0]}:{addr[1]}")

            # 检查是否有待处理的 P2P 请求
            pending = p2p_requests.get(username)
            if not pending:
                continue

            target = pending.get('target', '')
            if target not in udp_addrs:
                # 对方还没发 UDP 包
                continue

            # 双方 UDP 地址都已就绪
            my_addr = udp_addrs[username]
            peer_addr = udp_addrs[target]

            # 发给发起方
            ws_a = online_users[username]['ws']
            ws_send(ws_a, json.dumps({
                'type': 'thisisyourpeer_udp',
                'name': target,
                'ip': peer_addr['ip'],
                'port': peer_addr['port'],
            }))

            # 发给目标方
            ws_b = online_users[target]['ws']
            ws_send(ws_b, json.dumps({
                'type': 'thisisyourpeer_udp',
                'name': username,
                'ip': my_addr['ip'],
                'port': my_addr['port'],
            }))

            # 清除请求记录
            if username in p2p_requests:
                del p2p_requests[username]
            if target in p2p_requests:
                del p2p_requests[target]

            print(f"[P2P] {username} <-> {target} 双向请求就绪，已通知双方打洞")


def start_udp_server(port):
    t = threading.Thread(target=udp_server_thread, args=(port,), daemon=True)
    t.start()


# ==================== 主循环 ====================

def main():
    global HOST, PORT, UDP_PORT

    parse_args()

    # 确保 static 目录存在
    if not os.path.exists('static'):
        os.makedirs('static')
        print("注意: static 目录已创建，需要放入 index.html")

    # 启动 UDP 服务器
    start_udp_server(UDP_PORT)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    server.setblocking(False)

    print(f"p2pnet 服务器启动 {HOST}:{PORT}，UDP {UDP_PORT}/UDP")

    connections = [server]
    ws_conns = {}  # sock -> WSConn

    while True:
        readable, _, _ = select.select(connections, [], [], 1.0)

        for sock in readable:
            if sock is server:
                client, addr = server.accept()
                client.setblocking(False)
                connections.append(client)
                ws_conns[client] = WSConn(client, addr)
                print(f"[连接] {addr}")
            else:
                ws = ws_conns.get(sock)
                if not ws:
                    continue

                try:
                    data = sock.recv(4096)
                except:
                    data = b''

                if not data:
                    on_disconnect(ws)
                    connections.remove(sock)
                    del ws_conns[sock]
                    try:
                        sock.close()
                    except:
                        pass
                    continue

                ws.buffer += data

                if not ws.handshake_done:
                    if b'\r\n\r\n' in ws.buffer:
                        header_str = ws.buffer.decode('utf-8', errors='ignore')
                        if 'Upgrade: websocket' in header_str:
                            headers = header_str.split('\r\n')
                            if ws_handshake(sock, headers):
                                ws.handshake_done = True
                                ws.buffer = b''
                                print(f"[WS握手完成] {ws.addr}")
                            else:
                                sock.close()
                        else:
                            handle_http(sock, ws.buffer)
                            connections.remove(sock)
                            del ws_conns[sock]
                            sock.close()
                    continue

                while ws.buffer:
                    frame, ws.buffer = ws_decode(ws.buffer)
                    if frame is None:
                        break

                    if frame['opcode'] == 0x8:
                        on_disconnect(ws)
                        connections.remove(sock)
                        del ws_conns[sock]
                        try:
                            sock.close()
                        except:
                            pass
                        break
                    elif frame['opcode'] == 0x1:
                        handle_message(ws, frame['payload'].decode('utf-8'))

    server.close()


if __name__ == '__main__':
    main()
