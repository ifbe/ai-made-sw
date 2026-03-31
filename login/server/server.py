#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logintest 服务器 - 最小实现
仅包含: 登录/登出记录 + list 命令
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

# 导入密码管理（复用 secret.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret import PasswordManager

# WebSocket 握手用的魔数
WS_MAGIC = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

# 在线用户: username -> {conn, token, ip, port}
online_users = {}

# 挑战码: username -> {challenge, timestamp}
challenges = {}

# 密码管理器
pm = PasswordManager('passwd.json')

# 配置
HOST = '0.0.0.0'
PORT = 9999

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
    """
    解码 WebSocket 帧，返回 (frame_dict, left_data) 或 (None, data) 表示数据不够
    frame_dict: {'opcode': int, 'payload': bytes}
    """
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
    """编码 WebSocket 文本帧"""
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


# ==================== WebSocket 连接封装 ====================

class WSConn:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.username = None   # 登录前为 None
        self.handshake_done = False  # WebSocket 握手是否完成
        self.ip = addr[0]      # 对方 IP
        self.port = addr[1]    # 对方 port
        self.buffer = b''

    def send_text(self, msg):
        try:
            self.sock.send(ws_encode(msg.encode('utf-8')))
        except Exception as e:
            print(f"[发送失败] {self.addr}: {e}")

    def close(self):
        try:
            self.sock.close()
        except:
            pass


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
    """发送静态文件"""
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
    """处理普通 HTTP 请求，直接返回静态文件"""
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
    ws.send_text(json.dumps({'type': 'error', 'message': msg}))


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

    # ---- login ----
    if msg_type == 'login':
        handle_login(ws, msg)

    # ---- list ----
    elif msg_type == 'list':
        handle_list(ws, msg)

    # ---- logout ----
    elif msg_type == 'logout':
        handle_logout(ws)

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
        ws.send_text(json.dumps({
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
            v['ws'].send_text(json.dumps({'type': 'kicked', 'message': 're-login from another connection'}))
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
        'login_time': time.time(),
    }
    ws.username = username

    print(f"[登录] {username} 从 {ws.ip}:{ws.port}，当前在线 {len(online_users)} 人")

    ws.send_text(json.dumps({
        'type': 'login_ok',
        'username': username,
        'token': token,
    }))

    # 广播用户加入
    broadcast({'type': 'user_joined', 'username': username, 'ip': ws.ip}, exclude=username)


def handle_list(ws, msg):
    # 服务器通过 WebSocket 连接本身知道是谁发的
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
        })

    ws.send_text(json.dumps({
        'type': 'list_result',
        'users': users,
    }))


def handle_logout(ws):
    if ws.username and ws.username in online_users:
        del online_users[ws.username]
        print(f"[登出] {ws.username}，当前在线 {len(online_users)} 人")
        broadcast({'type': 'user_left', 'username': ws.username}, exclude=ws.username)
    ws.username = None
    ws.send_text(json.dumps({'type': 'logout_ok'}))


def broadcast(msg, exclude=None):
    """广播消息给所有已登录用户"""
    data = json.dumps(msg).encode('utf-8')
    for info in online_users.values():
        if info['username'] != exclude:
            info['ws'].send_text(json.dumps(msg))


def on_disconnect(ws):
    """连接断开时调用"""
    if ws.username and ws.username in online_users:
        del online_users[ws.username]
        print(f"[断开] {ws.username}，当前在线 {len(online_users)} 人")
        broadcast({'type': 'user_left', 'username': ws.username})


# ==================== 主循环 ====================

def main():
    # 确保 static 目录存在
    if not os.path.exists('static'):
        os.makedirs('static')
        print("注意: static 目录已创建，需要放入 index.html")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    server.setblocking(False)

    print(f"logintest 服务器启动 {HOST}:{PORT}")

    connections = [server]
    ws_conns = {}  # sock -> WSConn

    while True:
        readable, _, _ = select.select(connections, [], [], 1.0)

        for sock in readable:
            if sock is server:
                # 新连接
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

                # 尚未完成握手，判断是 HTTP 还是 WebSocket
                if not ws.handshake_done:
                    if b'\r\n\r\n' in ws.buffer:
                        # 完整 HTTP 头已收齐
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
                            # 普通 HTTP 请求
                            handle_http(sock, ws.buffer)
                            connections.remove(sock)
                            del ws_conns[sock]
                            sock.close()
                    # 数据不完整，等更多
                    continue

                # WebSocket 帧处理（已完成握手）
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
