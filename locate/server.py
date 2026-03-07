#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import argparse
import secrets
import hashlib
import hmac
import logging
import socket
import threading
import base64
import struct
import select
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs
from secret import PasswordManager

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger(__name__)

# WebSocket 魔术字符串
WEBSOCKET_MAGIC = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

# 全局配置
CONFIG = {
    'passwd_file': 'passwd.json',
    'host': '0.0.0.0',
    'port': 9999,
    'debug': False
}

# 在线用户存储
online_users = {}  # username -> {conn, lat, lng, heading, last_update, nickname, token}
token_to_username = {}  # token -> username

# 挑战码存储
challenges = {}  # username -> {challenge, timestamp}

# 密码管理器
passwd_mgr = None

# 配置常量
CHALLENGE_TIMEOUT = 300  # 5分钟
TOKEN_TIMEOUT = 86400  # 24小时

class AuthManager:
    @staticmethod
    def generate_challenge(username):
        challenge = secrets.token_hex(32)
        challenges[username] = {
            'challenge': challenge,
            'timestamp': time.time()
        }
        logger.info(f"生成挑战码: username={username}, challenge={challenge[:16]}...")
        return challenge
    
    @staticmethod
    def verify_challenge(username, response):
        if username not in challenges:
            logger.warning(f"验证失败: 挑战码不存在, username={username}")
            return False, "挑战码不存在", None
        
        challenge_data = challenges[username]
        
        if time.time() - challenge_data['timestamp'] > CHALLENGE_TIMEOUT:
            del challenges[username]
            logger.warning(f"验证失败: 挑战码已过期, username={username}")
            return False, "挑战码已过期", None
        
        if username not in passwd_mgr.users:
            logger.warning(f"验证失败: 用户不存在, username={username}")
            return False, "用户不存在", None
        
        stored_hash = passwd_mgr.users[username]['hash']
        
        logger.debug(f"存储的哈希: {stored_hash}")
        logger.debug(f"收到的响应: {response[:32]}...")
        
        try:
            if ':' in stored_hash:
                salt, password_hash = stored_hash.split(':', 1)
                logger.debug(f"提取的盐值: {salt}")
                logger.debug(f"提取的密码哈希: {password_hash[:32]}...")
            else:
                logger.error(f"哈希格式错误: {stored_hash}")
                return False, "密码哈希格式错误", None
        except Exception as e:
            logger.error(f"解析哈希错误: {e}")
            return False, "密码解析错误", None
        
        expected_response = hmac.new(
            password_hash.encode('utf-8'),
            challenge_data['challenge'].encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        logger.debug(f"期望的响应: {expected_response[:32]}...")
        logger.debug(f"收到的响应: {response[:32]}...")
        
        if hmac.compare_digest(expected_response, response):
            del challenges[username]
            session_token = secrets.token_hex(32)
            logger.info(f"✅ 验证成功: username={username}")
            return True, "认证成功", session_token
        
        logger.warning(f"❌ 验证失败: 响应不匹配, username={username}")
        logger.debug(f"完整期望: {expected_response}")
        logger.debug(f"完整收到: {response}")
        return False, "认证失败", None

auth_manager = AuthManager()

# WebSocket 工具函数
def websocket_handshake(client_socket, headers):
    """WebSocket 握手"""
    key = None
    for header in headers:
        if header.startswith('Sec-WebSocket-Key:'):
            key = header.split(':')[1].strip()
            break
    
    if not key:
        return False
    
    accept_key = base64.b64encode(hashlib.sha1((key + WEBSOCKET_MAGIC.decode()).encode()).digest()).decode()
    
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )
    client_socket.send(response.encode())
    return True

def websocket_decode_frame(data):
    """解码 WebSocket 帧"""
    if len(data) < 2:
        return None, data
    
    first_byte = data[0]
    second_byte = data[1]
    
    opcode = first_byte & 0x0F
    masked = (second_byte & 0x80) >> 7
    payload_len = second_byte & 0x7F
    
    offset = 2
    
    if payload_len == 126:
        if len(data) < 4:
            return None, data
        payload_len = struct.unpack('>H', data[2:4])[0]
        offset = 4
    elif payload_len == 127:
        if len(data) < 10:
            return None, data
        payload_len = struct.unpack('>Q', data[2:10])[0]
        offset = 10
    
    if masked:
        if len(data) < offset + 4:
            return None, data
        mask_key = data[offset:offset+4]
        offset += 4
    
    if len(data) < offset + payload_len:
        return None, data
    
    payload = data[offset:offset+payload_len]
    
    if masked:
        decoded = bytearray()
        for i in range(payload_len):
            decoded.append(payload[i] ^ mask_key[i % 4])
        payload = bytes(decoded)
    
    return {'opcode': opcode, 'payload': payload}, data[offset+payload_len:]

def websocket_encode_frame(payload, opcode=0x1):
    """编码 WebSocket 帧"""
    data = bytearray()
    
    first_byte = 0x80 | (opcode & 0x0F)
    data.append(first_byte)
    
    payload_len = len(payload)
    if payload_len < 126:
        data.append(payload_len)
    elif payload_len < 65536:
        data.append(126)
        data.extend(struct.pack('>H', payload_len))
    else:
        data.append(127)
        data.extend(struct.pack('>Q', payload_len))
    
    data.extend(payload)
    return bytes(data)

class WebSocketConnection:
    """WebSocket 连接处理类"""
    def __init__(self, client_socket, addr):
        self.socket = client_socket
        self.addr = addr
        self.username = None
        self.buffer = b''
    
    def send(self, message):
        try:
            frame = websocket_encode_frame(message.encode('utf-8'))
            self.socket.send(frame)
        except Exception as e:
            logger.error(f"发送消息错误: {e}")
    
    def close(self):
        try:
            self.socket.close()
        except:
            pass

class CombinedServer:
    """同时处理 HTTP 和 WebSocket 的服务器"""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.websocket_connections = {}  # socket -> WebSocketConnection
        self.running = False
    
    def start(self):
        """启动服务器"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.server_socket.setblocking(False)
        self.running = True
        
        logger.info(f"综合服务器启动在 {self.host}:{self.port} (HTTP + WebSocket)")
        
        # 用于 select 的连接列表
        connections = [self.server_socket]
        
        while self.running:
            try:
                # 使用 select 监听所有连接
                readable, _, _ = select.select(connections, [], [], 1.0)
                
                for sock in readable:
                    if sock is self.server_socket:
                        # 新连接
                        client_sock, addr = self.server_socket.accept()
                        client_sock.setblocking(False)
                        connections.append(client_sock)
                        logger.info(f"新连接: {addr}")
                    else:
                        # 已有连接的数据
                        self.handle_client(sock, connections)
                        
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"服务器错误: {e}")
        
        self.stop()
    
    def handle_client(self, client_sock, connections):
        """处理客户端数据"""
        try:
            data = client_sock.recv(4096)
            if not data:
                # 连接关闭
                self.remove_connection(client_sock, connections)
                return
            
            # 检查是否是 WebSocket 连接
            if client_sock in self.websocket_connections:
                # 已有 WebSocket 连接，处理 WebSocket 帧
                ws_conn = self.websocket_connections[client_sock]
                ws_conn.buffer += data
                
                while ws_conn.buffer:
                    frame, ws_conn.buffer = websocket_decode_frame(ws_conn.buffer)
                    if frame is None:
                        break
                    
                    if frame['opcode'] == 0x8:  # 关闭帧
                        logger.info(f"WebSocket关闭: {ws_conn.addr}")
                        self.remove_connection(client_sock, connections)
                        return
                    
                    if frame['opcode'] == 0x1:  # 文本帧
                        self.handle_websocket_message(ws_conn, frame['payload'].decode('utf-8'))
            else:
                # 新连接，判断是否是 WebSocket 升级请求
                header_data = data.decode('utf-8', errors='ignore')
                
                if 'Upgrade: websocket' in header_data:
                    # WebSocket 握手
                    headers = header_data.split('\r\n')
                    if websocket_handshake(client_sock, headers):
                        logger.info(f"WebSocket 握手成功: {client_sock.getpeername()}")
                        self.websocket_connections[client_sock] = WebSocketConnection(client_sock, client_sock.getpeername())
                    else:
                        logger.warning(f"WebSocket 握手失败")
                        self.remove_connection(client_sock, connections)
                else:
                    # HTTP 请求
                    self.handle_http_request(client_sock, data)
                    self.remove_connection(client_sock, connections)  # HTTP 请求后关闭连接
                    
        except Exception as e:
            logger.error(f"处理客户端错误: {e}")
            self.remove_connection(client_sock, connections)
    
    def handle_http_request(self, client_sock, data):
        """处理 HTTP 请求"""
        try:
            # 解析请求行
            lines = data.decode('utf-8', errors='ignore').split('\r\n')
            if not lines:
                return
            
            request_line = lines[0]
            method, path, _ = request_line.split(' ')
            
            # 解析 headers
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
            
            # 处理请求
            if method == 'GET':
                if path == '/' or path == '/index.html':
                    self.serve_file(client_sock, 'static/index.html', 'text/html')
                elif path.startswith('/static/'):
                    filepath = path[1:]  # 去掉开头的 /
                    content_type = 'text/html'
                    if path.endswith('.css'):
                        content_type = 'text/css'
                    elif path.endswith('.js'):
                        content_type = 'application/javascript'
                    self.serve_file(client_sock, filepath, content_type)
                else:
                    self.send_http_response(client_sock, 404, 'Not Found')
                    
            elif method == 'POST' and path == '/api/challenge':
                # 读取 body
                content_length = int(headers.get('content-length', 0))
                body = data.split(b'\r\n\r\n', 1)[1][:content_length] if content_length > 0 else b''
                self.handle_challenge_api(client_sock, body)
            else:
                self.send_http_response(client_sock, 404, 'Not Found')
                
        except Exception as e:
            logger.error(f"HTTP 请求处理错误: {e}")
            self.send_http_response(client_sock, 500, 'Internal Server Error')
    
    def serve_file(self, client_sock, filepath, content_type):
        """提供静态文件"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(content)}\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n"
            ).encode('utf-8') + content
            
            client_sock.send(response)
        except FileNotFoundError:
            self.send_http_response(client_sock, 404, 'File Not Found')
    
    def send_http_response(self, client_sock, code, message, content_type='text/plain'):
        """发送 HTTP 响应"""
        response = (
            f"HTTP/1.1 {code} {message}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            f"{message}"
        ).encode('utf-8')
        client_sock.send(response)
    
    def handle_challenge_api(self, client_sock, body):
        """处理挑战码 API"""
        try:
            data = json.loads(body.decode('utf-8'))
            username = data.get('username')
            
            if not username:
                self.send_json_response(client_sock, {'success': False, 'message': '用户名不能为空'}, 400)
                return
            
            if username not in passwd_mgr.users:
                self.send_json_response(client_sock, {'success': False, 'message': '用户不存在'}, 404)
                return
            
            stored_hash = passwd_mgr.users[username]['hash']
            salt = stored_hash.split(':')[0] if ':' in stored_hash else ''
            challenge = auth_manager.generate_challenge(username)
            
            self.send_json_response(client_sock, {
                'success': True,
                'challenge': challenge,
                'salt': salt
            })
            
        except Exception as e:
            logger.error(f"挑战码 API 错误: {e}")
            self.send_json_response(client_sock, {'success': False, 'message': '服务器错误'}, 500)
    
    def send_json_response(self, client_sock, data, status=200):
        """发送 JSON 响应"""
        body = json.dumps(data).encode('utf-8')
        response = (
            f"HTTP/1.1 {status} OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        ).encode('utf-8') + body
        client_sock.send(response)
    
    def handle_websocket_message(self, ws_conn, message):
        """处理 WebSocket 消息"""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            #logger.debug(f"收到 WebSocket 消息: type={msg_type}, from={ws_conn.username}")
            
            if msg_type == 'login':
                self.handle_login(ws_conn, data)
            elif msg_type == 'update_position':
                self.handle_position(ws_conn, data)
            elif msg_type == 'get_users':
                self.handle_get_users(ws_conn, data)
            elif msg_type == 'logout':
                self.handle_logout(ws_conn, data)
            else:
                ws_conn.send(json.dumps({'type': 'error', 'message': '未知消息类型'}))
                
        except json.JSONDecodeError:
            logger.warning(f"无效的 JSON 消息: {message[:100]}...")
        except Exception as e:
            logger.error(f"处理 WebSocket 消息错误: {e}")
    
    def handle_login(self, ws_conn, data):
        """处理登录"""
        username = data.get('username')
        response = data.get('response')
        lat = data.get('lat', 31.2317)
        lng = data.get('lng', 121.4725)
        heading = data.get('heading', 0)
        
        logger.info(f"登录请求: username={username}")
        
        if not username or not response:
            ws_conn.send(json.dumps({'type': 'error', 'message': '用户名和响应不能为空'}))
            return
        
        success, message, session_token = auth_manager.verify_challenge(username, response)
        
        if not success:
            ws_conn.send(json.dumps({'type': 'error', 'message': message}))
            return
        
        nickname = passwd_mgr.users[username].get('nickname', username)
        
        # 检查是否已在别处登录
        for conn, existing_ws in self.websocket_connections.items():
            if existing_ws.username == username and existing_ws != ws_conn:
                existing_ws.send(json.dumps({
                    'type': 'force_logout',
                    'message': '您的账号已在其他地方登录'
                }))
                existing_ws.username = None
        
        # 保存用户信息
        ws_conn.username = username
        online_users[username] = {
            'conn': ws_conn,
            'lat': lat,
            'lng': lng,
            'heading': heading,
            'last_update': time.time(),
            'nickname': nickname,
            'token': session_token,
            'login_time': time.time()
        }
        token_to_username[session_token] = username
        
        logger.info(f"登录成功: username={username}")
        
        # 发送登录成功
        ws_conn.send(json.dumps({
            'type': 'login_success',
            'username': username,
            'nickname': nickname,
            'token': session_token
        }))
        
        # 广播用户加入
        self.broadcast(json.dumps({
            'type': 'user_joined',
            'username': username,
            'nickname': nickname,
            'lat': lat,
            'lng': lng,
            'heading': heading
        }), exclude=ws_conn)
        
        # 发送用户列表
        self.send_user_list(ws_conn)
    
    def handle_position(self, ws_conn, data):
        """处理位置更新"""
        token = data.get('token')
        username = data.get('username')
        lat = data.get('lat')
        lng = data.get('lng')
        heading = data.get('heading')
        
        if not self.authenticate(token, username):
            ws_conn.send(json.dumps({'type': 'error', 'message': '认证失败'}))
            return
        
        if username in online_users:
            if lat is not None:
                online_users[username]['lat'] = lat
            if lng is not None:
                online_users[username]['lng'] = lng
            if heading is not None:
                online_users[username]['heading'] = heading
            online_users[username]['last_update'] = time.time()
            
            logger.info(f"位置更新 - 用户: {username}, 经纬度: ({lat:.6f}, {lng:.6f}), 朝向: {heading}°")
            
            # 广播位置更新
            self.broadcast(
                json.dumps({
                'type': 'position_update',
                'username': username,
                'lat': online_users[username]['lat'],
                'lng': online_users[username]['lng'],
                'heading': online_users[username]['heading'],
                'timestamp': time.time() * 1000
                })
            )
    
    def handle_get_users(self, ws_conn, data):
        """处理获取用户列表"""
        token = data.get('token')
        username = data.get('username')
        
        if not self.authenticate(token, username):
            ws_conn.send(json.dumps({'type': 'error', 'message': '认证失败'}))
            return
        
        self.send_user_list(ws_conn)
    
    def handle_logout(self, ws_conn, data):
        """处理登出"""
        username = ws_conn.username
        token = data.get('token')
        
        logger.info(f"用户登出: {username}")
        
        if username in online_users:
            del online_users[username]
        if token in token_to_username:
            del token_to_username[token]
        
        ws_conn.username = None
        
        # 广播用户离开
        self.broadcast(json.dumps({
            'type': 'user_left',
            'username': username,
            'timestamp': time.time() * 1000
        }))
        
        ws_conn.send(json.dumps({'type': 'logout_success'}))
    
    def authenticate(self, token, username):
        """验证认证信息"""
        if not token or not username:
            return False
        if username not in online_users:
            return False
        if online_users[username].get('token') != token:
            return False
        return True
    
    def send_user_list(self, ws_conn):
        """发送用户列表"""
        users_list = []
        for username, info in online_users.items():
            users_list.append({
                'username': username,
                'nickname': info.get('nickname', username),
                'lat': info['lat'],
                'lng': info['lng'],
                'heading': info['heading']
            })
        
        ws_conn.send(json.dumps({
            'type': 'user_list',
            'users': users_list
        }))
    
    def broadcast(self, message, exclude=None):
        """广播消息给所有 WebSocket 客户端"""
        for conn in self.websocket_connections.values():
            if conn != exclude and conn.username:
                try:
                    conn.send(message)
                except:
                    pass
    
    def remove_connection(self, client_sock, connections):
        """移除连接"""
        if client_sock in connections:
            connections.remove(client_sock)
        
        if client_sock in self.websocket_connections:
            ws_conn = self.websocket_connections[client_sock]
            if ws_conn.username and ws_conn.username in online_users:
                del online_users[ws_conn.username]
                self.broadcast(json.dumps({
                    'type': 'user_left',
                    'username': ws_conn.username,
                    'timestamp': time.time() * 1000
                }))
            del self.websocket_connections[client_sock]
        
        try:
            client_sock.close()
        except:
            pass
    
    def stop(self):
        """停止服务器"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for conn in self.websocket_connections.values():
            conn.close()

def parse_args():
    parser = argparse.ArgumentParser(description='旅迹定位服务端')
    parser.add_argument('-p', '--port', type=int, default=9999, help='监听端口')
    parser.add_argument('--host', default='0.0.0.0', help='监听地址')
    parser.add_argument('-f', '--passwd-file', default='passwd.json', help='密码文件路径')
    parser.add_argument('-d', '--debug', action='store_true', help='调试模式')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    CONFIG['port'] = args.port
    CONFIG['host'] = args.host
    CONFIG['passwd_file'] = args.passwd_file
    CONFIG['debug'] = args.debug
    
    if CONFIG['debug']:
        logger.setLevel(logging.DEBUG)
    
    # 初始化密码管理器
    passwd_mgr = PasswordManager(CONFIG['passwd_file'])
    
    logger.info("=" * 60)
    logger.info("旅迹定位服务端启动")
    logger.info("=" * 60)
    logger.info(f"监听地址: {CONFIG['host']}:{CONFIG['port']}")
    logger.info(f"密码文件: {CONFIG['passwd_file']}")
    logger.info(f"调试模式: {CONFIG['debug']}")
    logger.info(f"访问地址: http://localhost:{CONFIG['port']}")
    logger.info(f"WebSocket: ws://localhost:{CONFIG['port']}")
    logger.info("=" * 60)
    
    print(f"\n服务端启动成功！")
    print(f"访问地址: http://localhost:{CONFIG['port']}")
    print(f"WebSocket: ws://localhost:{CONFIG['port']}")
    print(f"查看日志: tail -f server.log")
    
    # 确保static目录存在
    if not os.path.exists('static'):
        os.makedirs('static')
        print("提示: 请将index.html文件放入static目录")
    
    # 启动综合服务器
    server = CombinedServer(CONFIG['host'], CONFIG['port'])
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n服务端停止")
        server.stop()
        logger.info("服务端已停止")
