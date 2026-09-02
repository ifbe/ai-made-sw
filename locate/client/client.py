#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
命令行GPS客户端 - 用于向旅迹服务端上报位置
只使用Python标准库，无需额外安装
支持 HTTP/HTTPS 和 WS/WSS
"""

import os
import sys
import time
import json
import argparse
import socket
import threading
import hashlib
import hmac
import base64
import struct
import subprocess
import platform
import ssl
from datetime import datetime
from urllib.parse import urlparse

# 配置常量
UPDATE_INTERVAL = 5  # 默认5秒上报一次
# 尼莫点坐标 (海洋难抵极)
DEFAULT_LAT = -48.876667   # 南纬 48°52'36"
DEFAULT_LNG = -123.393333  # 西经 123°23'36"

# WebSocket 魔术字符串
WEBSOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocketConnection:
    """简单的 WebSocket 连接实现，支持 WS 和 WSS"""
    
    def __init__(self):
        self.sock = None
        self.connected = False
        self.recv_buffer = b''
        self.ssl_context = None
    
    def _create_ssl_context(self):
        """创建 SSL 上下文"""
        context = ssl.create_default_context()
        # 忽略证书验证错误（用于自签名证书）
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    
    def connect(self, host, port, path='/', ssl_enabled=False):
        """建立 WebSocket 连接"""
        try:
            # 创建 socket 连接
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((host, port))
            
            # 如果是 WSS，包装 SSL
            if ssl_enabled:
                context = self._create_ssl_context()
                self.sock = context.wrap_socket(self.sock, server_hostname=host)
            
            # 发送 WebSocket 握手请求
            key = base64.b64encode(os.urandom(16)).decode()
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            )
            self.sock.send(handshake.encode())
            
            # 接收握手响应
            response = self.sock.recv(4096).decode()
            if "101 Switching Protocols" not in response:
                return False
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"WebSocket连接失败: {e}")
            return False
    
    def send(self, data):
        """发送 WebSocket 帧"""
        if not self.connected:
            return False
        
        try:
            # 编码为 WebSocket 帧
            frame = self._encode_frame(data.encode())
            self.sock.send(frame)
            return True
        except Exception as e:
            print(f"发送失败: {e}")
            return False
    
    def recv(self):
        """接收 WebSocket 帧"""
        if not self.connected:
            return None
        
        try:
            data = self.sock.recv(4096)
            if not data:
                return None
            
            self.recv_buffer += data
            messages = []
            
            while len(self.recv_buffer) >= 2:
                # 解析帧头
                first_byte = self.recv_buffer[0]
                second_byte = self.recv_buffer[1]
                
                opcode = first_byte & 0x0F
                masked = (second_byte & 0x80) >> 7
                payload_len = second_byte & 0x7F
                
                offset = 2
                
                # 获取实际负载长度
                if payload_len == 126:
                    if len(self.recv_buffer) < 4:
                        break
                    payload_len = struct.unpack('>H', self.recv_buffer[2:4])[0]
                    offset = 4
                elif payload_len == 127:
                    if len(self.recv_buffer) < 10:
                        break
                    payload_len = struct.unpack('>Q', self.recv_buffer[2:10])[0]
                    offset = 10
                
                # 检查是否有掩码
                if masked:
                    if len(self.recv_buffer) < offset + 4:
                        break
                    mask_key = self.recv_buffer[offset:offset+4]
                    offset += 4
                
                # 检查是否有完整数据
                if len(self.recv_buffer) < offset + payload_len:
                    break
                
                # 提取负载数据
                payload = self.recv_buffer[offset:offset+payload_len]
                
                # 如果有掩码，解码
                if masked:
                    decoded = bytearray()
                    for i in range(payload_len):
                        decoded.append(payload[i] ^ mask_key[i % 4])
                    payload = bytes(decoded)
                
                # 如果是关闭帧
                if opcode == 0x8:
                    self.close()
                    return None
                
                # 如果是文本帧
                if opcode == 0x1:
                    messages.append(payload.decode('utf-8'))
                
                # 移除已处理的数据
                self.recv_buffer = self.recv_buffer[offset+payload_len:]
            
            return messages
            
        except socket.timeout:
            return []
        except Exception as e:
            print(f"接收失败: {e}")
            return None
    
    def _encode_frame(self, payload):
        """编码 WebSocket 帧（从客户端到服务器，需要掩码）"""
        frame = bytearray()
        
        # FIN + opcode (文本帧)
        frame.append(0x81)
        
        # 负载长度
        payload_len = len(payload)
        if payload_len < 126:
            frame.append(0x80 | payload_len)  # 设置掩码位
        elif payload_len < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack('>H', payload_len))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack('>Q', payload_len))
        
        # 生成掩码
        mask = os.urandom(4)
        frame.extend(mask)
        
        # 掩码处理数据
        for i in range(payload_len):
            frame.append(payload[i] ^ mask[i % 4])
        
        return bytes(frame)
    
    def close(self):
        """关闭连接"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.connected = False


class SimpleHTTPClient:
    """简单的 HTTP 客户端，支持 HTTP 和 HTTPS"""
    
    @staticmethod
    def _create_ssl_context():
        """创建 SSL 上下文"""
        context = ssl.create_default_context()
        # 忽略证书验证错误（用于自签名证书）
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    
    @staticmethod
    def post_json(url, data):
        """发送 POST JSON 请求，支持 HTTP 和 HTTPS"""
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path or '/'
            
            # 创建连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # 如果是 HTTPS，包装 SSL
            if parsed.scheme == 'https':
                context = SimpleHTTPClient._create_ssl_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # 构建请求
            body = json.dumps(data)
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            
            sock.send(request.encode())
            
            # 接收响应
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            
            # 解析响应
            response_str = response.decode('utf-8', errors='ignore')
            header_end = response_str.find('\r\n\r\n')
            if header_end == -1:
                return None
            
            headers = response_str[:header_end]
            body = response_str[header_end+4:]
            
            # 检查状态码
            if '200 OK' not in headers:
                return None
            
            return json.loads(body)
            
        except Exception as e:
            print(f"HTTP请求失败: {e}")
            return None


class GPSClient:
    def __init__(self, server_url, username, password, gps_source='fixed', fixed_pos=None, debug=False, initial_target=None, status_auto=False):
        """
        初始化GPS客户端
        """
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.gps_source = gps_source  # 'fixed' 或 'gps'
        self.fixed_pos = fixed_pos
        self.debug = debug
        self.initial_target = initial_target

        self.session_token = None
        self.running = False
        self.lat = DEFAULT_LAT
        self.lng = DEFAULT_LNG
        self.heading = 0
        self.target_lat = None
        self.target_lng = None
        self.ws = None
        self.input_thread = None

        # 存储其他用户位置
        self.other_users = {}
        self.display_lock = threading.Lock()
        
        # 状态显示控制
        self.status_auto = status_auto  # 由命令行参数控制
        self.status_line = ""    # 当前状态行内容
        self.print_lock = threading.Lock()  # 打印锁，保证输出不混乱

        # 解析服务器地址
        parsed = urlparse(self.server_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.ws_path = '/'
        self.api_path = '/api/challenge'
        
        # 判断是否启用 SSL
        self.ssl_enabled = parsed.scheme == 'https'
        
        # WebSocket URL
        ws_scheme = 'wss' if self.ssl_enabled else 'ws'
        self.ws_url = f"{ws_scheme}://{self.host}:{self.port}"

        self.log(f"🌐 服务器地址: {self.server_url}")
        self.log(f"🔌 WebSocket: {self.ws_url}")
        self.log(f"🔒 SSL: {'启用' if self.ssl_enabled else '禁用'}")

        # 如果有初始目标，设置
        if self.initial_target:
            self.target_lat, self.target_lng = self.initial_target
            self.log(f"🎯 初始目标: ({self.target_lat}, {self.target_lng})")

    def log(self, msg, level="INFO"):
        """统一日志输出 - 带锁保证线程安全"""
        if level == "DEBUG" and not self.debug:
            return
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_msg = f"[{timestamp}] [{level}] {msg}"
        
        with self.print_lock:
            # 1. 清除当前行（状态行）
            if self.status_auto and self.status_line:
                sys.stdout.write('\r\033[K')
            
            # 2. 输出消息（带换行）
            print(formatted_msg)
            
            # 3. 重新显示状态行
            if self.status_auto and self.status_line:
                sys.stdout.write(self.status_line)
                sys.stdout.flush()

    def debug_log(self, msg):
        """调试日志"""
        self.log(msg, "DEBUG")

    def get_system_gps(self):
        """获取系统GPS位置（简化版，返回None）"""
        # 简化版不实现真实GPS，返回None
        return None

    def get_current_position(self):
        """获取当前位置"""
        if self.gps_source == 'gps':
            # 从GPS获取位置
            gps_pos = self.get_system_gps()
            if gps_pos:
                return gps_pos
            # GPS获取失败，返回默认位置
            return {'lat': self.lat, 'lng': self.lng, 'heading': self.heading}
        else:
            # 使用固定位置
            if self.fixed_pos:
                return {
                    'lat': self.fixed_pos[0],
                    'lng': self.fixed_pos[1],
                    'heading': self.fixed_pos[2] if len(self.fixed_pos) > 2 else 0
                }
            return {'lat': self.lat, 'lng': self.lng, 'heading': self.heading}

    def set_position(self, lat, lng, heading=0):
        """手动设置位置"""
        self.lat = lat
        self.lng = lng
        self.heading = heading
        self.log(f"📍 手动设置位置: ({lat:.6f}, {lng:.6f}) 朝向: {heading}°")
        self.send_position_update()

    def set_target(self, lat, lng):
        """设置目标"""
        self.target_lat = lat
        self.target_lng = lng
        self.log(f"🎯 设置目标: ({lat:.6f}, {lng:.6f})")
        self.send_target_update()

    def clear_target(self):
        """清除目标"""
        self.target_lat = None
        self.target_lng = None
        self.log("🎯 清除目标")
        self.send_target_update()

    def send_position_update(self):
        """发送位置更新"""
        if not self.session_token or not self.ws or not self.ws.connected:
            return False

        try:
            msg = {
                'type': 'update_position',
                'token': self.session_token,
                'username': self.username,
                'lat': self.lat,
                'lng': self.lng,
                'heading': self.heading
            }
            self.debug_log(f"发送位置: {msg}")
            self.ws.send(json.dumps(msg))
            return True
        except Exception as e:
            self.debug_log(f"发送位置失败: {e}")
            return False

    def send_target_update(self):
        """发送目标更新"""
        if not self.session_token or not self.ws or not self.ws.connected:
            return False

        try:
            msg = {
                'type': 'target_update',
                'token': self.session_token,
                'username': self.username,
                'target_lat': self.target_lat,
                'target_lng': self.target_lng
            }
            self.debug_log(f"发送目标: {msg}")
            self.ws.send(json.dumps(msg))
            return True
        except Exception as e:
            self.debug_log(f"发送目标失败: {e}")
            return False

    def authenticate(self):
        """进行挑战-响应认证"""
        try:
            self.log(f"🔐 正在认证用户 {self.username}...")

            # 1. 获取挑战码
            protocol = 'https' if self.ssl_enabled else 'http'
            challenge_url = f"{protocol}://{self.host}:{self.port}/api/challenge"
            data = {'username': self.username}
            
            result = SimpleHTTPClient.post_json(challenge_url, data)
            if not result or not result.get('success'):
                self.log(f"❌ 认证失败: 无法获取挑战码")
                return False

            challenge = result['challenge']
            salt = result['salt']

            # 2. 计算响应
            password_hash = hashlib.sha256(
                (self.password + salt).encode()
            ).hexdigest()

            hmac_obj = hmac.new(
                password_hash.encode(),
                challenge.encode(),
                hashlib.sha256
            )
            response_hash = hmac_obj.hexdigest()

            # 3. 建立 WebSocket 连接
            self.ws = WebSocketConnection()
            if not self.ws.connect(self.host, self.port, self.ws_path, self.ssl_enabled):
                self.log("❌ WebSocket连接失败")
                return False

            # 发送登录消息
            login_msg = {
                'type': 'login',
                'username': self.username,
                'response': response_hash,
                'lat': self.lat,
                'lng': self.lng,
                'heading': self.heading
            }
            self.ws.send(json.dumps(login_msg))

            # 等待登录响应
            timeout = 10
            while timeout > 0:
                messages = self.ws.recv()
                if messages:
                    for msg_str in messages:
                        try:
                            data = json.loads(msg_str)
                            if data.get('type') == 'login_success':
                                self.session_token = data['token']
                                self.log(f"✅ 登录成功！欢迎 {data.get('nickname', self.username)}")
                                
                                # 发送初始目标
                                if self.target_lat is not None:
                                    time.sleep(0.5)
                                    self.send_target_update()
                                return True
                            elif data.get('type') == 'user_list':
                                with self.display_lock:
                                    self.other_users = {u['username']: u for u in data['users']}
                        except:
                            pass
                time.sleep(0.5)
                timeout -= 0.5

            self.log("❌ 登录超时")
            return False

        except Exception as e:
            self.log(f"❌ 认证错误: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return False

    def process_messages(self):
        """处理接收到的消息"""
        while self.running and self.ws and self.ws.connected:
            try:
                messages = self.ws.recv()
                if messages is None:
                    break
                
                for msg_str in messages:
                    try:
                        data = json.loads(msg_str)
                        
                        if data.get('type') == 'user_list':
                            with self.display_lock:
                                self.other_users = {u['username']: u for u in data['users']}
                        
                        elif data.get('type') == 'target_update':
                            with self.display_lock:
                                if data['username'] != self.username:
                                    self.other_users[data['username']] = {
                                        **self.other_users.get(data['username'], {}),
                                        'target_lat': data['target_lat'],
                                        'target_lng': data['target_lng']
                                    }
                        
                        elif data.get('type') == 'user_joined':
                            self.log(f"👋 用户加入: {data['username']}")
                        
                        elif data.get('type') == 'user_left':
                            self.log(f"👋 用户离开: {data['username']}")
                            with self.display_lock:
                                if data['username'] in self.other_users:
                                    del self.other_users[data['username']]
                        
                        elif data.get('type') == 'error':
                            self.log(f"❌ 服务器错误: {data.get('message')}")
                            
                    except Exception as e:
                        self.debug_log(f"处理消息错误: {e}")
                        
            except Exception as e:
                self.debug_log(f"接收消息错误: {e}")
                time.sleep(0.1)

    def input_handler(self):
        """处理命令行输入"""
        self.log("\n📝 命令行模式已启动，输入命令:")
        self.log("  position <lat>,<lng> [heading]  - 设置位置")
        self.log("  target [clear|<lat>,<lng>]      - 设置目标")
        self.log("  status [on|off]                 - 显示状态/开启自动显示/关闭自动显示")
        self.log("  quit                             - 退出")
        
        while self.running:
            try:
                cmd = input().strip()
                if not cmd:
                    continue
                    
                parts = cmd.split()
                if parts[0] == 'quit':
                    self.running = False
                    break
                    
                elif parts[0] == 'status':
                    if len(parts) >= 2:
                        if parts[1] == 'on':
                            self.status_auto = True
                            self.log("📊 自动状态显示已开启")
                        elif parts[1] == 'off':
                            self.status_auto = False
                            # 关闭时清除状态行
                            with self.print_lock:
                                sys.stdout.write('\r\033[K')
                                sys.stdout.flush()
                            self.log("📊 自动状态显示已关闭")
                        else:
                            self.log("❌ 用法: status [on|off]")
                    else:
                        # 不带参数时，显示一次状态
                        self.show_status()
                    
                elif parts[0] == 'position':
                    if len(parts) >= 2:
                        try:
                            coord_str = parts[1].replace(' ', '')
                            lat_str, lng_str = coord_str.split(',')
                            lat = float(lat_str)
                            lng = float(lng_str)
                            heading = float(parts[2]) if len(parts) >= 3 else self.heading
                            self.set_position(lat, lng, heading)
                        except:
                            self.log(f"❌ 位置格式错误: 使用 position lat,lng [heading]")
                            
                elif parts[0] == 'target':
                    if len(parts) >= 2 and parts[1] == 'clear':
                        self.clear_target()
                    elif len(parts) >= 2:
                        try:
                            coord_str = parts[1].replace(' ', '')
                            lat_str, lng_str = coord_str.split(',')
                            lat = float(lat_str)
                            lng = float(lng_str)
                            self.set_target(lat, lng)
                        except:
                            self.log(f"❌ 目标格式错误: 使用 target lat,lng 或 target clear")
                            
            except Exception as e:
                self.log(f"❌ 输入错误: {e}")

    def show_status(self):
        """显示当前状态（一次性）"""
        with self.display_lock:
            self.log("\n=== 当前状态 ===")
            self.log(f"用户: {self.username}")
            self.log(f"位置: ({self.lat:.6f}, {self.lng:.6f}) 朝向: {self.heading}°")
            if self.target_lat is not None:
                self.log(f"目标: ({self.target_lat:.6f}, {self.target_lng:.6f})")
            else:
                self.log("目标: 未设置")
            self.log(f"在线用户: {len(self.other_users)}")
            for u, info in self.other_users.items():
                if u != self.username:
                    target_info = ""
                    if info.get('target_lat'):
                        target_info = f" 目标:({info['target_lat']:.4f},{info['target_lng']:.4f})"
                    self.log(f"  {u}: ({info['lat']:.4f},{info['lng']:.4f}){target_info}")

    def update_status_line(self):
        """更新状态行内容（不输出）"""
        with self.display_lock:
            other_count = len([u for u in self.other_users if u != self.username])
            target_info = f" 🎯({self.target_lat:.4f},{self.target_lng:.4f})" if self.target_lat is not None else ""
            self.status_line = f"[{datetime.now().strftime('%H:%M:%S')}] 📍 {self.username}: ({self.lat:.6f}, {self.lng:.6f}){target_info} | 👥 在线: {other_count+1}"

    def display_status(self):
        """状态显示线程 - 负责更新并显示状态行"""
        while self.running:
            # 更新状态行内容
            self.update_status_line()
            
            # 如果自动显示开启，输出状态行
            if self.status_auto and self.status_line:
                with self.print_lock:
                    sys.stdout.write(f'\r{self.status_line}')
                    sys.stdout.flush()
            
            time.sleep(1)

    def run(self, interval=UPDATE_INTERVAL):
        """运行客户端"""
        self.log("\n" + "="*60)
        self.log("🚐 旅迹定位客户端启动 (纯标准库版)")
        self.log("="*60)
        self.log(f"📡 GPS来源: {'GPS设备' if self.gps_source == 'gps' else '固定位置'}")
        self.log(f"⏱️  更新间隔: {interval}秒")
        self.log(f"🔧 调试模式: {'开启' if self.debug else '关闭'}")
        self.log(f"🔒 SSL/TLS: {'启用' if self.ssl_enabled else '禁用'}")
        self.log(f"📊 自动状态显示: {'开启' if self.status_auto else '关闭'}")
        if self.gps_source == 'fixed' and self.fixed_pos:
            self.log(f"📍 固定位置: ({self.fixed_pos[0]}, {self.fixed_pos[1]})")
        if self.initial_target:
            self.log(f"🎯 初始目标: ({self.initial_target[0]}, {self.initial_target[1]})")
        self.log("="*60)

        if not self.authenticate():
            return

        self.running = True

        # 启动消息处理线程
        msg_thread = threading.Thread(target=self.process_messages, daemon=True)
        msg_thread.start()

        # 启动状态显示线程
        display_thread = threading.Thread(target=self.display_status, daemon=True)
        display_thread.start()

        # 启动输入处理线程
        self.input_thread = threading.Thread(target=self.input_handler, daemon=True)
        self.input_thread.start()

        self.log("\n📡 开始上报位置 (按 Ctrl+C 停止)...")

        try:
            last_update = 0
            while self.running:
                current_time = time.time()
                
                # 定时更新位置
                if current_time - last_update >= interval:
                    self.send_position_update()
                    last_update = current_time
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.log("\n\n👋 用户中断")
        finally:
            if self.ws:
                self.ws.close()
            self.log("👋 客户端已退出")


def parse_coordinate(coord_str):
    """解析坐标字符串 "lat,lng" """
    try:
        coord_str = coord_str.replace(' ', '')
        lat_str, lng_str = coord_str.split(',')
        return (float(lat_str), float(lng_str))
    except:
        return None


def main():
    parser = argparse.ArgumentParser(
        description='旅迹定位命令行客户端 (纯标准库版，支持 HTTPS/WSS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -u http://localhost:9999 --user alice --pass 123456
  %(prog)s -u https://example.com --user bob --pass 123456 --position 32.0455,118.7908,90
  %(prog)s -u https://example.com --user charlie --pass 123456 --target 32.0455,118.7908
  %(prog)s -u https://example.com --user charlie --pass 123456 --status on
  
运行后可用命令:
  position <lat>,<lng> [heading]  - 设置位置
  target [clear|<lat>,<lng>]      - 设置目标/清除目标
  status [on|off]                 - 显示状态/开启自动显示/关闭自动显示
  quit                             - 退出
        """
    )

    parser.add_argument('-u', '--url', required=True,
                       help='服务器URL (http:// 或 https://)')
    parser.add_argument('--user', required=False,
                       help='用户名')
    parser.add_argument('--pass', dest='password', required=False,
                       help='密码')

    parser.add_argument('--position', type=str,
                       help='固定位置: "纬度,经度[,朝向]" 例如: 32.0455,118.7908,90 (如果使用 --position gps 则从GPS获取位置)')

    parser.add_argument('--target', type=str,
                       help='初始目标: "纬度,经度" 例如: 32.0455,118.7908')

    parser.add_argument('--status', choices=['on', 'off'], default='off',
                       help='启动后自动状态显示开关 (默认: off)')

    parser.add_argument('-i', '--interval', type=int, default=UPDATE_INTERVAL,
                       help=f'上报间隔(秒) (默认: {UPDATE_INTERVAL})')

    parser.add_argument('--debug', action='store_true',
                       help='开启调试模式，显示详细日志')

    args = parser.parse_args()

    # 检查并获取用户名
    username = args.user
    if not username:
        username = input("请输入用户名: ").strip()
        if not username:
            print("❌ 用户名不能为空")
            return

    # 检查并获取密码
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("请输入密码: ").strip()
        if not password:
            print("❌ 密码不能为空")
            return

    # 解析位置
    gps_source = 'fixed'
    fixed_pos = None
    if args.position:
        if args.position.lower() == 'gps':
            gps_source = 'gps'
            print("📡 使用GPS获取位置")
        else:
            try:
                parts = args.position.replace(' ', '').split(',')
                if len(parts) >= 2:
                    lat = float(parts[0])
                    lng = float(parts[1])
                    heading = float(parts[2]) if len(parts) >= 3 else 0
                    fixed_pos = (lat, lng, heading)
                    print(f"📍 固定位置: ({lat}, {lng}) 朝向: {heading}°")
            except:
                print(f"❌ 位置格式错误: 使用 --position \"纬度,经度[,朝向]\" 或 --position gps")
                return

    # 解析初始目标
    initial_target = None
    if args.target:
        try:
            coord = parse_coordinate(args.target)
            if coord:
                initial_target = coord
                print(f"🎯 初始目标: ({coord[0]}, {coord[1]})")
        except:
            print(f"❌ 目标格式错误: 使用 --target \"纬度,经度\"")
            return

    # 解析自动状态显示
    status_auto = args.status == 'on'

    # 创建客户端
    client = GPSClient(
        server_url=args.url,
        username=username,
        password=password,
        gps_source=gps_source,
        fixed_pos=fixed_pos,
        debug=args.debug,
        initial_target=initial_target,
        status_auto=status_auto
    )

    # 运行
    client.run(interval=args.interval)


if __name__ == '__main__':
    main()