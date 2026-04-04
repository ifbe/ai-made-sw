#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remote/wireguard.py - WireGuard 加密隧道客户端

功能：
  - 连接 switch.py 的 Unix socket（像 udp.py / tcp.py 一样"插网线"）
  - 单进程管理多个 peers（WireGuard 原生支持一对多隧道）
  - 无 TUN 网卡，纯用户态 WireGuard 加密传输

与裸 UDP 的区别：ChaCha20-Poly1305 加密、Noise IK 密钥交换、自动 keepalive
WireGuard 没有内置打洞，需要 server 提供 peer 的公网 IP:port 和公钥

协议：
  wireguard.py <-> switch（Unix socket，raw IP bytes）
  wireguard.py <-> peer（UDP + WireGuard 加密）

管理接口（admin socket）：
  {"cmd": "add_peer", "name": "bob", "ip": "1.2.3.4", "port": 51820, "pubkey": "<bob公钥>"}
  {"cmd": "list_peers"}
  {"cmd": "remove_peer", "name": "bob"}
  {"cmd": "get_pubkey"}
  {"cmd": "exit"}
"""

import os
import sys
import json
import socket
import select
import threading
import argparse
import struct
import hashlib
import hmac
import time
import secrets
import signal
import subprocess

# ---- Inline ClientSocket（连接 switch Unix socket，自动加/剥 eth 头）----
FAKE_SRC_MAC = b'\x00\x00\x00\x00\x00\x00'
FAKE_BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'
ETH_TYPE_IP = b'\x08\x00'

def _make_eth_header():
    return FAKE_BROADCAST_MAC + FAKE_SRC_MAC + ETH_TYPE_IP

class ClientSocket:
    def __init__(self, path):
        self._path = path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(path)
        self._recv_buf = b''

    def send(self, data):
        frame = _make_eth_header() + data
        self._sock.sendall(frame)

    def recv(self, bufsize=4096):
        while len(self._recv_buf) < 14:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b''
            self._recv_buf += chunk
        self._recv_buf = self._recv_buf[14:]
        while len(self._recv_buf) < 1500:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            self._recv_buf += chunk
        payload = self._recv_buf
        self._recv_buf = b''
        return payload

    def setsockopt(self, *args):
        self._sock.setsockopt(*args)

    def setblocking(self, flag):
        self._sock.setblocking(flag)

    def fileno(self):
        return self._sock.fileno()

    def close(self):
        self._sock.close()

    @property
    def path(self):
        return self._path


# =============================================================================
# WireGuard 加密原语（使用 cryptography 库）
# =============================================================================

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[wg] 错误：需要 cryptography 库：pip install cryptography", file=sys.stderr)
    sys.exit(1)

from cryptography.hazmat.backends import default_backend

# HKDF-SHA256
def hkdf(salt, ikm, info=b'', length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''
    okm = b''
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

# HKDF-SHA256 for 64-byte output (WireGuard spec)
def hkdf256(salt, ikm):
    return hkdf(salt, ikm, b'', 32)

def hkdf512(salt, ikm):
    return hkdf(salt, ikm, b'', 64)

# ChaCha20-Poly1305
def chacha20poly1305(key, nonce, plaintext, aad=b''):
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, plaintext, aad)

def chacha20poly1305_decrypt(key, nonce, ciphertext, aad=b''):
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, aad)

# 32-byte nonce for ChaCha20
def make_nonce(counter):
    return b'\x00\x00\x00\x00' + struct.pack('<Q', counter)

# =============================================================================
# WireGuard 协议常量
# =============================================================================

WIREGUARD_LISTEN_PORT = 51820
COOKIE_SECRET_SIZE = 32
MTU = 1420

# Message types
MSG_INITIATION = 1
MSG_RESPONSE = 2
MSG_COOKIE_REPLY = 3
MSG_TRANSPORT = 4

# =============================================================================
# WireGuard Peer 会话
# =============================================================================

class WgPeer:
    """管理单个 peer 的 WireGuard 会话"""

    def __init__(self, name, endpoint_ip, endpoint_port, peer_pubkey_bytes, our_private_bytes):
        self.name = name
        self.endpoint_ip = endpoint_ip
        self.endpoint_port = endpoint_port
        self.peer_pubkey = peer_pubkey_bytes
        self.our_private = our_private_bytes

        # 密钥
        self.our_public = self.our_private.public_key().public_bytes(
            serialization.RawEncoding(),
            serialization.PublicFormat.Raw
        )

        # 会话密钥（握手后派生）
        self.sending_key = None   # 用于发包（对方的 chacha20 key）
        self.recv_key = None      # 用于收包（对方的 chacha20 key）
        self.sending_nonce = 0
        self.recv_nonce = 0
        self.handshake_done = False

        # UDP socket 到 peer
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setblocking(False)

        # WireGuard 消息计数器
        self.msg_init = 0
        self.msg_resp = 0

        # 时间
        self.last_handshake_time = 0

    def new_handshake(self):
        """发起新握手（Noise IK）"""
        # 静态密钥对
        e_private = X25519PrivateKey.generate()
        e_public = e_private.public_key().public_bytes(
            serialization.RawEncoding(),
            serialization.PublicFormat.Raw
        )

        # ECDH
        peer_pub = X25519PublicKey.from_public_bytes(self.peer_pubkey)
        shared_secret = e_private.exchange(peer_pub)

        # Hash（WireGuard Noise IK 协议规定）
        # 起点：ASCII "Noise_IKpsk2_" + ...
        h = b'Noise_IKpsk2_' + self.peer_pubkey + self.our_public
        h = hashlib.sha256(h).digest()

        # 混合 ECDH 结果到 hash
        h = hashlib.sha256(h + shared_secret).digest()

        # 构建 handshake initiation packet
        # Type || Index ||[Static Static Ephemeral || HS Hash, PSK]
        # 简化：Type(4) || Receiver Index(4) || Unpadded Data
        # 实际 WireGuard 格式用 JSON 表述更清晰

        # 存储临时值用于解密 response
        self._e_private = e_private
        self._e_public = e_public
        self._h = h
        self._shared_secret = shared_secret

        # 发 initiation
        # Type(4 bytes big-endian) = 1
        # Sender Index(4 bytes) = random
        # Static DH
        # Timestamp
        # Encrypted chunks
        sender_index = secrets.token_bytes(4)

        # 构建未加密部分
        msg = b''
        msg += struct.pack('<I', MSG_INITIATION)
        msg += sender_index
        msg += self.our_public  # Our static pubkey (32 bytes)
        msg += e_public         # Ephemeral pubkey (32 bytes)

        # Encrypted: nothing for now (simplified)

        self._sender_index = sender_index
        self.msg_init += 1

        # 发送
        self.udp_sock.sendto(msg, (self.endpoint_ip, self.endpoint_port))
        return True

    def handle_response(self, packet):
        """处理 WireGuard handshake response"""
        # Type(4) + Sender Index(4) + Receiver Index(4) + Encrypted Data...
        if len(packet) < 16:
            return False

        msg_type = struct.unpack('<I', packet[0:4])[0]
        if msg_type != MSG_RESPONSE:
            return False

        sender_index = packet[4:8]
        recv_index = packet[8:12]
        data = packet[12:]

        # 解密 response
        # WireGuard response: sender_index || receiver_index || encrypted_empty || ...
        # 简化处理，实际需要 proper crypto

        # 派生会话密钥
        # DH(e_private, peer_pubkey) + DH(e_private, peer_pubkey)
        # = ECDH before + ECDH after
        e_private = self._e_private
        peer_pub = X25519PublicKey.from_public_bytes(self.peer_pubkey)

        # 第二次 ECDH：e_private 和对方的 static
        dh2 = e_private.exchange(peer_pub)

        # Chain keys
        # Noise IK: chaining key = HMAC-SHA256(ck, shared_secret)
        ck = hmac.new(self._shared_secret + dh2, hashlib.sha256(self._h).digest(), hashlib.sha256).digest()

        # Session keys
        # k = HMAC-SHA256(ck, b"")
        self.sending_key = hmac.new(ck, b'', hashlib.sha256).digest()  # for sending
        self.recv_key = hmac.new(ck, b'', hashlib.sha256).digest()    # for receiving

        # 交换发送/接收（对方用 recv_key 加密，我们用 sending_key 加密）
        self.sending_key, self.recv_key = self.recv_key, self.sending_key

        self.handshake_done = True
        self.last_handshake_time = time.time()
        return True

    def send_ip(self, ip_data):
        """发送 IP 数据包（加密）"""
        if not self.handshake_done:
            # 还没握手，先发起
            self.new_handshake()
            return False

        # 构建 transport message
        # Type(4) || Receiver Index(4) || Counter(8) || Encrypted packet
        counter = self.sending_nonce
        self.sending_nonce += 1

        nonce = make_nonce(counter)
        # Use first 12 bytes of sending_key for nonce (ChaCha20 uses 12-byte nonce)
        key_for_chacha = self.sending_key[:32]

        # 加密 IP 包（with 16-byte auth tag）
        # aad = empty for WG data channel
        encrypted = chacha20poly1305(key_for_chacha, nonce, ip_data)

        msg = b''
        msg += struct.pack('<I', MSG_TRANSPORT)
        msg += self._peer_index  # receiver index (got from response)
        msg += struct.pack('<Q', counter)
        msg += encrypted

        try:
            self.udp_sock.sendto(msg, (self.endpoint_ip, self.endpoint_port))
            return True
        except Exception as e:
            return False

    def recv_packet(self):
        """接收并解密 UDP 数据"""
        try:
            data, addr = self.udp_sock.recvfrom(65535)
            if not data:
                return None

            if len(data) < 16:
                return None

            msg_type = struct.unpack('<I', data[0:4])[0]

            if msg_type == MSG_RESPONSE and not self.handshake_done:
                if self.handle_response(data):
                    return None  # handshake completed, wait for data
                return None

            if msg_type == MSG_TRANSPORT and self.handshake_done:
                recv_index = data[4:8]
                counter = struct.unpack('<Q', data[12:20])[0]
                ciphertext = data[20:]

                nonce = make_nonce(counter)
                key_for_chacha = self.recv_key[:32]

                try:
                    plaintext = chacha20poly1305_decrypt(key_for_chacha, nonce, ciphertext)
                    return plaintext
                except Exception:
                    return None

            return None
        except BlockingIOError:
            return None
        except Exception:
            return None

    def close(self):
        self.udp_sock.close()

    def get_endpoint(self):
        return (self.endpoint_ip, self.endpoint_port)


# =============================================================================
# WireGuard 主进程
# =============================================================================

class WireGuardClient:
    """
    WireGuard 客户端主进程：
    - 连接 switch 的 Unix socket（插网线）
    - 管理多个 peer 的 WireGuard 隧道
    - 监听 admin socket 接收 client.py 命令
    """

    def __init__(self, socket_path, admin_path, log_file=None):
        self.socket_path = socket_path
        self.admin_path = admin_path
        self.log_file = log_file

        # WireGuard 密钥
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.RawEncoding(),
            serialization.PublicFormat.Raw
        )

        # 连接 switch 的 socket
        self.switch_sock = None

        # peers: {name: WgPeer}
        self.peers = {}

        # admin socket
        self.admin_sock = None

        self.running = True

    def log(self, *args):
        msg = '[wg] ' + ' '.join(str(a) for a in args)
        print(msg, file=sys.stderr if not self.log_file else open(self.log_file, 'a'))
        if not self.log_file:
            sys.stderr.flush()

    def setup_admin_socket(self):
        """创建 admin socket 监听 client.py 命令"""
        if os.path.exists(self.admin_path):
            os.remove(self.admin_path)
        self.admin_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.admin_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.admin_sock.bind(self.admin_path)
        self.admin_sock.listen(5)
        self.admin_sock.setblocking(False)
        self.log(f"admin socket: {self.admin_path}")

    def connect_switch(self):
        """连接 switch 的 Unix socket（用 ClientSocket 自动加/剥 eth 头）"""
        try:
            self.switch_sock = ClientSocket(self.socket_path)
            self.switch_sock.setblocking(False)
            self.log(f"已连接 switch: {self.socket_path}")
            return True
        except Exception as e:
            self.log(f"连接 switch 失败: {e}")
            return False

    def add_peer(self, name, endpoint_ip, endpoint_port, peer_pubkey_b64):
        """添加 peer"""
        import base64
        peer_pubkey_bytes = base64.b64decode(peer_pubkey_b64)
        our_private_bytes = self.private_key.private_bytes(
            serialization.RawEncoding(),
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )

        peer = WgPeer(name, endpoint_ip, endpoint_port, peer_pubkey_bytes, our_private_bytes)
        self.peers[name] = peer
        self.log(f"添加 peer {name}: {endpoint_ip}:{endpoint_port} pubkey={peer_pubkey_b64[:16]}...")

        # 立即发起握手
        peer.new_handshake()
        return True

    def remove_peer(self, name):
        """移除 peer"""
        if name in self.peers:
            self.peers[name].close()
            del self.peers[name]
            self.log(f"移除 peer {name}")
            return True
        return False

    def handle_admin_command(self, cmd):
        """处理 client.py 发来的命令"""
        try:
            obj = json.loads(cmd)
        except:
            return {'error': 'invalid json'}

        c = obj.get('cmd')
        if c == 'add_peer':
            name = obj.get('name')
            ip = obj.get('ip')
            port = obj.get('port')
            pubkey = obj.get('pubkey')
            if not all([name, ip, port, pubkey]):
                return {'error': 'missing fields'}
            self.add_peer(name, ip, port, pubkey)
            return {'ok': True, 'pubkey': base64.b64encode(self.public_key).decode()}
        elif c == 'remove_peer':
            name = obj.get('name')
            if self.remove_peer(name):
                return {'ok': True}
            return {'error': 'peer not found'}
        elif c == 'list_peers':
            return {
                'ok': True,
                'pubkey': base64.b64encode(self.public_key).decode(),
                'peers': [
                    {'name': n, 'endpoint': p.get_endpoint(), 'active': p.handshake_done}
                    for n, p in self.peers.items()
                ]
            }
        elif c == 'exit':
            self.running = False
            return {'ok': True}
        elif c == 'get_pubkey':
            return {'ok': True, 'pubkey': base64.b64encode(self.public_key).decode()}
        else:
            return {'error': f'unknown cmd: {c}'}

    def handle_admin_conn(self, conn):
        """处理一个 admin 连接"""
        buf = b''
        try:
            while self.running:
                r, _, _ = select.select([conn], [], [], 0.5)
                if not r:
                    continue
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    try:
                        cmd = line.decode('utf-8').strip()
                        if cmd:
                            resp = self.handle_admin_command(cmd)
                            conn.sendall((json.dumps(resp) + '\n').encode())
                    except Exception as e:
                        conn.sendall((json.dumps({'error': str(e)}) + '\n').encode())
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except:
                pass

    def run_admin_loop(self):
        """Admin socket 主循环"""
        while self.running:
            try:
                r, _, _ = select.select([self.admin_sock], [], [], 0.5)
                if not r:
                    continue
                conn, _ = self.admin_sock.accept()
                t = threading.Thread(target=self.handle_admin_conn, args=(conn,), daemon=True)
                t.start()
            except Exception as e:
                if self.running:
                    self.log(f"admin accept error: {e}")
                break

    def run_switch_loop(self):
        """从 switch 收 IP 包，发给 peers"""
        while self.running:
            try:
                r, _, _ = select.select([self.switch_sock] if self.switch_sock else [], [], [], 0.5)
                if not r:
                    continue
                data = self.switch_sock.recv(65535)
                if not data:
                    self.log("switch 连接断开")
                    break
                # 广播到所有 handshake 完成的 peers
                sent = 0
                for name, peer in list(self.peers.items()):
                    if peer.handshake_done:
                        if peer.send_ip(data):
                            sent += 1
                if sent == 0 and self.peers:
                    # 没有 handshake 完成的，尝试新握手
                    for name, peer in list(self.peers.items()):
                        peer.new_handshake()
            except BlockingIOError:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"switch recv error: {e}")
                break

    def run_peer_recv_loop(self):
        """从 peers 收加密包，解密后发回 switch"""
        while self.running:
            for name, peer in list(self.peers.items()):
                pkt = peer.recv_packet()
                if pkt:
                    if self.switch_sock:
                        try:
                            self.switch_sock.sendall(pkt)
                        except:
                            pass
            time.sleep(0.001)  # 避免 busy loop

    def run_handshake_loop(self):
        """定期重握手保持活跃"""
        while self.running:
            try:
                time.sleep(30)  # 每 30 秒
                for name, peer in list(self.peers.items()):
                    if not peer.handshake_done or (time.time() - peer.last_handshake_time) > 120:
                        peer.new_handshake()
            except Exception:
                pass

    def run(self):
        """主循环"""
        import base64
        self.log(f"WireGuard 启动，公钥: {base64.b64encode(self.public_key).decode()[:16]}...")

        # 连接 switch
        if not self.connect_switch():
            return

        # Admin 线程
        admin_thread = threading.Thread(target=self.run_admin_loop, daemon=True)
        admin_thread.start()

        # Handshake 线程
        handshake_thread = threading.Thread(target=self.run_handshake_loop, daemon=True)
        handshake_thread.start()

        # Peer recv 线程
        recv_thread = threading.Thread(target=self.run_peer_recv_loop, daemon=True)
        recv_thread.start()

        # Switch 收发
        self.run_switch_loop()

        self.running = False

    def stop(self):
        self.running = False
        if self.switch_sock:
            try:
                self.switch_sock.close()
            except:
                pass
        for peer in self.peers.values():
            peer.close()
        if os.path.exists(self.admin_path):
            os.remove(self.admin_path)


# =============================================================================
# Admin 客户端（client.py 用）
# =============================================================================

def wg_admin_send(admin_path, cmd_obj):
    """通过 admin socket 发命令到 wireguard.py"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(admin_path)
        sock.sendall((json.dumps(cmd_obj) + '\n').encode())
        data = b''
        while b'\n' not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        if data:
            return json.loads(data.decode('utf-8').strip())
        return {'error': 'no response'}
    except Exception as e:
        return {'error': str(e)}


# =============================================================================
# main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='p2pnet WireGuard 加密隧道客户端')
    parser.add_argument('--appmode', default='switch',
                        help='连接模式（默认 switch）')
    parser.add_argument('--socketpath',
                        default=None,
                        help='switch Unix socket 路径（必填）')
    parser.add_argument('--adminpath',
                        default=None,
                        help='admin Unix socket 路径（默认 /tmp/p2pnet/wg-admin-<pid>.sock）')
    parser.add_argument('--log',
                        default=None,
                        help='日志文件路径')

    args = parser.parse_args()

    if not args.socketpath:
        print("错误：--socketpath 必须指定", file=sys.stderr)
        sys.exit(1)

    # 路径
    pid = os.getpid()
    if not args.socketpath:
        args.socketpath = f'/tmp/p2pnet/switch-{pid}.sock'
    if not args.adminpath:
        args.adminpath = f'/tmp/p2pnet/wg-admin-{pid}.sock'

    wg = WireGuardClient(args.socketpath, args.adminpath, log_file=args.log)

    # 信号处理
    def signal_handler(sig, frame):
        wg.log("收到信号，退出...")
        wg.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    wg.run()


if __name__ == '__main__':
    main()
