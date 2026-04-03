#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet 密码学工具

实现：
  - HKDF-SHA256
  - HMAC-SHA256
  - ECDH 密钥交换（X25519）
  - ChaCha20-Poly1305 对称加密
"""

import os
import hmac
import hashlib
import struct
import secrets

# ---- HKDF-SHA256 ----

def hkdf_sha256(ikm, salt, info=b''):
    """HKDF-SHA256(IKM, salt, info) -> 32-byte key"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''
    okm = b''
    i = 1
    while len(okm) < 32:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:32]


# ---- HMAC-SHA256 ----

def hmac_sha256(key, data):
    """HMAC-SHA256"""
    return hmac.new(key, data, hashlib.sha256).digest()


# ---- ECDH X25519 ----

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization
    HAS_X25519 = True
except ImportError:
    HAS_X25519 = False


def ecdh_keygen():
    """
    生成 ECDH X25519 临时密钥对。
    返回 (private_key_bytes, public_key_bytes)
    """
    if not HAS_X25519:
        raise RuntimeError("cryptography 库未安装：pip install cryptography")
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        priv.private_bytes(
            encoding=serialization.Encoding.raw,
            format=serialization.PrivateFormat.raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        pub.public_bytes(
            encoding=serialization.Encoding.raw,
            format=serialization.PublicFormat.raw
        )
    )


def ecdh_shared(priv_a: bytes, pub_b: bytes) -> bytes:
    """
    ECDH 共享密钥：ECDH(priv_a, pub_b) -> 32-byte shared secret
    priv_a / pub_b 均为原始字节（32 bytes X25519）
    """
    if not HAS_X25519:
        raise RuntimeError("cryptography 库未安装：pip install cryptography")
    priv = X25519PrivateKey.from_encoded_bytes(priv_a)
    pub = X25519PublicKey.from_encoded_bytes(pub_b)
    shared = priv.exchange(pub)
    # X25519 共享密钥已是 32 bytes，但做一次 HKDF 衍生更安全
    return hkdf_sha256(shared, salt=b'p2pnet-v1')


# ---- ChaCha20-Poly1305 ----

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    HAS_CHACHAPOLY = True
except ImportError:
    HAS_CHACHAPOLY = False


def chacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    ChaCha20-Poly1305 加密。
    key: 32 bytes
    nonce: 12 bytes（每次加密必须不同，推荐 secrets.randbytes(12)）
    plaintext: 任意长度
    返回：ciphertext + tag（cryptography 库自动 append tag）
    """
    if not HAS_CHACHAPOLY:
        raise RuntimeError("cryptography 库未安装：pip install cryptography")
    cp = ChaCha20Poly1305(key)
    return cp.encrypt(nonce, plaintext, None)


def chacha20_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    ChaCha20-Poly1305 解密。
    key: 32 bytes
    nonce: 12 bytes
    ciphertext: 密文（含 Poly1305 tag）
    返回：明文（AuthenticityError 如果验证失败）
    """
    if not HAS_CHACHAPOLY:
        raise RuntimeError("cryptography 库未安装：pip install cryptography")
    cp = ChaCha20Poly1305(key)
    return cp.decrypt(nonce, ciphertext, None)


# ---- 辅助 ----

def new_nonce(n=12):
    """生成随机的 12-byte nonce"""
    return secrets.randbytes(n)
