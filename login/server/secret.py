#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码管理工具 - 类似/etc/passwd的加盐哈希密码存储
支持命令: list, add, del, mod, verify, testauth
"""

import os
import sys
import getpass
import hashlib
import secrets
import json
import argparse
import hmac
from datetime import datetime

class PasswordManager:
    def __init__(self, passwd_file='passwd.json'):
        """初始化密码管理器"""
        self.passwd_file = passwd_file
        self.users = self._load_users()
    
    def _load_users(self):
        """加载用户数据"""
        if os.path.exists(self.passwd_file):
            try:
                with open(self.passwd_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"警告: 无法读取密码文件: {e}", file=sys.stderr)
                return {}
        return {}
    
    def _save_users(self):
        """保存用户数据"""
        if os.path.exists(self.passwd_file):
            backup_file = f"{self.passwd_file}.bak"
            try:
                import shutil
                shutil.copy2(self.passwd_file, backup_file)
            except:
                pass
        
        try:
            with open(self.passwd_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)
            os.chmod(self.passwd_file, 0o600)
            return True
        except IOError as e:
            print(f"错误: 无法保存密码文件: {e}", file=sys.stderr)
            return False
    
    def _generate_salt(self, length=16):
        """生成随机盐值"""
        return secrets.token_hex(length)
    
    def _hash_password(self, password, salt=None):
        """
        生成密码哈希
        返回格式: salt:hash
        """
        if salt is None:
            salt = self._generate_salt()
        
        # 使用 SHA256
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt).encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        
        return f"{salt}:{password_hash}"
    
    def _verify_password(self, password, stored_hash):
        """验证密码"""
        try:
            # 解析哈希格式
            if ':' not in stored_hash:
                print(f"警告: 不支持的哈希格式: {stored_hash[:20]}...", file=sys.stderr)
                return False
            
            salt, hash_value = stored_hash.split(':', 1)
            
            # 重新计算哈希
            hash_obj = hashlib.sha256()
            hash_obj.update((password + salt).encode('utf-8'))
            calculated_hash = hash_obj.hexdigest()
            
            return secrets.compare_digest(calculated_hash, hash_value)
        except Exception as e:
            print(f"验证错误: {e}", file=sys.stderr)
            return False
    
    def list_users(self, show_details=False):
        """列出所有用户"""
        if not self.users:
            print("没有用户")
            return
        
        print(f"\n用户列表 (共 {len(self.users)} 个):")
        print("-" * 60)
        
        for username, info in sorted(self.users.items()):
            if show_details:
                created = info.get('created', '未知')
                modified = info.get('modified', '未知')
                hash_value = info.get('hash', '')
                print(f"用户名: {username}")
                print(f"  哈希: {hash_value[:30]}...")
                print(f"  创建: {created}")
                print(f"  修改: {modified}")
            else:
                print(f"  • {username}")
        
        print("-" * 60)
    
    def add_user(self, username, password=None, interactive=True):
        """添加新用户"""
        if username in self.users:
            print(f"错误: 用户 '{username}' 已存在", file=sys.stderr)
            return False
        
        if interactive:
            print(f"添加用户: {username}")
            if password is None:
                password = getpass.getpass("输入密码: ")
                confirm = getpass.getpass("确认密码: ")
                if password != confirm:
                    print("错误: 两次输入的密码不一致", file=sys.stderr)
                    return False
        
        if not password:
            print("错误: 密码不能为空", file=sys.stderr)
            return False
        
        password_hash = self._hash_password(password)
        
        self.users[username] = {
            'hash': password_hash,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat(),
            'nickname': username
        }
        
        if self._save_users():
            print(f"用户 '{username}' 添加成功")
            print(f"密码哈希: {password_hash}")
            return True
        return False
    
    def delete_user(self, username, force=False):
        """删除用户"""
        if username not in self.users:
            print(f"错误: 用户 '{username}' 不存在", file=sys.stderr)
            return False
        
        if not force:
            confirm = input(f"确定要删除用户 '{username}'? [y/N] ")
            if confirm.lower() not in ['y', 'yes']:
                print("取消删除")
                return False
        
        del self.users[username]
        
        if self._save_users():
            print(f"用户 '{username}' 删除成功")
            return True
        return False
    
    def modify_user(self, username, new_password=None):
        """修改用户密码"""
        if username not in self.users:
            print(f"错误: 用户 '{username}' 不存在", file=sys.stderr)
            return False
        
        print(f"修改用户密码: {username}")
        
        # 验证旧密码（可选）
        verify_old = input("是否验证旧密码? [y/N] ").lower() in ['y', 'yes']
        if verify_old:
            old_password = getpass.getpass("输入旧密码: ")
            if not self._verify_password(old_password, self.users[username]['hash']):
                print("错误: 旧密码错误", file=sys.stderr)
                return False
        
        if new_password is None:
            new_password = getpass.getpass("输入新密码: ")
            confirm = getpass.getpass("确认新密码: ")
            if new_password != confirm:
                print("错误: 两次输入的密码不一致", file=sys.stderr)
                return False
        
        new_hash = self._hash_password(new_password)
        
        self.users[username]['hash'] = new_hash
        self.users[username]['modified'] = datetime.now().isoformat()
        
        if self._save_users():
            print(f"用户 '{username}' 密码修改成功")
            print(f"新密码哈希: {new_hash}")
            return True
        return False
    
    def verify_user(self, username, password=None):
        """验证用户密码（本地验证）"""
        if username not in self.users:
            print(f"错误: 用户 '{username}' 不存在")
            return False
        
        if password is None:
            password = getpass.getpass("输入密码: ")
        
        stored_hash = self.users[username]['hash']
        print(f"存储的哈希: {stored_hash}")
        
        if self._verify_password(password, stored_hash):
            print(f"✅ 用户 '{username}' 密码验证成功")
            return True
        else:
            print(f"❌ 用户 '{username}' 密码验证失败")
            return False
    
    def debug_user(self, username):
        """调试用户信息"""
        if username not in self.users:
            print(f"用户 '{username}' 不存在")
            return
        
        print(f"\n用户 '{username}' 的详细信息:")
        print("-" * 40)
        info = self.users[username]
        for key, value in info.items():
            if key == 'hash':
                print(f"  {key}: {value}")
                if ':' in value:
                    salt, hash_part = value.split(':', 1)
                    print(f"    salt: {salt}")
                    print(f"    hash: {hash_part[:20]}...")
            else:
                print(f"  {key}: {value}")
        print("-" * 40)
    
    def test_auth(self, username, password=None):
        """
        测试完整的挑战-响应认证流程
        模拟前端和后端的交互过程
        """
        if username not in self.users:
            print(f"错误: 用户 '{username}' 不存在")
            return False
        
        print("=" * 60)
        print(f"挑战-响应认证测试 - 用户: {username}")
        print("=" * 60)
        
        # 1. 获取存储的哈希
        stored_hash = self.users[username]['hash']
        print(f"\n[1] 存储的哈希: {stored_hash}")
        
        # 2. 提取盐值和密码哈希
        if ':' in stored_hash:
            salt, password_hash = stored_hash.split(':', 1)
            print(f"[2] 提取的盐值: {salt}")
            print(f"    提取的密码哈希: {password_hash}")
        else:
            print(f"[2] 错误: 哈希格式异常")
            return False
        
        # 3. 生成挑战码（模拟服务器）
        challenge = secrets.token_hex(32)
        print(f"\n[3] 服务器生成挑战码: {challenge}")
        
        # 4. 前端计算响应（模拟前端）
        if password is None:
            password = getpass.getpass("\n[4] 请输入密码进行测试: ")
        
        # 重要修正：前端计算密码哈希时需要使用相同的盐值！
        # 实际前端不知道盐值，所以这个测试需要模拟正确的流程
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt).encode('utf-8'))
        frontend_password_hash = hash_obj.hexdigest()
        print(f"[4.1] 前端计算密码哈希 (password + salt): {frontend_password_hash}")
        
        # 前端：HMAC-SHA256(密码哈希, 挑战码)
        frontend_response = hmac.new(
            frontend_password_hash.encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()
        print(f"[4.2] 前端计算响应: {frontend_response}")
        
        # 5. 后端验证（模拟服务器）
        print(f"\n[5] 服务器验证:")
        
        # 后端使用存储的密码哈希计算期望值
        expected_response = hmac.new(
            password_hash.encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()
        print(f"    期望的响应: {expected_response}")
        print(f"    收到的响应: {frontend_response}")
        
        # 安全比较
        if hmac.compare_digest(expected_response, frontend_response):
            print("\n✅ 认证成功！前后端验证一致")
            
            # 6. 生成会话token
            session_token = secrets.token_hex(32)
            print(f"   生成的会话token: {session_token[:16]}...")
            
            return True
        else:
            print("\n❌ 认证失败！响应不匹配")
            
            # 诊断信息
            print("\n[诊断信息]")
            print(f"存储的密码哈希: {password_hash}")
            print(f"前端计算的密码哈希: {frontend_password_hash}")
            
            if password_hash != frontend_password_hash:
                print("⚠️  密码哈希不匹配！")
                print(f"   存储的哈希: {password_hash[:20]}...")
                print(f"   前端计算的: {frontend_password_hash[:20]}...")
                print(f"   使用的盐值: {salt}")
            else:
                print("✓ 密码哈希一致，问题可能在HMAC计算")
            
            return False

def main():
    parser = argparse.ArgumentParser(description='密码管理工具')
    
    parser.add_argument('-f', '--file', default='passwd.json', help='密码文件路径')
    
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='列出所有用户')
    list_parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    
    # add 命令
    add_parser = subparsers.add_parser('add', help='添加用户')
    add_parser.add_argument('username', help='用户名')
    add_parser.add_argument('-p', '--password', help='密码')
    
    # del 命令
    del_parser = subparsers.add_parser('del', help='删除用户')
    del_parser.add_argument('username', help='用户名')
    del_parser.add_argument('-f', '--force', action='store_true', help='强制删除')
    
    # mod 命令
    mod_parser = subparsers.add_parser('mod', help='修改用户密码')
    mod_parser.add_argument('username', help='用户名')
    mod_parser.add_argument('-p', '--password', help='新密码')
    
    # verify 命令
    verify_parser = subparsers.add_parser('verify', help='验证用户密码')
    verify_parser.add_argument('username', help='用户名')
    verify_parser.add_argument('-p', '--password', help='密码（直接输入，不推荐）')
    
    # debug 命令
    debug_parser = subparsers.add_parser('debug', help='调试用户信息')
    debug_parser.add_argument('username', help='用户名')
    
    # testauth 命令
    testauth_parser = subparsers.add_parser('testauth', help='测试挑战-响应认证流程')
    testauth_parser.add_argument('username', help='用户名')
    testauth_parser.add_argument('-p', '--password', help='密码（直接输入，不推荐）')
    
    args = parser.parse_args()
    
    pm = PasswordManager(args.file)
    
    if args.command == 'list':
        pm.list_users(show_details=args.verbose)
    
    elif args.command == 'add':
        pm.add_user(args.username, args.password)
    
    elif args.command == 'del':
        pm.delete_user(args.username, args.force)
    
    elif args.command == 'mod':
        pm.modify_user(args.username, args.password)
    
    elif args.command == 'verify':
        pm.verify_user(args.username, args.password)
    
    elif args.command == 'debug':
        pm.debug_user(args.username)
    
    elif args.command == 'testauth':
        pm.test_auth(args.username, args.password)
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
