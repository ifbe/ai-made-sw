#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet proxy：网络转发业务

把打洞建立的 P2P 连接当作裸 TCP/UDP 通道：
  - 从 udp.py/tcp.py 收到的数据 → netcat 转发到指定地址:端口
  - netcat 收到的数据 → 发回 udp.py/tcp.py

典型用法：
  - 远程桌面：proxy 连接对端主机的 3389
  - SSH：proxy 连接对端 22 端口
  - 端口转发：proxy 把打洞流量转发到任意服务
"""
