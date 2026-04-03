#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet hub：中心交换进程

职责：
  维护一张路由表：peer_name → (app_socket, remote_socket)
  select 监听所有子进程 socket，收到数据后查表转发到对应目标

子进程类型：
  remote/udp.py   × m 个  — m 个 UDP P2P 连接
  remote/tcp.py   × n 个  — n 个 TCP P2P 连接
  app/tun.py  / app/tap.py — × 1 个  — IP / Ethernet 隧道

内部结构：

  Hub 监听：
    /tmp/p2p/{username}/hub.sock  （Unix DGRAM server，所有子进程连入）

  子进程注册（连入时首包）：
    remote udp →  {"type": "register", "role": "remote", "transport": "udp", "peer": "bob"}
    remote tcp →  {"type": "register", "role": "remote", "transport": "tcp", "peer": "bob"}
    app tun/tap → {"type": "register", "role": "app", "mode": "tun", "peer": "bob"}

  路由表：
    peer "bob" -> {
        "remote_udp": <socket_path for bob's udp.py>,
        "remote_tcp": <socket_path for bob's tcp.py>,  # 如果有
        "app": <socket_path for bob's tun.py>,
    }

  收到的包格式（所有子进程发给 hub 的统一格式）：
    {
        "type": "data",
        "peer": "bob",           # 目标 peer
        "transport": "udp" | "tcp" | None,  # 走哪个 remote，None 表示所有
        "payload": <bytes>,
        "from": "bob",            # 来源（app 或 remote）
    }

  数据流：

    app -> hub -> remote（发送方向）：
      app/tun.py 收到 IP 包
        -> hub（Unix DGRAM）
        -> hub 查路由表，找 remote socket
        -> remote/udp.py  或 remote/tcp.py 发送

    remote -> hub -> app（接收方向）：
      remote/udp.py 收到 P2P 数据
        -> hub（Unix DGRAM）
        -> hub 查路由表，找 app socket
        -> app/tun.py 写入

    remote <-> remote（tun/tap 模式下，IP 包直接双向转发）：
      remote/udp.py <-> hub <-> app/tun.py  形成闭环
      app/tun.py 从 tun 读，写回 hub，hub 转发给 remote

  select 循环：

    所有 socket 分两类：
      hub_sock（监听子进程连入）
      registered_socks[]（已注册的子进程 socket，map {sock -> handler}）

    while True:
      readable, _, exceptional = select.select([hub_sock] + registered_socks, [], [])

      for sock in readable:
        if sock is hub_sock:
          conn, addr = hub_sock.accept()
          registered_socks.append(conn)

        elif sock in remote_handlers:
          data, addr = sock.recvfrom(65535)
          remote_handler = remote_handlers[sock]
          peer = remote_handler.peer
          # 查 app socket，投递到 app
          if peer in routing_table and routing_table[peer]['app']:
            routing_table[peer]['app'].sendto(data, addr)

        elif sock in app_handlers:
          data = sock.recv(65535)
          app_handler = app_handlers[sock]
          peer = app_handler.peer
          mode = app_handler.mode
          # 查所有 remote socket，轮询或广播
          if peer in routing_table:
            rt = routing_table[peer]
            if rt.get('remote_udp'):
              rt['remote_udp'].sendto(data, addr)
            if rt.get('remote_tcp'):
              rt['remote_tcp'].send(data)

  注意事项：
    - TCP remote 的 send 是流式的，需要自行处理分包
    - m 个 UDP + n 个 TCP + 1 个 tun/tap，Hub 只做转发，不改数据
    - Hub 崩溃/退出时，client.py 负责重启并重新分发 peer 路由信息
"""
