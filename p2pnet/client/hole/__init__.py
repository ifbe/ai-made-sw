# -*- coding: utf-8 -*-
"""打洞：每个洞的打洞步骤（都在 client.py 主进程里跑）。

    udp.py     UDP 打洞 6 步（hello burst → 服务器告知地址 → 互发 ping/pong）
    tcp.py     TCP 打洞 5 步（注册 → 服务器告知地址 → 同时 listen/connect → 交内核 fd）
    direct.py  直连（占位，协议待定）
    upnp.py    路由器开端口映射（占位，协议待定）

洞的**总表格**（记录列表 + 锁 + 查/删）在 client.py：这里只负责"某个洞怎么打"。
打洞成功后通过 ctx 回调 client.py，由 client.py 决定自动拉起哪个 app/ 下的协议。

注意：__init__ 里**不要** import 上面这些子模块，否则会和
`from hole import core` 形成循环导入；client.py 直接 `from hole import udp, tcp` 。
"""


def stop_hole(hole):
    """关掉一个洞的 socket、停掉它的 ping 线程（协议无关）

    TCP 洞没有 socket，只有状态，所以这里是空操作。
    """
    hole['stop'].set()
    sock = hole.get('sock')
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
        hole['sock'] = None
