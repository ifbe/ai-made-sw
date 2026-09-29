# -*- coding: utf-8 -*-
"""upnp：和路由器协商直接开端口映射（协议待定，还没实现）。

计划：用 UPnP IGD（SSDP 发现 + AddPortMapping）让路由器开一个外网端口映射，
映射成功就相当于自己有公网地址，不需要打洞。
"""

from hole import core


def run():
    core.log("[upnp] 协议待定，还没实现。计划：")
    core.log("  用 UPnP IGD（SSDP 发现 + AddPortMapping）让路由器开一个外网端口映射，")
    core.log("  映射成功就相当于自己有公网地址，不需要打洞")
