#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet media：RTMP 输入/输出

RTMP 输入（对端推流过来，本地播放）：
  - 监听本地 RTMP 端口
  - 接收对端的 FLV 流
  - 解码播放（ffplay / SDL）

RTMP 输出（本地推流给对端）：
  - 捕获麦克风/摄像头
  - ffmpeg 编码 + FLV 封装
  - 通过 TCP 打洞建立的连接推流给对端
"""
