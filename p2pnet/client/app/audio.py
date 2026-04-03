#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet 音频业务进程
双向音频：麦克风捕获 + 扬声器播放

数据流：
  接收方向：网络 bytes → 解密 → 音频数据写入扬声器
  发送方向：麦克风捕获 → 编码 → 加密 → 网络

依赖：pip install pyaudio
      （Linux 需先安装 portaudio：apt install portaudio19-dev）
"""

import sys
import os
import argparse
import threading
import socket
import time

try:
    import pyaudio
    HAS_PYAUDIO = True
except ImportError:
    HAS_PYAUDIO = False


DEFAULT_CHANNELS = 1      # 语音单声道
DEFAULT_RATE = 16000       # 语音采样率
CHUNK_SIZE = 1024          # 每次读取的采样帧数


def list_devices(p):
    """列出所有音频设备"""
    print("可用音频设备：", file=sys.stderr)
    print(f"  {'index':<6} {'name':<40} {'in':>4} {'out':>4} {'default rate':>12}", file=sys.stderr)
    print(f"  {'-'*6} {'-'*40} {'-'*4} {'-'*4} {'-'*12}", file=sys.stderr)
    for i in range(p.get_device_count()):
        info = p.get_device_info_by_index(i)
        in_ch = info['maxInputChannels']
        out_ch = info['maxOutputChannels']
        if in_ch > 0 or out_ch > 0:
            print(f"  {i:<6} {info['name']:<40} {in_ch:>4} {out_ch:>4} {info['defaultSampleRate']:>12.0f}", file=sys.stderr)


def find_device(p, name_or_idx, io_type='input'):
    """
    根据设备名或 index 查找设备。
    io_type: 'input'（麦克风）或 'output'（喇叭）
    返回 (device_index, channels, rate)
    """
    if isinstance(name_or_idx, str) and name_or_idx.isdigit():
        idx = int(name_or_idx)
    elif isinstance(name_or_idx, str):
        # 按名字搜索（模糊匹配）
        idx = None
        for i in range(p.get_device_count()):
            info = p.get_device_info_by_index(i)
            if name_or_idx.lower() in info['name'].lower():
                idx = i
                break
        if idx is None:
            raise ValueError(f"找不到设备：{name_or_idx}")
    else:
        idx = int(name_or_idx)

    info = p.get_device_info_by_index(idx)
    if io_type == 'input' and info['maxInputChannels'] == 0:
        raise ValueError(f"设备 {idx}（{info['name']}）不支持输入")
    if io_type == 'output' and info['maxOutputChannels'] == 0:
        raise ValueError(f"设备 {idx}（{info['name']}）不支持输出")

    # 取设备推荐值
    rate = int(info['defaultSampleRate'])
    max_ch = info['maxInputChannels'] if io_type == 'input' else info['maxOutputChannels']
    channels = 1 if max_ch == 1 else 2  # 优先立体声（如支持）

    return idx, channels, rate


class AudioSession:
    """双向音频会话：同时录音和播放"""

    def __init__(self, input_idx, output_idx, in_channels, in_rate,
                 out_channels, out_rate, recv_cb, send_cb):
        self.input_idx = input_idx
        self.output_idx = output_idx
        self.in_channels = in_channels
        self.in_rate = in_rate
        self.out_channels = out_channels
        self.out_rate = out_rate
        self.recv_cb = recv_cb    # 上层给的回调：发送数据时调用
        self.send_cb = send_cb    # 上层给的回调：收到数据时调用
        self.running = False
        self.p = None
        self.in_stream = None
        self.out_stream = None
        self.in_thread = None

    def start(self):
        if not HAS_PYAUDIO:
            raise RuntimeError("pyaudio 未安装，请运行：pip install pyaudio")

        self.p = pyaudio.PyAudio()

        # 打开输入流（麦克风）
        self.in_stream = self.p.open(
            input=True,
            input_device_index=self.input_idx,
            channels=self.in_channels,
            rate=self.in_rate,
            format=pyaudio.paInt16,
            frames_per_buffer=CHUNK_SIZE,
            stream_callback=self._in_callback,
        )

        # 打开输出流（喇叭）
        self.out_stream = self.p.open(
            output=True,
            output_device_index=self.output_idx,
            channels=self.out_channels,
            rate=self.out_rate,
            format=pyaudio.paInt16,
            frames_per_buffer=CHUNK_SIZE,
        )

        self.running = True
        self.in_stream.start_stream()

        print(f"[audio] 启动成功", file=sys.stderr)
        print(f"[audio] 麦克风：设备 {self.input_idx}  {self.in_channels}ch {self.in_rate}Hz", file=sys.stderr)
        print(f"[audio] 喇叭：  设备 {self.output_idx}  {self.out_channels}ch {self.out_rate}Hz", file=sys.stderr)

        # 用线程读输入流，避免阻塞
        self.in_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.in_thread.start()

    def _in_callback(self, in_data, frame_count, time_info, status):
        """PyAudio 输入回调（线程安全，直接返回）"""
        return (None, pyaudio.paContinue)

    def _read_loop(self):
        """从麦克风读取数据，通过 send_cb 发送"""
        while self.running and self.in_stream.is_active():
            try:
                data = self.in_stream.read(CHUNK_SIZE, exception_on_overflow=False)
                if data and self.send_cb:
                    self.send_cb(data)
            except Exception as e:
                print(f"[audio] 读取麦克风错误: {e}", file=sys.stderr)
                break

    def write(self, data: bytes):
        """收到网络数据，写入喇叭播放"""
        if not self.running or not self.out_stream:
            return
        try:
            self.out_stream.write(data)
        except Exception as e:
            print(f"[audio] 播放错误: {e}", file=sys.stderr)

    def stop(self):
        self.running = False
        if self.in_stream:
            self.in_stream.stop_stream()
            self.in_stream.close()
        if self.out_stream:
            self.out_stream.stop_stream()
            self.out_stream.close()
        if self.p:
            self.p.terminate()
        print("[audio] 已停止", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='p2pnet 音频业务')
    parser.add_argument('--input-device', default='-1',
                        help='麦克风设备 index 或名字（默认：系统默认）')
    parser.add_argument('--output-device', default='-1',
                        help='喇叭设备 index 或名字（默认：系统默认）')
    parser.add_argument('--channels', type=int, default=None,
                        help='声道数（不指定则用设备推荐值）')
    parser.add_argument('--rate', type=int, default=None,
                        help='采样率 Hz（不指定则用设备推荐值）')
    parser.add_argument('--list-devices', action='store_true',
                        help='列出所有音频设备并退出')
    args = parser.parse_args()

    if not HAS_PYAUDIO:
        print("错误：pyaudio 未安装", file=sys.stderr)
        print("  pip install pyaudio", file=sys.stderr)
        sys.exit(1)

    p = pyaudio.PyAudio()

    if args.list_devices:
        list_devices(p)
        p.terminate()
        sys.exit(0)

    # 确定输入设备
    if args.input_device == '-1':
        in_idx = -1
        in_info = p.get_device_info_by_index(-1)
        in_channels = DEFAULT_CHANNELS
        in_rate = DEFAULT_RATE
    else:
        in_idx, in_channels, in_rate = find_device(p, args.input_device, 'input')

    # 确定输出设备
    if args.output_device == '-1':
        out_idx = -1
        out_channels = DEFAULT_CHANNELS
        out_rate = DEFAULT_RATE
    else:
        out_idx, out_channels, out_rate = find_device(p, args.output_device, 'output')

    # 用户指定的参数覆盖设备推荐值
    if args.channels is not None:
        in_channels = args.channels
        out_channels = args.channels
    if args.rate is not None:
        in_rate = args.rate
        out_rate = args.rate

    p.terminate()

    # stdin 接收，stdout 发送（与 remote/udp.py 的 stdin/stdout 对接）
    def send_cb(data):
        """麦克风数据写入 stdout，发给 remote"""
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    def recv_cb(data):
        """从 stdin 读取网络数据，写入喇叭"""
        session.write(data)

    # 从 stdin 读取远端数据
    def stdin_reader():
        while session.running:
            try:
                data = sys.stdin.buffer.read(1024)
                if not data:
                    break
                recv_cb(data)
            except Exception as e:
                print(f"[audio] stdin 错误: {e}", file=sys.stderr)
                break

    session = AudioSession(
        input_idx=in_idx,
        output_idx=out_idx,
        in_channels=in_channels,
        in_rate=in_rate,
        out_channels=out_channels,
        out_rate=out_rate,
        recv_cb=recv_cb,
        send_cb=send_cb,
    )

    session.start()

    # stdin 线程：读取远端发来的音频数据
    reader_thread = threading.Thread(target=stdin_reader, daemon=True)
    reader_thread.start()

    # 等待结束
    try:
        while session.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        session.stop()


if __name__ == '__main__':
    main()
