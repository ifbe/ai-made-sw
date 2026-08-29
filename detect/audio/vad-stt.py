import sounddevice as sd
import webrtcvad
import queue
import sys
import wave
import io
import threading
import itertools
import requests
from datetime import datetime
from collections import deque

# ================== 配置区 ==================
SERVER_URL = "http://macmini.local:12345"
API_KEY = "52755227"
MODEL_NAME = "Qwen3-ASR-0.6B-4bit"
API_ENDPOINT = "/v1/audio/transcriptions"
# ============================================

# 1. 配置音频参数
SAMPLE_RATE = 16000
CHANNELS = 1
BLOCK_DURATION_MS = 20
BLOCK_SIZE = int(SAMPLE_RATE * BLOCK_DURATION_MS / 1000)

# 2. 状态机阈值配置
START_THRESHOLD_FRAMES = 5  # 连续 100ms 有声音触发
END_THRESHOLD_FRAMES = 10   # 连续 200ms 无声音结束

# 3. 初始化 VAD 和 全局流水号
vad = webrtcvad.Vad(1)
seq_generator = itertools.count(1)  # 从 1 开始无限递增

# 4. 线程间通信队列
audio_queue = queue.Queue()      # 音频采集线程 -> 主线程
send_queue = queue.Queue()       # 主线程 -> 发送线程

# 5. 全局状态行
status_line = "[待机中]"

def print_log(msg):
    """打印日志，然后恢复状态行"""
    print(f"\r\033[K{msg}")
    print(f"\r{status_line}", end="", flush=True)

def print_status():
    print(f"\r\033[K{status_line}", end="", flush=True)

# 6. 后台发送线程逻辑
def sender_worker():
    while True:
        task = send_queue.get()
        if task is None: break  # 收到退出信号

        current_seq, wav_bytes = task

        # 准备请求数据
        files = {
            'file': ('audio.wav', wav_bytes, 'audio/wav'),
        }
        data = {
            'model': MODEL_NAME,
            'stream': 'true'
        }
        headers = {
            'Authorization': f'Bearer {API_KEY}'
        }

        try:
            # 发送 POST 请求
            with requests.post(
                f"{SERVER_URL}{API_ENDPOINT}",
                headers=headers,
                files=files,
                data=data,
                stream=True,
                timeout=30
            ) as response:
                response.raise_for_status() # 检查HTTP错误

                # 处理流式响应
                recognized_text = ""

                for line in response.iter_lines():
                    if line:
                        try:
                            line_str = line.decode('utf-8')
                            if line_str.startswith('data: '):
                                json_str = line_str[6:]
                                if json_str != '[DONE]':
                                    import json
                                    chunk = json.loads(json_str)
                                    if chunk.get('type') == 'transcript.text.done':
                                        recognized_text = chunk.get('text', '')
                                        now = datetime.now()
                                        print_log(f"recv👋seq={current_seq} msg={recognized_text}")
                        except:
                            pass

        except Exception as e:
            print_log(f"❌ seq={current_seq} msg=请求失败: {e}")

        send_queue.task_done()

def audio_callback(indata, frames, time_info, status):
    if status:
        print_log(f"⚠️ 音频状态警告: {status}")
    audio_queue.put(indata.copy())

def main():
    global status_line
    
    print("🎙️ 正在监听麦克风... (按 Ctrl+C 退出)")
    
    # 初始化状态行
    status_line = "[待机中]"
    print_status()
    
    # 启动后台发送线程
    sender_thread = threading.Thread(target=sender_worker, daemon=True)
    sender_thread.start()

    # 状态机变量
    state = "IDLE"
    audio_buffer = []
    consecutive_speech = 0
    consecutive_silence = 0
    speech_start_time = None
    speech_start_frame = 0  # 【新增】记录开始说话的帧索引
    
    # 历史记录
    history = deque(maxlen=60)
    
    # 【新增】帧计数器
    frame_counter = 0

    with sd.InputStream(
        samplerate=SAMPLE_RATE, channels=CHANNELS, 
        blocksize=BLOCK_SIZE, dtype='int16', callback=audio_callback
    ):
        try:
            while True:
                audio_block = audio_queue.get()
                audio_bytes = audio_block.tobytes()
                is_speech = vad.is_speech(audio_bytes, sample_rate=SAMPLE_RATE)
                
                # 【新增】每处理一帧，计数器+1
                frame_counter += 1
                
                # 记录历史
                history.append(is_speech)

                # ================= 状态机核心逻辑 =================
                
                # 【状态 1：待机中 (IDLE)】
                if state == "IDLE":
                    if is_speech:
                        consecutive_speech += 1
                        if consecutive_speech >= START_THRESHOLD_FRAMES:
                            state = "SPEAKING"
                            speech_start_time = datetime.now()
                            speech_start_frame = frame_counter  # 【新增】记录开始帧
                            consecutive_silence = 0
                            audio_buffer = [audio_block.copy()]
                    else:
                        consecutive_speech = 0

                # 【状态 2：说话中 (SPEAKING)】
                elif state == "SPEAKING":
                    audio_buffer.append(audio_block.copy())
                    
                    if is_speech:
                        consecutive_silence = 0
                    else:
                        consecutive_silence += 1
                        
                        if consecutive_silence >= END_THRESHOLD_FRAMES:
                            # 1. 计算时长并格式化时间戳（使用帧索引计算）
                            duration_ms = (frame_counter - speech_start_frame) * BLOCK_DURATION_MS
                            timestamp = speech_start_time.strftime("%H:%M:%S.%f")[:-3]  # 修复：加上秒数
                            
                            # 2. 打印，发送
                            if duration_ms >= 500:
                                # 打印流水号
                                current_seq = next(seq_generator)
                                print_log(f"send✅{timestamp} {duration_ms}ms seq={current_seq}")
                            
                                # 将音频打包成 WAV 格式并放入发送队列
                                wav_buffer = io.BytesIO()
                                with wave.open(wav_buffer, 'wb') as wf:
                                    wf.setnchannels(CHANNELS)
                                    wf.setsampwidth(2)  # int16 = 2 bytes
                                    wf.setframerate(SAMPLE_RATE)
                                    wf.writeframes(b''.join([b.tobytes() for b in audio_buffer]))
                                send_queue.put((current_seq, wav_buffer.getvalue()))
                            else:
                                print_log(f"drop❌{timestamp} {duration_ms}ms")

                            # 3. 状态重置
                            state = "IDLE"
                            audio_buffer = []
                            consecutive_speech = 0
                            consecutive_silence = 0

                # ================= 控制台单行刷新显示 =================
                # 构建历史字符串：o=有声音，.=静音
                history_str = ''.join(['o' if h else '.' for h in history])
                # 补齐到60个字符（不足用空格填充）
                history_str = history_str.ljust(60)
                
                if state == "SPEAKING":
                    current_duration = (frame_counter - speech_start_frame) * BLOCK_DURATION_MS  # 使用帧索引计算
                    status_line = f"{history_str} [说话中 {current_duration}ms]"
                else:
                    status_line = f"{history_str} [待机中]        "
                
                print_status()

        except KeyboardInterrupt:
            print("\n\n👋 麦克风监听已停止。")

if __name__ == "__main__":
    main()