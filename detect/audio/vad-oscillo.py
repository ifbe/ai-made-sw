import sounddevice as sd
import webrtcvad
import queue
import sys
from datetime import datetime
from collections import deque

# 1. 配置音频参数
SAMPLE_RATE = 16000
CHANNELS = 1
BLOCK_DURATION_MS = 20  # 底层 20ms 帧长
BLOCK_SIZE = int(SAMPLE_RATE * BLOCK_DURATION_MS / 1000)  # 320 个样本

# 2. 状态机阈值配置
START_THRESHOLD_FRAMES = 5  # 连续 5 帧(100ms) 有声音，才认为开始说话
END_THRESHOLD_FRAMES = 5    # 连续 5 帧(100ms) 无声音，才认为说话结束

# 3. 初始化 VAD
vad = webrtcvad.Vad(2)

# 4. 线程间通信队列
audio_queue = queue.Queue()

def audio_callback(indata, frames, time_info, status):
    if status:
        print(f"\n⚠️ 音频状态警告: {status}", file=sys.stderr)
    audio_queue.put(indata.copy())

def main():
    print("🎙️ 正在监听麦克风... (按 Ctrl+C 退出)")
    print(f"📊 采样率: {SAMPLE_RATE}Hz | 块大小: {BLOCK_SIZE} ({BLOCK_DURATION_MS}ms)")
    
    # 状态机变量
    state = "IDLE"             # 当前状态: IDLE (待机) 或 SPEAKING (说话中)
    consecutive_speech = 0     # 连续检测到有声音的帧数
    consecutive_silence = 0    # 连续检测到无声音的帧数
    speech_start_time = None   # 记录开始说话的时间
    speech_start_frame = 0     # 记录开始说话的帧索引
    
    # 历史记录：存储每一帧的结果 (True=有声音, False=静音)
    history = deque(maxlen=60)  # 只保留最近60帧
    
    # 帧计数器
    frame_counter = 0

    with sd.InputStream(
        samplerate=SAMPLE_RATE, 
        channels=CHANNELS, 
        blocksize=BLOCK_SIZE, 
        dtype='int16',
        callback=audio_callback
    ):
        try:
            while True:
                audio_block = audio_queue.get()
                audio_bytes = audio_block.tobytes()
                is_speech = vad.is_speech(audio_bytes, sample_rate=SAMPLE_RATE)
                
                # 每处理一帧，计数器+1
                frame_counter += 1
                
                # 记录历史
                history.append(is_speech)

                # ================= 状态机核心逻辑 =================
                
                # 【状态 1：待机中 (IDLE)】
                if state == "IDLE":
                    if is_speech:
                        consecutive_speech += 1
                        # 达到头部触发阈值，正式进入说话状态
                        if consecutive_speech >= START_THRESHOLD_FRAMES:
                            state = "SPEAKING"
                            speech_start_time = datetime.now()
                            speech_start_frame = frame_counter
                            consecutive_silence = 0
                    else:
                        consecutive_speech = 0  # 只要遇到无声音，立刻重置计数

                # 【状态 2：说话中 (SPEAKING)】
                elif state == "SPEAKING":
                    if is_speech:
                        consecutive_silence = 0  # 只要遇到有声音，重置静音计数
                    else:
                        consecutive_silence += 1
                        
                        # 达到尾部结束阈值，正式结束说话状态
                        if consecutive_silence >= END_THRESHOLD_FRAMES:
                            # 使用帧索引计算时长（更精确）
                            duration_ms = (frame_counter - speech_start_frame) * BLOCK_DURATION_MS
                            timestamp = speech_start_time.strftime("%H:%M:%S.%f")[:-3]
                            
                            # 换行打印最终结果
                            #print(f"\n{timestamp}  {duration_ms}ms")
                            
                            # 状态重置
                            state = "IDLE"       
                            consecutive_speech = 0
                            consecutive_silence = 0

                # ================= 控制台单行刷新显示 =================
                # 构建历史字符串：o=有声音，.=静音，补齐到60个字符
                history_str = ''.join(['o' if h else '.' for h in history])
                history_str = history_str.ljust(60)
                
                if state == "SPEAKING":
                    current_duration = (frame_counter - speech_start_frame) * BLOCK_DURATION_MS
                    status_line = f"{history_str} [说话中 {current_duration}ms]"
                else:
                    status_line = f"{history_str} [待机中]        "
                
                print(f"\r{status_line}", end="", flush=True)

        except KeyboardInterrupt:
            print("\n\n👋 麦克风监听已停止。")

if __name__ == "__main__":
    main()