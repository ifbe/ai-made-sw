import sounddevice as sd
import webrtcvad
import queue
from datetime import datetime

SAMPLE_RATE = 16000
BLOCK_SIZE = 320

vad = webrtcvad.Vad(2)
audio_queue = queue.Queue()
frame_counter = 0

def audio_callback(indata, frames, time_info, status):
    global frame_counter
    if status:
        print(f"\n⚠️ {status}")
    audio_queue.put((indata.copy(), time_info, frame_counter))
    frame_counter += 1

def main():
    print("🎙️ 正在监听麦克风... (按 Ctrl+C 退出)")
    
    with sd.InputStream(
        samplerate=SAMPLE_RATE,
        channels=1,
        blocksize=BLOCK_SIZE,
        dtype='int16',
        callback=audio_callback
    ):
        try:
            while True:
                audio_block, time_info, frame_idx = audio_queue.get()
                is_speech = vad.is_speech(audio_block.tobytes(), SAMPLE_RATE)
                
                # 获取 inputBufferAdcTime
                adc_time = getattr(time_info, 'inputBufferAdcTime', None)
                if adc_time is not None and adc_time > 0:
                    timestamp = datetime.fromtimestamp(adc_time).strftime("%H:%M:%S.%f")[:-3]
                else:
                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                
                symbol = "✅" if is_speech else "❌"
                print(f"\r[{frame_idx:>6}] [{timestamp}] {symbol}", end="", flush=True)
                
        except KeyboardInterrupt:
            print("\n\n👋 已停止监听。")

if __name__ == "__main__":
    main()