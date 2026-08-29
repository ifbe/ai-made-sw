import cv2
from ultralytics import YOLO
import time
from datetime import datetime
import os
import numpy as np
from collections import deque
import subprocess
import threading
import queue

# ========== 配置 ==========
MODEL_PATH = "yolov8n.pt"
CONFIDENCE = 0.4
FRAME_WIDTH = 640
FRAME_HEIGHT = 360
FPS = 15

START_FRAMES = 3
END_FRAMES = 5
# ==========================

# 语音队列
speech_queue = queue.Queue()

def speech_worker():
    """后台语音播报线程"""
    while True:
        text = speech_queue.get()
        if text is None:  # 退出信号
            break
        try:
            subprocess.run(["espeak-ng", "-a", "100", "-v", "zh", text], check=False)
        except Exception as e:
            print(f"\n⚠️ espeak-ng 调用失败: {e}")
        speech_queue.task_done()

# 启动语音线程
speech_thread = threading.Thread(target=speech_worker, daemon=True)
speech_thread.start()

class HumanDetector:
    def __init__(self):
        self.model = YOLO(MODEL_PATH)
        self.state = "IDLE"
        self.human_count = 0
        self.empty_count = 0
        self.cap = None
        self.picam2 = None
        
        # 历史记录：存储每一帧的检测结果 (True=有人, False=无人)
        self.history = deque(maxlen=60)
        
        # 帧计数器
        self.frame_counter = 0
        
    def init_camera(self):
        """初始化树莓派摄像头"""
        try:
            # 尝试使用 Picamera2（树莓派官方）
            from picamera2 import Picamera2
            from libcamera import controls
            
            self.picam2 = Picamera2()
            
            # 配置分辨率
            config = self.picam2.create_video_configuration(
                main={"size": (FRAME_WIDTH, FRAME_HEIGHT)}
            )
            self.picam2.configure(config)
            
            # 自动对焦
            self.picam2.set_controls({
                "AfMode": controls.AfModeEnum.Continuous
            })
            
            self.picam2.start()
            time.sleep(1)  # 让摄像头稳定
            print(f"Picamera2: w={FRAME_WIDTH} h={FRAME_HEIGHT}")
            return True
            
        except ImportError:
            # Picamera2 不可用，尝试普通 USB 摄像头
            print(f"VideoCapture: w={FRAME_WIDTH} h={FRAME_HEIGHT}")
            self.cap = cv2.VideoCapture(0)
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
            return True
        except Exception as e:
            print(f"❌ 摄像头初始化失败: {e}")
            return False
    
    def read_frame(self):
        """读取一帧"""
        if self.picam2:
            # Picamera2 模式
            frame = self.picam2.capture_array()
            # Picamera2 默认是 RGB，YOLO 需要 BGR
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
            return True, frame
        elif self.cap:
            # USB 摄像头模式
            ret, frame = self.cap.read()
            return ret, frame
        return False, None
    
    def has_human(self, frame):
        """检测当前帧是否有人"""
        results = self.model(frame, conf=CONFIDENCE, verbose=False)
        for box in results[0].boxes:
            if box.cls == 0:
                return True
        return False
    
    def print_status(self):
        """打印状态行（类似音频程序）"""
        # 构建历史字符串：o=有人，.=无人，补齐到60个字符
        history_str = ''.join(['o' if h else '.' for h in self.history])
        history_str = history_str.ljust(60)
        
        if self.state == "SPEAKING":
            status_line = f"{history_str} [检测到人]"
        else:
            status_line = f"{history_str} [待机中]"
        
        # 使用 \r 覆盖当前行
        print(f"\r{status_line}", end="", flush=True)
    
    def speak(self, text):
        """将语音放入队列"""
        speech_queue.put(text)
    
    def process_frame(self, frame):
        self.frame_counter += 1
        
        has_human = self.has_human(frame)
        
        # 记录历史
        self.history.append(has_human)
        
        if self.state == "IDLE":
            if has_human:
                self.human_count += 1
                self.empty_count = 0
                if self.human_count >= START_FRAMES:
                    self.state = "SPEAKING"
                    self.speak("欢迎光临")  # 检测到人时说 hello
                    self.human_count = 0
            else:
                self.human_count = 0
                
        elif self.state == "SPEAKING":
            if has_human:
                self.empty_count = 0
            else:
                self.empty_count += 1
                if self.empty_count >= END_FRAMES:
                    self.state = "IDLE"
                    self.speak("下次再见")  # 人离开时说 byebye
                    self.empty_count = 0
        
        # 每帧更新状态显示
        self.print_status()
    
    def run(self):
        if not self.init_camera():
            return
        
        print("🎥 监控启动，按 Ctrl+C 退出")
        self.print_status()
        
        try:
            while True:
                ret, frame = self.read_frame()
                if not ret:
                    print("⚠️ 读取帧失败")
                    break
                
                self.process_frame(frame)
                
                # 在画面上显示状态（可选）
                status = "👤 有人" if self.state == "SPEAKING" else "💤 无人"
                cv2.putText(frame, status, (10, 30), 
                           cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                #cv2.imshow("Human Detection", frame)
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
                    
        except KeyboardInterrupt:
            print("\n👋 退出")
        finally:
            # 发送退出信号给语音线程
            speech_queue.put(None)
            if self.picam2:
                self.picam2.stop()
            if self.cap:
                self.cap.release()
            cv2.destroyAllWindows()

if __name__ == "__main__":
    detector = HumanDetector()
    detector.run()
