import cv2
from ultralytics import YOLO
import time
from datetime import datetime
import os
import numpy as np
import av
from fractions import Fraction
from collections import deque

# ========== 配置 ==========
MODEL_PATH = "yolov8n.pt"
CONFIDENCE = 0.4

# 检测分辨率（低，提速）
DETECT_WIDTH = 640
DETECT_HEIGHT = 360

# 录像分辨率（高，清晰）
RECORD_WIDTH = 1920
RECORD_HEIGHT = 1080

RECORD_SECONDS = 30

START_FRAMES = 3  # 连续3帧有人触发
END_FRAMES = 3    # 连续3帧无人结束
# ==========================

# 全局状态行
status_line = "[待机中]"

def print_log(msg):
    """打印日志，然后恢复状态行"""
    print(f"\r\033[K{msg}")
    print(f"\r{status_line}", end="", flush=True)

def print_status(msg):
    """更新状态行"""
    global status_line
    status_line = msg
    print(f"\r\033[K{msg}", end="", flush=True)

class HumanDetector:
    def __init__(self):
        self.model = YOLO(MODEL_PATH)
        self.state = "IDLE"
        self.human_count = 0
        self.empty_count = 0
        self.container = None
        self.stream = None
        self.video_start_time = None
        self.last_pts = 0
        self.cap = None
        self.picam2 = None
        self.frame_counter = 0
        self.record_frame_count = 0
        self.history = deque(maxlen=60)

        # 缓存帧队列
        self.frame_buffer = deque(maxlen=START_FRAMES)

    def init_camera(self):
        """初始化树莓派摄像头"""
        try:
            from picamera2 import Picamera2
            from libcamera import controls

            self.picam2 = Picamera2()
            # 配置录像分辨率（高）
            config = self.picam2.create_video_configuration(
                main={"size": (RECORD_WIDTH, RECORD_HEIGHT)}
            )
            self.picam2.configure(config)
            self.picam2.set_controls({
                "AfMode": controls.AfModeEnum.Continuous
            })
            self.picam2.start()
            time.sleep(1)
            print_log(f"📷 Picamera2: 录像={RECORD_WIDTH}x{RECORD_HEIGHT}, 检测={DETECT_WIDTH}x{DETECT_HEIGHT}")
            return True

        except ImportError:
            print_log("⚠️ Picamera2 不可用，尝试 USB 摄像头")
            self.cap = cv2.VideoCapture(0)
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, RECORD_WIDTH)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, RECORD_HEIGHT)
            return True
        except Exception as e:
            print_log(f"❌ 摄像头初始化失败: {e}")
            return False

    def read_frame(self):
        """读取一帧，返回 (检测帧, 录像帧)"""
        if self.picam2:
            # Picamera2 模式 - 获取高分辨率帧
            high_res_frame = self.picam2.capture_array()
            high_res_frame = cv2.cvtColor(high_res_frame, cv2.COLOR_RGB2BGR)
            
            # 缩放到检测分辨率
            detect_frame = cv2.resize(high_res_frame, (DETECT_WIDTH, DETECT_HEIGHT))
            
            return True, detect_frame, high_res_frame
            
        elif self.cap:
            # USB 摄像头模式
            ret, high_res_frame = self.cap.read()
            if not ret:
                return False, None, None
            
            # 缩放到检测分辨率
            detect_frame = cv2.resize(high_res_frame, (DETECT_WIDTH, DETECT_HEIGHT))
            return True, detect_frame, high_res_frame
            
        return False, None, None

    def detect_human(self, detect_frame, record_frame):
        """
        检测画面中的人
        detect_frame: 低分辨率，用于YOLO推理
        record_frame: 高分辨率，用于画框和录像
        返回 (是否有人, 带矩形框的录像帧)
        """
        results = self.model(detect_frame, conf=CONFIDENCE, verbose=False)
        has_human = False
        frame_with_boxes = record_frame.copy()  # 在高分辨率帧上画框
        
        # 计算缩放比例（从检测分辨率到录像分辨率）
        scale_x = RECORD_WIDTH / DETECT_WIDTH
        scale_y = RECORD_HEIGHT / DETECT_HEIGHT
        
        for box in results[0].boxes:
            if box.cls == 0:  # class 0 = 人
                has_human = True
                # 获取检测帧上的坐标（低分辨率）
                x1, y1, x2, y2 = box.xyxy[0].tolist()
                # 缩放到录像分辨率
                x1, y1, x2, y2 = int(x1 * scale_x), int(y1 * scale_y), int(x2 * scale_x), int(y2 * scale_y)
                # 画矩形框（在高分辨率帧上）
                cv2.rectangle(frame_with_boxes, (x1, y1), (x2, y2), (0, 255, 0), 2)
                conf = box.conf[0].item()
                cv2.putText(frame_with_boxes, f"{conf:.2f}", (x1, y1-10),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)

        return has_human, frame_with_boxes

    def get_history_bar(self):
        """生成历史记录字符串：o=有人，.=无人"""
        history_str = ''.join(['o' if h else '.' for h in self.history])
        return history_str.ljust(60)

    def write_frame_to_video(self, frame):
        """写入一帧到视频（带时间戳）"""
        if not self.container or not self.stream:
            return

        now = time.time()
        pts_ms = int((now - self.video_start_time) * 1000)

        if pts_ms <= self.last_pts:
            return
        self.last_pts = pts_ms
        self.record_frame_count += 1

        img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        av_frame = av.VideoFrame.from_ndarray(img_rgb, format='rgb24')
        av_frame.pts = pts_ms

        for packet in self.stream.encode(av_frame):
            self.container.mux(packet)

    def start_recording(self, frame):
        """开始录像（PyAV VFR）"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_filename = f"record_{timestamp}.mp4"
        filename = self.current_filename

        # 创建 PyAV 容器
        self.container = av.open(filename, mode='w')
        self.stream = self.container.add_stream('h264', rate=1)

        self.stream.codec_context.time_base = Fraction(1, 1000)
        self.stream.width = RECORD_WIDTH
        self.stream.height = RECORD_HEIGHT
        self.stream.pix_fmt = 'yuv420p'

        self.video_start_time = time.time()
        self.last_pts = 0
        self.record_frame_count = 0

        # 先写入缓存的帧
        for cached_frame in self.frame_buffer:
            self.write_frame_to_video(cached_frame)

        # 再写入当前帧
        self.write_frame_to_video(frame)

        self.state = "RECORDING"
        print_log(f"🎬 开始录像: {filename} (包含前{len(self.frame_buffer)}帧缓存)")

    def stop_recording(self):
        """停止录像"""
        if self.container:
            for packet in self.stream.encode():
                self.container.mux(packet)
            self.container.close()
            self.container = None
            self.stream = None

        total_duration = int(time.time() - self.video_start_time) if self.video_start_time else 0
        total_frames = self.record_frame_count

        self.video_start_time = None
        self.last_pts = 0
        self.record_frame_count = 0
        self.state = "IDLE"

        print_log(f"⏹ 停止录像: {self.current_filename} 时长:{total_duration}s 帧数:{total_frames}")

    def process_frame(self, detect_frame, record_frame):
        """处理每一帧 - detect_frame用于检测，record_frame用于录像和画框"""
        # 检测人，画框在录像帧上
        has_human, frame_with_boxes = self.detect_human(detect_frame, record_frame)

        # 更新历史
        self.history.append(has_human)
        self.frame_counter += 1

        # 缓存当前帧（带框的录像帧）
        self.frame_buffer.append(frame_with_boxes)

        history_bar = self.get_history_bar()

        if self.state == "IDLE":
            if has_human:
                self.human_count += 1
                self.empty_count = 0
                print_status(f"{history_bar} [待机中] 连续检测到人: {self.human_count}帧")
                if self.human_count >= START_FRAMES:
                    # 触发时传入当前帧，内部会先写入缓存帧
                    self.start_recording(frame_with_boxes)
            else:
                # 如果还没触发就没人了，清空缓存
                if self.human_count > 0:
                    self.frame_buffer.clear()
                self.human_count = 0
                print_status(f"{history_bar} [待机中]")

        elif self.state == "RECORDING":
            self.write_frame_to_video(frame_with_boxes)

            if time.time() - self.video_start_time > RECORD_SECONDS:
                self.stop_recording()
                print_status(f"{history_bar} [待机中]")
                return

            if has_human:
                self.empty_count = 0
                duration = int(time.time() - self.video_start_time)
                print_status(f"{history_bar} [录像中 {duration}s] 连续检测到人: {self.human_count + 1}帧")
                self.human_count += 1
            else:
                self.empty_count += 1
                duration = int(time.time() - self.video_start_time)
                print_status(f"{history_bar} [录像中 {duration}s] 无人 {self.empty_count}/{END_FRAMES}帧")
                if self.empty_count >= END_FRAMES:
                    self.stop_recording()
                    print_status(f"{history_bar} [待机中]")

    def run(self):
        if not self.init_camera():
            return

        print_log("🎥 监控启动，按 Ctrl+C 退出")
        print_status("                                                            [待机中]")

        try:
            while True:
                ret, detect_frame, record_frame = self.read_frame()
                if not ret:
                    print_log("⚠️ 读取帧失败")
                    break

                self.process_frame(detect_frame, record_frame)

                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break

        except KeyboardInterrupt:
            print_log("\n👋 退出")
        finally:
            if self.state == "RECORDING":
                self.stop_recording()
            if self.picam2:
                self.picam2.stop()
            if self.cap:
                self.cap.release()
            cv2.destroyAllWindows()

if __name__ == "__main__":
    detector = HumanDetector()
    detector.run()
