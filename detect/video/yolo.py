import cv2
from ultralytics import YOLO
import time
from datetime import datetime

# ========== 配置 ==========
MODEL_PATH = "yolov8n.pt"
CONFIDENCE = 0.4
FRAME_WIDTH = 640
FRAME_HEIGHT = 360
# ==========================

class HumanDetector:
    def __init__(self):
        self.model = YOLO(MODEL_PATH)
        self.cap = None
        self.picam2 = None
        
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
            print(f"📷 Picamera2: w={FRAME_WIDTH} h={FRAME_HEIGHT}")
            return True
            
        except ImportError:
            # Picamera2 不可用，尝试普通 USB 摄像头
            print(f"📷 VideoCapture: w={FRAME_WIDTH} h={FRAME_HEIGHT}")
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
    
    def run(self):
        if not self.init_camera():
            return
        
        print("🎥 监控启动，按 Ctrl+C 退出")
        
        try:
            while True:
                ret, frame = self.read_frame()
                if not ret:
                    print("\n⚠️ 读取帧失败")
                    break
                
                # 检测
                has_human = self.has_human(frame)
                
                # 显示结果
                symbol = "✅" if has_human else "❌"
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                print(f"\r{timestamp} {symbol}", end="", flush=True)
                    
        except KeyboardInterrupt:
            print("\n\n👋 退出")
        finally:
            if self.picam2:
                self.picam2.stop()
            if self.cap:
                self.cap.release()
            cv2.destroyAllWindows()

if __name__ == "__main__":
    detector = HumanDetector()
    detector.run()
