# logbuf.py
"""
全局日志缓冲区: 跨层 (serial/motor) 共享, 通过回调写入
- can_serial/cybergear 各自暴露 set_log_callback(cb), cb(msg: str)
- main-web.py 注册一个 cb, 把消息写入 LogBuffer
- /api/logs 读 LogBuffer 返回给前端
"""
import threading
from collections import deque


class LogBuffer:
    def __init__(self, maxlen=500):
        self._buf = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def append(self, msg):
        with self._lock:
            self._buf.append(msg)

    def get_all(self, limit=None):
        with self._lock:
            items = list(self._buf)
        if limit:
            return items[-limit:]
        return items

    def clear(self):
        with self._lock:
            self._buf.clear()
