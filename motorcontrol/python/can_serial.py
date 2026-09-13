# can_serial.py
"""
串口转CAN模块
功能：
1. 串口扫描、打开、关闭
2. CAN帧打包成串口消息 (41 54 ... 0D 0A)
3. 串口消息解包成CAN帧 (CAN ID + data)
"""
import serial
import serial.tools.list_ports
import threading
import time
from queue import Queue, Empty


# 模块级 log 回调 (供 main-web.py 注册, 接收所有 [_serial]tx/rx/err 行)
_LOG_CB = None  # func(msg: str) -> None


def set_log_callback(cb):
    """设置日志回调, main-web.py 注册一个, 把消息写入 LogBuffer
    cb(msg: str) -> None
    """
    global LOG_CB
    LOG_CB = cb


class SerialCan:
    """串口转CAN通信类 - 只负责串口和CAN帧的打包解包"""
    
    # 帧头帧尾
    HEADER = bytes([0x41, 0x54])
    FOOTER = bytes([0x0D, 0x0A])
    
    def __init__(self):
        self.serial_port = None
        self.is_running = False
        self.rx_buffer = bytearray()
        self.rx_callback = None  # 接收回调 function(can_id, data, dlc)
        self.read_thread = None
        self.packet_count = 0
        # 调试: 由外部 --debug 参数同步设置, 不走环境变量
        self.debug = False
        
    def list_ports(self):
        """扫描并列出所有可用的串口"""
        ports = serial.tools.list_ports.comports()
        result = []
        for port in ports:
            info = {
                'device': port.device,
                'description': port.description,
                'vid': port.vid,
                'pid': port.pid,
            }
            result.append(info)
        return result
    
    def open(self, port, baudrate=115200, timeout=0.1):
        """打开串口"""
        try:
            self.serial_port = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout
            )
            self.is_running = True
            return True, f"成功打开串口 {port} @ {baudrate} bps"
        except serial.SerialException as e:
            return False, f"打开串口失败: {e}"
        except Exception as e:
            return False, f"发生错误: {e}"
    
    def close(self):
        """关闭串口"""
        self.is_running = False
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=0.5)
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            return True, "串口已关闭"
        return True, "串口已关闭"
    
    def is_open(self):
        """检查串口是否打开"""
        return self.serial_port is not None and self.serial_port.is_open

    def _log_tx(self, frame):
        if self.debug:
            msg = f"[serial]tx {frame.hex()}"
            print(msg, flush=True)
            if LOG_CB is not None:
                LOG_CB(msg)

    def _log_rx(self, data):
        if self.debug:
            msg = f"[serial]rx {data.hex()}"
            print(msg, flush=True)
            if LOG_CB is not None:
                LOG_CB(msg)
    
    def set_rx_callback(self, callback):
        """
        设置接收回调函数
        callback: function(can_id, data, dlc)
            - can_id: 29位CAN ID (int)
            - data: 数据字节 (bytes)
            - dlc: 数据长度 (int)
        """
        self.rx_callback = callback
    
    def start_receiver(self):
        """启动接收线程"""
        if not self.serial_port or not self.serial_port.is_open:
            return False, "串口未打开"
        
        if self.read_thread and self.read_thread.is_alive():
            return True, "接收线程已运行"
        
        self.is_running = True
        self.read_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.read_thread.start()
        return True, "接收线程已启动"
    
    def stop_receiver(self):
        """停止接收线程"""
        self.is_running = False
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=0.5)
        return True, "接收线程已停止"
    
    def _receiver_loop(self):
        """接收循环（运行在独立线程中）"""
        while self.is_running and self.serial_port and self.serial_port.is_open:
            try:
                if self.serial_port.in_waiting > 0:
                    data = self.serial_port.read(self.serial_port.in_waiting)
                    self._log_rx(data)
                    self.rx_buffer.extend(data)
                    self._process_rx_buffer()
                else:
                    time.sleep(0.01)
            except serial.SerialException as e:
                if self.debug:
                    print(f"[serial]err SerialException {e}", flush=True)
                if self.rx_callback:
                    self.rx_callback(None, None, None)
                break
            except Exception as e:
                if self.debug:
                    print(f"[serial]err Exception {e}", flush=True)
                if self.rx_callback:
                    self.rx_callback(None, None, None)
                break
    
    def _process_rx_buffer(self):
        """处理接收缓冲区，提取完整的数据包"""
        while len(self.rx_buffer) >= 2:
            found = False
            for i in range(len(self.rx_buffer) - 1):
                if self.rx_buffer[i] == 0x0D and self.rx_buffer[i+1] == 0x0A:
                    # 找到完整的数据包
                    packet = bytes(self.rx_buffer[:i+2])
                    self.rx_buffer = self.rx_buffer[i+2:]
                    self._parse_packet(packet)
                    found = True
                    break
            if not found:
                break
    
    def _parse_packet(self, data):
        """
        解析串口数据包，解包成CAN帧
        串口格式: 41 54 + CAN ID(4字节) + DLC(1字节) + 数据(0-8字节) + 0D 0A
        """
        if len(data) < 9:
            return
        
        self.packet_count += 1
        
        # 检查帧头和帧尾
        if not (data[0] == 0x41 and data[1] == 0x54):
            return
        if not (data[-2] == 0x0D and data[-1] == 0x0A):
            return
        
        # 提取CAN ID (大端)
        can_id_bytes = data[2:6]
        can_id_raw = int.from_bytes(can_id_bytes, 'big')
        can_id_29bit = can_id_raw >> 3  # 去掉bit3
        
        # 提取DLC
        dlc = data[6] if len(data) > 6 else 0
        if dlc > 8:
            dlc = 8
        
        # 提取数据
        data_start = 7
        can_data = bytes(data[data_start:data_start+dlc]) if len(data) >= data_start+dlc else b''
        
        # 调用回调函数，传递CAN帧
        if self.rx_callback:
            self.rx_callback(can_id_29bit, can_data, dlc)
    
    def pack_can_frame(self, can_id_29bit, data_bytes=b''):
        """
        将CAN帧打包成串口消息
        can_id_29bit: 29位CAN ID (int)
        data_bytes: 数据字节 (bytes)，最多8字节
        返回: bytes 串口消息
        """
        dlc = len(data_bytes)
        if dlc > 8:
            dlc = 8
            data_bytes = data_bytes[:8]
        
        # 将29位CAN ID左移3位 (添加bit3)
        can_id_raw = can_id_29bit << 3
        can_id_bytes = can_id_raw.to_bytes(4, 'big')
        
        # 构建串口帧: 41 54 + CAN ID(4) + DLC(1) + 数据 + 0D 0A
        frame = bytearray()
        frame.extend(self.HEADER)
        frame.extend(can_id_bytes)
        frame.append(dlc)
        frame.extend(data_bytes)
        frame.extend(self.FOOTER)
        
        return bytes(frame)
    
    def send_can(self, can_id_29bit, data_bytes=b''):
        """
        发送CAN帧
        can_id_29bit: 29位CAN ID
        data_bytes: 数据字节 (最多8字节)
        返回: (成功, 消息或发送的原始数据)
        """
        if not self.serial_port or not self.serial_port.is_open:
            return False, "串口未打开"

        # 打包成串口消息
        frame = self.pack_can_frame(can_id_29bit, data_bytes)

        if self.debug:
            self._log_tx(frame)

        try:
            self.serial_port.write(frame)
            return True, frame
        except Exception as e:
            return False, str(e)
    
    def get_stats(self):
        """获取统计信息"""
        return {
            'packet_count': self.packet_count,
            'rx_buffer_size': len(self.rx_buffer),
            'is_open': self.is_open(),
            'is_running': self.is_running
        }


# 使用示例
if __name__ == "__main__":
    # 测试代码
    can = SerialCan()
    
    # 扫描串口
    ports = can.list_ports()
    print("可用串口:")
    for i, p in enumerate(ports):
        print(f"  {i+1}. {p['device']} - {p['description']}")
    
    # 打开串口
    if ports:
        success, msg = can.open(ports[0]['device'], 115200)
        print(msg)
        
        if success:
            # 设置回调
            def on_rx(can_id, data, dlc):
                print(f"收到CAN帧: CAN_ID=0x{can_id:08X}, DLC={dlc}, data={data.hex() if data else ''}")
            
            can.set_rx_callback(on_rx)
            can.start_receiver()
            
            # 发送CAN帧示例 (获取设备ID: 通信类型0, 主机ID=0, 目标ID=1)
            can_id = (0 << 24) | (0x00 << 8) | 0x01
            success, result = can.send_can(can_id, b'')
            print(f"发送结果: {success}, 帧: {result.hex() if isinstance(result, bytes) else result}")
            
            time.sleep(2)
            
            can.close()
