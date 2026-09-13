# cybergear.py
"""
小米 CyberGear 电机控制库
封装 CAN 协议解析 + 串口收发 + 电机状态管理。
不依赖任何 CLI / Web 框架；不依赖 can_serial 之外的串口实现。
"""
import math
import os
import struct
import threading
import time
from can_serial import SerialCan


# 模块级 log 回调 (供 main-web.py 注册, 接收所有 [motor]tx/rx/info 行)
LOG_CB = None  # func(msg: str) -> None


def set_log_callback(cb):
    """设置日志回调, cb(msg: str) -> None
    通常 main-web.py 注册一个, 把消息写入 LogBuffer
    """
    global LOG_CB
    LOG_CB = cb


class CanProtocol:
    """CAN 协议常量 + 解析工具"""

    # 通信类型定义
    CMD_GET_ID = 0
    CMD_MOTION_CONTROL = 1
    CMD_FEEDBACK = 2
    CMD_ENABLE = 3
    CMD_STOP = 4
    CMD_SET_ZERO = 6
    CMD_SET_CAN_ID = 7
    CMD_READ_PARAM = 17   # 0x11
    CMD_WRITE_PARAM = 18  # 0x12
    CMD_FAULT = 21        # 0x15
    CMD_SET_BAUDRATE = 22 # 0x16

    COMM_TYPE_NAMES = {
        0: "获取设备ID",
        1: "运控模式控制指令",
        2: "电机反馈数据",
        3: "电机使能运行",
        4: "电机停止运行",
        6: "设置电机机械零位",
        7: "设置电机CAN_ID",
        17: "单个参数读取",
        18: "单个参数写入",
        21: "故障反馈帧",
        22: "波特率修改",
    }

    # 参数索引表 (按 xiaomi_cybergear_driver.cpp defs.h 对齐)
    # 元组格式: (name, desc, type, writable)
    PARAM_NAMES = {
        0x7005: ("run_mode",         "运行模式: 0-运控,1-位置,2-速度,3-电流", "uint8",   True),
        0x7006: ("iq_ref",           "电流模式Iq指令",                            "float",   True),
        0x700A: ("spd_ref",          "速度模式转速指令",                          "float",   True),
        0x700B: ("limit_torque",     "转矩限制 (运行) (Nm)",                      "float",   True),
        0x7010: ("cur_kp",           "电流KP",                                    "float",   True),
        0x7011: ("cur_ki",           "电流KI",                                    "float",   True),
        0x7014: ("cur_filt_gain",    "电流滤波系数",                              "float",   True),
        0x7016: ("loc_ref",          "位置模式角度指令 (rad)",                    "float",   True),
        0x7017: ("limit_spd",        "位置模式速度限制 (运行) (rad/s)",           "float",   True),
        0x7018: ("limit_cur",        "位置/速度模式电流限制 (运行) (A)",          "float",   True),
        0x2014: ("spd_kp",           "速度 KP",                                   "float",   True),
        0x2015: ("spd_ki",           "速度 KI",                                   "float",   True),
        0x2016: ("loc_kp",           "位置 KP",                                   "float",   True),
        0x2017: ("spd_filt_gain",    "速度滤波系数 (默认 0.1, 范围 0~1)",         "float",   True),  # 手册 3.3.3
        0x2018: ("limit_spd_store",  "位置模式速度限制 (存储) (rad/s)",            "float",   True),  # 手册 3.3.3
        0x2019: ("limit_cur_store",  "位置/速度模式电流限制 (存储) (A)",           "float",   True),  # 手册 3.3.3
        # CAN 配置 (手册 3.3.3)
        0x2007: ("limit_torque_store","转矩限制 (存储) (Nm)",                       "float",   True),  # 手册 3.3.3
        0x200A: ("CAN_ID",           "本节点CAN ID",                              "uint8",   True),
        0x200B: ("CAN_MASTER",       "CAN主机ID",                                 "uint8",   True),
        0x200C: ("CAN_TIMEOUT",      "CAN 看门狗超时 (ms, 0=禁用)",               "uint32",  True),  # 手册 3.3.3
        0x200D: ("motorOverTemp",    "电机保护温度值 (度*10)",                    "int16",   True),
        0x200E: ("overTempTime",     "过温时间",                                  "uint32",  True),
        # 手册 3.3.3 只读参数
        0x302E: ("rated_i",          "额定电流 (只读) (A)",                        "float",   False),
        0x302F: ("limit_i",          "硬件极限电流 (只读) (A)",                    "float",   False),
        # 电压 (手册 3.3.3, 以手册为准)
        0x3007: ("vBus_mv",          "母线电压 (mV)",                              "uint16",  False),
        0x300C: ("VBUS",             "母线电压 (V, 浮点)",                         "float",   False),
        0x302B: ("v_bus",            "闭环实时母线电压 (V, 推荐用)",                "float",   False),
        # 电流 (手册 3.3.3)
        0x3020: ("iq",               "q 轴转矩电流 (A, 推荐)",                     "float",   False),
        0x301E: ("iqf",              "q 轴滤波电流 (A)",                            "float",   False),
        0x3021: ("id",               "d 轴励磁电流 (A)",                            "float",   False),
        0x3019: ("ia",               "U 相电流 (A)",                                "float",   False),
        0x301A: ("ib",               "V 相电流 (A)",                                "float",   False),
        0x301B: ("ic",               "W 相电流 (A)",                                "float",   False),
    }

    # 模式名 -> RUN_MODE raw 值
    MODE_ALIASES = {
        'ctrl': 0, 'motion': 0, '0': 0,
        'pos':  1, 'position': 1, '1': 1,
        'spd':  2, 'speed': 2,    '2': 2,
        'cur':  3, 'current': 3,  '3': 3,
    }

    # 反馈帧的物理范围 (参考 xiaomi_cybergear_driver.cpp)
    POS_MIN, POS_MAX = -12.5, 12.5
    V_MIN,   V_MAX   = -30.0, 30.0
    T_MIN,   T_MAX   = -12.0, 12.0
    KP_MIN,  KP_MAX  = 0.0,   500.0
    KD_MIN,  KD_MAX  = 0.0,   5.0
    KI_MIN,  KI_MAX  = 0.0,   10.0
    I_MIN,   I_MAX   = -27.0, 27.0
    CURRENT_FILTER_GAIN_MIN, CURRENT_FILTER_GAIN_MAX = 0.0, 1.0

    @classmethod
    def build_can_id(cls, comm_type, host_id, target_id):
        """构建 29 位 CAN ID"""
        return (comm_type << 24) | (host_id << 8) | target_id

    @classmethod
    def parse_can_id(cls, can_id):
        """解析 29 位 CAN ID"""
        comm_type = (can_id >> 24) & 0x1F
        host_id   = (can_id >> 8) & 0xFF
        target_id = can_id & 0xFF
        comm_name = cls.COMM_TYPE_NAMES.get(comm_type, f"未知类型({comm_type})")
        return comm_type, comm_name, host_id, target_id

    @classmethod
    def parse_feedback(cls, data):
        """解析电机反馈 (通信类型 2), 按参考库 _uint_to_float 公式"""
        if len(data) < 8:
            return None
        pos_raw    = (data[0] << 8) | data[1]
        speed_raw  = (data[2] << 8) | data[3]
        torque_raw = (data[4] << 8) | data[5]
        temp_raw   = (data[6] << 8) | data[7]
        position = pos_raw    / 65535.0 * (cls.POS_MAX - cls.POS_MIN) + cls.POS_MIN
        speed    = speed_raw  / 65535.0 * (cls.V_MAX   - cls.V_MIN)   + cls.V_MIN
        torque   = torque_raw / 65535.0 * (cls.T_MAX   - cls.T_MIN)   + cls.T_MIN
        return {
            'position': position,
            'speed':    speed,
            'torque':   torque,
            'temperature': temp_raw,  # uint16 raw
        }

    @classmethod
    def parse_param_response(cls, data):
        """解析参数读取响应 (通信类型 17).
        响应包可能丢字节 (8 变 7), 也可能只到 4 字节. 尽可能取出能识别的字段.
        index 总是会被 _on_rx 里的 _pending_read 覆盖, 不用太信这里.
        返回 dict 同时带 value_int 和 value_float, 前端根据 type 选.
        """
        if len(data) < 4:
            return None
        if len(data) >= 8:
            param_index = data[0] | (data[1] << 8)
            value_bytes = data[4:8]
        else:
            param_index = 0
            value_bytes = data[-4:]
        param_info = cls.PARAM_NAMES.get(param_index)
        param_name = param_info[0] if param_info else f"未知参数(0x{param_index:04X})"
        vtype     = param_info[2] if param_info else 'float'
        value_int = int.from_bytes(value_bytes, 'little')
        value_float = struct.unpack('<f', value_bytes)[0]
        return {
            'index': param_index,
            'name':  param_name,
            'vtype': vtype,           # uint8/uint16/uint32/int16/float
            'value_int':   value_int,
            'value_float': value_float,
        }

    @classmethod
    def parse_fault(cls, data):
        """解析故障反馈帧 (通信类型 21)"""
        if len(data) < 4:
            return None
        fault = int.from_bytes(data[0:4], 'little')
        fault_msgs = []
        if fault & 0x01:   fault_msgs.append("电机过温故障")
        if fault & 0x02:   fault_msgs.append("驱动芯片故障")
        if fault & 0x04:   fault_msgs.append("欠压故障")
        if fault & 0x08:   fault_msgs.append("过压故障")
        if fault & 0x10:   fault_msgs.append("B相电流采样过流")
        if fault & 0x20:   fault_msgs.append("C相电流采样过流")
        if fault & 0x80:   fault_msgs.append("编码器未标定")
        if fault & 0xFF00: fault_msgs.append("过载故障")
        if fault & 0x10000:fault_msgs.append("A相电流采样过流")
        result = {'fault': fault, 'fault_msgs': fault_msgs}
        if len(data) >= 8:
            warning = int.from_bytes(data[4:8], 'little')
            warning_msgs = []
            if warning & 0x01:
                warning_msgs.append("电机过温预警")
            result['warning'] = warning
            result['warning_msgs'] = warning_msgs
        return result

    @classmethod
    def _float_to_uint(cls, x, x_min, x_max, bits=16):
        if bits > 16: bits = 16
        if x > x_max: x = x_max
        elif x < x_min: x = x_min
        span = x_max - x_min
        return int(round((x - x_min) * ((1 << bits) - 1) / span))

    @classmethod
    def mode_from_alias(cls, s):
        """'pos'/'spd'/'cur'/'ctrl'/'0/1/2/3' -> int (None if invalid)"""
        return cls.MODE_ALIASES.get(str(s).lower())


class MotorStatus:
    """一个电机的实时状态"""
    def __init__(self, target_id):
        self.target_id   = target_id
        self.position    = 0.0
        self.speed       = 0.0
        self.torque      = 0.0
        self.temperature = 0
        self.mode        = None     # 由 setmode 命令记录
        self.enabled     = False    # 由 enable/stop 命令记录
        self.last_update = 0.0      # time.time()
        self.mcu_id      = None     # 由 ls 响应记录

    def to_dict(self):
        return {
            'target_id':   self.target_id,
            'position':    self.position,
            'speed':       self.speed,
            'torque':      self.torque,
            'temperature': self.temperature,
            'mode':        self.mode,
            'enabled':     self.enabled,
            'last_update': self.last_update,
            'mcu_id':      self.mcu_id,
        }


class CyberGearMotor:
    """
    电机高层类:
    - 串口收发 (依赖 SerialCan)
    - 维护所有已知电机的状态缓存
    - 提供 enable/stop/setmode/setpos/setspeed/... 高层方法
    - 支持回调注册 (反馈帧 / 状态变化)
    线程安全: 所有写操作加 self._lock; 状态读可不加锁 (atomic 单字段读)
    """

    def __init__(self, port=None, baudrate=115200):
        self._serial = SerialCan()
        self._lock = threading.Lock()
        self._motors = {}  # target_id -> MotorStatus
        self._param_cache = {}  # (motor_id, addr) -> param dict (read_param 异步响应缓存)
        self._pending_read = {}  # motor_id -> addr (read_param 设入, _on_rx 取走)
        self._feedback_cb = None  # func(status_dict)
        self._param_read_cb = None  # func(motor_id, addr, entry)
        self._raw_packet_cb = None  # func(can_id, data, dlc) for CLI 调试打印
        # 调试: 仅由 --debug 参数设置, 不走环境变量
        self._debug_rx = False

    def _log(self, *args):
        if self._debug_rx:
            msg = 'motor info ' + ' '.join(str(a) for a in args)
            print(msg, flush=True)
            if LOG_CB is not None:
                LOG_CB(msg)

    def _log_tx(self, can_id, data):
        """统一 TX 日志: [motor]tx canid=0x<hex> data=<hex 拼接>"""
        if self._debug_rx:
            msg = f"[motor]tx canid=0x{can_id:08X} data={data.hex() if data else ''}"
            print(msg, flush=True)
            if LOG_CB is not None:
                LOG_CB(msg)

    def _log_rx(self, can_id, data):
        """统一 RX 日志: [motor]rx canid=0x<hex> data=<hex 拼接>"""
        if self._debug_rx:
            msg = f"[motor]rx canid=0x{can_id:08X} data={data.hex() if data else ''}"
            print(msg, flush=True)
            if LOG_CB is not None:
                LOG_CB(msg)

    # -------------------- 串口 --------------------

    def list_ports(self):
        """列可用串口 (包装 SerialCan.list_ports)
        main-web 不该直接 import can_serial, 全部走 CyberGearMotor
        """
        return self._serial.list_ports()

    def open(self, port, baudrate=115200, timeout=0.1):
        ok, msg = self._serial.open(port, baudrate, timeout)
        if ok:
            self._serial.set_rx_callback(self._on_rx)
            ok2, msg2 = self._serial.start_receiver()
            if not ok2:
                self._serial.close()
                return False, f"打开串口成功但接收线程启动失败: {msg2}"
            self._log(f"串口已开: {port} @ {baudrate}")
        return ok, msg

    def close(self):
        return self._serial.close()

    def is_open(self):
        return self._serial.is_open()

    def set_feedback_callback(self, cb):
        """注册反馈回调, cb(status_dict)"""
        self._feedback_cb = cb

    def set_param_read_callback(self, cb):
        """注册参数读取回调, cb(motor_id, addr, entry)
        任何参数读取响应到达时都会调 (不论谁发起的查询).
        entry: {index, name, vtype, value_int, value_float}
        """
        self._param_read_cb = cb

    def set_raw_packet_callback(self, cb):
        """注册原始包回调 (CLI 用), cb(can_id, data, dlc)"""
        self._raw_packet_cb = cb

    def set_log_callback(self, cb):
        """注册全局 log 回调, cb(msg: str)
        会同时设置 motor 层和 serial 层 (serial 包内转发), 调用者不需要知道 serial
        """
        set_log_callback(cb)
        try:
            from can_serial import set_log_callback as _set_serial_cb
            _set_serial_cb(cb)
        except Exception:
            pass

    # -------------------- 接收回调 --------------------

    def _on_rx(self, can_id, data, dlc):
        if can_id is None:
            print(f"motor serial error: {data}")
            return
        # 原始包回调 (CLI 调试用)
        if self._raw_packet_cb:
            self._raw_packet_cb(can_id, data, dlc)
        # 解析
        comm_type, comm_name, host_id, target_id = CanProtocol.parse_can_id(can_id)

        # 响应帧 (GET_ID, READ_PARAM) 的 host_id 字段才是电机的真实 ID
        # (target_id 是请求时的目标地址, 即 0=master)
        # 反馈/控制帧的 target_id 才是这台电机
        if comm_type in (CanProtocol.CMD_GET_ID, CanProtocol.CMD_READ_PARAM):
            motor_id = host_id
        else:
            motor_id = target_id

        # 统一打印 RX (过滤前也打, 让数据可见)
        self._log_rx(can_id, data)

        # motor_id=0 是主机自身 / 总线噪音, 不存进缓存
        if motor_id == 0:
            return

        with self._lock:
            if motor_id not in self._motors:
                self._motors[motor_id] = MotorStatus(motor_id)
            m = self._motors[motor_id]

            if comm_type == CanProtocol.CMD_GET_ID and len(data) >= 8:
                mcu_id = int.from_bytes(data[0:8], 'little')
                m.mcu_id = f"0x{mcu_id:016X}"
                m.last_update = time.time()

            elif comm_type == CanProtocol.CMD_FEEDBACK and len(data) >= 8:
                fb = CanProtocol.parse_feedback(data)
                if fb:
                    m.position    = fb['position']
                    m.speed       = fb['speed']
                    m.torque      = fb['torque']
                    m.temperature = fb['temperature']
                    m.last_update = time.time()
                    # 反馈回调 (主 web 用: 推到 /ws/status 订阅者)
                    if self._feedback_cb:
                        try:
                            self._feedback_cb(motor_id, fb)
                        except Exception:
                            pass

            elif comm_type == CanProtocol.CMD_READ_PARAM and len(data) >= 4:
                self._log(f"got CMD_READ_PARAM rx motor_id=0x{motor_id:02X} data_len={len(data)} data={data.hex()}")
                try:
                    pr = CanProtocol.parse_param_response(data)
                    if pr:
                        # 已在 _on_rx 外层 lock 里, 不需要再 with self._lock
                        # 响应里 addr 字段不一定可靠, 优先用请求时记录的 addr
                        requested_addr = self._pending_read.pop(motor_id, pr['index'])
                        pr['index'] = requested_addr
                        self._param_cache[(motor_id, requested_addr)] = pr
                        # 如果是 RUN_MODE (0x7005), 顺便更新 MotorStatus.mode (getmode 用)
                        if motor_id in self._motors and requested_addr == 0x7005:
                            mode_int = int(pr['value_int']) & 0xFF
                            self._motors[motor_id].mode = ['ctrl', 'pos', 'spd', 'cur'][mode_int] if mode_int < 4 else None
                        self._log(f"parsed param id={motor_id} 0x{requested_addr:04X} ({pr['name']}) = {pr['value_float']:.6f}")
                        # 参数读取回调 (主 web 用: 推电压/电流到 /ws/status)
                        if self._param_read_cb:
                            try:
                                self._param_read_cb(motor_id, requested_addr, pr)
                            except Exception:
                                pass
                    else:
                        self._log(f"parse_param_response returned None for data={data.hex()}")
                except Exception as e:
                    self._log(f"CMD_READ_PARAM exception: {type(e).__name__}: {e}")

        # 反馈回调 (在锁外调用, 避免回调里再调库方法死锁)
        if comm_type == CanProtocol.CMD_FEEDBACK and self._feedback_cb:
            with self._lock:
                snap = m.to_dict()
            try:
                self._feedback_cb(snap)
            except Exception:
                pass

    # -------------------- 状态查询 --------------------

    def get_motors(self):
        """返回所有已知电机状态 (list of dict)"""
        with self._lock:
            return [m.to_dict() for m in self._motors.values()]

    def get_status(self, target_id):
        with self._lock:
            m = self._motors.get(target_id)
            return m.to_dict() if m else None

    # -------------------- 控制命令 --------------------
    # 每个方法都接收 target_id (int). host_id 写死 0 (按你的要求不动).
    # 不包 stop/enable 时序, 命令各自独立.

    def enable(self, target_id):
        self._log(f"enable -> id={target_id}")
        can_id = CanProtocol.build_can_id(CanProtocol.CMD_ENABLE, 0x00, target_id)
        data = bytearray(8)
        self._log_tx(can_id, bytes(data))
        ok, result = self._serial.send_can(can_id, bytes(data))
        if ok:
            with self._lock:
                if target_id not in self._motors:
                    self._motors[target_id] = MotorStatus(target_id)
                self._motors[target_id].enabled = True
        return ok, result

    def stop(self, target_id):
        self._log(f"stop -> id={target_id}")
        can_id = CanProtocol.build_can_id(CanProtocol.CMD_STOP, 0x00, target_id)
        data = bytearray(8)
        self._log_tx(can_id, bytes(data))
        ok, result = self._serial.send_can(can_id, bytes(data))
        if ok:
            with self._lock:
                if target_id not in self._motors:
                    self._motors[target_id] = MotorStatus(target_id)
                self._motors[target_id].enabled = False
        return ok, result

    def set_zero(self, target_id):
        self._log(f"set_zero -> id={target_id}")
        can_id = CanProtocol.build_can_id(CanProtocol.CMD_SET_ZERO, 0x00, target_id)
        data = bytearray(8)
        data[0] = 1
        self._log_tx(can_id, bytes(data))
        return self._serial.send_can(can_id, bytes(data))

    def set_can_id(self, target_id, new_id):
        self._log(f"set_can_id: {target_id} -> {new_id}")
        can_id = CanProtocol.build_can_id(CanProtocol.CMD_SET_CAN_ID, 0x00, target_id)
        data = bytearray(8)
        data[0] = new_id & 0xFF
        self._log_tx(can_id, bytes(data))
        ok, result = self._serial.send_can(can_id, bytes(data))
        # 不在缓存里改名, 用户应该重新 ls
        return ok, result

    def _read_param_sync(self, target_id, addr, timeout=0.5):
        """同步读参数: 清缓存, 发 read_param, 轮询 _param_cache 直到响应进或超时
        timeout 默认 500ms (足够响应). 永远不会卡死, 到点一定 return None
        返回 param dict (含 index/name/value_int/value_float), 或 None (超时)
        """
        with self._lock:
            self._param_cache.pop((target_id, addr), None)
        ok, _ = self.read_param(target_id, addr)
        if not ok:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.01)
            with self._lock:
                entry = self._param_cache.get((target_id, addr))
            if entry:
                return entry
        self._log(f"_read_param_sync timeout: id={target_id} 0x{addr:04X} waited {timeout}s, cache miss")
        return None

    def set_mode(self, target_id, mode_str):
        """mode_str: 'ctrl'/'pos'/'spd'/'cur' 或 '0'/'1'/'2'/'3'
        RUN_MODE (0x7005) 是 uint8 寄存器, 走 write_param(vtype='uint8')
        SPD 模式特殊: 先读 + 设 SPD_KP/KI 为手册默认值 (kp=2.0, ki=0.021)
        不包 stop/enable 时序, 命令各自独立
        """
        self._log(f"set_mode -> id={target_id} mode={mode_str}")
        v = CanProtocol.mode_from_alias(mode_str)
        if v is None:
            self._log(f"  未知模式: {mode_str}")
            return False, f"未知模式: {mode_str}"

        # SPD 模式特殊处理: 先读 + 设 PID 参数为手册默认 (防止旧参数导致电机不转/抖动)
        if mode_str == 'spd':
            self._log(f"  spd 模式: 先读 + 设 SPD_KP/KI 为手册默认 (2.0 / 0.021)")
            kp_entry = self._read_param_sync(target_id, 0x2014)
            if kp_entry:
                self._log(f"    当前 SPD_KP (0x2014) = {kp_entry['value_float']:.6f}")
            else:
                self._log(f"    当前 SPD_KP (0x2014) 读超时")
            ki_entry = self._read_param_sync(target_id, 0x2015)
            if ki_entry:
                self._log(f"    当前 SPD_KI (0x2015) = {ki_entry['value_float']:.6f}")
            else:
                self._log(f"    当前 SPD_KI (0x2015) 读超时")
            ok1, _ = self.write_param(target_id, 0x2014, 2.0)
            ok2, _ = self.write_param(target_id, 0x2015, 0.021)
            if ok1 and ok2:
                self._log(f"    设 SPD_KP=2.0, SPD_KI=0.021 ✓")
            else:
                self._log(f"    设 SPD_KP/KI 失败!")
                return False, "设 SPD_KP/KI 失败"

        ok, result = self.write_param(target_id, 0x7005, v, vtype='uint8')
        if not ok:
            return False, result

        with self._lock:
            if target_id not in self._motors:
                self._motors[target_id] = MotorStatus(target_id)
            self._motors[target_id].mode = mode_str
        return True, "模式设置完成"

    def set_position_ref(self, target_id, n):
        """n 单位 1/60 圈"""
        angle_rad = n * (2.0 * math.pi) / 60.0
        self._log(f"set_pos -> id={target_id} n={n} ({angle_rad:.4f} rad)")
        return self.write_param(target_id, 0x7016, angle_rad)

    def set_speed_ref(self, target_id, rad_per_s, limit_cur=1.0):
        """速度模式: 同时写 LIMIT_CUR (0x7018) + SPD_REF (0x700A)
        参考 Arduino mimotor.ino: 速度模式必写 LIMIT_CUR=1A, 否则限流=0 电机不转
        """
        self._log(f"set_spd -> id={target_id} limit_cur={limit_cur}A rad={rad_per_s}")
        ok1, r1 = self.write_param(target_id, 0x7018, float(limit_cur))
        ok2, r2 = self.write_param(target_id, 0x700A, float(rad_per_s))
        return ok1 and ok2, r2 if ok2 else r1

    def set_current_ref(self, target_id, a):
        self._log(f"set_cur -> id={target_id} a={a}")
        return self.write_param(target_id, 0x7006, float(a))

    def write_param(self, target_id, addr, value, vtype='float'):
        """通用写参数 (RAM_WRITE 0x12). data[0..1]=addr LE u16, data[4..7]=value
        vtype: 'float' (LE f32, 4字节) 或 'uint8' (1字节) 或 'uint32' (LE u32, 4字节)
        """
        self._log(f"write_param -> id={target_id} 0x{addr:04X}={value} type={vtype}")
        can_id = CanProtocol.build_can_id(CanProtocol.CMD_WRITE_PARAM, 0x00, target_id)
        data = bytearray(8)
        data[0] = addr & 0xFF
        data[1] = (addr >> 8) & 0xFF
        if vtype == 'float':
            data[4:8] = struct.pack('<f', float(value))
        elif vtype == 'uint8':
            data[4] = int(value) & 0xFF
        elif vtype == 'uint32':
            data[4:8] = int(value).to_bytes(4, 'little', signed=False)
        else:
            return False, f"未知类型: {vtype}"
        # 统一 TX 日志
        self._log_tx(can_id, bytes(data))
        return self._serial.send_can(can_id, bytes(data))

    def read_param(self, target_id, addr):
        """读参数 (RAM_READ 0x11). 响应是异步的, 通过 _on_rx 进入缓存.
        响应里的 addr 字段不一定可靠 (可能被吞字节/填 0), 所以预先记录请求的 addr,
        _on_rx 里用它当 cache key, 不依赖响应里 data[0:2].
        """
        self._log(f"read_param -> id={target_id} 0x{addr:04X}")
        with self._lock:
            self._pending_read[target_id] = addr
        can_id = CanProtocol.build_can_id(CanProtocol.CMD_READ_PARAM, 0x00, target_id)
        data = bytearray(8)
        data[0] = addr & 0xFF
        data[1] = (addr >> 8) & 0xFF
        self._log_tx(can_id, bytes(data))
        return self._serial.send_can(can_id, bytes(data))

    def send_motion(self, target_id, pos, vel, kp, kd, torque):
        """运控模式 (通信类型 0x01)
        pos/vel/kp/kd 进 data (uint16 缩放), torque 进 CAN ID option (bit23..8)
        """
        self._log(f"motion -> id={target_id} pos={pos} vel={vel} kp={kp} kd={kd} tor={torque}")
        pos_u = CanProtocol._float_to_uint(pos,    CanProtocol.POS_MIN, CanProtocol.POS_MAX)
        vel_u = CanProtocol._float_to_uint(vel,    CanProtocol.V_MIN,   CanProtocol.V_MAX)
        kp_u  = CanProtocol._float_to_uint(kp,     CanProtocol.KP_MIN,  CanProtocol.KP_MAX)
        kd_u  = CanProtocol._float_to_uint(kd,     CanProtocol.KD_MIN,  CanProtocol.KD_MAX)
        tor_u = CanProtocol._float_to_uint(torque, CanProtocol.T_MIN,   CanProtocol.T_MAX)
        data = bytearray(8)
        data[0] = (pos_u >> 8) & 0xFF
        data[1] = pos_u & 0xFF
        data[2] = (vel_u >> 8) & 0xFF
        data[3] = vel_u & 0xFF
        data[4] = (kp_u  >> 8) & 0xFF
        data[5] = kp_u  & 0xFF
        data[6] = (kd_u  >> 8) & 0xFF
        data[7] = kd_u  & 0xFF
        can_id = (CanProtocol.CMD_MOTION_CONTROL << 24) | (tor_u << 8) | target_id
        self._log_tx(can_id, bytes(data))
        return self._serial.send_can(can_id, bytes(data))

    def scan(self, targets=None, broadcast=True, host_id=0x00, timeout=0.2):
        """发送 GET_ID 帧并等待响应.
        targets: list[int] 指定目标; None + broadcast=True 时发到 0xFE.
        返回更新后的 motors dict (target_id -> dict). 响应是异步的, 需要 sleep.
        """
        if targets is None and broadcast:
            tgts = [0xFE]
            self._log(f"scan: 广播 GET_ID -> 0xFE")
        elif targets is None:
            self._log("scan: 无目标, 返回当前缓存")
            return self.get_motors()
        else:
            tgts = list(targets)
            self._log(f"scan: GET_ID -> {tgts}")
        for t in tgts:
            can_id = CanProtocol.build_can_id(CanProtocol.CMD_GET_ID, host_id, t)
            self._log_tx(can_id, b'')
            ok, _ = self._serial.send_can(can_id, b'')
            if not ok:
                self._log(f"  send_can 失败")
            time.sleep(0.05)
        time.sleep(timeout)
        motors = self.get_motors()
        self._log(f"scan: 完成, 发现 {len(motors)} 个电机: {[m['target_id'] for m in motors]}")
        return motors
