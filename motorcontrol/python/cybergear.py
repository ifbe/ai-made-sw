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

    # 参数索引表 (按手册 4.1.12「可读写单个参数列表」, 即 CAN 表)
    # 元组格式: (name, desc, type, writable)
    #
    # ⚠ 只放**手册 4.1.12「可读写单个参数列表」**里的地址 (0x7005~0x7020):
    #   这是 CAN 通信类型 17/18 唯一能寻址的表.
    #   手册 3.3.3 那张上位机调试参数表 (0x00xx/0x10xx/0x20xx/0x30xx) 里虽然也有
    #   同名参数 (spd_kp/loc_kp/VBUS/iq...), 但**不能用 CAN 读** —— 电机对不认识的
    #   index 只填 index, 数据区回上一次的残留字节 (实测 0x2014/0x2015 都回 8313.374).
    #   调试表地址速查见 doc/cybergear.md §7, 用厂家上位机软件访问.
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
        # ---- 下面 8 个是手册 4.1.12 CAN 参数表的尾部 (0x7019~0x7020) ----
        # ⚠ 手册注明: 这 8 个需要固件 >= 1.2.1.5 才能读
        0x7019: ("mechPos",          "负载端计圈机械角度 (rad, 只读)",            "float",   False),
        0x701A: ("iqf",              "q 轴滤波电流 (A, 只读)",                    "float",   False),
        0x701B: ("mechVel",          "负载端转速 (rad/s, 只读)",                  "float",   False),
        0x701C: ("VBUS",             "母线电压 (V, 只读)",                        "float",   False),
        0x701D: ("rotation",         "圈数 (int16)",                              "int16",   True),
        0x701E: ("loc_kp",           "位置环 KP (默认 30)",                       "float",   True),
        0x701F: ("spd_kp",           "速度环 KP (默认 1)",                        "float",   True),
        0x7020: ("spd_ki",           "速度环 KI (默认 0.002)",                    "float",   True),
    }

    # 参数归类: 哪些地址是"电压/电流", 给界面更新显示用
    # (CAN 参数表里只有这两个: 电压 0x701C VBUS, 电流 0x701A iqf)
    VOLTAGE_PARAMS = frozenset({0x701C})
    CURRENT_PARAMS = frozenset({0x701A})

    @classmethod
    def param_kind(cls, addr):
        """参数属于哪一类: 'voltage' / 'current' / None"""
        if addr in cls.VOLTAGE_PARAMS:
            return 'voltage'
        if addr in cls.CURRENT_PARAMS:
            return 'current'
        return None

    # 模式名 -> RUN_MODE raw 值
    MODE_ALIASES = {
        'ctrl': 0, 'motion': 0, '0': 0,
        'pos':  1, 'position': 1, '1': 1,
        'spd':  2, 'speed': 2,    '2': 2,
        'cur':  3, 'current': 3,  '3': 3,
    }

    # 反馈帧 ID 里的故障位 (手册 4.1.3: bit16~21 -> 这里 bit0~5)
    FAULT_ID_TEXT = {
        0x01: '欠压故障', 0x02: '过流故障', 0x04: '过温故障',
        0x08: '磁编码故障', 0x10: 'HALL编码故障', 0x20: '未标定',
    }
    # 反馈帧 ID 的 bit22~23: 电机状态
    STATE_NAMES = {0: 'Reset', 1: 'Cali', 2: 'Motor'}

    @classmethod
    def fault_id_text(cls, bits):
        """把反馈帧 ID 里的故障位翻成文字"""
        return ', '.join(t for b, t in cls.FAULT_ID_TEXT.items() if bits & b) or '无'

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
        """解析电机反馈 (通信类型 2).

        手册 4.1.3 的数据域 (大端 16 位 —— 实测温度 326 = 32.6°C 印证了大端):
          Byte0~1 当前角度   [0~65535] -> (-4π ~ 4π)
          Byte2~3 当前角速度 [0~65535] -> (-30 ~ 30 rad/s)
          Byte4~5 当前力矩   [0~65535] -> (-12 ~ 12 Nm)
          Byte6~7 当前温度   = 摄氏度 * 10    <- 这里除 10 换成 °C

        ⚠ 角度满量程手册写 (-4π~4π) = ±12.5664, 而 main.py/参考库写 ±12.5,
          两者差 0.53% (手册 4.2.1 的样例代码自己写的也是 ±12.5, 手册前后不一致).
          暂时沿用 ±12.5, 待实测确认 (读 0x7019 mechPos 对比最直接).
        """
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
            'temperature':     temp_raw / 10.0,   # 摄氏度 (上报值是 度*10)
            'temperature_raw': temp_raw,          # 原始上报值, 便于对照排查
        }

    # 手册 4.1.12: 通信类型 17 能读的参数 (0x7019~0x7020 需固件 >= 1.2.1.5).
    # 不在这张表里的地址 (如 0x2014/0x3007 那些) 属于 3.3.3 上位机调试参数表,
    # 用 CAN 读它们, 电机只回残留数据, 值没有意义.
    CAN_PARAM_ADDRS = frozenset({
        0x7005, 0x7006, 0x700A, 0x700B, 0x7010, 0x7011, 0x7014,
        0x7016, 0x7017, 0x7018,
        0x7019, 0x701A, 0x701B, 0x701C, 0x701D, 0x701E, 0x701F, 0x7020,
    })

    # 每种类型占几个字节 + 是否有符号 (用于按类型截取 data[4:8])
    TYPE_SIZE = {
        'uint8': (1, False), 'int8':  (1, True),
        'uint16': (2, False), 'int16': (2, True),
        'uint32': (4, False), 'int32': (4, True),
        'float': (4, False),
    }

    @classmethod
    def parse_param_response(cls, data):
        """解析参数读取响应 (通信类型 17).

        手册 4.1.8 应答帧: Byte0~1 = index, Byte2~3 = 00,
        Byte4~7 = 参数数据 —— **"1 字节数据在 Byte4"**.
        也就是说短类型只占低字节, 剩下的高字节是上一次响应残留的垃圾,
        必须按类型宽度只取前 N 个字节, 不能一律当 4 字节读.

        (实测: 读 0x7005 run_mode 响应 data=05 70 00 00 01 e5 01 46,
         真值在 Byte4 = 0x01, 高 3 字节 e5 01 46 是残留;
         老代码把 4 字节一起读 -> 0x4601E501 = 1174529281, 完全错.)

        响应包可能丢字节 (8 变 7), 也可能只到 4 字节. index 总会被 _on_rx 里的
        _pending_read 覆盖, 不用太信这里. 返回 dict 同时带 value_int 和 value_float,
        前端根据 type 选.
        """
        if len(data) < 4:
            return None
        if len(data) >= 8:
            param_index = data[0] | (data[1] << 8)
            raw = bytes(data[4:8])
        else:
            param_index = 0
            raw = bytes(data[-4:])
        param_info = cls.PARAM_NAMES.get(param_index)
        param_name = param_info[0] if param_info else f"未知参数(0x{param_index:04X})"
        vtype     = param_info[2] if param_info else 'float'
        size, signed = cls.TYPE_SIZE.get(vtype, (4, False))
        val_bytes = raw[:size]                       # 只取该类型自己的字节数
        value_int = int.from_bytes(val_bytes, 'little', signed=signed)
        # float 用原始 4 字节; 其它类型给一个有意义的浮点表示 (日志/显示用)
        value_float = struct.unpack('<f', raw)[0] if vtype == 'float' else float(value_int)
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
        self.fault_bits  = 0        # 反馈帧 ID 里的故障位 (手册 4.1.3)
        self.state       = None     # 反馈帧 ID 里的状态: Reset / Cali / Motor
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
            'fault_bits':  self.fault_bits,
            'state':       self.state,
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
        # target_id -> (已写入的 LIMIT_CUR, 时间戳)  仅用于 set_speed_ref 去重
        self._last_limit_cur = {}
        self._last_scan = {}   # scan() 的结果快照 (含"本次应答"的 id 列表)
        self._feedback_cb = None  # func(status_dict)
        self._param_read_cb = None  # func(motor_id, addr, entry)
        self._raw_packet_cb = None  # func(can_id, data, dlc) for CLI 调试打印
        # 静默: 仅由 --silent 参数设置. 默认 False = 打印所有 info 日志
        self._silent = False

    def set_silent(self, silent=True):
        """静默模式: 只打 4 类报文, 其它 info/err 不打 (给 CLI 的 --silent 用).
        串口层也要一起设, 所以外面不要再直接改 _silent / _serial.silent."""
        self._silent = bool(silent)
        self._serial.silent = bool(silent)

    def _log(self, *args):
        # info 类日志: --silent 时不打 (4 类报文不在这里, 它们总是打)
        if not self._silent:
            msg = 'motor info ' + ' '.join(str(a) for a in args)
            print(msg, flush=True)
            if LOG_CB is not None:
                LOG_CB(msg)

    def _log_tx(self, can_id, data):
        """统一 TX 日志: [motor]tx canid=0x<hex> data=<hex 拼接> (4 类必打之一, 不受 silent 影响)"""
        msg = f"[motor]tx canid=0x{can_id:08X} data={data.hex() if data else ''}"
        print(msg, flush=True)
        if LOG_CB is not None:
            LOG_CB(msg)

    def _log_rx(self, can_id, data):
        """统一 RX 日志: [motor]rx canid=0x<hex> data=<hex 拼接> (4 类必打之一, 不受 silent 影响)"""
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
            # 换了串口/重新上电, 之前记的 LIMIT_CUR 不一定还在电机里 -> 清空去重缓存
            with self._lock:
                self._last_limit_cur.clear()
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

        # 手册 4.1 的 29 位 ID 布局 (方向不同, 字段含义不同):
        #   主机 -> 电机 (1 运控/3 使能/4 停止/6 设零位/7 改ID/17 请求/18 写/22):
        #       bit15~8 = 主 CAN_ID,  bit7~0 = 目标电机 CAN_ID
        #   电机 -> 主机 (0 应答/2 反馈/17 应答/21 故障):
        #       bit15~8 = 电机 CAN_ID, bit7~0 = 主 CAN_ID
        # ⚠ 反馈帧以前按 target_id 取, 拿到的是"主机 id"(本代码固定 0) ->
        #   被下面的 motor_id==0 当成总线噪音整帧丢掉, 网页上 pos/vel/trq/tmp 永不更新.
        #   (你抓的读应答帧 canid=0x11000200 也印证了: 低字节=主机 id=0, bit15~8=电机 id=2)
        if comm_type in (CanProtocol.CMD_GET_ID, CanProtocol.CMD_FEEDBACK,
                         CanProtocol.CMD_READ_PARAM, CanProtocol.CMD_FAULT):
            motor_id = host_id or target_id     # 兜底: 个别固件把电机 id 放在低字节
        else:
            motor_id = target_id

        # 反馈帧的 ID 里还带了故障位和状态位 (手册 4.1.3), 别丢
        fault_bits = (can_id >> 16) & 0x3F      # bit16~21: 欠压/过流/过温/磁编码/HALL/未标定
        state_bits = (can_id >> 22) & 0x03      # bit22~23: 0 Reset / 1 Cali / 2 Motor

        # 统一打印 RX (过滤前也打, 让数据可见)
        self._log_rx(can_id, data)

        # motor_id=0 是主机自身 / 总线噪音, 不存进缓存
        if motor_id == 0:
            return

        fb_updated = False   # 本帧是否真的刷新了反馈状态 (决定要不要回调)

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
                    # 手册 4.1.3: 故障位/状态位在 ID 里, 一起收下来 (变了才打日志)
                    if m.fault_bits != fault_bits:
                        m.fault_bits = fault_bits
                        if fault_bits:
                            self._log(f"⚠ 电机 {motor_id} 上报故障位 0x{fault_bits:02X}: "
                                      f"{CanProtocol.fault_id_text(fault_bits)}")
                    m.state = CanProtocol.STATE_NAMES.get(state_bits)
                    fb_updated = True

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
                        # 地址不属于 CAN 参数表 -> 电机只会回残留数据, 明确提醒一下
                        if requested_addr not in CanProtocol.CAN_PARAM_ADDRS:
                            self._log(f"  ⚠ 0x{requested_addr:04X} 不在手册 4.1.12 的 CAN 参数表里 "
                                      f"(它属于 3.3.3 上位机参数表), 这个值没有意义")
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

        # 反馈回调: 只在真的刷新了反馈状态时调, 统一签名 cb(motor_id, status_dict).
        # 在锁外调用, 避免回调里再调库方法时死锁 (原来这里少传了 motor_id,
        # 必然 TypeError 被 except 吞掉, 等于回调永远不生效).
        if fb_updated and self._feedback_cb:
            with self._lock:
                snap = m.to_dict()
            try:
                self._feedback_cb(motor_id, snap)
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

    def get_param(self, target_id, addr):
        """取已缓存的参数读结果 (main-web 的 /api/param 用).
        异步读的响应由 _on_rx 填入 _param_cache; 没读到过就返回 None.
        """
        with self._lock:
            return self._param_cache.get((target_id, addr))

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

        # SPD 模式特殊处理: 先读 + 设 SPD_KP/KI (防止旧参数导致电机不转/抖动)
        # ⚠ 地址必须是 CAN 参数表里的 0x701F/0x7020 (spd_kp/spd_ki).
        #   原来写的是 0x2014/0x2015 —— 上位机调试表地址, CAN 读写都无效,
        #   等于每次切速度模式都做了两次静默空操作.
        #   手册注明 0x7019~0x7020 需固件 >= 1.2.1.5, 老固件下这两次写也读不到.
        if mode_str == 'spd':
            self._log(f"  spd 模式: 先读 + 设 SPD_KP/KI (0x701F/0x7020) = 2.0 / 0.021")
            kp_entry = self._read_param_sync(target_id, 0x701F)
            if kp_entry:
                self._log(f"    当前 SPD_KP (0x701F) = {kp_entry['value_float']:.6f}")
            else:
                self._log(f"    当前 SPD_KP (0x701F) 读超时 (固件 < 1.2.1.5 时读不到)")
            ki_entry = self._read_param_sync(target_id, 0x7020)
            if ki_entry:
                self._log(f"    当前 SPD_KI (0x7020) = {ki_entry['value_float']:.6f}")
            else:
                self._log(f"    当前 SPD_KI (0x7020) 读超时 (固件 < 1.2.1.5 时读不到)")
            ok1, _ = self.write_param(target_id, 0x701F, 2.0)
            ok2, _ = self.write_param(target_id, 0x7020, 0.021)
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
            # 切模式后保险起见让 LIMIT_CUR 重写一次 (下次速度指令会带上)
            self._last_limit_cur.pop(target_id, None)
        return True, "模式设置完成"

    def set_position_ref(self, target_id, n):
        """n 单位 1/60 圈"""
        angle_rad = n * (2.0 * math.pi) / 60.0
        self._log(f"set_pos -> id={target_id} n={n} ({angle_rad:.4f} rad)")
        return self.write_param(target_id, 0x7016, angle_rad)

    # 同一个 LIMIT_CUR 最多缓存这么久, 超过就重写一次:
    # 防止电机掉电重启后寄存器被复位成 0 (那样电机会不转)
    LIMIT_CUR_REWRITE_S = 2.0

    def set_speed_ref(self, target_id, rad_per_s, limit_cur=1.0):
        """速度模式: 写 SPD_REF (0x700A), 可选写 LIMIT_CUR (0x7018).

        limit_cur:
          - 省略 (默认 1.0): 先写 LIMIT_CUR 再写速度 —— 留原始行为给 CLI 等调用方
            (参考 Arduino mimotor.ino: 速度模式必写 LIMIT_CUR=1A, 否则限流=0 电机不转)
          - None: 只写 SPD_REF, 完全不碰 0x7018 —— 网页拖动条走这条,
            限流由用户在参数行点 set 单独下发

        写 LIMIT_CUR 时会去重: 值没变 (且缓存没超过 LIMIT_CUR_REWRITE_S) 就跳过,
        避免拖动条把 CAN 帧数翻倍.
        失效时机: 重新打开串口 / 切模式 / 任何其它路径直写 0x7018 都会更新缓存.
        """
        if limit_cur is None:
            self._log(f"set_spd -> id={target_id} rad={rad_per_s} (只发速度, 不动 LIMIT_CUR)")
            return self.write_param(target_id, 0x700A, float(rad_per_s))

        limit_cur = float(limit_cur)
        now = time.time()
        with self._lock:
            last = self._last_limit_cur.get(target_id)
        need_limit = (last is None
                      or abs(last[0] - limit_cur) > 1e-9
                      or (now - last[1]) > self.LIMIT_CUR_REWRITE_S)

        self._log(f"set_spd -> id={target_id} limit_cur={limit_cur}A rad={rad_per_s}"
                  + ("" if need_limit else " (limit_cur 未变, 跳过 0x7018)"))
        if need_limit:
            ok1, r1 = self.write_param(target_id, 0x7018, limit_cur)
            if not ok1:
                return False, r1
        ok2, r2 = self.write_param(target_id, 0x700A, float(rad_per_s))
        return ok2, r2

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
        ok, result = self._serial.send_can(can_id, bytes(data))
        # 任何写 0x7018 的路径都同步去重缓存 (set_speed_ref / setlimitcur / setprop ...)
        if ok and addr == 0x7018 and vtype == 'float':
            with self._lock:
                self._last_limit_cur[target_id] = (float(value), time.time())
        return ok, result

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

    # 逐个扫描时给串口留的帧间隔 (115200 下一帧约 1.7ms, 3ms 足够且不把适配器冲爆)
    SCAN_GAP_S = 0.003
    # 全部 id 的范围: 手册调试表里 CAN_ID 最大 127, 主机 id 是 0 -> 电机只能是 1~127
    SCAN_ID_RANGE = range(1, 128)

    def scan(self, targets=None, broadcast=False, host_id=0x00, timeout=0.25,
             id_range=None, gap=None):
        """扫描电机: 逐个 id 发 GET_ID (通信类型 0), 谁应答谁存在.

        ⚠ 实测: 向 0xFE 发广播**没有任何应答**(手册也只在"获取设备 ID 的应答帧"里
          出现过 0XFE, 从没说它是广播地址). 所以默认行为改成"真正逐个 id 发报文":
          targets=None -> 扫 1~127 全部 id; targets=[...] -> 只探这些 id.
          broadcast 参数保留仅为兼容旧调用, 现在等于"扫全部 id".

        每帧之间只留 SCAN_GAP_S, 发完后统一等 timeout 收应答 —— 127 个 id 约 0.6s.
        GET_ID 的应答会刷新 MotorStatus.last_update, 调用方据此判断"本次是否在总线上".
        返回更新后的电机列表 (注意是累积缓存).
        """
        if targets is None:
            tgts = list(id_range if id_range is not None else self.SCAN_ID_RANGE)
            self._log(f"scan: 逐个 GET_ID -> 1~127 共 {len(tgts)} 个 id"
                      + (" (broadcast 参数已不再发 0xFE)" if broadcast else ""))
        else:
            tgts = [int(t) for t in targets]
            self._log(f"scan: GET_ID -> {tgts}")
        gap = self.SCAN_GAP_S if gap is None else gap
        t0 = time.time()
        for t in tgts:
            can_id = CanProtocol.build_can_id(CanProtocol.CMD_GET_ID, host_id, t)
            self._log_tx(can_id, b'')
            ok, _ = self._serial.send_can(can_id, b'')
            if not ok:
                self._log(f"  send_can 失败 (id={t})")
                break            # 串口没了就不用继续发
            time.sleep(gap)
        time.sleep(timeout)
        motors = self.get_motors()
        # "本次是否在总线上"只能看应答有没有刷新 last_update —— get_motors() 是累积缓存,
        # 拔掉的电机也会留在里面. 把结论记在 _last_scan 里给调用方用 (CLI/Web 都别自己算).
        self._last_scan = {
            'started':  t0,
            'duration': time.time() - t0,
            'targets':  list(tgts),
            'answered': [m['target_id'] for m in motors if m.get('last_update', 0) >= t0],
        }
        self._log(f"scan: 完成 {self._last_scan['duration']:.2f}s, "
                  f"本次应答 {len(self._last_scan['answered'])} 台 {self._last_scan['answered']}, "
                  f"缓存共 {len(motors)} 台")
        return motors

    def last_scan_answered(self):
        """最近一次 scan() 里真正应答的电机 id 列表 (""=还没扫过)."""
        return list(self._last_scan.get('answered', []))

    def send_raw(self, can_id, data=b'', log=True):
        """直接发一帧原生 CAN 报文 (给 CLI 的调试命令用, 不要在外面碰 _serial)."""
        if log:
            self._log_tx(can_id, data)
        with self._lock:
            return self._serial.send_can(can_id, data)


class SetpointChannel:
    """连续控制指令 (位置/速度) 的合并通道.

    拖动条会不停下发目标值, 但只有"最新值"有意义. 直接同步写串口的话:
      快速拖动 -> 一堆请求排队抢 MOTOR_LOCK -> 后面点 stop 还得排在它们后面,
      而且停完之后残留的旧位置指令还会把电机带走.
    这里:
      - submit() 直接覆盖旧值, 排队深度恒 <= 1, 不会堆积;
      - 单独线程按 min_interval 限速下发, 不刷爆串口;
      - discard() 必须在持有 MOTOR_LOCK 时调用, 保证丢弃后不会再有旧值落到电机上
        (取值的时机放在"拿到 MOTOR_LOCK 之后", 见 _run).
    """

    def __init__(self, name, apply_fn, lock, log_fn=None, min_interval=0.02):
        """
        name:        通道名 (日志用)
        apply_fn:    func(target, payload) —— 真正写串口的动作
        lock:        串口事务锁 (调用方持有 discard() 时必须已持有它)
        log_fn:      func(msg) 可选日志回调
        """
        self.name = name
        self._apply = apply_fn
        self._lock = lock
        self._log_fn = log_fn
        self._min_interval = min_interval
        self._cv = threading.Condition()
        self._pending = None      # (target, payload) 或 None
        self._dropped = 0
        self._closed = False
        threading.Thread(target=self._run, name=f'setpoint-{name}', daemon=True).start()

    def _log(self, msg):
        if self._log_fn:
            try:
                self._log_fn(msg)
            except Exception:
                pass

    def submit(self, target, payload):
        """入队 (非阻塞, 立刻返回). 返回被顶掉的旧值条数 (0 或 1)."""
        with self._cv:
            dropped = 1 if self._pending is not None else 0
            self._pending = (target, payload)
            self._dropped += dropped
            self._cv.notify()
            return dropped

    def discard(self):
        """丢弃还没下发的指令. ⚠ 必须在持有构造时传入的那把锁的情况下调用."""
        with self._cv:
            n = 1 if self._pending is not None else 0
            self._pending = None
            self._dropped += n
            return n

    def _run(self):
        while not self._closed:
            with self._cv:
                while self._pending is None and not self._closed:
                    self._cv.wait()
            # 先抢串口锁, 拿到锁之后才把最新值取走 -> 持锁的 discard() 一定能拦住旧值
            with self._lock:
                with self._cv:
                    item, self._pending = self._pending, None
                    dropped, self._dropped = self._dropped, 0
                if item is not None:
                    try:
                        self._apply(*item)
                    except Exception as e:
                        self._log(f"{self.name}指令下发失败: {e}")
                    if dropped:
                        self._log(f"{self.name}指令合并丢弃 {dropped} 条旧值 (拖动过快)")
            time.sleep(self._min_interval)
