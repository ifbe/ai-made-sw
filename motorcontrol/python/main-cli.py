# main-cli.py
"""
串口转CAN数据监听工具 - 命令行入口
所有电机逻辑在 cybergear.py, 这里只管 CLI / 打印 / 命令循环。
"""
import os
import sys
import time
import struct
import threading
import queue

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cybergear import CanProtocol, CyberGearMotor


class Console:
    """控制台输出队列, 避免多线程打印冲突"""

    def __init__(self):
        self.print_queue = queue.Queue()
        self.running = False
        self.worker_thread = None

    def start(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.running = False
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=0.5)

    def put(self, msg):
        self.print_queue.put(msg)

    def flush(self):
        while not self.print_queue.empty():
            time.sleep(0.01)

    def _worker(self):
        while self.running:
            try:
                msg = self.print_queue.get(timeout=0.1)
                if msg is None:
                    continue
                print(msg)
                self.print_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                pass


class MotorCli:
    def __init__(self):
        self.motor = CyberGearMotor()
        self.console = Console()
        self.running = False
        self.current_target = None
        self.packet_count = 0

    def _on_raw_packet(self, can_id, data, dlc):
        """原始包回调 - 打印 CAN 帧解析 (调试用)"""
        if can_id is None:
            return
        self.packet_count += 1
        comm_type, comm_name, host_id, target_id = CanProtocol.parse_can_id(can_id)
        lines = []
        lines.append("")
        lines.append("~" * 70)
        lines.append(f"📦 数据包 #{self.packet_count} (CAN帧)")
        lines.append(f"   CAN ID (29位): 0x{can_id:08X}")
        lines.append(f"   DLC: {dlc}")
        lines.append(f"   数据: {data.hex() if data else ''}")
        lines.append("")
        lines.append(f"   📌 CAN帧解析:")
        lines.append(f"   通信类型: 0x{comm_type:02X} ({comm_name})")
        lines.append(f"   主机ID: 0x{host_id:02X} ({host_id})")
        lines.append(f"   目标电机CAN ID: 0x{target_id:02X} ({target_id})")

        if comm_type == CanProtocol.CMD_GET_ID and len(data) >= 8:
            mcu_id = int.from_bytes(data[0:8], 'little')
            lines.append(f"   设备CAN ID: 0x{host_id:02X} ({host_id})")
            lines.append(f"   MCU唯一标识: 0x{mcu_id:016X}")

        elif comm_type == CanProtocol.CMD_READ_PARAM and len(data) >= 8:
            param = CanProtocol.parse_param_response(data)
            if param:
                lines.append(f"   参数Index: 0x{param['index']:04X} ({param['name']})")
                lines.append(f"   参数值(整数): {param['value_int']} (0x{param['value_int']:08X})")
                lines.append(f"   参数值(浮点): {param['value_float']:.6f}")

        elif comm_type == CanProtocol.CMD_FEEDBACK and len(data) >= 8:
            fb = CanProtocol.parse_feedback(data)
            if fb:
                lines.append(f"   角度: {fb['position']:.4f} rad")
                lines.append(f"   速度: {fb['speed']:.4f} rad/s")
                lines.append(f"   力矩: {fb['torque']:.4f} Nm")
                lines.append(f"   温度: {fb['temperature']} (raw)")

        elif comm_type == CanProtocol.CMD_FAULT:
            fault_info = CanProtocol.parse_fault(data)
            if fault_info:
                lines.append(f"   Fault值: 0x{fault_info['fault']:08X}")
                if fault_info['fault_msgs']:
                    lines.append("   ⚠️ 有故障!")
                    for msg in fault_info['fault_msgs']:
                        lines.append(f"      - {msg}")

        elif comm_type == CanProtocol.CMD_SET_CAN_ID and len(data) >= 1:
            lines.append(f"   预设CAN_ID: 0x{data[0]:02X} ({data[0]})")

        elif comm_type == CanProtocol.CMD_WRITE_PARAM and len(data) >= 8:
            param_index = data[0] | (data[1] << 8)
            lines.append(f"   参数Index: 0x{param_index:04X}")
            value_int = int.from_bytes(data[4:8], 'little')
            value_float = struct.unpack('<f', data[4:8])[0]
            lines.append(f"   写入值(整数): {value_int} (0x{value_int:08X})")
            lines.append(f"   写入值(浮点): {value_float:.6f}")

        elif comm_type == CanProtocol.CMD_SET_BAUDRATE and len(data) >= 1:
            baud_val = data[0]
            baud_map = {1: "1Mbps", 2: "500kbps", 3: "250kbps", 4: "125kbps"}
            lines.append(f"   波特率: {baud_map.get(baud_val, f'未知({baud_val})')}")

        lines.append("~" * 70)
        for line in lines:
            self.console.put(line)

    def _send_can(self, can_id, data=b''):
        if not self.motor.is_open():
            self.console.put("❌ 串口未打开")
            return False
        ok, result = self.motor._serial.send_can(can_id, data)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 发送失败: {result}")
        return ok

    def _parse_target(self, args):
        """解析目标设备ID"""
        if self.current_target is not None:
            return self.current_target
        if args:
            try:
                arg = args[0]
                if arg.startswith('0x') or arg.startswith('0X'):
                    return int(arg, 16)
                return int(arg)
            except ValueError:
                pass
        return None

    def _target_args(self, args):
        """返回 (target_id, remaining_args), 处理 @ 前缀"""
        if self.current_target is not None:
            return self.current_target, args
        if args:
            try:
                arg = args[0]
                if arg.startswith('0x') or arg.startswith('0X'):
                    return int(arg, 16), args[1:]
                return int(arg), args[1:]
            except ValueError:
                pass
        return None, args

    # ===================== 命令 =====================

    def cmd_ls(self, args):
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("🔍 扫描CAN总线上的设备...")
        self.console.put("=" * 70)

        if self.current_target is not None:
            targets = [self.current_target]
            self.console.put(f"\n   📌 模式: 指定设备 0x{self.current_target:02X}({self.current_target}) (来自@前缀)")
        elif not args:
            targets = [0xFE]
            self.console.put("\n   📌 模式: 广播 (目标ID: 0xFE)")
        else:
            targets = []
            for arg in args:
                try:
                    if arg.startswith('0x') or arg.startswith('0X'):
                        target_id = int(arg, 16)
                    else:
                        target_id = int(arg)
                    if 0 <= target_id <= 127:
                        targets.append(target_id)
                    else:
                        self.console.put(f"   ⚠️ 跳过无效ID: {arg} (范围 0-127)")
                except ValueError:
                    self.console.put(f"   ⚠️ 跳过无效参数: {arg}")

            if not targets:
                self.console.put("   ❌ 没有有效的设备ID")
                return True

        # 调用库的 scan
        before = {m['target_id'] for m in self.motor.get_motors()}
        results = self.motor.scan(targets=targets, broadcast=False)
        new = [r for r in results if r['target_id'] in set(targets) and r['target_id'] not in before]

        if new:
            self.console.put(f"\n   ✅ 收到 {len(new)} 个新响应:")
            for resp in new:
                self.console.put(f"      - 设备CAN ID: 0x{resp['target_id']:02X} ({resp['target_id']})")
                if resp.get('mcu_id'):
                    self.console.put(f"        MCU唯一标识: {resp['mcu_id']}")
        else:
            # 看是不是已有但有 mcu_id
            existing = [r for r in results if r['target_id'] in set(targets)]
            if existing:
                for resp in existing:
                    self.console.put(f"\n   ℹ️  设备 0x{resp['target_id']:02X} 已有缓存"
                                     + (f" (MCU: {resp['mcu_id']})" if resp.get('mcu_id') else ""))
            else:
                self.console.put("\n   ⚠️ 未收到响应")
        self.console.put("=" * 70)
        return True

    def cmd_getprop(self, args):
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("📊 获取参数")
        self.console.put("=" * 70)

        if not args:
            self.console.put("\n   📋 可查询的参数列表:")
            self.console.put("   " + "-" * 60)
            for idx, (name, desc, dtype) in sorted(CanProtocol.PARAM_NAMES.items()):
                self.console.put(f"   0x{idx:04X}  {name:20s}  {dtype:10s}  {desc}")
            self.console.put("   " + "-" * 60)
            self.console.put(f"   共 {len(CanProtocol.PARAM_NAMES)} 个参数")
            self.console.put("\n   💡 使用 'getprop 0x7005' 获取指定参数")
            self.console.put("=" * 70)
            return True

        target_id = self.current_target
        if target_id is None:
            self.console.put("   ❌ 请先使用 @设备ID 指定目标设备，例如: @1 getprop 0x7005")
            self.console.put("=" * 70)
            return True

        for arg in args:
            try:
                if arg.startswith('0x') or arg.startswith('0X'):
                    param_index = int(arg, 16)
                else:
                    param_index = int(arg)
                param_info = CanProtocol.PARAM_NAMES.get(param_index)
                param_name = param_info[0] if param_info else f"未知参数(0x{param_index:04X})"
                self.console.put(f"\n   📝 读取参数: 0x{param_index:04X} ({param_name})")
                ok, result = self.motor.read_param(target_id, param_index)
                if ok:
                    self.console.put(f"   📤 发送: {result.hex()}")
                else:
                    self.console.put(f"   ❌ 失败: {result}")
                time.sleep(0.05)
            except ValueError:
                self.console.put(f"   ⚠️ 无效参数: {arg}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_enable(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: enable 1 或 @1 enable")
            return True
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("⚡ 电机使能")
        self.console.put("=" * 70)
        ok, result = self.motor.enable(target_id)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
            self.console.put(f"\n   📝 发送使能指令: 目标ID=0x{target_id:02X}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_stop(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: stop 1 或 @1 stop")
            return True
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("⏹️ 电机停止")
        self.console.put("=" * 70)
        ok, result = self.motor.stop(target_id)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
            self.console.put(f"\n   📝 发送停止指令: 目标ID=0x{target_id:02X}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_setmode(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: setmode pos 或 @1 setmode pos")
            return True
        if not args:
            self.console.put("")
            self.console.put("=" * 70)
            self.console.put("🎛️ 运行模式 (写入 RUN_MODE 0x7005)")
            self.console.put("=" * 70)
            self.console.put("  0 / ctrl   - 运控模式")
            self.console.put("  1 / pos    - 位置模式")
            self.console.put("  2 / spd    - 速度模式")
            self.console.put("  3 / cur    - 电流模式")
            self.console.put("")
            self.console.put("  💡 用法: setmode pos   或   setmode 1")
            self.console.put("=" * 70)
            return True

        mode_str = str(args[0]).lower()
        if CanProtocol.mode_from_alias(mode_str) is None:
            self.console.put(f"   ❌ 未知模式: {args[0]} (ctrl/pos/spd/cur 或 0/1/2/3)")
            return True

        self.console.put("")
        self.console.put("=" * 70)
        self.console.put(f"🎛️ 设置模式: {mode_str}")
        self.console.put("=" * 70)
        ok, result = self.motor.set_mode(target_id, mode_str)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_setprop(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: @1 setprop 0x7016 3.14")
            return True
        if len(args) < 2:
            self.console.put("   ❌ 用法: setprop <addr> <float>")
            self.console.put("      例: setprop 0x7016 3.14")
            self.console.put("      例: setprop 0x700A 5.0  (速度模式 SPD_REF)")
            return True
        try:
            addr_str = args[0]
            if addr_str.startswith('0x') or addr_str.startswith('0X'):
                addr = int(addr_str, 16)
            else:
                addr = int(addr_str)
            value = float(args[1])
        except ValueError:
            self.console.put(f"   ❌ 参数解析失败")
            return True

        param_info = CanProtocol.PARAM_NAMES.get(addr)
        param_name = param_info[0] if param_info else f"未知参数(0x{addr:04X})"

        self.console.put("")
        self.console.put("=" * 70)
        self.console.put(f"✏️ 写参数: {param_name}")
        self.console.put("=" * 70)
        ok, result = self.motor.write_param(target_id, addr, value)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_getmode(self, args):
        return self.cmd_getprop(['0x7005'])

    def cmd_pos(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: @1 pos 60")
            return True
        if not args:
            self.console.put("   ❌ 用法: pos <n>  (n 单位 1/60 圈, 60=1圈, 1=6°)")
            return True
        try:
            n = float(args[0])
        except ValueError:
            self.console.put(f"   ❌ 无效参数: {args[0]}")
            return True

        import math
        angle_rad = n * (2.0 * math.pi) / 60.0
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put(f"📍 位置模式: n={n} -> {angle_rad:.6f} rad ({n/60:.4f} 圈)")
        self.console.put("=" * 70)
        ok, result = self.motor.set_position_ref(target_id, n)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_speed(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: @1 speed 3.14")
            return True
        if not args:
            self.console.put("   ❌ 用法: speed <rad/s>")
            return True
        try:
            v = float(args[0])
        except ValueError:
            self.console.put(f"   ❌ 无效参数: {args[0]}")
            return True
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put(f"💨 速度模式: SPD_REF = {v} rad/s")
        self.console.put("=" * 70)
        ok, result = self.motor.set_speed_ref(target_id, v)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_cur(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: @1 cur 0.5")
            return True
        if not args:
            self.console.put("   ❌ 用法: cur <A>")
            return True
        try:
            i = float(args[0])
        except ValueError:
            self.console.put(f"   ❌ 无效参数: {args[0]}")
            return True
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put(f"⚡ 电流模式: IQ_REF = {i} A")
        self.console.put("=" * 70)
        ok, result = self.motor.set_current_ref(target_id, i)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_ctrl(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: @1 ctrl <pos> <vel> <kp> <kd> <torque>")
            return True
        if len(args) < 5:
            self.console.put("   ❌ 用法: ctrl <pos> <vel> <kp> <kd> <torque>")
            self.console.put("      pos:    rad         [-12.5, +12.5]")
            self.console.put("      vel:    rad/s       [-30,   +30  ]")
            self.console.put("      kp:     0~500")
            self.console.put("      kd:     0~5")
            self.console.put("      torque: Nm          [-12,   +12  ]")
            return True
        try:
            pos    = float(args[0])
            vel    = float(args[1])
            kp     = float(args[2])
            kd     = float(args[3])
            torque = float(args[4])
        except ValueError as e:
            self.console.put(f"   ❌ 参数解析失败: {e}")
            return True

        self.console.put("")
        self.console.put("=" * 70)
        self.console.put(f"🎮 运控模式: pos={pos} vel={vel} kp={kp} kd={kd} tor={torque}")
        self.console.put("=" * 70)
        ok, result = self.motor.send_motion(target_id, pos, vel, kp, kd, torque)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_set_zero(self, args):
        target_id = self._parse_target(args)
        if target_id is None:
            self.console.put("   ❌ 请指定目标设备: setzero 1 或 @1 setzero")
            return True
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("📍 设置机械零位")
        self.console.put("=" * 70)
        ok, result = self.motor.set_zero(target_id)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
            self.console.put(f"\n   📝 发送设置零位指令: 目标ID=0x{target_id:02X}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_set_can_id(self, args):
        if len(args) < 2:
            self.console.put("   ❌ 用法: setcanid 旧ID 新ID 或 @旧ID setcanid 新ID")
            return True
        try:
            target_id = self._parse_target(args[:1])
            if target_id is None:
                old_id = int(args[0]) if not args[0].startswith('0x') else int(args[0], 16)
                target_id = old_id
            new_id = int(args[1]) if not args[1].startswith('0x') else int(args[1], 16)
        except ValueError:
            self.console.put("   ❌ 无效的ID格式")
            return True
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("🔄 设置CAN ID")
        self.console.put("=" * 70)
        ok, result = self.motor.set_can_id(target_id, new_id)
        if ok:
            self.console.put(f"   📤 发送: {result.hex()}")
            self.console.put(f"\n   📝 发送设置CAN_ID: 目标ID=0x{target_id:02X} -> 新ID=0x{new_id:02X}")
        else:
            self.console.put(f"   ❌ 失败: {result}")
        time.sleep(0.1)
        self.console.put("=" * 70)
        return True

    def cmd_help(self, args):
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("可用命令:")
        self.console.put("=" * 70)
        self.console.put("  @设备ID 命令         - 指定目标设备执行命令")
        self.console.put("  示例:")
        self.console.put("    @1 ls              - 向设备1发送获取设备ID")
        self.console.put("    @1 getprop 0x7005  - 获取设备1的参数")
        self.console.put("")
        self.console.put("  ls                  - 发送获取设备ID到广播地址(0xFE)")
        self.console.put("  ls 1                - 发送获取设备ID到设备1")
        self.console.put("")
        self.console.put("  getprop             - 列出所有可查询的参数")
        self.console.put("  getprop 0x7005      - 获取指定参数 (别名 getparam)")
        self.console.put("  getmode             - 读取 RUN_MODE (0x7005), 等价 getprop 0x7005")
        self.console.put("")
        self.console.put("  enable / stop       - 使能/停止电机 (需指定设备)")
        self.console.put("  setzero / setcanid  - 设零位 / 改 CAN ID")
        self.console.put("")
        self.console.put("  运控四件套 (都只发 setparam 或 motion 帧, 不包 enable):")
        self.console.put("    setmode [ctrl|pos|spd|cur]  - 不带参: 列模式; 带参: 写 RUN_MODE (0x7005)")
        self.console.put("    setprop <addr> <float>      - 写任意参数 (float LE, 别名 setparam)")
        self.console.put("    pos <n>                     - 位置模式: n 单位 1/60 圈 (写 0x7016)")
        self.console.put("    speed <rad/s>               - 速度模式 (写 0x700A)")
        self.console.put("    cur <A>                     - 电流模式 (写 0x7006)")
        self.console.put("    ctrl <pos> <vel> <kp> <kd> <torque>  - 运控 (通信类型 0x01)")
        self.console.put("")
        self.console.put("  启动示例 (位置模式转一圈):")
        self.console.put("    @1 setmode pos      # 切到位置模式 (写 0x7005=1)")
        self.console.put("    @1 enable           # 使能电机")
        self.console.put("    @1 pos 60           # 转 1 圈 (写 0x7016=2π)")
        self.console.put("")
        self.console.put("  help                - 显示此帮助")
        self.console.put("  quit / exit / q     - 退出程序")
        self.console.put("=" * 70)
        return True

    def cmd_quit(self, args):
        self.console.put("\n👋 正在退出...")
        self.running = False
        return False

    def _process_command(self, cmd_line):
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return True
        # @设备ID 前缀
        if cmd_line.startswith('@'):
            parts = cmd_line.split()
            if len(parts) >= 2:
                prefix = parts[0]
                try:
                    if prefix[1:].startswith('0x') or prefix[1:].startswith('0X'):
                        target_id = int(prefix[1:], 16)
                    else:
                        target_id = int(prefix[1:])
                    if 0 <= target_id <= 127:
                        self.current_target = target_id
                        self.console.put(f"   🎯 目标设备: {target_id}")
                        cmd_line = ' '.join(parts[1:])
                    else:
                        self.console.put(f"⚠️ 无效设备ID: {target_id} (范围 0-127)")
                        return True
                except ValueError:
                    self.console.put(f"⚠️ 无效设备ID: {prefix[1:]}")
                    return True
        parts = cmd_line.split()
        if not parts:
            return True
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        commands = {
            'ls': self.cmd_ls,
            'getprop': self.cmd_getprop,
            'getparam': self.cmd_getprop,
            'getmode': self.cmd_getmode,
            'enable': self.cmd_enable,
            'stop': self.cmd_stop,
            'setmode': self.cmd_setmode,
            'setprop': self.cmd_setprop,
            'setparam': self.cmd_setprop,
            'pos': self.cmd_pos,
            'speed': self.cmd_speed,
            'cur': self.cmd_cur,
            'ctrl': self.cmd_ctrl,
            'setzero': self.cmd_set_zero,
            'setcanid': self.cmd_set_can_id,
            'help': self.cmd_help,
            '?': self.cmd_help,
            'quit': self.cmd_quit,
            'exit': self.cmd_quit,
            'q': self.cmd_quit,
        }
        if cmd in commands:
            return commands[cmd](args)
        else:
            self.console.put(f"❌ 未知命令: {cmd} (输入 'help' 查看可用命令)")
            return True

    def _command_loop(self):
        self.console.put("")
        self.console.put("=" * 70)
        self.console.put("💡 输入 'help' 查看可用命令，输入 'quit' 退出")
        self.console.put("=" * 70)
        while self.running:
            self.console.flush()
            try:
                cmd = input("> ").strip()
                if not cmd:
                    continue
                if not self._process_command(cmd):
                    break
            except KeyboardInterrupt:
                self.console.put("\n")
                break
            except EOFError:
                break
            except Exception as e:
                self.console.put(f"❌ 错误: {e}")

    def run(self):
        print("=" * 70)
        print("🔌 串口转CAN数据监听工具 (CLI)")
        print("   协议: 41 54 帧头 | 0D 0A 帧尾 | USB转CAN模块")
        print("=" * 70)

        ports = self.motor._serial.list_ports()
        if not ports:
            print("未找到任何串口设备！")
            return
        print("\n可用的串口列表:")
        print("-" * 60)
        for i, p in enumerate(ports):
            print(f"  {i+1}. {p['device']} - {p['description']}")
            if p['vid'] is not None and p['pid'] is not None:
                print(f"     VID:PID = {p['vid']:04X}:{p['pid']:04X}")
        print("-" * 60)

        while True:
            try:
                choice = input(f"\n请选择串口 (1-{len(ports)}): ")
                idx = int(choice) - 1
                if 0 <= idx < len(ports):
                    port = ports[idx]['device']
                    break
                else:
                    print(f"请输入 1 到 {len(ports)} 之间的数字")
            except ValueError:
                print("请输入有效的数字")
            except KeyboardInterrupt:
                print("\n用户取消")
                return

        baudrates = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
        print("\n可用的波特率:")
        print("-" * 60)
        for i, baud in enumerate(baudrates):
            print(f"  {i+1}. {baud}")
        print("-" * 60)
        while True:
            try:
                choice = input(f"\n请选择波特率 (1-{len(baudrates)}, 默认 115200): ")
                if choice.strip() == "":
                    baudrate = 115200
                    break
                idx = int(choice) - 1
                if 0 <= idx < len(baudrates):
                    baudrate = baudrates[idx]
                    break
                else:
                    print(f"请输入 1 到 {len(baudrates)} 之间的数字")
            except ValueError:
                print("请输入有效的数字")
            except KeyboardInterrupt:
                print("\n用户取消")
                return

        ok, msg = self.motor.open(port, baudrate)
        print(msg)
        if not ok:
            return

        self.console.start()
        self.motor.set_raw_packet_callback(self._on_raw_packet)
        self.running = True

        try:
            self._command_loop()
        finally:
            self.running = False
            self.motor.close()
            self.console.stop()
            print("👋 程序退出")


def main():
    cli = MotorCli()
    try:
        cli.run()
    except KeyboardInterrupt:
        print("\n\n👋 程序被用户中断")
        sys.exit(0)


if __name__ == "__main__":
    main()
