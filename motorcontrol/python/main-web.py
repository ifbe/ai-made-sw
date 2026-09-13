# main-web.py
"""
小米 CyberGear 电机 - Web 控制端 (Flask)
- --addr 默认 127.0.0.1, --port 默认 9999
- 一个 CyberGearMotor 实例, 多线程共享
"""
import argparse
import json
import os
import sys
import threading
import time
import logging

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_sock import Sock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cybergear import CanProtocol, CyberGearMotor
from logbuf import LogBuffer

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

# 单进程共享的电机实例
MOTOR = CyberGearMotor()
MOTOR_LOCK = threading.Lock()  # 用于写操作的串行化

# 全局 log buffer + 回调 (供 /api/logs + WS 推送使用)
GLOBAL_LOG = LogBuffer(maxlen=500)
def _push_log(msg):
    GLOBAL_LOG.append(msg)
    _broadcast_log(msg)  # 推送到 /log 订阅者
    # 如果是帧日志, 同时也推一份原始帧到 /ws/frames 订阅者
    fm = _FRAME_RE.search(msg)
    if fm:
        direction = fm.group(1)             # 'tx' | 'rx'
        can_id    = int(fm.group(2), 16)     # 原始 int
        data_hex  = fm.group(3) or ''        # hex 字符串 (可能空)
        _broadcast_frame(direction, can_id, data_hex)
# 启动时调用 motor 的 set_log_callback, motor 内部会转给 serial
MOTOR.set_log_callback(_push_log)

# 电机反馈状态回调 -> 推 /ws/status (pos/vel/torque/temp 被动更新)
def _push_status(motor_id, status):
    """CyberGearMotor feedback 回调: 反馈帧到达 -> 推 status WS."""
    try:
        _broadcast(json.dumps({
            "type": "status",
            "motor_id": motor_id,
            "data": status,
        }), kind='status')
    except Exception:
        pass
MOTOR.set_feedback_callback(_push_status)

# 参数读取响应回调 -> 凡是电压/电流地址的回复都推到 /ws/status (被动, 谁查的都算)
# 地址全部以 PDF 手册 3.3.3 节为准
_VOLTAGE_ADDRS = {0x3007, 0x300C, 0x302B}  # vBus_mv / VBUS / v_bus(闭环)
_CURRENT_ADDRS = {0x3020, 0x301E, 0x3021, 0x3019, 0x301A, 0x301B, 0x302E, 0x302F}  # iq/iqf/id/ia/ib/ic/rated_i/limit_i

def _push_param_read(motor_id, addr, entry):
    """CyberGearMotor param-read 回调: 仅电压/电流地址推到 status WS."""
    if addr in _VOLTAGE_ADDRS:
        # 电压: 0x3007 是 mV (uint16), 0x300C 是 V (float) — 统一转 V
        if addr == 0x3007:
            voltage_v = float(entry.get('value_int', 0)) / 1000.0
        else:
            voltage_v = float(entry.get('value_float', 0.0))
        try:
            _broadcast(json.dumps({
                "type": "status",
                "motor_id": motor_id,
                "data": {"voltage": voltage_v, "last_update": time.time()},
            }), kind='status')
        except Exception:
            pass
    elif addr in _CURRENT_ADDRS:
        # 电流全是 A
        current_a = float(entry.get('value_float', 0.0))
        try:
            _broadcast(json.dumps({
                "type": "status",
                "motor_id": motor_id,
                "data": {"current": current_a, "last_update": time.time()},
            }), kind='status')
        except Exception:
            pass
MOTOR.set_param_read_callback(_push_param_read)

app = Flask(__name__, static_folder=None)
sock = Sock(app)

# ===================== WebSocket: 多频道推送 (按 URL 分桶) =====================
# 连接 URL 决定此连接的身份 (永远是某个频道的订阅者):
#   /log        -> 'logs' 桶  收人读的文本日志
#   /ws/frames  -> 'frames' 桶  收原始 CAN 帧
#   /ws/status  -> 'status' 桶  收电机反馈 (pos/vel/torque/temp)
# 客户端连到哪个 URL 就只收哪种消息, 不会跨频道串
_WS_CLIENTS = {'logs': set(), 'frames': set(), 'status': set()}
_WS_LOCK = threading.Lock()

# 从 [serial]tx/rx 或 [motor]tx/rx canid=0x... data=... 日志中提取原始 CAN 帧
import re as _re
_FRAME_RE = _re.compile(
    r'\[(?:serial|motor)\](tx|rx) canid=(0x[0-9A-Fa-f]+) data=([0-9a-fA-F]*)'
)

def _broadcast(payload, kind):
    """发 JSON 到所有订阅 kind 的 WS 客户端. 断开自动清理."""
    clients = _WS_CLIENTS.get(kind)
    if not clients:
        return
    dead = []
    with _WS_LOCK:
        for c in list(clients):
            try:
                c.send(payload)
            except Exception:
                dead.append(c)
        for d in dead:
            clients.discard(d)

def _broadcast_log(msg):
    """一条新日志 -> 推送给 /log 订阅者."""
    try:
        _broadcast(json.dumps({"type": "log", "data": msg}), kind='logs')
    except Exception:
        pass

def _broadcast_clear():
    """清空事件 -> 推送给 /log 订阅者."""
    try:
        _broadcast(json.dumps({"type": "clear"}), kind='logs')
    except Exception:
        pass

def _broadcast_frame(direction, can_id, data_hex):
    """原始 CAN 帧 -> 推送给 /ws/frames 订阅者.
    direction: 'tx' | 'rx'
    can_id:   int (32-bit)
    data_hex: hex 字符串 (e.g. "0808c05580097fff01250d0a")
    """
    try:
        payload = json.dumps({
            "type":   "frame",
            "dir":    direction,
            "can_id": f"0x{can_id:08X}",
            "data":   data_hex,
            "ts":     time.time(),
        })
        _broadcast(payload, kind='frames')
    except Exception:
        pass

# 静默 Flask 默认访问日志 (我们打自己的)
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)


# ===================== HTTP 工具 =====================

def ok(data=None, msg=""):
    payload = {"ok": True, "msg": msg}
    if data is not None:
        payload["data"] = data
    return jsonify(payload)


def fail(msg, code=400):
    return jsonify({"ok": False, "msg": msg}), code


# ===================== 静态文件 =====================

@app.route('/')
def index():
    return send_from_directory(WEB_DIR, 'index.html')


@app.route('/app.js')
def app_js():
    return send_from_directory(WEB_DIR, 'app.js', mimetype='application/javascript')


@app.route('/style.css')
def style_css():
    return send_from_directory(WEB_DIR, 'style.css', mimetype='text/css')


# ===================== API =====================

@app.route('/api/info')
def api_info():
    return ok(data={
        'serial_open': MOTOR.is_open(),
        'mode_aliases': CanProtocol.MODE_ALIASES,
        'param_names': {hex(k): v[0] for k, v in CanProtocol.PARAM_NAMES.items()},
    })


@app.route('/api/logs')
def api_logs():
    return ok(data=GLOBAL_LOG.get_all(limit=300))


@app.route('/api/logs/clear', methods=['POST'])
def api_logs_clear():
    GLOBAL_LOG.clear()
    _broadcast_clear()
    return ok(msg='log cleared')


# ===================== WebSocket: /log =====================
# 非 WS 的 GET 请求会被 Flask-Sock 拒为 400. 这里显式回复友好提示 (不是直接 close).
@app.route('/log', methods=['GET'])
def http_log_only_ws():
    return Response('仅支持ws\n', status=400, mimetype='text/plain; charset=utf-8')

@sock.route('/log')
def ws_logs(ws):
    """实时日志推送 (URL 决定: 此连接永远是日志订阅者).
    客户端连上后, 立刻拿到当前 buffer 中的全部历史日志 (作为 seed).
    之后任何新日志 (_push_log) 都会立即推送.
    客户端可发 {\"type\":\"clear\"} 触发全局清空.
    """
    with _WS_LOCK:
        _WS_CLIENTS['logs'].add(ws)
    try:
        # 先发历史 (seed): 一条一条推, 避免一个超大的 JSON
        for msg in list(GLOBAL_LOG.get_all(limit=300)):
            try:
                ws.send(json.dumps({"type": "log", "data": msg}))
            except Exception:
                return  # 连接已断
        # 阻塞接收客户端消息 (用来检测断开 + 处理 clear)
        while True:
            data = ws.receive()
            if data is None:
                break
            try:
                obj = json.loads(data)
                if isinstance(obj, dict) and obj.get('type') == 'clear':
                    GLOBAL_LOG.clear()
                    _broadcast_clear()
            except Exception:
                pass
    finally:
        with _WS_LOCK:
            _WS_CLIENTS['logs'].discard(ws)


@sock.route('/ws/frames')
def ws_frames(ws):
    """原始 CAN 帧推送 (URL 决定: 此连接永远是帧订阅者).
    单向推送, 客户端不发指令. 帧数据从 _push_log 里解析 [serial]tx/rx 得出.
    """
    with _WS_LOCK:
        _WS_CLIENTS['frames'].add(ws)
    try:
        # 帧是单向推送, 无 seed; 阻塞等断开即可
        while True:
            data = ws.receive()
            if data is None:
                break
    finally:
        with _WS_LOCK:
            _WS_CLIENTS['frames'].discard(ws)


@sock.route('/ws/status')
def ws_status(ws):
    """电机反馈状态推送 (URL 决定: 此连接永远是 status 订阅者).
    每收到一帧电机反馈 (comm_type=2) -> 推一个 {type:"status", motor_id, data: {pos,vel,torque,temp}} 给本连接.
    被动推送: motor 不发反馈就不推 (不动无更新).
    """
    with _WS_LOCK:
        _WS_CLIENTS['status'].add(ws)
    try:
        # 状态是单向推送, 无 seed; 阻塞等断开即可
        while True:
            data = ws.receive()
            if data is None:
                break
    finally:
        with _WS_LOCK:
            _WS_CLIENTS['status'].discard(ws)


@app.route('/api/params_info')
def api_params_info():
    """返回所有已知参数的信息 (高级区动态列表用)
    每项: {addr, name, desc, type, writable}
    """
    items = []
    for addr, info in CanProtocol.PARAM_NAMES.items():
        name   = info[0]
        desc   = info[1] if len(info) > 1 else ''
        vtype  = info[2] if len(info) > 2 else 'float'
        wflag  = info[3] if len(info) > 3 else True
        items.append({
            'addr':     hex(addr),
            'name':     name,
            'desc':     desc,
            'type':     vtype,
            'writable': bool(wflag),
        })
    # 按地址排序, 0x2xxx 在前 0x7xxx 在后
    items.sort(key=lambda x: int(x['addr'], 16))
    return ok(data=items)


@app.route('/api/param')
def api_param():
    """查询已缓存的参数读结果: /api/param?target=1&addr=0x7005"""
    tgt = int(request.args.get('target', '0'))
    addr_str = str(request.args.get('addr', '0'))
    addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
    entry = MOTOR.get_param(tgt, addr)
    if entry:
        return ok(data=entry)
    return ok(data=None, msg='未缓存 (可能是刚发请求或读失败)')


@app.route('/api/params', methods=['POST'])
def api_params():
    """批量读参数: {target, addrs: [0x7016, 0x7017, ...]}
    每个 addr 调 _read_param_sync 同步等响应 (200ms 超时)
    返回 {hex(addr): {name, type, value_int, value_float, value}, ...}
    value: 根据 type 选 value_int (uint/int) 或 value_float (float), 保留向后兼容
    """
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    addrs = request.json.get('addrs', [])
    if not addrs:
        return ok(data={})
    _push_log(f"[web] params -> id={tgt} addrs={[hex(a) for a in addrs]}")
    result = {}
    ok_count = 0
    for addr in addrs:
        a = int(addr)
        _push_log(f"[web] params -> 读 {hex(a)}")
        entry = MOTOR._read_param_sync(tgt, a, timeout=0.2)
        if entry:
            vtype = entry.get('vtype', 'float')
            v_int = entry.get('value_int', 0)
            v_flt = entry.get('value_float', 0.0)
            # value 字段: 整数类型用 int, 浮点用 float (避免 uint8=1 变成 1.4e-45)
            is_int = vtype in ('uint8', 'uint16', 'uint32', 'int16', 'int32')
            result[hex(a)] = {
                'name':        entry.get('name', ''),
                'type':        vtype,
                'value_int':   v_int,
                'value_float': v_flt,
                'value':       v_int if is_int else v_flt,
            }
            ok_count += 1
            _push_log(f"[web] params -> {hex(a)} = {entry['value_float']:.6f} ({entry.get('name', '')})")
        else:
            _push_log(f"[web] params -> {hex(a)} 超时")
    _push_log(f"[web] params -> 完成 {ok_count}/{len(addrs)}")
    return ok(data=result)


@app.route('/api/motors')
def api_motors():
    return ok(data=MOTOR.get_motors())


def _require_open():
    if not MOTOR.is_open():
        return fail("串口未打开")
    return None


@app.route('/api/ls', methods=['POST'])
def api_ls():
    err = _require_open()
    if err: return err
    targets = request.json.get('targets') if request.json else None
    if targets is None:
        data = MOTOR.scan(broadcast=True)
    else:
        data = MOTOR.scan(targets=targets, broadcast=False)
    return ok(data=data, msg=f"扫描完成, 发现 {len(data)} 个电机")


@app.route('/api/enable', methods=['POST'])
def api_enable():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    ok_result, _ = MOTOR.enable(tgt)
    return ok(msg=f"已使能 {tgt}") if ok_result else fail("使能失败")


@app.route('/api/stop', methods=['POST'])
def api_stop():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    ok_result, _ = MOTOR.stop(tgt)
    return ok(msg=f"已停止 {tgt}") if ok_result else fail("停止失败")


@app.route('/api/setzero', methods=['POST'])
def api_setzero():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    ok_result, _ = MOTOR.set_zero(tgt)
    return ok(msg=f"已设零位 {tgt}") if ok_result else fail("设零位失败")


@app.route('/api/setcanid', methods=['POST'])
def api_setcanid():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    new_id = int(request.json.get('new'))
    ok_result, _ = MOTOR.set_can_id(tgt, new_id)
    return ok(msg=f"{tgt} -> {new_id}") if ok_result else fail("改 ID 失败")


@app.route('/api/setmode', methods=['POST'])
def api_setmode():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    mode = str(request.json.get('mode'))
    ok_result, _ = MOTOR.set_mode(tgt, mode)
    return ok(msg=f"模式 {mode}") if ok_result else fail(f"未知模式: {mode}")


@app.route('/api/setprop', methods=['POST'])
def api_setprop():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    addr_str = str(request.json.get('addr'))
    addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
    value = float(request.json.get('value'))
    ok_result, _ = MOTOR.write_param(tgt, addr, value)
    return ok(msg=f"写入 0x{addr:04X}={value}") if ok_result else fail("写入失败")


@app.route('/api/getprop', methods=['POST'])
def api_getprop():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    addr_str = str(request.json.get('addr'))
    addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
    ok_result, _ = MOTOR.read_param(tgt, addr)
    return ok(msg=f"已发读取请求 0x{addr:04X}") if ok_result else fail("读取失败")


@app.route('/api/pos', methods=['POST'])
def api_pos():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    n = float(request.json.get('n'))
    ok_result, _ = MOTOR.set_position_ref(tgt, n)
    return ok(msg=f"位置 n={n} ({n/60:.4f} 圈)") if ok_result else fail("位置指令失败")


@app.route('/api/speed', methods=['POST'])
def api_speed():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    rad = float(request.json.get('rad'))
    limit_cur = float(request.json.get('limit_cur', 1.0))
    ok_result, _ = MOTOR.set_speed_ref(tgt, rad, limit_cur)
    return ok(msg=f"速度 {rad} rad/s, limitcur={limit_cur}A") if ok_result else fail("速度指令失败")


@app.route('/api/cur', methods=['POST'])
def api_cur():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    a = float(request.json.get('a'))
    ok_result, _ = MOTOR.set_current_ref(tgt, a)
    return ok(msg=f"电流 {a} A") if ok_result else fail("电流指令失败")


@app.route('/api/ctrl', methods=['POST'])
def api_ctrl():
    err = _require_open()
    if err: return err
    tgt  = int(request.json.get('target'))
    pos  = float(request.json.get('pos'))
    vel  = float(request.json.get('vel'))
    kp   = float(request.json.get('kp'))
    kd   = float(request.json.get('kd'))
    tor  = float(request.json.get('torque'))
    ok_result, _ = MOTOR.send_motion(tgt, pos, vel, kp, kd, tor)
    return ok(msg=f"运控 pos={pos} vel={vel}") if ok_result else fail("运控失败")


@app.route('/api/setlimitcur', methods=['POST'])
def api_setlimitcur():
    err = _require_open()
    if err: return err
    tgt = int(request.json.get('target'))
    a = float(request.json.get('a'))
    ok_result, _ = MOTOR.write_param(tgt, 0x7018, a)
    return ok(msg=f"电流限制 {a} A") if ok_result else fail("设置电流限制失败")


# ===================== 串口选择 =====================

def select_port():
    # 走 CyberGearMotor 包装, 不直接 import can_serial
    ports = MOTOR.list_ports()
    if not ports:
        print("未找到任何串口设备！")
        sys.exit(1)
    print("\n可用的串口列表:")
    print("-" * 60)
    for i, p in enumerate(ports):
        print(f"  {i+1}. {p['device']} - {p['description']}")
    print("-" * 60)
    while True:
        try:
            choice = input(f"\n请选择串口 (1-{len(ports)}): ")
            idx = int(choice) - 1
            if 0 <= idx < len(ports):
                return ports[idx]['device']
        except (ValueError, KeyboardInterrupt):
            pass
        print("无效输入")


def select_baudrate():
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
                return 115200
            idx = int(choice) - 1
            if 0 <= idx < len(baudrates):
                return baudrates[idx]
        except (ValueError, KeyboardInterrupt):
            pass
        print("无效输入")


def main():
    parser = argparse.ArgumentParser(description='CyberGear Web 控制端 (Flask)')
    parser.add_argument('--addr', default='127.0.0.1', help='bind 地址 (默认 127.0.0.1)')
    parser.add_argument('--port', type=int, default=9999, help='端口 (默认 9999)')
    parser.add_argument('--serial', default=None, help='串口设备 (可选, 不传则启动时问)')
    parser.add_argument('--baud', type=int, default=None, help='波特率 (可选, 不传则启动时问)')
    parser.add_argument('--debug', action='store_true', help='启动时打开 CAN 原始包日志')
    args = parser.parse_args()

    if args.debug:
        MOTOR._debug_rx = True
        MOTOR._serial.debug = True

    # 串口
    port = args.serial or select_port()
    baud = args.baud or select_baudrate()
    ok_result, msg = MOTOR.open(port, baud)
    print(f"[serial] {msg}")
    if not ok_result:
        sys.exit(1)

    print(f"\n[web] http://{args.addr}:{args.port}/")
    print(f"[web] 打开浏览器访问上述地址")
    print(f"[web] Ctrl+C 退出\n")
    try:
        # Flask 自带 werkzeug, threaded=True 让多线程处理请求
        app.run(host=args.addr, port=args.port, threaded=True, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[web] 关闭中...")
    finally:
        MOTOR.close()
        print("[web] 已退出")


if __name__ == "__main__":
    main()
