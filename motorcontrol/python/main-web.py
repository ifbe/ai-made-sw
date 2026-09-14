# main-web.py
"""
小米 CyberGear 电机 - Web 控制端 (Flask)
- --addr 默认 127.0.0.1, --port 默认 9999
- 一个 CyberGearMotor 实例, 多线程共享
- 串口操作由 MOTOR_LOCK 串行化; WS 推送走每连接队列, 不阻塞串口接收线程
- 所有 POST 接口的 JSON 参数统一校验, 失败返回 400 JSON (不会 415/500)
"""
import argparse
import json
import os
import queue
import re
import sys
import threading
import time
import logging

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_sock import Sock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cybergear import CanProtocol, CyberGearMotor, SetpointChannel
from logbuf import LogBuffer

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

# 单进程共享的电机实例
MOTOR = CyberGearMotor()
# 串口事务串行化锁: 所有"发指令 / 发一帧并等回包"的操作都要持锁.
# 否则 Flask threaded=True 下多个请求并发读写同一串口会串帧、串回包
# (read_param 的 _pending_read 是按 motor_id 记账的, 并发读会互相覆盖).
# 用 RLock: 允许同线程嵌套获取 (set_mode -> _read_param_sync -> read_param).
MOTOR_LOCK = threading.RLock()

# 从 [serial]tx/rx 或 [motor]tx/rx canid=0x... data=... 日志中提取原始 CAN 帧.
# 必须在 MOTOR.set_log_callback 之前定义: 回调在导入期就可能被触发.
_FRAME_RE = re.compile(
    r'\[(?:serial|motor)\](tx|rx) canid=(0x[0-9A-Fa-f]+) data=([0-9a-fA-F]*)'
)

# 全局 log buffer + 回调 (供 /api/logs + WS 推送使用)
GLOBAL_LOG = LogBuffer(maxlen=500)

def _push_log(msg):
    """串口/电机线程的日志回调入口, 绝不能把异常抛回接收线程."""
    try:
        GLOBAL_LOG.append(msg)
        _broadcast_log(msg)  # 推送到 /log 订阅者
        # 如果是帧日志, 同时也推一份原始帧到 /ws/frames 订阅者
        fm = _FRAME_RE.search(msg)
        if fm:
            direction = fm.group(1)             # 'tx' | 'rx'
            can_id    = int(fm.group(2), 16)     # 原始 int
            data_hex  = fm.group(3) or ''        # hex 字符串 (可能空)
            _broadcast_frame(direction, can_id, data_hex)
    except Exception:
        pass

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

# 参数读取响应回调 -> 电压/电流类参数推到 /ws/status (被动, 谁查的都算)
# "哪些地址是电压/电流"这种领域知识在 cybergear.py 的 CanProtocol.param_kind 里,
# 这里只负责把它变成一条 WS 消息.
def _push_param_read(motor_id, addr, entry):
    kind = CanProtocol.param_kind(addr)          # 'voltage' / 'current' / None
    if kind is None:
        return
    value = float(entry.get('value_float', 0.0))  # 0x701C 是 V, 0x701A 是 A
    try:
        _broadcast(json.dumps({
            "type": "status",
            "motor_id": motor_id,
            "data": {kind: value, "last_update": time.time()},
        }), kind='status')
    except Exception:
        pass
MOTOR.set_param_read_callback(_push_param_read)


# ===================== 连续指令序号防线 =====================
# 网页端每条离散指令 (stop/enable/setzero/setmode/setprop/...) 都会带一个递增的 seq,
# 这里记下见过的最大值; 序号更小的连续指令(位置/速度)说明是在那条离散指令之前发出的,
# 即使因为网络/线程调度晚到, 也必须丢弃 —— 否则 stop 之后电机又会被旧指令带走.
# (连续指令走 WS, 离散指令走 HTTP, 两条连接之间没有顺序保证, 靠这个序号补齐)
_LAST_DISCRETE_SEQ = 0


def _seq_of(body):
    """取请求里的 seq (JS 数字可能是 int 也可能是 float), 没有就返回 None."""
    v = body.get('seq') if hasattr(body, 'get') else None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return int(v)


def _note_discrete_seq(body):
    """离散指令: 让序号前进. 之后到达的、序号更小的连续指令一律作废."""
    global _LAST_DISCRETE_SEQ
    seq = _seq_of(body)
    if seq is not None and seq > _LAST_DISCRETE_SEQ:
        _LAST_DISCRETE_SEQ = seq
        return seq
    return None


def _is_stale_setpoint(body):
    seq = _seq_of(body)
    return seq is not None and seq < _LAST_DISCRETE_SEQ




# 位置 / 速度 两条连续通道 (合并通道的实现搬在 cybergear.py 里)
_SETPOINT_POS = SetpointChannel('位置', lambda tgt, n: MOTOR.set_position_ref(tgt, n),
                                lock=MOTOR_LOCK, log_fn=_push_log)
# limit_cur 可能是 None -> 只发速度, 不碰 LIMIT_CUR (网页拖动条走这条)
_SETPOINT_SPD = SetpointChannel('速度', lambda tgt, p: MOTOR.set_speed_ref(tgt, p['rad'], p.get('limit_cur')),
                                lock=MOTOR_LOCK, log_fn=_push_log)

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
_WS_QUEUE_MAX = 1000   # 单连接积压上限, 满了丢最旧的


class _WSClient:
    """一个 WS 订阅者 = 独立发送队列 + 独立发送线程.

    为什么不在 _broadcast 里直接 ws.send(): 广播是在串口/电机接收线程里被触发的,
    一次同步 send 遇到慢客户端 (对端不回 ACK / TCP 窗口满) 就会阻塞, 从而反压整个
    串口接收线程. 改成入队后, 广播方永不阻塞, 单个连接积压只影响它自己.
    """

    def __init__(self, ws, kind):
        self.ws    = ws
        self.kind  = kind
        self.alive = True
        self._q    = queue.Queue(maxsize=_WS_QUEUE_MAX)
        self._t    = threading.Thread(target=self._pump, name=f'ws-{kind}', daemon=True)
        self._t.start()

    def _pump(self):
        while self.alive:
            item = self._q.get()
            if item is None:
                break
            try:
                self.ws.send(item)
            except Exception:
                break          # 连接已断, 交给 handler 的 finally 收尾
        self.alive = False

    def put(self, payload):
        """非阻塞入队; 队列满时丢弃最旧的一条 (宁可丢帧, 不拖慢串口)."""
        if not self.alive:
            return
        try:
            self._q.put_nowait(payload)
        except queue.Full:
            try:
                self._q.get_nowait()
                self._q.put_nowait(payload)
            except (queue.Empty, queue.Full):
                pass

    def close(self):
        self.alive = False
        try:
            self._q.put_nowait(None)   # 唤醒发送线程退出
        except queue.Full:
            pass


def _register(ws, kind):
    """新连接入桶. 返回 client, 调用方负责在 finally 里 _unregister."""
    client = _WSClient(ws, kind)
    with _WS_LOCK:
        _WS_CLIENTS[kind].add(client)
    return client


def _unregister(client):
    with _WS_LOCK:
        _WS_CLIENTS.get(client.kind, set()).discard(client)
    client.close()


def _broadcast(payload, kind):
    """发 JSON 到所有订阅 kind 的 WS 客户端. 只入队, 不在此线程做 IO."""
    with _WS_LOCK:
        clients = list(_WS_CLIENTS.get(kind, ()))
    for c in clients:
        c.put(payload)

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


class BadRequest(Exception):
    """参数校验失败. 由 _on_bad_request 统一转成 400 JSON 响应,
    避免 request.json 为 None / 缺字段时抛 415 / TypeError(500)."""


_MISSING = object()   # 区分"没传"和"传了 None"


def _body():
    """取 JSON body, 非 JSON 对象直接 400."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BadRequest('请求体必须是 JSON 对象 (Content-Type: application/json)')
    return data


def _int_field(body, key, default=_MISSING):
    if body.get(key) is None:
        if default is not _MISSING:
            return default
        raise BadRequest(f'缺少参数 {key}')
    try:
        return int(body[key])
    except (TypeError, ValueError):
        raise BadRequest(f'参数 {key} 必须是整数, 收到 {body[key]!r}')


def _float_field(body, key, default=_MISSING):
    v = body.get(key)
    if v is None:
        if default is not _MISSING:
            return default
        raise BadRequest(f'缺少参数 {key}')
    try:
        return float(v)
    except (TypeError, ValueError):
        raise BadRequest(f'参数 {key} 必须是数字, 收到 {v!r}')


def _target_field(body):
    t = _int_field(body, 'target')
    if not 0 <= t <= 0xFF:
        raise BadRequest(f'参数 target 超出范围 (0-255): {t}')
    return t


def _addr_field(body, key='addr', default=_MISSING):
    """接受 0x7016 / "0x7016" / 28694 三种写法."""
    v = body.get(key)
    if v is None:
        if default is not _MISSING:
            return default
        raise BadRequest(f'缺少参数 {key}')
    s = str(v)
    try:
        return int(s, 16) if s.lower().startswith('0x') else int(s)
    except ValueError:
        raise BadRequest(f'参数 {key} 必须是参数地址 (如 "0x7016"), 收到 {v!r}')


def _require_can_param(addr):
    """地址必须落在手册 4.1.12 的 CAN 参数表 (0x7005~0x7020) 里.

    手册 3.3.3 那张上位机调试参数表 (0x00xx/0x10xx/0x20xx/0x30xx) 里的同名参数
    (spd_kp / loc_kp / VBUS / iq ...) 用 CAN 是寻址不到的: 电机对不认识的 index
    只填 index, 数据区回上一次的残留字节 —— 实测 0x2014/0x2015 都读回 8313.374.
    所以这里直接拦住, 而不是给一个"看起来成功"的假结果.
    """
    if addr not in CanProtocol.CAN_PARAM_ADDRS:
        raise BadRequest(
            f'0x{addr:04X} 不在 CAN 参数表里 (手册 4.1.12 只有 0x7005~0x7020). '
            f'它属于手册 3.3.3 的上位机调试参数表, 用 CAN 读写不到; '
            f'调试表地址清单见 doc/cybergear.md §7')


# 参数校验失败统一返回 400 JSON (而不是 Flask 默认的 HTML 错误页)
@app.errorhandler(BadRequest)
def _on_bad_request(e):
    return fail(str(e), 400)


# ===================== 静态文件 =====================

def _asset_version(fname):
    """静态资源版本号 (文件 mtime), 用来给 index.html 里的 css/js 加 ?v="""
    try:
        return str(int(os.path.getmtime(os.path.join(WEB_DIR, fname))))
    except OSError:
        return '0'


_INDEX_CACHE = {'key': None, 'html': None}


@app.route('/')
def index():
    """首页: 顺手把 css/js 的 ?v=<mtime> 版本号注入进去, 并在 after_request 里发 no-store.

    ⚠ 踩过的坑: 前端改了以后浏览器还在用旧的 index.html (没有 #webLogArea),
    表现是"console 有日志, 但网页日志框不显示/根本不存在".
    所以: 每次都重新读 index.html, 资源带上 mtime 版本号, 且一律 no-store.
    """
    path = os.path.join(WEB_DIR, 'index.html')
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, _asset_version('app.js'), _asset_version('style.css'))
        if _INDEX_CACHE['key'] != key:
            with open(path, encoding='utf-8') as f:
                html = f.read()
            html = html.replace('/style.css', f"/style.css?v={key[2]}")
            html = html.replace('/app.js', f"/app.js?v={key[1]}")
            _INDEX_CACHE.update(key=key, html=html)
        return Response(_INDEX_CACHE['html'], mimetype='text/html; charset=utf-8')
    except OSError as e:
        return fail(f"读取 index.html 失败: {e}", 500)


@app.after_request
def _no_store(resp):
    """本地工具: 所有响应都不许缓存. 改完前端刷新一次就是新的, 不用清缓存."""
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


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
    客户端可发 {"type":"clear"} 触发全局清空.
    """
    client = _register(ws, 'logs')
    try:
        # 先发历史 (seed): 一条一条推, 避免一个超大的 JSON.
        # 走队列 (而不是直接 ws.send), 否则会和发送线程并发写同一个 socket.
        for msg in list(GLOBAL_LOG.get_all(limit=300)):
            client.put(json.dumps({"type": "log", "data": msg}))
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
        _unregister(client)


@sock.route('/ws/frames')
def ws_frames(ws):
    """原始 CAN 帧推送 (URL 决定: 此连接永远是帧订阅者).
    单向推送, 客户端不发指令. 帧数据从 _push_log 里解析 [serial]tx/rx 得出.
    """
    client = _register(ws, 'frames')
    try:
        # 帧是单向推送, 无 seed; 阻塞等断开即可
        while True:
            data = ws.receive()
            if data is None:
                break
    finally:
        _unregister(client)


@sock.route('/ws/status')
def ws_status(ws):
    """电机反馈状态推送 + 连续指令下行 (同一条连接, 收发互不干扰).

    这个连接有两个方向:
      下行 (server -> client): {type:"status", motor_id, data} 电机反馈 / 电压电流
      上行 (client -> server): {type:"cmd", cmd:"speed", target:1, rad:3.0, seq:N}

    拖动条为什么走 WS 而不是 HTTP: 拖动是"发了就不管"的连续指令, 而 HTTP 是
    请求/应答模型, 必然存在"上一个还在飞"的状态 —— 一旦某个响应卡住, 后面的命令
    就再也发不出去 (点一次好、再点没反应就是这么来的). WS 没有这个状态, 发完即忘;
    而且同一条连接内的消息按顺序到达, 后端又在同一个接收循环里按顺序处理,
    所以既不会堆积, 也不需要等回复.
    HTTP 的 /api/pos /api/speed 仍然保留, WS 没连上时作兜底.
    """
    client = _register(ws, 'status')
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            try:
                msg = json.loads(data)
            except Exception:
                continue                      # 不是 JSON 就忽略 (客户端只发 cmd)
            if isinstance(msg, dict) and msg.get('type') == 'cmd':
                _handle_ws_cmd(msg)
    finally:
        _unregister(client)


def _handle_ws_cmd(msg):
    """处理网页端从 /ws/status 发来的连续指令 (位置/速度).

    只处理连续指令; stop/enable 等离散指令仍走 HTTP (要有 ok/msg 回执给用户看).
    在接收循环里同步执行 -> 同一条连接内的指令天然按发送顺序生效.
    """
    if not MOTOR.is_open():
        _push_log("[web] ws 指令被拒: 串口未打开")
        return
    cmd = msg.get('cmd')
    try:
        if cmd == 'pos':
            tgt = _target_field(msg)
            n = _float_field(msg, 'n')
            if _is_stale_setpoint(msg):
                _push_log("[web] ws 位置指令已过期 (晚到的旧值), 丢弃")
                return
            _SETPOINT_POS.submit(tgt, n)
        elif cmd == 'speed':
            tgt = _target_field(msg)
            rad = _float_field(msg, 'rad')
            limit_cur = _float_field(msg, 'limit_cur', None)
            if _is_stale_setpoint(msg):
                _push_log("[web] ws 速度指令已过期 (晚到的旧值), 丢弃")
                return
            payload = {'rad': rad}
            if limit_cur is not None:
                payload['limit_cur'] = limit_cur
            _SETPOINT_SPD.submit(tgt, payload)
        else:
            _push_log(f"[web] ws 未知指令: {cmd}")
    except BadRequest as e:
        _push_log(f"[web] ws 指令参数错误: {e}")


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
    tgt  = _int_field(request.args, 'target', 0)
    addr = _addr_field(request.args, 'addr', 0)
    _require_can_param(addr)
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
    body = _body()
    tgt = _target_field(body)
    raw_addrs = body.get('addrs', [])
    if not isinstance(raw_addrs, list):
        raise BadRequest('参数 addrs 必须是数组')
    if not raw_addrs:
        return ok(data={})
    try:
        addrs = [int(str(a), 16) if str(a).lower().startswith('0x') else int(a) for a in raw_addrs]
    except (TypeError, ValueError):
        raise BadRequest(f'addrs 里有非法地址: {raw_addrs!r}')
    for a in addrs:
        _require_can_param(a)          # 不可达地址直接拦掉, 不给假结果
    _push_log(f"[web] params -> id={tgt} addrs={[hex(a) for a in addrs]}")
    result = {}
    ok_count = 0
    # 整批读持锁: 一次请求内不要被别的请求插队, 否则 _pending_read 会串
    with MOTOR_LOCK:
        for a in addrs:
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
                _push_log(f"[web] params -> {hex(a)} = {v_flt:.6f} ({entry.get('name', '')})")
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
    # body 可选: 不传 / 空对象 = 广播扫描
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise BadRequest('请求体必须是 JSON 对象')
    targets = body.get('targets')
    # 手册 4.1.1 的"获取设备 ID"(通信类型 0) 是唯一的发现机制:
    #   请求: ID 的 bit7~0 = 目标电机 CAN_ID, 数据区全 0
    #   应答: ID 的 bit23~8 = 电机 CAN_ID, bit7~0 = 0XFE, 数据 = 64 位 MCU 唯一标识符
    # ⚠ 实测**向 0xFE 广播没有任何应答**(手册也只在应答帧里出现过 0XFE,
    #   从没说它是广播地址), 所以现在是真正逐个 id 发报文 (1~127).
    # ⚠ get_motors() 返回的是**累积缓存**, 应答过的电机断电后仍在列表里;
    #   "本次是否真的存在"由 CyberGearMotor.last_scan_answered() 给出 (库里算好的).
    with MOTOR_LOCK:
        if targets is None:
            data = MOTOR.scan()                      # 逐个 id 扫 1~127
        else:
            if not isinstance(targets, list):
                raise BadRequest('参数 targets 必须是数组')
            try:
                targets = [int(t) for t in targets]
            except (TypeError, ValueError):
                raise BadRequest(f'targets 里有非法 id: {targets!r}')
            data = MOTOR.scan(targets=targets, broadcast=False)
    answered = MOTOR.last_scan_answered()          # 本次真正应答的 id 列表
    return ok(data=data,
              msg=f"扫描完成: 本次应答 {len(answered)} 台 "
                  f"({answered}), 缓存共 {len(data)} 台")


@app.route('/api/enable', methods=['POST'])
def api_enable():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)          # 离散指令: 让序号前进, 之前的连续指令作废
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.enable(tgt)
    return ok(msg=f"已使能 {tgt}") if ok_result else fail("使能失败")


@app.route('/api/stop', methods=['POST'])
def api_stop():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)          # 离散指令: 让序号前进, 之前的连续指令作废
    with MOTOR_LOCK:
        # 先丢弃排队中的位置/速度指令, 再发 stop:
        # 否则 stop 之后残留的旧指令会把电机又带走 (拖动后立刻点停止的场景)
        dropped = _SETPOINT_POS.discard() + _SETPOINT_SPD.discard()
        ok_result, _ = MOTOR.stop(tgt)
    msg = f"已停止 {tgt}" + (f" (丢弃 {dropped} 条待发指令)" if dropped else "")
    return ok(msg=msg) if ok_result else fail("停止失败")


@app.route('/api/setzero', methods=['POST'])
def api_setzero():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)
    with MOTOR_LOCK:
        # 设零位会改变基准, 后面不能再落一条旧的位置指令
        _SETPOINT_POS.discard()
        _SETPOINT_SPD.discard()
        ok_result, _ = MOTOR.set_zero(tgt)
    return ok(msg=f"已设零位 {tgt}") if ok_result else fail("设零位失败")


@app.route('/api/setcanid', methods=['POST'])
def api_setcanid():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)
    new_id = _int_field(body, 'new')
    if not 0 <= new_id <= 0xFF:
        raise BadRequest(f'参数 new 超出范围 (0-255): {new_id}')
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.set_can_id(tgt, new_id)
    return ok(msg=f"{tgt} -> {new_id}") if ok_result else fail("改 ID 失败")


@app.route('/api/setmode', methods=['POST'])
def api_setmode():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)
    mode = str(body.get('mode') or '')
    if not mode:
        raise BadRequest('缺少参数 mode')
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.set_mode(tgt, mode)
    return ok(msg=f"模式 {mode}") if ok_result else fail(f"未知模式: {mode}")


@app.route('/api/setprop', methods=['POST'])
def api_setprop():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)
    addr = _addr_field(body)
    value = _float_field(body, 'value')
    _require_can_param(addr)
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.write_param(tgt, addr, value)
    return ok(msg=f"写入 0x{addr:04X}={value}") if ok_result else fail("写入失败")


@app.route('/api/getprop', methods=['POST'])
def api_getprop():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    addr = _addr_field(body)
    _require_can_param(addr)
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.read_param(tgt, addr)
    return ok(msg=f"已发读取请求 0x{addr:04X}") if ok_result else fail("读取失败")


@app.route('/api/pos', methods=['POST'])
def api_pos():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    n = _float_field(body, 'n')
    if _is_stale_setpoint(body):
        # 这条位置指令是在某条 stop/enable/... 之前发出的, 晚到了 -> 丢弃
        _push_log(f"[web] 位置指令 n={n} 已过期 (晚到的旧值), 丢弃")
        return ok(msg=f"位置 n={n} 已过期, 丢弃")
    # 连续指令: 立刻返回, 由 _SETPOINT_POS 线程合并后下发 (快速拖动不堆积)
    dropped = _SETPOINT_POS.submit(tgt, n)
    msg = f"位置 n={n} ({n/60:.4f} 圈)"
    if dropped:
        msg += f" [顶掉 {dropped} 条旧指令]"
    return ok(msg=msg)


@app.route('/api/speed', methods=['POST'])
def api_speed():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    rad = _float_field(body, 'rad')
    # limit_cur 可选: 不传 = 只发速度, 不动 LIMIT_CUR (拖动条就是这个用法;
    # 限流由用户在参数行点 set 单独下发)
    limit_cur = _float_field(body, 'limit_cur', None)
    if _is_stale_setpoint(body):
        _push_log(f"[web] 速度指令 rad={rad} 已过期 (晚到的旧值), 丢弃")
        return ok(msg=f"速度 {rad} 已过期, 丢弃")
    payload = {'rad': rad}
    if limit_cur is not None:
        payload['limit_cur'] = limit_cur
    # 连续指令: 立刻返回, 由 _SETPOINT_SPD 线程合并后下发
    dropped = _SETPOINT_SPD.submit(tgt, payload)
    msg = f"速度 {rad} rad/s"
    msg += f", limitcur={limit_cur}A" if limit_cur is not None else " (只发速度)"
    if dropped:
        msg += f" [顶掉 {dropped} 条旧指令]"
    return ok(msg=msg)


@app.route('/api/cur', methods=['POST'])
def api_cur():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)
    a = _float_field(body, 'a')
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.set_current_ref(tgt, a)
    return ok(msg=f"电流 {a} A") if ok_result else fail("电流指令失败")


@app.route('/api/ctrl', methods=['POST'])
def api_ctrl():
    err = _require_open()
    if err: return err
    body = _body()
    tgt  = _target_field(body)
    _note_discrete_seq(body)
    pos  = _float_field(body, 'pos')
    vel  = _float_field(body, 'vel')
    kp   = _float_field(body, 'kp')
    kd   = _float_field(body, 'kd')
    tor  = _float_field(body, 'torque')
    with MOTOR_LOCK:
        ok_result, _ = MOTOR.send_motion(tgt, pos, vel, kp, kd, tor)
    return ok(msg=f"运控 pos={pos} vel={vel}") if ok_result else fail("运控失败")


@app.route('/api/setlimitcur', methods=['POST'])
def api_setlimitcur():
    err = _require_open()
    if err: return err
    body = _body()
    tgt = _target_field(body)
    _note_discrete_seq(body)
    a = _float_field(body, 'a')
    with MOTOR_LOCK:
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
    parser.add_argument('--silent', action='store_true', help='静默模式: 仅打 4 类报文 (serial/can rx/tx), 其他 info/err 不打')
    args = parser.parse_args()

    if args.silent:
        MOTOR.set_silent(True)

    # 串口
    port = args.serial or select_port()
    baud = args.baud or select_baudrate()
    ok_result, msg = MOTOR.open(port, baud)
    print(f"[serial] {msg}")
    if not ok_result:
        sys.exit(1)

    print(f"\n[web] http://{args.addr}:{args.port}/")
    print(f"[web] 打开浏览器访问上述地址")
    if args.addr not in ('127.0.0.1', 'localhost', '::1'):
        print(f"[web] ⚠ 警告: 绑定了 {args.addr}, 本服务无任何鉴权, "
              f"同一网络内任何人都能控制电机. 仅在可信网络下这样用.")
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
