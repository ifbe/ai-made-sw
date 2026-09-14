// app.js - CyberGear Web 控制台
// 不依赖任何前端框架, 纯 vanilla JS.

const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

// ===================== 网页日志区: 把 console 输出镜像到右侧矩形 =====================
// 做法是劫持 console.log/info/warn/error: 先原样输出到 DevTools, 再往 #webLogArea
// 追加一行. 这样现有所有 console 调用 (以及以后新加的) 都会自动出现在网页日志里.
const WEB_LOG_MAX_DOM = 500;    // 网页日志框最多保留多少行

function fmtLogArg(a) {
  if (typeof a === 'string') return a;
  if (a instanceof Error) return a.name + ': ' + a.message;
  if (a === undefined) return 'undefined';
  if (a === null) return 'null';
  try { return JSON.stringify(a); } catch (e) { return String(a); }
}

// 按内容上色, 和左边服务器日志保持同一套配色:
// tx=发出(绿) rx=收到(蓝) err=红 warn=黄 info=浅灰
function webLogClass(level, text) {
  if (level === 'error') return 'err';
  if (level === 'warn') return 'warn';
  if (text.includes('→')) return 'tx';
  if (text.includes('←')) return 'rx';
  return 'info';
}

let webLogBusy = false;    // 防止日志区自身出错时递归
let webLogWarned = false;  // 缺少日志框时只提醒一次

// 取网页日志框; 取不到说明当前页面的 index.html 是旧缓存 (没有 #webLogArea 这块)
// -> 明确喊一声, 别静默丢日志 (之前就是这个原因让人以为镜像没生效)
function webLogPane() {
  const area = $('webLogArea');
  if (area) return area;
  if (!webLogWarned) {
    webLogWarned = true;
    console.warn('[ui] 页面上找不到 #webLogArea: 当前 index.html 是旧缓存 (改动前的页面).'
      + ' 请用 Ctrl+Shift+R (Mac: Cmd+Shift+R) 强制刷新一次;'
      + ' 在刷新之前, console 内容只能显示在 DevTools 里.');
  }
  return null;
}

function appendWebLog(level, args) {
  if (webLogBusy) return;
  webLogBusy = true;
  try {
    const area = webLogPane();
    if (!area) return;
    const text = args.map(fmtLogArg).join(' ');
    const wasAtBottom = area.scrollTop + area.clientHeight >= area.scrollHeight - 10;
    const div = document.createElement('div');
    div.className = 'log-line ' + webLogClass(level, text);
    div.textContent = text;
    area.appendChild(div);
    while (area.children.length > WEB_LOG_MAX_DOM) area.removeChild(area.firstChild);
    if (wasAtBottom) area.scrollTop = area.scrollHeight;
  } catch (e) {
    /* 日志区自己出问题也绝不能影响业务 */
  } finally {
    webLogBusy = false;
  }
}

['log', 'info', 'warn', 'error'].forEach((level) => {
  const orig = console[level].bind(console);
  console[level] = (...args) => {
    orig(...args);                 // DevTools 里照旧
    appendWebLog(level, args);     // 再镜像到网页日志矩形
  };
});

// ===================== 状态 =====================
const state = {
  selectedTarget: null,      // 当前选中的电机 ID (int)
  motors: [],                // 后端返回的电机列表
  pollTimer: null,
};

// ===================== 连续指令: 走 /ws/status 那条 WebSocket =====================
// 为什么连续指令(拖动条)不走 HTTP: 拖动是"发出去就不管", 而 HTTP 是请求/应答模型,
// 必然存在"上一个还在飞"的状态 —— 只要某个响应卡住, 后面的命令就再也发不出去
// (点一次能改、再点没反应就是这个原因). WS 没有这个状态, 发完即忘.
// 同一条连接内的消息按顺序到达, 后端也在同一个接收循环里按顺序处理, 不堆积也不需要等回复.
// HTTP /api/pos /api/speed 仍然保留: WS 没连上时兜底.
const SLIDER_SEND_MS = 80;      // 拖动时的最小发送间隔 (别把串口刷爆)
const SETPOINT_SENDERS = [];    // 各拖动条, 关键指令前统一 cancelPending()

// 连续指令序号: 每条离散指令(stop/enable/...)会让它 +1.
// 服务端据此丢弃"序号更小 = 在离散指令之前发出"的晚到连续指令,
// 保证跨连接(WS 连续指令 / HTTP 离散指令)也有正确的先后关系.
let cmdSeq = 0;

function cmdWsReady() {
  return !!statusWs && statusWs.readyState === WebSocket.OPEN;
}

// 往 /ws/status 发一条连续指令; WS 没连上返回 false (调用方回退 HTTP)
function wsSendSetpoint(cmd, payload) {
  if (!cmdWsReady()) return false;
  const msg = { type: 'cmd', cmd, seq: cmdSeq, ...payload };
  try {
    statusWs.send(JSON.stringify(msg));
    console.log(`[ws] → cmd ${cmd}`, msg);
    return true;
  } catch (e) {
    console.error('[ws] 发送失败, 回退 HTTP', e);
    return false;
  }
}

// 拖动条发送器: 只做限流合并, 不等任何回复 (没有"在飞"状态, 所以不会卡死)
function makeSetpointSender(fire, gapMs = SLIDER_SEND_MS, tag = 'setpoint') {
  const s = { timer: null };
  const sender = {
    // 拖动中: 限流 (到点发最新值)
    queue() {
      if (s.timer) return;
      s.timer = setTimeout(() => { s.timer = null; console.log(`[${tag}] 发送 (限流到点)`); fire(); }, gapMs);
    },
    // 松手 / 点击定位 / 数字框回车: 立刻发最终值
    flush() {
      if (s.timer) { clearTimeout(s.timer); s.timer = null; }
      console.log(`[${tag}] 发送 (立即)`);
      fire();
    },
    // 关键指令前: 只取消"还没发出去的"排队值. 没有在飞状态, 不需要等
    cancel() {
      if (s.timer) { clearTimeout(s.timer); s.timer = null; }
    },
  };
  SETPOINT_SENDERS.push(sender);
  return sender;
}

// 关键指令 (stop / enable / 设零位 / 切模式 / 发送) 之前调用:
// 丢掉还没发出去的连续指令排队值 (已经在路上的由服务端按 cmdSeq 丢弃)
function settleSetpoints() {
  SETPOINT_SENDERS.forEach(s => s.cancel());
}

// ===================== Toast =====================
let toastTimer = null;
function toast(msg, isErr = false) {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast show ' + (isErr ? 'err' : 'ok');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 2000);
}

// ===================== HTTP =====================
// quiet=true: 成功时不弹 toast (拖动条连续发送时用, 否则提示会一直闪)
// 每次调用都会打 console 日志: [api] → 请求 / ← 响应(状态码+耗时+JSON)
// (200ms 轮询 /api/motors 不走这里, 否则控制台会被刷爆; 见 refreshMotors)
const API_TIMEOUT_MS = 8000;   // 请求超时: 避免某个请求永不落地
// 连续指令 (位置/速度) 只带当前序号; 改变电机状态的离散指令让序号 +1,
// 服务端据此丢弃"更早发出但晚到"的连续指令 (跨 WS/HTTP 两条连接的顺序保证)
const SETPOINT_PATHS = new Set(['/api/pos', '/api/speed']);
const DISCRETE_PATHS = new Set([
  '/api/enable', '/api/stop', '/api/setzero', '/api/setcanid', '/api/setmode',
  '/api/setprop', '/api/ctrl', '/api/cur', '/api/setlimitcur',
]);

async function api(path, body, quiet = false) {
  const method = body ? 'POST' : 'GET';
  if (body && typeof body === 'object') {
    if (SETPOINT_PATHS.has(path)) {
      body = { ...body, seq: cmdSeq };
    } else if (DISCRETE_PATHS.has(path)) {
      cmdSeq += 1;
      body = { ...body, seq: cmdSeq };
    }
  }
  const t0 = performance.now();
  console.log(`[api] → ${method} ${path}`, body === undefined ? '' : body);
  const ctl = new AbortController();
  const killer = setTimeout(() => ctl.abort(), API_TIMEOUT_MS);
  try {
    const r = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal,
    });
    const j = await r.json();
    console.log(`[api] ← ${r.status} ${path} (${(performance.now() - t0).toFixed(1)}ms)`, j);
    if (!j.ok) {
      toast('❌ ' + (j.msg || '失败'), true);
    } else if (j.msg && !quiet) {
      toast('✅ ' + j.msg);
    }
    return j;
  } catch (e) {
    console.error(`[api] ✗ ${method} ${path} (${(performance.now() - t0).toFixed(1)}ms)`, e);
    toast('❌ 网络错误: ' + (e.message || e), true);
    return { ok: false };
  } finally {
    clearTimeout(killer);
  }
}

// ===================== 渲染: 电机卡片 =====================
// 只在"电机集合/顺序/选中项"变化时才重建卡片 DOM; 其他情况原地改文本.
// 以前每 200ms 轮询都 innerHTML='' 重建一遍, 会导致:
//   1) 选中的绿框一直闪 (DOM 每秒被拆掉重建 5 次);
//   2) 吃掉点击 —— mousedown 落在旧按钮、mouseup 落在新按钮上时, 浏览器不会派发
//      click 事件, 表现就是"点了 stop/start 没反应 / 好像不是立即发命令".
let renderedMotorSig = null;

function rebuildMotorCards() {
  const list = $('motorList');
  list.innerHTML = '';

  for (const m of state.motors) {
    const id = m.target_id;
    const card = document.createElement('div');
    card.className = 'motor-card' + (id === state.selectedTarget ? ' selected' : '');
    card.dataset.target = id;
    const enabledClass = m.enabled ? 'enabled' : 'disabled';
    const age = m.last_update ? ((Date.now() / 1000 - m.last_update).toFixed(1)) : '--';
    // 全部用 Number()/|| 兜底: 这里抛异常会顺着 refreshMotors 冒到发送器, 把它卡死
    card.innerHTML = `
      <div class="motor-head">
        <span class="motor-id">ID ${id}</span>
        <span class="motor-mode">${m.mode || '?'}</span>
        <button class="motor-onoff ${enabledClass}" data-onoff="1" title="${m.enabled ? '点击停止' : '点击使能'}">${m.enabled ? 'ON' : 'OFF'}</button>
      </div>
      <div class="motor-body">
        <div class="kv"><span>pos</span><b>${Number(m.position || 0).toFixed(3)}</b><i>rad</i></div>
        <div class="kv"><span>vel</span><b>${Number(m.speed || 0).toFixed(3)}</b><i>rad/s</i></div>
        <div class="kv"><span>trq</span><b>${Number(m.torque || 0).toFixed(3)}</b><i>Nm</i></div>
        <div class="kv"><span>tmp</span><b>${Number(m.temperature != null ? m.temperature : 0).toFixed(1)}</b><i>°C</i></div>
        <div class="kv kv-vol"><span>vol</span><b>${m.voltage !== undefined ? Number(m.voltage).toFixed(2) : '--'}</b><i>V</i></div>
        <div class="kv kv-cur"><span>cur</span><b>${m.current !== undefined ? Number(m.current).toFixed(2) : '--'}</b><i>A</i></div>
      </div>
      <div class="motor-foot">${age}s</div>
    `;
    card.addEventListener('click', () => selectMotor(id));
    // 右上角 on/off 按钮: 点它调使能/停止, 不触发卡片选中
    card.querySelector('.motor-onoff').addEventListener('click', async (e) => {
      e.stopPropagation();
      // 用"点击这一刻"的最新状态判断该 enable 还是 stop
      // (state.motors 每 200ms 会被后端刷新, 闭包里的 m 可能已经过期)
      const cur = state.motors.find(x => x.target_id === id) || m;
      const wasEnabled = !!cur.enabled;
      const act  = wasEnabled ? 'stop' : 'enable';
      const path = '/api/' + act;
      const t0 = performance.now();
      // 点开始就立刻打一条 console 日志: 用于确认点击有没有被收到
      console.log(`[motor] 收到 ON/OFF 点击: id=${id} 当前=${wasEnabled ? 'ON' : 'OFF'} -> 将要 ${act.toUpperCase()}`);
      // 先让拖动条在飞的指令落地, 再发 stop/enable (settle 有 300ms 上限, 卡住也不会阻塞)
      await settleSetpoints();
      const t1 = performance.now();
      console.log(`[motor] ${act} id=${id}: 拖动条指令已落地 (等待 ${(t1 - t0).toFixed(1)}ms), 现在 POST ${path}`);
      const r = await api(path, { target: id });
      const t2 = performance.now();
      console.log(`[motor] ${act} id=${id}: 响应 ${r.ok ? 'OK' : 'FAIL'} "${r.msg || ''}" `
        + `(请求 ${(t2 - t1).toFixed(1)}ms, 从点击算 ${(t2 - t0).toFixed(1)}ms)`, r);
      if (r.ok) toast(`✅ ${wasEnabled ? '已停止' : '已使能'} ID ${id}`);
      else       toast(`❌ ${wasEnabled ? '停止' : '使能'}失败: ${r.msg || ''}`, true);
      await refreshMotors();   // 立刻拿最新 enabled 状态
    });
    list.appendChild(card);
  }

  // + 按钮永远在最后 (innerHTML='' 会把它一起清掉, 这里重新加上)
  const addBtn = document.createElement('button');
  addBtn.id = 'btnAddMotor';
  addBtn.className = 'btn-add';
  addBtn.title = '添加电机';
  addBtn.textContent = '+';
  addBtn.addEventListener('click', onAddMotorClick);
  list.appendChild(addBtn);
}

// 原地刷新卡片数值 (不动 DOM 结构 -> 不会闪, 也不会吃掉点击)
function refreshMotorCardValues() {
  const set = (el, txt) => { if (el && el.textContent !== txt) el.textContent = txt; };
  for (const m of state.motors) {
    const card = document.querySelector(`.motor-card[data-target="${m.target_id}"]`);
    if (!card) continue;
    const kvs = card.querySelectorAll('.kv b');
    if (kvs.length >= 6) {
      set(kvs[0], Number(m.position || 0).toFixed(3));
      set(kvs[1], Number(m.speed || 0).toFixed(3));
      set(kvs[2], Number(m.torque || 0).toFixed(3));
      set(kvs[3], Number(m.temperature != null ? m.temperature : 0).toFixed(1));
      set(kvs[4], m.voltage !== undefined ? m.voltage.toFixed(2) : '--');
      set(kvs[5], m.current !== undefined ? m.current.toFixed(2) : '--');
    }
    set(card.querySelector('.motor-mode'), m.mode || '?');
    const btn = card.querySelector('.motor-onoff');
    if (btn) {
      const cls = 'motor-onoff ' + (m.enabled ? 'enabled' : 'disabled');
      if (btn.className !== cls) btn.className = cls;
      set(btn, m.enabled ? 'ON' : 'OFF');
      const title = m.enabled ? '点击停止' : '点击使能';
      if (btn.title !== title) btn.title = title;
    }
    set(card.querySelector('.motor-foot'),
        (m.last_update ? ((Date.now() / 1000 - m.last_update).toFixed(1)) : '--') + 's');
  }
}

function renderMotors() {
  const sig = state.motors.map(x => x.target_id).join(',') + '#' + state.selectedTarget;
  if (sig === renderedMotorSig) {   // 结构没变 -> 只刷数值
    refreshMotorCardValues();
    return;
  }
  renderedMotorSig = sig;
  rebuildMotorCards();
}

// ===================== 选中电机 =====================
function selectTarget(targetId) {
  // 验证电机存在
  const exists = state.motors.find(m => m.target_id === targetId);
  if (!exists) {
    toast(`❌ 电机 ${targetId} 不存在, 请先扫描`, true);
    return false;
  }
  state.selectedTarget = targetId;
  renderMotors();
  return true;
}

function selectMotor(targetId) {
  state.selectedTarget = targetId;
  renderMotors();
}

// ===================== 添加电机 (+ 按钮) =====================
// 微信内置浏览器禁用 window.prompt(), 用自定义模态对话框代替
function showAddMotorModal() {
  // 如果已有模态, 重复点击 + 不重建
  if (document.getElementById('addMotorModal')) {
    document.getElementById('addMotorInput').focus();
    return;
  }
  const mask = document.createElement('div');
  mask.id = 'addMotorModal';
  mask.className = 'modal-mask';
  mask.innerHTML = `
    <div class="modal-box">
      <h4>添加电机</h4>
      <p>输入电机 ID (0~127 或 0x..):</p>
      <input type="text" id="addMotorInput" placeholder="例如 1 或 0x7F" autocomplete="off">
      <div class="modal-actions">
        <button id="addMotorCancel" class="btn">取消</button>
        <button id="addMotorOk" class="btn btn-primary">添加</button>
      </div>
    </div>
  `;
  document.body.appendChild(mask);

  const input = document.getElementById('addMotorInput');
  const okBtn = document.getElementById('addMotorOk');
  const cancelBtn = document.getElementById('addMotorCancel');

  const close = () => mask.remove();

  const submit = async () => {
    const v = input.value.trim();
    if (!v) { close(); return; }
    let id;
    try {
      id = (v.startsWith('0x') || v.startsWith('0X')) ? parseInt(v, 16) : parseInt(v, 10);
    } catch (e) {
      toast('❌ 无效 ID', true);
      return;
    }
    if (isNaN(id) || id < 0 || id > 127) {
      toast('❌ ID 范围 0~127', true);
      return;
    }
    close();
    toast(`⏳ 正在查询电机 ${id}...`);
    const t0 = Date.now() / 1000;
    await api('/api/ls', { targets: [id] });
    await refreshMotors();
    // ⚠ /api/motors 返回的是累积缓存: 以前发现过、现在已经断电的电机也还在列表里,
    //   所以"这台是否存在"要看本次探测之后 last_update 有没有被刷新 (GET_ID 应答会刷新),
    //   不能只看它在不在列表里.
    const m = state.motors.find(x => x.target_id === id);
    if (m && (m.last_update || 0) >= t0 - 0.5) {
      state.selectedTarget = id;
      renderMotors();
      toast(`✅ 电机 ${id} 已添加`);
    } else {
      toast(`❌ 电机 ${id} 无响应 (总线上没有这台)`, true);
    }
  };

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submit();
    else if (e.key === 'Escape') close();
  });
  okBtn.addEventListener('click', submit);
  cancelBtn.addEventListener('click', close);
  mask.addEventListener('click', (e) => { if (e.target === mask) close(); });
  setTimeout(() => input.focus(), 50);
}

async function onAddMotorClick() {
  showAddMotorModal();
}

function setupAddButton() {
  const btn = $('btnAddMotor');
  if (btn) btn.addEventListener('click', onAddMotorClick);
}

// ===================== 参数行: get (读回来填进输入框) =====================
// 位置卡的 n 单位是 1/60 圈, 电机里存的是 rad -> 两个方向都要换算
const nToRad = (n) => n * 2 * Math.PI / 60;

// 参数行里的 [get]: addr 在 .param-row[data-addr] 上, 输入框是行内那个 .num
async function readAddrIntoInput(btn) {
  const t = requireTarget();
  if (t === null) return;
  const row = btn.closest('.param-row');
  const addr = btn.dataset.addr || (row && row.dataset.addr);
  if (!addr) { toast('❌ 这个按钮没配 addr', true); return; }
  const input = row ? row.querySelector('.num') : null;
  if (!input) { toast('❌ 找不到对应输入框', true); return; }

  const origText = btn.textContent;
  const short = btn.classList.contains('btn-param-get');   // [get] 按钮位置窄, 只显示符号
  btn.textContent = '…';
  btn.disabled = true;
  btn.classList.remove('ok', 'err');

  try {
    const r = await api('/api/params', { target: t, addrs: [parseInt(addr, 16)] });
    // 后端返回的 key 是 hex(a) = '0x700a' 小写, 前端 addr 是 '0x700A' 大写
    // 用 toLowerCase() 统一, 避免 0x700A / 0x700a 这种字母触发大小写不一致
    const entry = r.ok && r.data ? r.data[addr.toLowerCase()] : null;
    if (entry) {
      const v = Number(entry.value);
      const isN = input.dataset.f === 'n' || (row && row.dataset.conv === 'n2rad');
      if (isN) {
        // 0x7016 存的是 rad, 输入框是 n = 1/60 圈
        input.value = (v * 60 / (2 * Math.PI)).toFixed(2);
      } else {
        input.value = Number.isFinite(v) ? v.toFixed(4) : String(entry.value);
      }
      // 通知监听者: 位置/速度卡的拖动条要跟着数字框同步
      input.dispatchEvent(new Event('input', { bubbles: true }));
      btn.textContent = short ? '✓' : ('✓ ' + addr);
      btn.classList.add('ok');
    } else {
      btn.textContent = short ? '✗' : '✗ 超时';
      btn.classList.add('err');
      toast(`❌ 读取 ${addr} 失败 (超时)`, true);
    }
  } catch (e) {
    btn.textContent = short ? '✗' : '✗ 错误';
    btn.classList.add('err');
    toast('❌ 错误: ' + (e.message || e), true);
  } finally {
    setTimeout(() => {
      btn.textContent = origText;
      btn.disabled = false;
      btn.classList.remove('ok', 'err');
    }, 1200);
  }
}

// ===================== 扫描 =====================
$('btnLs').addEventListener('click', async () => {
  // 逐个 id 发 GET_ID, 1~127 全扫一遍约 0.6s, 先给个提示
  toast('⏳ 正在逐个 id 扫描 1~127 ...');
  await api('/api/ls', {});
  await refreshMotors();
});

// 200ms 轮询也走这里 (不走 api(), 否则控制台每秒被刷 5 条)
// ⚠ 这里绝对不能抛异常: 它被 sendFields 在发送成功后 await,
//   一抛就会让拖动条发送器卡在"在飞"状态 (点一次好、再点就没反应)
async function refreshMotors() {
  try {
    const r = await fetch('/api/motors');
    const j = await r.json();
    if (!j.ok || !Array.isArray(j.data)) return;
    state.motors = j.data;
    $('serialStatus').className = 'dot dot-on';
    $('serialText').textContent = `已连接 ${state.motors.length} 个电机`;
    renderMotors();
  } catch (e) {
    console.error('[api] ✗ GET /api/motors (轮询)', e);
  }
}

// ===================== 当前目标取参 =====================
function requireTarget() {
  if (state.selectedTarget === null) {
    toast('❌ 请先选电机 (点 + 或点卡片)', true);
    return null;
  }
  return state.selectedTarget;
}

// ===================== 4 个模式矩形 =====================
document.querySelectorAll('.mode-card').forEach(card => {
  const mode = card.dataset.mode;

  // 把本卡 .num 输入框的值打包发给电机
  // onlyField: 只发某一个字段 (拖动条用) —— 速度卡的拖动条只发 rad, 不带上 limit_cur
  // 拖动条(onlyField 非空)优先走 /ws/status 那条 WebSocket: 发了就不管, 不等回复,
  // 没有"上一个还在飞"的状态; WS 没连上才回退 HTTP
  const sendFields = async (quiet = false, onlyField = null) => {
    const t = state.selectedTarget;
    if (t === null) {
      if (!quiet) toast('❌ 请先选电机 (点 + 或点卡片)', true);
      return false;
    }
    const fields = {};
    card.querySelectorAll('.num').forEach(inp => {
      if (inp.disabled) return;                 // 置灰的输入框 (如设零位那行) 不参与发送
      if (onlyField && inp.dataset.f !== onlyField) return;
      fields[inp.dataset.f] = parseFloat(inp.value);
    });
    if (onlyField && wsSendSetpoint(mode, { target: t, ...fields })) return true;
    // WS 不可用: 回退 HTTP (后端同样会合并, 只是有请求/应答开销)
    const r = await api('/api/' + mode, { target: t, ...fields }, quiet);
    if (!quiet) await refreshMotors();
    return r.ok;
  };

  // setmode 按钮
  card.querySelector('.btn-mode').addEventListener('click', async () => {
    const t = requireTarget(); if (t === null) return;
    await settleSetpoints();          // 先让拖动条的指令落地, 再切模式
    await api('/api/setmode', { target: t, mode });
  });

  // 发送按钮 (运控/电流卡还是按钮; 位置/速度卡已改成拖动条)
  const btnSend = card.querySelector('.btn-send');
  if (btnSend) btnSend.addEventListener('click', async () => {
    await settleSetpoints();
    await sendFields(false);
  });

  // 拖动条 (位置/速度): 与数字框双向同步, 拖动/点击/松手都发给电机
  card.querySelectorAll('.slider').forEach(sl => {
    const num = card.querySelector(`.num[data-f="${sl.dataset.f}"]`);
    const fld = sl.dataset.f;
    const pushToNum = () => { if (num) num.value = sl.value; };
    // ⚠ 只发这条拖动条自己的字段: 速度卡里的 LIMIT_CUR 不跟着发
    //   (限流由用户在参数行点 set 单独下发)
    // 固定 quiet=true: 连续指令走 WS 没有回执, 也不额外打 /api/motors;
    // 屏幕上的数值就是反馈, 需要排查时看 console 日志
    const sender = makeSetpointSender(() => sendFields(true, fld), SLIDER_SEND_MS, `slider:${fld}`);

    sl.addEventListener('pointerdown', () => { sl._warned = false; });

    // 拖动中 (含点击轨道): 限流 + 最多 1 个请求在飞, 不弹成功提示
    sl.addEventListener('input', () => {
      pushToNum();
      console.log(`[slider:${fld}] input ${fld}=${sl.value}${state.selectedTarget === null ? ' (未选电机)' : ''}`);
      if (state.selectedTarget === null) {
        if (!sl._warned) { toast('❌ 请先选电机 (点 + 或点卡片)', true); sl._warned = true; }
        return;
      }
      sender.queue();
    });

    // 松手 / 点击定位: 立刻把最终值发一次, 并正常提示
    sl.addEventListener('change', () => {
      pushToNum();
      console.log(`[slider:${fld}] change ${fld}=${sl.value} -> flush (点击/松手, 立即发送)`);
      sl._warned = false;
      if (state.selectedTarget === null) {
        toast('❌ 请先选电机 (点 + 或点卡片)', true);
        return;
      }
      sender.flush();
    });

    // 数字框改动 (含"📥 从电机读"填入) -> 同步回拖动条
    if (num) {
      num.addEventListener('input', () => {
        const v = parseFloat(num.value);
        if (!Number.isFinite(v)) return;
        sl.value = String(Math.min(Number(sl.max), Math.max(Number(sl.min), v)));
      });
      // 直接在数字框里改值 (回车/失焦) 也发一次, 与拖动条行为一致
      num.addEventListener('change', () => {
        console.log(`[slider:${fld}] 数字框 ${fld}=${num.value} -> flush`);
        if (state.selectedTarget === null) return;
        sender.flush();
      });
    }
  });

  // 参数行 [名字][输入文本框][get][set]
  //   get: 从电机读该行的 addr 填进输入框;  set: 把输入框的值写进该 addr
  //   没有 data-addr 的行 (运控的 kp/kd/torque: 电机没有对应寄存器) 按钮保持 disabled
  //   data-conv="n2rad": 输入框是 n (1/60 圈), 写入前换算成 rad (位置卡)
  card.querySelectorAll('.param-row').forEach(row => {
    const input = row.querySelector('.num');
    const addr = row.dataset.addr;
    const getBtn = row.querySelector('.btn-param-get');
    const setBtn = row.querySelector('.btn-param-set');
    if (!addr || !input) return;
    if (getBtn) getBtn.addEventListener('click', () => readAddrIntoInput(getBtn));
    if (setBtn) setBtn.addEventListener('click', async () => {
      const t = requireTarget(); if (t === null) return;
      let v = parseFloat(input.value);
      if (!Number.isFinite(v)) { toast('❌ 值不是有效数字', true); return; }
      if (row.dataset.conv === 'n2rad') v = nToRad(v);
      await doAdvWrite(setBtn, t, addr, v);   // 内部已 settleSetpoints + /api/setprop
    });
  });

  // data-cmd 行 (设零位这类"只有动作、没有数值"的行):
  // 输入框和 get 在 HTML 里就 disabled, 只有 set 可点 -> 调对应的接口
  card.querySelectorAll('.param-row[data-cmd]').forEach(row => {
    const setBtn = row.querySelector('.btn-param-set');
    if (!setBtn) return;
    setBtn.addEventListener('click', async () => {
      const t = requireTarget(); if (t === null) return;
      setBtn.disabled = true;
      try {
        await settleSetpoints();                  // 先丢掉还没发出的连续指令排队值
        await api('/api/' + row.dataset.cmd, { target: t });   // api() 负责提示 + 日志
      } finally {
        setTimeout(() => { setBtn.disabled = false; }, 600);
      }
    });
  });
  // (原来的 📥 地址按钮已全部改成参数行的 [get], 上面已绑定)
});

// (高级区 getprop/setprop 初始化在 loadParamsList() 里做, 见文件末尾)

// ===================== WebSocket 变量 (必须在 connect*() 之前声明, 避免 TDZ) =====================
let ws = null;
let wsRetryMs = 1000;            // 指数退避 1s → 10s
let statusWs = null;
let statusWsRetryMs = 1000;

// ===================== 启动 =====================
// app.js 自己的版本号 (由后端注入的 ?v=<mtime>), 方便一眼看出页面是不是新资源
const APP_VERSION = (() => {
  try { return new URL(document.currentScript.src).searchParams.get('v') || '?'; }
  catch (e) { return '?'; }
})();

setupAddButton();
bindClearLog();
bindClearWebLog();
console.log(`[ui] 控制台已加载 (app.js v=${APP_VERSION})`);
if (!$('webLogArea')) webLogPane();      // 一进来就检查日志框在不在, 不在就提醒
refreshMotors();
state.pollTimer = setInterval(refreshMotors, 200);
connectWs();        // WebSocket 实时日志推送 (取代之前 500ms 轮询)
connectStatusWs();  // WebSocket 电机反馈推送 (pos/vel/torque/temp 被动更新)

// ===================== 实时日志区 (WebSocket) =====================
function classifyLogLine(msg) {
  if (msg.startsWith('[serial]tx') || msg.startsWith('[motor]tx')) return 'tx';
  if (msg.startsWith('[serial]rx') || msg.startsWith('[motor]rx')) return 'rx';
  if (msg.startsWith('[serial]err') || msg.startsWith('[motor]err')) return 'err';
  return 'info';
}

// 单行追加 (增量渲染, 不用每次重绘整个区域)
const LOG_MAX_DOM = 500;  // DOM 中最多保留 500 行, 超出的从头删
function appendLogLine(msg) {
  const area = $('logArea');
  if (!area) return;
  const wasAtBottom = area.scrollTop + area.clientHeight >= area.scrollHeight - 10;
  const cls = classifyLogLine(msg);
  const div = document.createElement('div');
  div.className = 'log-line ' + cls;
  div.textContent = msg;                 // textContent 自动转义, 不用手工 replace
  area.appendChild(div);
  while (area.children.length > LOG_MAX_DOM) {
    area.removeChild(area.firstChild);
  }
  if (wasAtBottom) {
    area.scrollTop = area.scrollHeight;
  }
}

function connectWs() {
  if (ws && ws.readyState <= 1) return;  // 已在连接/已连接
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/log`;
  ws = new WebSocket(url);
  ws.onopen = () => {
    wsRetryMs = 1000;  // 连上后重置退避
  };
  ws.onmessage = (e) => {
    let m;
    try { m = JSON.parse(e.data); } catch { return; }
    if (m.type === 'log') appendLogLine(m.data);
    else if (m.type === 'clear') {
      $('logArea').innerHTML = '';
    }
  };
  ws.onerror = () => { /* onclose 会负责重连 */ };
  ws.onclose = () => {
    ws = null;
    setTimeout(connectWs, wsRetryMs);
    wsRetryMs = Math.min(wsRetryMs * 2, 10000);
  };
}

function bindClearLog() {
  $('btnClearLog').addEventListener('click', async () => {
    // 走 HTTP (后端会清 GLOBAL_LOG + WS 广播 clear 事件给所有客户端)
    // 用 api() 以便打 console 日志; quiet=true 是不弹"成功"提示
    await api('/api/logs/clear', {}, true);
  });
}

// 网页日志框的清空: 只清这个矩形 (DevTools 里的历史不动)
function bindClearWebLog() {
  const btn = $('btnClearWebLog');
  if (btn) btn.addEventListener('click', () => { $('webLogArea').innerHTML = ''; });
}

// ===================== 高级区参数列表 (统一表格: 自定义 + 全部参数) =====================
const INT_TYPES = new Set(['uint8', 'uint16', 'uint32', 'int16', 'int32']);
function isIntType(t) { return INT_TYPES.has(t); }
function formatValue(v, t) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return String(v);
  if (isIntType(t)) return String(Math.round(v));
  return v.toFixed(4);
}

function makeAdvRow({ name, addr, desc='', writable=true, addrInput=false, valInput=false }) {
  const row = document.createElement('div');
  row.className = 'adv-row' + (writable ? '' : ' adv-row-ro');
  const addrEl = addrInput
    ? `<input type="text" class="adv-addr" id="inpAddr" value="${addr || '0x7005'}" title="${desc || '输入任意 addr (hex)'}">`
    : `<span class="adv-addr" title="${desc}">${addr}</span>`;
  const valEl = valInput
    ? `<input type="text" class="adv-val" id="inpValue" placeholder="value" title="输入要写的值">`
    : `<input type="text" class="adv-val" data-addr="${addr}" placeholder="-" title="${desc}">`;
  const setDisabled = writable ? '' : 'disabled';
  const setTitle    = writable ? `点击写 ${addr} = 输入框的值` : `${addr} 只读, 不能写`;
  const getId = addrInput ? 'id="btnGetprop"' : `data-addr="${addr}"`;
  const setId = addrInput ? 'id="btnSetprop"' : `data-addr="${addr}"`;
  const getClass = addrInput ? 'adv-btn' : 'adv-btn adv-btn-get';
  const setClass = addrInput ? 'adv-btn' : 'adv-btn adv-btn-set';
  row.innerHTML = `
    <span class="adv-name" title="${desc || '自定义 addr'}">${name}</span>
    ${addrEl}
    ${valEl}
    <button class="${getClass}" ${getId} title="读 ${addr || '自定义'}">get</button>
    <button class="${setClass}" ${setId} ${setDisabled} title="${setTitle}">set</button>
  `;
  return row;
}

async function loadParamsList() {
  const list = $('paramsList');
  if (!list) return;
  list.innerHTML = '';
  // Row 1: 自定义 (可填任意 addr)
  const customRow = makeAdvRow({ name: '自定义', addr: '0x7005', addrInput: true, valInput: true, writable: true });
  list.appendChild(customRow);
  $('btnGetprop').addEventListener('click', advancedReadCustom);
  $('btnSetprop').addEventListener('click', advancedWriteCustom);

  // Row 2+: 从 API 拉所有参数
  const r = await api('/api/params_info', null);
  if (!r.ok) { list.innerHTML = '<div class="params-list-hint">❌ 加载失败</div>'; return; }
  for (const p of r.data) {
    const row = makeAdvRow({ name: p.name, addr: p.addr, desc: p.desc, writable: p.writable });
    list.appendChild(row);
  }
  // 绑定动态行的 get/set 按钮
  list.querySelectorAll('.adv-btn-get').forEach(btn => {
    btn.addEventListener('click', () => advancedReadParam(btn));
  });
  list.querySelectorAll('.adv-btn-set').forEach(btn => {
    btn.addEventListener('click', () => advancedWriteParam(btn));
  });
}

async function advancedReadCustom() {
  const t = requireTarget();
  if (t === null) return;
  const addr = $('inpAddr').value.trim();
  if (!addr) { toast('❌ 请先填 addr', true); return; }
  const btn = $('btnGetprop');
  const orig = btn.textContent;
  btn.textContent = '…';
  btn.disabled = true;
  try {
    const r = await api('/api/params', { target: t, addrs: [parseInt(addr, 16)] });
    const entry = r.ok && r.data ? r.data[addr.toLowerCase()] : null;
    if (entry) {
      $('inpValue').value = formatValue(entry.value, entry.type);
      btn.textContent = '✓';
    } else {
      btn.textContent = '✗';
    }
  } catch (e) {
    btn.textContent = '✗';
  } finally {
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 800);
  }
}

async function advancedWriteCustom() {
  const t = requireTarget();
  if (t === null) return;
  const addr = $('inpAddr').value.trim();
  const valStr = $('inpValue').value.trim();
  if (!addr || !valStr) { toast('❌ 请填 addr 和 value', true); return; }
  const value = parseFloat(valStr);
  if (!Number.isFinite(value)) { toast('❌ value 不是有效数字', true); return; }
  await doAdvWrite($('btnSetprop'), t, addr, value);
}

async function advancedReadParam(btn) {
  const t = requireTarget();
  if (t === null) return;
  const addr = btn.dataset.addr;
  const input = document.querySelector(`.adv-val[data-addr="${addr}"]`);
  const orig = btn.textContent;
  btn.textContent = '…';
  btn.disabled = true;
  try {
    const r = await api('/api/params', { target: t, addrs: [parseInt(addr, 16)] });
    const entry = r.ok && r.data ? r.data[addr.toLowerCase()] : null;
    if (entry && input) {
      input.value = formatValue(entry.value, entry.type);
      btn.textContent = '✓';
    } else {
      btn.textContent = '✗';
    }
  } catch (e) {
    btn.textContent = '✗';
  } finally {
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 800);
  }
}

async function advancedWriteParam(btn) {
  const t = requireTarget();
  if (t === null) return;
  const addr = btn.dataset.addr;
  const input = document.querySelector(`.adv-val[data-addr="${addr}"]`);
  if (!input || !input.value.trim()) { toast('❌ 请先在输入框填值', true); return; }
  const value = parseFloat(input.value);
  if (!Number.isFinite(value)) { toast('❌ 值不是有效数字', true); return; }
  await doAdvWrite(btn, t, addr, value);
}

async function doAdvWrite(btn, t, addr, value) {
  const orig = btn.textContent;
  btn.textContent = '…';
  btn.disabled = true;
  try {
    await settleSetpoints();     // 参数写入前, 先让拖动条在飞的指令落地
    const r = await api('/api/setprop', { target: t, addr, value });
    if (r.ok) { btn.textContent = '✓'; toast(`✅ 写 ${addr} = ${value}`); }
    else     { btn.textContent = '✗'; toast(`❌ 写失败: ${r.msg || ''}`, true); }
  } catch (e) {
    btn.textContent = '✗';
  } finally {
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 800);
  }
}

// 页面加载后初始化参数列表
loadParamsList();

// ===================== 实时电机状态 (WebSocket) =====================
// /ws/status: motor 报告反馈帧时 (pos/vel/torque/temp), 增量刷新卡片对应行
function connectStatusWs() {
  if (statusWs && statusWs.readyState <= 1) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws/status`;
  statusWs = new WebSocket(url);
  statusWs.onopen = () => {
    statusWsRetryMs = 1000;
    console.log('[ws] /ws/status 已连接 (连续指令走这条, 发完即忘)');
  };
  statusWs.onmessage = (e) => {
    let m;
    try { m = JSON.parse(e.data); } catch { return; }
    if (m.type === 'status') updateMotorStatus(m.motor_id, m.data);
  };
  statusWs.onerror = () => {};
  statusWs.onclose = () => {
    console.warn('[ws] /ws/status 断开, 连续指令暂时回退 HTTP');
    statusWs = null;
    setTimeout(connectStatusWs, statusWsRetryMs);
    statusWsRetryMs = Math.min(statusWsRetryMs * 2, 10000);
  };
}

// 增量更新一张卡片的状态行 (pos/vel/trq/tmp/vol/cur + age), 不重渲染整张
// data 可部分 (反馈只带 pos/vel/trq/tmp, 电压电流广播只带 voltage/current)
function updateMotorStatus(motorId, data) {
  // 同步 state.motors (防后续 renderMotors 覆盖)
  let m = state.motors.find(x => x.target_id === motorId);
  const lu = data.last_update || (Date.now() / 1000);
  if (!m) {
    // 新电机 (反馈先于列表到达): 先塞进 state 再渲染一次
    state.motors.push({
      target_id: motorId,
      position: data.position || 0,
      speed: data.speed || 0,
      torque: data.torque || 0,
      temperature: data.temperature || 0,
      voltage: data.voltage,  // undefined if 没在
      current: data.current,
      mode: '?', enabled: false,
      last_update: lu,
    });
    renderMotors();
    return;
  }
  // 只更新 data 里实际带的字段 (避免电压电流广播抹掉 pos/vel/trq/tmp)
  if (data.position !== undefined) m.position = data.position;
  if (data.speed    !== undefined) m.speed    = data.speed;
  if (data.torque   !== undefined) m.torque   = data.torque;
  if (data.temperature !== undefined) m.temperature = data.temperature;
  if (data.voltage  !== undefined) m.voltage  = data.voltage;
  if (data.current  !== undefined) m.current  = data.current;
  m.last_update = lu;

  const card = document.querySelector(`.motor-card[data-target="${motorId}"]`);
  if (!card) { renderMotors(); return; }  // 卡片不在 -> 重渲染

  // 找 6 个 .kv 行 (顺序: pos/vel/trq/tmp/vol/cur), 只改 <b>
  const kvs = card.querySelectorAll('.kv b');
  if (kvs.length >= 6) {
    if (data.position !== undefined) kvs[0].textContent = Number(m.position || 0).toFixed(3);
    if (data.speed    !== undefined) kvs[1].textContent = Number(m.speed || 0).toFixed(3);
    if (data.torque   !== undefined) kvs[2].textContent = Number(m.torque || 0).toFixed(3);
    if (data.temperature !== undefined) kvs[3].textContent = Number(m.temperature != null ? m.temperature : 0).toFixed(1);
    if (data.voltage  !== undefined) kvs[4].textContent = Number(m.voltage || 0).toFixed(2);
    if (data.current  !== undefined) kvs[5].textContent = Number(m.current || 0).toFixed(2);
  }
  // 年龄
  const age = ((Date.now() / 1000 - m.last_update).toFixed(1));
  const foot = card.querySelector('.motor-foot');
  if (foot) foot.textContent = age + 's';
}
