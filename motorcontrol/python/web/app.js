// app.js - CyberGear Web 控制台
// 不依赖任何前端框架, 纯 vanilla JS.

const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

// ===================== 状态 =====================
const state = {
  selectedTarget: null,      // 当前选中的电机 ID (int)
  motors: [],                // 后端返回的电机列表
  pollTimer: null,
};

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
async function api(path, body) {
  try {
    const r = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const j = await r.json();
    if (!j.ok) {
      toast('❌ ' + (j.msg || '失败'), true);
    } else if (j.msg) {
      toast('✅ ' + j.msg);
    }
    return j;
  } catch (e) {
    toast('❌ 网络错误: ' + e.message, true);
    return { ok: false };
  }
}

// ===================== 渲染: 电机卡片 =====================
function renderMotors() {
  const list = $('motorList');
  list.innerHTML = '';

  // 已发现电机卡片
  for (const m of state.motors) {
    const card = document.createElement('div');
    card.className = 'motor-card' + (m.target_id === state.selectedTarget ? ' selected' : '');
    card.dataset.target = m.target_id;
    const enabledClass = m.enabled ? 'enabled' : 'disabled';
    const age = m.last_update ? ((Date.now() / 1000 - m.last_update).toFixed(1)) : '--';
    card.innerHTML = `
      <div class="motor-head">
        <span class="motor-id">ID ${m.target_id}</span>
        <span class="motor-mode">${m.mode || '?'}</span>
        <span class="motor-state ${enabledClass}">${m.enabled ? 'ENA' : 'OFF'}</span>
      </div>
      <div class="motor-body">
        <div class="kv"><span>pos</span><b>${m.position.toFixed(3)}</b><i>rad</i></div>
        <div class="kv"><span>vel</span><b>${m.speed.toFixed(3)}</b><i>rad/s</i></div>
        <div class="kv"><span>trq</span><b>${m.torque.toFixed(3)}</b><i>Nm</i></div>
        <div class="kv"><span>tmp</span><b>${m.temperature}</b><i>raw</i></div>
        <div class="kv kv-vol"><span>vol</span><b>${m.voltage !== undefined ? m.voltage.toFixed(2) : '--'}</b><i>V</i></div>
        <div class="kv kv-cur"><span>cur</span><b>${m.current !== undefined ? m.current.toFixed(2) : '--'}</b><i>A</i></div>
      </div>
      <div class="motor-foot">${age}s</div>
    `;
    card.addEventListener('click', () => selectMotor(m.target_id));
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

  // 当前目标显示
  $('curTarget').textContent = state.selectedTarget === null ? '未选' : `ID ${state.selectedTarget}`;
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
    await api('/api/ls', { targets: [id] });
    await refreshMotors();
    const exists = state.motors.find(m => m.target_id === id);
    if (exists) {
      state.selectedTarget = id;
      renderMotors();
      toast(`✅ 电机 ${id} 已添加`);
    } else {
      toast(`❌ 电机 ${id} 无响应`, true);
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

// ===================== 点击寄存器地址读取并填入输入框 =====================
async function readAddrIntoInput(btn) {
  const t = requireTarget();
  if (t === null) return;
  const addr = btn.dataset.addr;
  const targetField = btn.dataset.targetF;
  const card = btn.closest('.mode-card');
  const input = card.querySelector(`.num[data-f="${targetField}"]`);
  if (!input) { toast('❌ 找不到对应输入框', true); return; }

  const origText = btn.textContent;
  btn.textContent = '…';
  btn.disabled = true;
  btn.className = 'btn-read-addr';

  try {
    const r = await api('/api/params', { target: t, addrs: [parseInt(addr, 16)] });
    // 后端返回的 key 是 hex(a) = '0x700a' 小写, 前端 btn.dataset.addr 是 '0x700A' 大写
    // 用 toLowerCase() 统一, 避免 0x700A / 0x700a 这种字母触发大小写不一致
    const entry = r.ok && r.data ? r.data[addr.toLowerCase()] : null;
    if (entry) {
      const v = Number(entry.value);
      if (targetField === 'n') {
        // 0x7016 存的是 rad, 输入框是 n = 1/60 圈
        input.value = (v * 60 / (2 * Math.PI)).toFixed(2);
      } else {
        input.value = Number.isFinite(v) ? v.toFixed(4) : String(entry.value);
      }
      btn.textContent = '✓ ' + addr;
      btn.className = 'btn-read-addr ok';
    } else {
      btn.textContent = '✗ 超时';
      btn.className = 'btn-read-addr err';
      toast(`❌ 读取 ${addr} 失败 (超时)`, true);
    }
  } catch (e) {
    btn.textContent = '✗ 错误';
    btn.className = 'btn-read-addr err';
    toast('❌ 错误: ' + (e.message || e), true);
  } finally {
    setTimeout(() => {
      btn.textContent = origText;
      btn.disabled = false;
      btn.className = 'btn-read-addr';
    }, 1200);
  }
}

// ===================== 扫描 =====================
$('btnLs').addEventListener('click', async () => {
  await api('/api/ls', {});
  await refreshMotors();
});

async function refreshMotors() {
  const r = await fetch('/api/motors');
  const j = await r.json();
  if (j.ok) {
    state.motors = j.data;
    $('serialStatus').className = 'dot dot-on';
    $('serialText').textContent = `已连接 ${state.motors.length} 个电机`;
    renderMotors();
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

// ===================== 使能 / 停止 =====================
$('btnEnable').addEventListener('click', async () => {
  const t = requireTarget(); if (t === null) return;
  await api('/api/enable', { target: t });
  await refreshMotors();
});

$('btnStop').addEventListener('click', async () => {
  const t = requireTarget(); if (t === null) return;
  await api('/api/stop', { target: t });
  await refreshMotors();
});

// ===================== 4 个模式矩形 =====================
document.querySelectorAll('.mode-card').forEach(card => {
  const mode = card.dataset.mode;
  // setmode 按钮
  card.querySelector('.btn-mode').addEventListener('click', async () => {
    const t = requireTarget(); if (t === null) return;
    await api('/api/setmode', { target: t, mode });
  });
  // 发送按钮
  card.querySelector('.btn-send').addEventListener('click', async () => {
    const t = requireTarget(); if (t === null) return;
    const fields = {};
    card.querySelectorAll('.num').forEach(inp => {
      fields[inp.dataset.f] = parseFloat(inp.value);
    });
    await api('/api/' + mode, { target: t, ...fields });
    await refreshMotors();
  });
  // 辅助动作按钮 (data-act="setzero" 等)
  card.querySelectorAll('.btn-act').forEach(btn => {
    btn.addEventListener('click', async () => {
      const t = requireTarget(); if (t === null) return;
      const act = btn.dataset.act;
      if (act === 'setzero') {
        await api('/api/setzero', { target: t });
        toast('✅ 零位已设');
      }
    });
  });
  // 点击寄存器地址读取并填入对应输入框
  card.querySelectorAll('.btn-read-addr').forEach(btn => {
    btn.addEventListener('click', () => readAddrIntoInput(btn));
  });
});

// (高级区 getprop/setprop 初始化在 loadParamsList() 里做, 见文件末尾)

// ===================== 启动 =====================
setupAddButton();
bindClearLog();
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
  const wasAtBottom = area.scrollTop + area.clientHeight >= area.scrollHeight - 10;
  const cls = classifyLogLine(msg);
  const safe = msg.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const div = document.createElement('div');
  div.className = 'log-line ' + cls;
  div.innerHTML = safe;
  area.appendChild(div);
  while (area.children.length > LOG_MAX_DOM) {
    area.removeChild(area.firstChild);
  }
  if (wasAtBottom) {
    area.scrollTop = area.scrollHeight;
  }
}

let ws = null;
let wsRetryMs = 1000;  // 指数退避 1s → 2s → 4s → 8s → 10s 上限
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
    await fetch('/api/logs/clear', { method: 'POST' });
  });
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
let statusWs = null;
let statusWsRetryMs = 1000;
function connectStatusWs() {
  if (statusWs && statusWs.readyState <= 1) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws/status`;
  statusWs = new WebSocket(url);
  statusWs.onopen = () => { statusWsRetryMs = 1000; };
  statusWs.onmessage = (e) => {
    let m;
    try { m = JSON.parse(e.data); } catch { return; }
    if (m.type === 'status') updateMotorStatus(m.motor_id, m.data);
  };
  statusWs.onerror = () => {};
  statusWs.onclose = () => {
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
    if (data.position !== undefined) kvs[0].textContent = m.position.toFixed(3);
    if (data.speed    !== undefined) kvs[1].textContent = m.speed.toFixed(3);
    if (data.torque   !== undefined) kvs[2].textContent = m.torque.toFixed(3);
    if (data.temperature !== undefined) kvs[3].textContent = String(m.temperature);
    if (data.voltage  !== undefined) kvs[4].textContent = m.voltage.toFixed(2);
    if (data.current  !== undefined) kvs[5].textContent = m.current.toFixed(2);
  }
  // 年龄
  const age = ((Date.now() / 1000 - m.last_update).toFixed(1));
  const foot = card.querySelector('.motor-foot');
  if (foot) foot.textContent = age + 's';
}
