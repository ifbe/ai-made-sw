// findmedia — 前端逻辑（vanilla JS，无依赖）
const $  = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let tagKeysCache = null;

async function fetchJSON(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`${r.status} ${r.statusText} ${t.slice(0, 100)}`);
  }
  return r.json();
}

async function loadStats() {
  try {
    const s = await fetchJSON('/api/stats');
    $('#stats').textContent =
      `共 ${s.total || 0}（图 ${s.images || 0} / 音 ${s.audio || 0} / 视 ${s.video || 0} · 带JSON ${s.with_json || 0}）`;
  } catch (e) {
    $('#stats').textContent = 'stats 失败: ' + e.message;
  }
}

async function loadTagKeys() {
  if (tagKeysCache) return tagKeysCache;
  try {
    tagKeysCache = await fetchJSON('/api/keys');
  } catch (e) {
    tagKeysCache = {};
  }
  return tagKeysCache;
}

async function buildTagFilters() {
  const keys = await loadTagKeys();
  const container = $('#tag-filters');
  container.innerHTML = '';
  // 固定顺序：与 img2json.py 的枚举顺序保持一致，便于阅读
  const order = ['scene', 'time', 'weather', 'tone', 'composition', 'action', 'mood', 'subjects', 'objects'];
  const sortedKeys = [
    ...order.filter(k => k in keys),
    ...Object.keys(keys).filter(k => !order.includes(k)).sort(),
  ];
  for (const k of sortedKeys) {
    const values = keys[k];
    const sel = document.createElement('select');
    sel.dataset.key = k;
    sel.title = `${k} 的取值`;
    sel.innerHTML =
      `<option value="">${escapeHtml(k)}: 全部</option>` +
      values.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
    container.appendChild(sel);
    // 下拉框从开到关时读 sel.value 触发搜索
    let tagWasOpen = false;
    sel.addEventListener('click', (e) => {
      if (e.target.tagName !== 'SELECT') return;
      const isOpen = sel.matches(':open');
      tagWasOpen = isOpen;
      if (isOpen) return;
      console.log(`[TRIGGER tag 收起了] key=${sel.dataset.key} value=${sel.value}`);
      aiLabelsActive = true;
      clearGroupAC();
      updateRootBadge();
      search();
    });
  }
}

async function search() {
  const q = $('#q').value.trim();
  const typeVal = $('#type').value;
  const hasTag = !!$$('#tag-filters select').find(s => s.value);

  // 4 种模式互斥：任一维度激活就显结果；都没则空
  const hasFilter = currentPath !== null || currentTimeRange !== null || q || typeVal || hasTag || aiLabelsActive;
  if (!hasFilter) {
    renderResults([]);
    updateRootBadge();
    updateModeHighlights();
    return;
  }

  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (typeVal) params.set('type', typeVal);
  $$('#tag-filters select').forEach(sel => {
    if (sel.value) params.append('tag', `${sel.dataset.key}:${sel.value}`);
  });
  // AI 标签模式激活 → 始终只显带 JSON 的文件（AI标签模式的本质：看 metadata）
  if (aiLabelsActive) {
    params.set('has_json', '1');
  }
  if (currentPath !== null) params.set('path', currentPath);
  if (currentTimeRange) {
    params.set('tmin', String(currentTimeRange.min));
    params.set('tmax', String(currentTimeRange.max));
  }
  params.set('limit', '500');

  // 调试：打印本次查询的实际条件 + 模式来源
  console.log('[search params]', params.toString(), '| aiLabelsActive=', aiLabelsActive, '| path=', currentPath, '| time=', currentTimeRange ? `${currentTimeRange.min}~${currentTimeRange.max}` : null);

  try {
    const r = await fetchJSON('/api/search?' + params.toString());
    renderResults(r.hits);
    updateRootBadge();
    updateModeHighlights();
  } catch (e) {
    renderError('搜索失败: ' + e.message);
    updateModeHighlights();
  }
}

function renderError(msg) {
  $('#results').innerHTML = `<div class="empty">${escapeHtml(msg)}</div>`;
}

function renderResults(hits) {
  const main = $('#results');
  if (!hits || hits.length === 0) {
    const q = $('#q').value.trim();
    const typeVal = $('#type').value;
    const hasTag = !!$$('#tag-filters select').find(s => s.value);
    const hasFilter = currentPath !== null || currentTimeRange !== null || q || typeVal || hasTag || aiLabelsActive;
    const msg = hasFilter
      ? '没有匹配的结果'
      : `<div class="empty-hints">
          <div class="hint hint-top">↑ 按关键词查询</div>
          <div class="hint hint-left">← 按目录查询</div>
          <div class="hint hint-right">按 ai 标签查询 →</div>
          <div class="hint hint-bottom">↓ 按时间查询</div>
        </div>`;
    main.innerHTML = msg;
    return;
  }
  main.innerHTML = hits.map(h => {
    const typeLabel = { image: 'IMG', audio: 'AUD', video: 'VID' }[h.type] || h.type.toUpperCase();
    let thumb;
    if (h.type === 'image') {
      thumb = `<div class="thumb"><img data-src="/raw/${h.id}" alt=""></div>`;
    } else if (h.type === 'audio') {
      thumb = `<div class="thumb audio">♪</div>`;
    } else if (h.type === 'video') {
      thumb = `<div class="thumb video">▶</div>`;
    } else {
      thumb = `<div class="thumb">📄</div>`;
    }
    const tagPreview = (h.tags || []).slice(0, 3).map(t =>
      `${escapeHtml(t.key)}=${escapeHtml(t.value)}`).join('  ');
    return `<div class="card" data-id="${h.id}">
      ${thumb}
      <div class="info">
        <div class="info-row">
          <span class="type-badge ${h.type}">${typeLabel}</span>
          <span class="name" title="${escapeHtml(h.path)}">${escapeHtml(h.filename)}</span>
        </div>
        ${tagPreview ? `<div class="tag-preview">${tagPreview}</div>` : ''}
      </div>
    </div>`;
  }).join('');

  $$('.card').forEach(c => {
    c.addEventListener('click', () => {
      window.open(`/raw/${c.dataset.id}`, '_blank');
    });
  });

  // 注册新图片给懒加载观察器
  $$('img[data-src]', main).forEach(img => imageObserver.observe(img));
}

function ensureDetailOverlay() {
  let overlay = $('#detail');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'detail';
    overlay.className = 'detail-overlay hidden';
    overlay.innerHTML = '<div class="detail-panel" id="detail-panel"></div>';
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => {
      if (e.target === overlay) overlay.classList.add('hidden');
    });
  }
  return overlay;
}

async function openDetail(id) {
  try {
    const d = await fetchJSON('/api/media/' + id);
    let media = '';
    if (d.type === 'image') {
      media = `<img src="/raw/${d.id}">`;
    } else if (d.type === 'audio') {
      media = `<audio controls src="/raw/${d.id}"></audio>`;
    } else if (d.type === 'video') {
      media = `<video controls src="/raw/${d.id}"></video>`;
    }
    const tagsHtml = (d.tags || []).map(t =>
      `<span class="tag">${escapeHtml(t.key)}: ${escapeHtml(t.value)}</span>`
    ).join(' ');
    const html = `
      <button class="close" title="关闭">×</button>
      ${media}
      <h2>${escapeHtml(d.filename)}</h2>
      <div class="path">${escapeHtml(d.path)}</div>
      <div class="meta">${(d.size / 1024).toFixed(1)} KB · mtime ${new Date(d.mtime * 1000).toLocaleString()}</div>
      <h3>标签</h3>
      <div class="tags">${tagsHtml || '<em>无</em>'}</div>
    `;
    const overlay = ensureDetailOverlay();
    $('#detail-panel').innerHTML = html;
    overlay.querySelector('.close').addEventListener('click',
      () => overlay.classList.add('hidden'));
    overlay.classList.remove('hidden');
  } catch (e) {
    alert('详情加载失败: ' + e.message);
  }
}

// 事件
// 搜索框：只在按 Enter 时触发搜索，避免边打边发请求
// 中上：搜索框 Enter 触发
$('#q').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  console.log('[TRIGGER 中上 q] q="' + e.target.value.trim() + '"');
  clearGroupAC();
  updateRootBadge();
  search();
});
// 下拉框从开到关时读 select.value 触发搜索（覆盖重选同 value + 选新 value 两种场景）
let typeWasOpen = false;
$('#type').addEventListener('click', (e) => {
  if (e.target.tagName !== 'SELECT') return;
  const isOpen = $('#type').matches(':open');
  typeWasOpen = isOpen;
  if (isOpen) return; // 展开时不触发
  console.log('[TRIGGER type 收起了]', $('#type').value);
  aiLabelsActive = true;
  clearGroupAC();
  updateRootBadge();
  updateModeHighlights();
  search();
});
$('#reindex').addEventListener('click', async () => {
  const btn = $('#reindex');
  if (btn.disabled) return;
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = '⏳ 刷新中…';
  try {
    const r = await fetchJSON('/api/reindex', { method: 'POST' });
    tagKeysCache = null;  // 强制重新拉 tag key 列表
    const s = (r && r.stats) || {};
    btn.textContent = `✅ 新${s.indexed || 0}/跳${s.skipped || 0}`;
    await loadStats();
    await buildTagFilters();
    await search();
  } catch (e) {
    btn.textContent = '❌ 失败';
    console.error('reindex failed:', e);
  } finally {
    setTimeout(() => {
      btn.textContent = original;
      btn.disabled = false;
    }, 1500);
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const o = $('#detail');
    if (o && !o.classList.contains('hidden')) o.classList.add('hidden');
  }
});

// 懒加载观察器（IntersectionObserver）
const imageObserver = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    if (entry.isIntersecting) {
      const img = entry.target;
      const src = img.dataset.src;
      if (src) {
        img.src = src;
        img.removeAttribute('data-src');
      }
      imageObserver.unobserve(img);
    }
  }
}, {
  root: $('.middle'),
  rootMargin: '300px 0px',
  threshold: 0,
});

// 时间线
async function loadTimeline() {
  const data = await fetchJSON('/api/timeline').catch(() => null);
  const container = $('#timeline-ticks');
  const empty = $('#timeline-empty');
  container.innerHTML = '';
  if (!data || !data.points || data.points.length === 0) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const range = data.max_ts - data.min_ts;
  // 左右各留至少 3 天 padding，竖线不顶到边缘
  const padding = Math.max(86400 * 3, range * 0.05);
  const effectiveMin = data.min_ts - padding;
  const effectiveMax = data.max_ts + padding;
  const totalRange = effectiveMax - effectiveMin;
  timelineRange = { effectiveMin, effectiveMax, totalRange };
  const posFn = (totalRange > 0 && data.points.length > 1)
    ? (ts) => ((ts - effectiveMin) / totalRange) * 100
    : () => 50;

  const frag = document.createDocumentFragment();
  for (const p of data.points) {
    const tick = document.createElement('div');
    tick.className = 'timeline-tick';
    tick.style.left = `${posFn(p.ts)}%`;
    tick.title = `${p.date} · ${p.count} 个`;
    tick._point = p;
    tick.addEventListener('mouseenter', () => showTimelinePreview(p, tick));
    tick.addEventListener('mouseleave', hideTimelinePreview);
    tick.addEventListener('click', () => {
      // 点击竖线 → 新标签打开该时间段的代表文件
      window.open(`/raw/${p.media_id}`, '_blank');
    });
    frag.appendChild(tick);
  }
  container.appendChild(frag);
}

function showTimelinePreview(point, tickEl) {
  const preview = $('#timeline-preview');
  const tickRect = tickEl.getBoundingClientRect();
  // position: fixed → 用 viewport 坐标，不被 .bottom 的 overflow:hidden 裁掉
  const centerX = tickRect.left + tickRect.width / 2;
  const desiredTopY = Math.max(8, tickRect.top - 16); // 距顶至少 8px，避免贴近屏幕顶部
  const bottomVal = window.innerHeight - desiredTopY;
  preview.style.left = `${centerX}px`;
  preview.style.bottom = `${bottomVal}px`;

  const thumb = point.type === 'image'
    ? `<img src="/raw/${point.media_id}" alt="">`
    : `<div class="placeholder${point.type === 'video' ? ' video' : ''}">${point.type === 'audio' ? '♪' : '▶'}</div>`;
  preview.innerHTML = `
    ${thumb}
    <div class="date">${escapeHtml(point.date)}</div>
    <div class="count">${point.count} 个文件</div>
  `;
  preview.hidden = false;

  $$('.timeline-tick').forEach(t => {
    if (t !== tickEl) t.classList.add('faded');
  });
}

function hideTimelinePreview() {
  $('#timeline-preview').hidden = true;
  $$('.timeline-tick').forEach(t => t.classList.remove('faded'));
}

// 文件树
const fsCache = new Map();   // path → entries[]
const fsExpanded = new Set(); // 当前展开的 path
let currentPath = null;       // null = 无筛选；'' = 根目录本层；'foo/bar' = 子目录本层
let currentTimeRange = null;  // 时间轴选区 {min, max}；与 currentPath 不互斥
let timelineRange = null;     // {effectiveMin, effectiveMax, totalRange}；给选区算时间用
let aiLabelsActive = false;   // 用户碰过右边 type/tag select 即为激活；切其他模式时复位


async function fetchFs(path) {
  const params = new URLSearchParams();
  if (path) params.set('path', path);
  return await fetchJSON('/api/fs?' + params.toString());
}

function fsIcon(e) {
  if (e.type === 'dir') return '📁';
  switch (e.media_type) {
    case 'image': return '🖼️';
    case 'audio': return '🎵';
    case 'video': return '🎬';
    default:      return '📄';
  }
}

function fsRootName(rootPath) {
  // 取最后一段作为根名（处理 / 和 /Users/foo 这种）
  const parts = rootPath.split('/').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : rootPath;
}

function fsSetActivePath(path) {
  // 清除所有 active-path，标记匹配的 row
  $$('.fs-node.active-path').forEach(n => n.classList.remove('active-path'));
  if (!path) return;
  $$('.fs-node').forEach(n => {
    if (n.dataset.fsPath === path) n.classList.add('active-path');
  });
}

function fsMakeNode(entry, path, depth) {
  const wrap = document.createElement('div');

  const row = document.createElement('div');
  row.className = `fs-node ${entry.type}`;
  row.dataset.fsPath = path;

  const toggle = document.createElement('span');
  toggle.className = 'fs-toggle';
  toggle.textContent = entry.type === 'dir' ? '▶' : '';
  row.appendChild(toggle);

  const icon = document.createElement('span');
  icon.className = 'fs-icon';
  icon.textContent = fsIcon(entry);
  row.appendChild(icon);

  const name = document.createElement('span');
  name.className = 'fs-name';
  name.textContent = entry.name;
  name.title = entry.name;
  row.appendChild(name);

  if (entry.type === 'file' && entry.media_id) {
    const b = document.createElement('span');
    b.className = 'fs-badge';
    b.textContent = '索引';
    row.appendChild(b);
  } else if (entry.type === 'dir' && entry.has_media) {
    const b = document.createElement('span');
    b.className = 'fs-badge muted';
    b.textContent = '有媒体';
    row.appendChild(b);
  }

  // 右侧筛选箭头（仅文件夹），放在最右
  if (entry.type === 'dir') {
    const arrow = document.createElement('span');
    arrow.className = 'fs-filter-arrow';
    arrow.textContent = '→';
    arrow.title = '在中区筛选此文件夹本层的文件';
    arrow.addEventListener('click', (e) => {
      e.stopPropagation();
      console.log('[TRIGGER 中左 path] path="' + path + '"');
      clearAllFilters();
      currentPath = path;
      fsSetActivePath(path);
      updateRootBadge();
      search();
    });
    row.appendChild(arrow);
  }

  wrap.appendChild(row);

  if (entry.type === 'dir') {
    const childrenEl = document.createElement('div');
    childrenEl.className = 'fs-children';
    childrenEl.style.display = 'none';
    wrap.appendChild(childrenEl);

    row.addEventListener('click', async () => {
      const open = fsExpanded.has(path);
      if (open) {
        fsExpanded.delete(path);
        childrenEl.style.display = 'none';
        toggle.textContent = '▶';
      } else {
        fsExpanded.add(path);
        childrenEl.style.display = '';
        toggle.textContent = '▼';
        if (!fsCache.has(path)) {
          childrenEl.innerHTML = '<div class="fs-empty">加载中…</div>';
          try {
            const data = await fetchFs(path);
            fsCache.set(path, data.entries);
            renderFsChildren(data.entries, path, childrenEl, depth + 1);
          } catch (err) {
            childrenEl.innerHTML = `<div class="fs-empty">加载失败: ${escapeHtml(err.message)}</div>`;
          }
        }
      }
    });
  } else if (entry.type === 'file' && entry.media_id) {
    // 音/图/视频点击 → 新标签打开
    row.addEventListener('click', () => {
      window.open(`/raw/${entry.media_id}`, '_blank');
    });
  }

  return wrap;
}

function renderFsChildren(entries, parentPath, container, depth) {
  container.innerHTML = '';
  if (!entries || entries.length === 0) {
    container.innerHTML = '<div class="fs-empty">(空)</div>';
    return;
  }
  for (const e of entries) {
    const childPath = parentPath ? `${parentPath}/${e.name}` : e.name;
    container.appendChild(fsMakeNode(e, childPath, depth));
  }
}

async function loadFsTree() {
  const tree = $('#fs-tree');
  tree.innerHTML = '<div class="fs-empty">加载中…</div>';
  try {
    const data = await fetchFs('');
    fsCache.set('', data.entries);
    tree.innerHTML = '';

    // 根目录名头（点击 = 清除路径筛选；右箭头 = 筛选根目录本层）
    const rootName = fsRootName(data.root);
    const rootHeader = document.createElement('div');
    rootHeader.className = 'fs-root';
    rootHeader.innerHTML = `
      <span class="fs-root-icon">📂</span>
      <span class="fs-root-name" title="${escapeHtml(data.root)}">${escapeHtml(rootName)}</span>
      <span class="fs-root-badge"></span>
      <span class="fs-filter-arrow" title="显示根目录本层的媒体文件">→</span>
    `;
    rootHeader.addEventListener('click', () => {
      currentPath = '';
      fsSetActivePath('');
      updateRootBadge();
      search();
    });
    // 根目录右箭头独立点击：触发 path='' = 根目录本层筛选
    rootHeader.querySelector('.fs-filter-arrow').addEventListener('click', (e) => {
      e.stopPropagation();
      console.log('[TRIGGER 中左 root arrow] path="" (根目录本层)');
      clearAllFilters();
      currentPath = '';
      fsSetActivePath('');
      updateRootBadge();
      search();
    });
    tree.appendChild(rootHeader);

    // 根级条目容器（不缩进）
    const rootEntries = document.createElement('div');
    rootEntries.className = 'fs-root-entries';
    tree.appendChild(rootEntries);
    renderFsChildren(data.entries, '', rootEntries, 0);

    // 刷新根 header 上的筛选徽章
    updateRootBadge();
  } catch (err) {
    tree.innerHTML = `<div class="fs-empty">加载失败: ${escapeHtml(err.message)}</div>`;
  }
}

// 三种筛选维度互斥：设任何一种都清空另外两种
// 只清 Group A(path) + Group C(time)，保留 Group B(q/type/tag) 全部值
function clearGroupAC() {
  // 仅清 Group A(path) + Group C(time)；不重置 aiLabelsActive
  // （aiLabelsActive 由 type/tag change handler 自己控制，切其他模式才清）
  currentPath = null;
  currentTimeRange = null;
  fsSetActivePath('');
  hideTimelineSelection();
}

// 全清：q/type/tag/path/time 一起清（用于切到 Group A 或 Group C）
function clearAllFilters() {
  $('#q').value = '';
  $('#type').value = '';
  $$('#tag-filters select').forEach(sel => sel.value = '');
  aiLabelsActive = false;
  clearGroupAC();
}

function updateRootBadge() {
  const badge = document.querySelector('.fs-root-badge');
  if (!badge) return;
  const parts = [];
  if (currentPath !== null && currentPath !== '') parts.push(`path: ${currentPath || '根目录'}`);
  // time 范围不在这里显示，改在时间轴（.timeline-label）
  if (parts.length === 0) {
    badge.textContent = '全部';
    badge.className = 'fs-root-badge';
  } else {
    badge.textContent = parts.join(' + ');
    badge.className = 'fs-root-badge active';
  }
}

// 中上：状态入口（待处理/收藏/归档/回收站）
// =========================================================
// TODO: 状态逻辑需要：
//   1. DB media 表加 state TEXT DEFAULT 'inbox' 列
//   2. 后端新增 GET  /api/state-counts        → 各状态的文件数
//   3. 后端新增 POST /api/media/<id>/state     → 切换单文件状态
//   4. 右键菜单（或卡片按钮）调用 3 切换状态
//   5. /api/search 接受 state 参数 → 中中可按状态筛选
//   6. 中上点击 tile → 触发中中 search('state=<id>')
// =========================================================
const STATES_LEFT = [
  { id: 'inbox',    name: '待处理', icon: '⚡', color: '#3a76f0' },
  { id: 'starred',  name: '收藏',   icon: '⭐', color: '#f5b800' },
];
const STATES_RIGHT = [
  { id: 'archived', name: '归档',   icon: '📦', color: '#888'   },
  { id: 'trash',    name: '回收站', icon: '🗑', color: '#d33'   },
];

// TODO: 从后端拉真实计数（先写死 0）
const STATE_COUNTS = {
  inbox: 0, starred: 0, archived: 0, trash: 0
};

function loadStateTiles() {
  const render = (states) => {
    const frag = document.createDocumentFragment();
    for (const state of states) {
      const tile = document.createElement('div');
      tile.className = `state-tile ${state.id}`;
      tile.dataset.state = state.id;
      tile.title = `${state.name}（点击：TODO 联动到中中筛选）`;
      tile.innerHTML = `
        <div class="state-icon">${state.icon}</div>
        <div class="state-name">${state.name}</div>
        <div class="state-count">${STATE_COUNTS[state.id]}</div>
      `;
      tile.addEventListener('click', () => {
        console.log(`[TODO] 点击 state=${state.id} → 联动 search('state=${state.id}')`);
      });
      frag.appendChild(tile);
    }
    return frag;
  };
  const left = $('#state-tiles-left');
  const right = $('#state-tiles-right');
  if (left)  { left.innerHTML = '';  left.appendChild(render(STATES_LEFT)); }
  if (right) { right.innerHTML = ''; right.appendChild(render(STATES_RIGHT)); }
}

// 模式高亮：根据当前激活的筛选给对应 cell 换底色
function updateModeHighlights() {
  const q = $('#q').value.trim();
  const typeVal = $('#type').value;
  const hasTag = !!$$('#tag-filters select').find(s => s.value);
  const tm = $('.cell-tm');
  const ml = $('.cell-ml');
  const mr = $('.cell-mr');
  const bm = $('.cell-bm');
  [tm, ml, mr, bm].forEach(c => c && c.classList.remove('mode-active'));
  if (q) tm.classList.add('mode-active');
  if (typeVal || hasTag || aiLabelsActive) mr.classList.add('mode-active');
  if (currentPath !== null) ml.classList.add('mode-active');
  if (currentTimeRange !== null) bm.classList.add('mode-active');
}

// ===== 时间轴 box selection =====

function hideTimelineSelection() {
  const sel = $('#timeline-selection');
  if (sel) sel.remove();
  const label = $('#timeline-label');
  if (label) label.remove();
}

function showTimelineSelection() {
  hideTimelineSelection();
  if (!currentTimeRange || !timelineRange || timelineRange.totalRange <= 0) return;
  const startPct = (currentTimeRange.min - timelineRange.effectiveMin) / timelineRange.totalRange * 100;
  const endPct = (currentTimeRange.max - timelineRange.effectiveMin) / timelineRange.totalRange * 100;
  const fmt = (ts) => {
    const d = new Date(ts * 1000);
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  };
  // 选区矩形
  const sel = document.createElement('div');
  sel.id = 'timeline-selection';
  sel.className = 'timeline-selection persistent';
  sel.style.left = `${Math.max(0, startPct)}%`;
  sel.style.width = `${Math.max(0, endPct - startPct)}%`;
  sel.title = '点击清除时间轴选区';
  sel.addEventListener('click', (e) => {
    e.stopPropagation();
    currentTimeRange = null;
    hideTimelineSelection();
    updateRootBadge();
    search();
  });
  $('#timeline-ticks').appendChild(sel);
  // 时间段标签（显示在时间轴顶部）
  const label = document.createElement('div');
  label.id = 'timeline-label';
  label.className = 'timeline-label';
  label.textContent = `${fmt(currentTimeRange.min)} ~ ${fmt(currentTimeRange.max)}`;
  $('#timeline-ticks').appendChild(label);
}

function setupTimelineBoxSelection() {
  const ticksEl = $('#timeline-ticks');
  let dragStartX = 0;
  let dragEl = null;

  ticksEl.addEventListener('pointerdown', (e) => {
    // 点在 tick 上不处理（tick 自己有 handler）
    if (e.target.classList.contains('timeline-tick')) return;
    // 点在已有 persistent selection 上 → 清除
    if (e.target.classList.contains('timeline-selection')) {
      e.stopPropagation();
      currentTimeRange = null;
      hideTimelineSelection();
      updateRootBadge();
      search();
      return;
    }
    e.preventDefault();
    dragStartX = e.clientX;
    const ticksRect = ticksEl.getBoundingClientRect();
    dragEl = document.createElement('div');
    dragEl.className = 'timeline-selection dragging';
    dragEl.style.left = `${e.clientX - ticksRect.left}px`;
    dragEl.style.width = '0';
    ticksEl.appendChild(dragEl);

    const onMove = (ev) => {
      if (!dragEl) return;
      const rect = ticksEl.getBoundingClientRect();
      const startX = Math.min(dragStartX, ev.clientX) - rect.left;
      const endX = Math.max(dragStartX, ev.clientX) - rect.left;
      dragEl.style.left = `${startX}px`;
      dragEl.style.width = `${endX - startX}px`;
    };
    const onUp = (ev) => {
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
      if (!dragEl) return;
      const rect = ticksEl.getBoundingClientRect();
      const x1 = Math.min(dragStartX, ev.clientX) - rect.left;
      const x2 = Math.max(dragStartX, ev.clientX) - rect.left;
      const w = x2 - x1;
      dragEl.remove();
      dragEl = null;
      if (w < 5) return; // 不是拖动
      if (!timelineRange || timelineRange.totalRange <= 0) return;
      const startPct = Math.max(0, x1 / rect.width * 100);
      const endPct = Math.min(100, x2 / rect.width * 100);
      const tMin = Math.round(timelineRange.effectiveMin + (startPct / 100) * timelineRange.totalRange);
      const tMax = Math.round(timelineRange.effectiveMin + (endPct / 100) * timelineRange.totalRange);
      console.log('[TRIGGER 中下 time] tmin=' + tMin + ' tmax=' + tMax);
      // 三种维度互斥：设 time 清空 path + q/type/tag
      clearAllFilters();
      currentTimeRange = { min: tMin, max: tMax };
      showTimelineSelection();
      updateRootBadge();
      updateModeHighlights();
      search();
    };
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
  });
}

// 启动
(async () => {
  await loadStats();
  await buildTagFilters();
  await search();
  await loadTimeline();
  await loadFsTree();
  loadStateTiles();
  setupTimelineBoxSelection();
})();

// ===== 九宫格分割线拖动 =====
(function setupSplitters() {
  const grid = document.querySelector('.app-grid');
  if (!grid) return;

  const PROP = { v1: '--col1', v2: '--col3', h1: '--row1', h2: '--row3' };
  const OTHER = { v1: '--col3', v2: '--col1', h1: '--row3', h2: '--row1' };
  const AXIS = { v1: 'x', v2: 'x', h1: 'y', h2: 'y' };

  const root = document.documentElement;
  // 自定义属性 getPropertyValue 返回字面量（"10vmin" / "108px"），需解析单位转 px
  const getVal = (name) => {
    const raw = getComputedStyle(root).getPropertyValue(name).trim();
    let num = parseFloat(raw);
    if (!isFinite(num)) return 0;
    if (raw.endsWith('vmin')) num *= Math.min(window.innerWidth, window.innerHeight) / 100;
    else if (raw.endsWith('vmax')) num *= Math.max(window.innerWidth, window.innerHeight) / 100;
    else if (raw.endsWith('vh')) num *= window.innerHeight / 100;
    else if (raw.endsWith('vw')) num *= window.innerWidth / 100;
    return num;
  };
  const setVal = (name, v) => root.style.setProperty(name, `${v}px`);

  document.querySelectorAll('.splitter').forEach((sp) => {
    const split = sp.dataset.split;
    const prop = PROP[split];
    const otherProp = OTHER[split];
    const axis = AXIS[split];

    let active = false;
    let startValue = 0;
    let startPos = 0;

    sp.addEventListener('pointerdown', (e) => {
      active = true;
      startValue = getVal(prop);
      startPos = axis === 'x' ? e.clientX : e.clientY;
      sp.classList.add('dragging');
      try { sp.setPointerCapture(e.pointerId); } catch (_) {}
      document.body.style.userSelect = 'none';
      document.body.style.cursor = axis === 'x' ? 'ew-resize' : 'ns-resize';
      e.preventDefault();
    });

    sp.addEventListener('pointermove', (e) => {
      if (!active) return;
      const totalSize = axis === 'x' ? grid.clientWidth : grid.clientHeight;
      const otherValue = getVal(otherProp);
      const minSize = 30;
      const maxSize = Math.max(minSize, totalSize - otherValue - minSize);

      const currentPos = axis === 'x' ? e.clientX : e.clientY;
      const delta = currentPos - startPos;
      // v1/h1 用 left/top 定位（delta 方向同向）
      // v2/h2 用 right/bottom 定位（delta 方向反向）
      const sign = (split === 'v1' || split === 'h1') ? 1 : -1;
      let newValue = startValue + sign * delta;
      newValue = Math.max(minSize, Math.min(maxSize, newValue));
      setVal(prop, newValue);
    });

    const endDrag = (e) => {
      if (!active) return;
      active = false;
      sp.classList.remove('dragging');
      try { sp.releasePointerCapture(e.pointerId); } catch (_) {}
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    };

    sp.addEventListener('pointerup', endDrag);
    sp.addEventListener('pointercancel', endDrag);
  });
})();