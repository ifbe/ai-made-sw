(function (global) {
  'use strict';

  function $(id) {
    const el = document.getElementById(id);
    if (!el) console.error('[KiPreview] 找不到元素 #' + id + '，请检查 index.html');
    return el;
  }

  const closeBtn = $('close-btn');
  const urlInput = $('url-input');
  const urlBtn = $('url-btn');
  const mainEl = $('main');
  const hint = $('hint');
  const content = $('content');
  const canvas = $('cv');
  const layersEl = $('layers');
  const propertiesEl = $('properties');
  const coordTip = $('coord-tip');
  // 3D 相关元素是可选的：缺失时只是没有 3D，不影响 2D 主流程
  const viewBtn = $('view-btn');
  const glCanvas = $('gl');
  const glTip = $('gl-tip');
  // 底部模型库工具条
  const libInput = $('lib-input');
  const libBtn = $('lib-btn');
  const libClear = $('lib-clear');
  const libBar = $('libbar');

  if (!closeBtn || !urlInput || !urlBtn || !mainEl || !hint || !content ||
      !canvas || !layersEl || !propertiesEl) {
    console.error('[KiPreview] DOM 元素缺失，app.js 无法初始化。缺失清单：');
    if (!closeBtn) console.error('  - #close-btn');
    if (!urlInput) console.error('  - #url-input');
    if (!urlBtn) console.error('  - #url-btn');
    if (!mainEl) console.error('  - #main');
    if (!hint) console.error('  - #hint');
    if (!content) console.error('  - #content');
    if (!canvas) console.error('  - #cv');
    if (!layersEl) console.error('  - #layers');
    if (!propertiesEl) console.error('  - #properties');
    return;
  }

  const ctx = canvas.getContext('2d');

  const Sexpr = global.KiPreview && global.KiPreview.Sexpr;
  const Viewport = global.KiPreview && global.KiPreview.Viewport;
  const ParserKicadPcb = global.KiPreview && global.KiPreview.ParserKicadPcb;
  const ParserKicadSch = global.KiPreview && global.KiPreview.ParserKicadSch;
  const PcbRenderer = global.KiPreview && global.KiPreview.PcbRenderer;
  const SchRenderer = global.KiPreview && global.KiPreview.SchRenderer;
  const Layers = global.KiPreview && global.KiPreview.Layers;
  const HitTest = global.KiPreview && global.KiPreview.HitTest;
  const PropertiesPanel = global.KiPreview && global.KiPreview.PropertiesPanel;
  const Camera3D = global.KiPreview && global.KiPreview.Camera3D;
  const Mesh3D = global.KiPreview && global.KiPreview.Mesh3D;
  const Models3D = global.KiPreview && global.KiPreview.Models3D;
  const Pick3D = global.KiPreview && global.KiPreview.Pick3D;
  const GlRenderer = global.KiPreview && global.KiPreview.GlRenderer;
  // 独立 3D 模型格式的解析器（不经过 PCB 元素模型）
  const ParserStep = global.KiPreview && global.KiPreview.ParserStep;
  const ParserStl = global.KiPreview && global.KiPreview.ParserStl;
  const Parser3mf = global.KiPreview && global.KiPreview.Parser3mf;
  const ParserWrl = global.KiPreview && global.KiPreview.ParserWrl;

  if (!Sexpr || !Viewport || !ParserKicadPcb || !ParserKicadSch ||
      !PcbRenderer || !SchRenderer || !Layers ||
      !HitTest || !PropertiesPanel) {
    console.error('[KiPreview] 某个模块未加载，请检查 index.html 里的 <script> 顺序。');
    return;
  }

  const { parse } = Sexpr;
  const { create, fit, zoomAt, screenToWorld } = Viewport;

  const view = create();
  let currentBounds = null;
  let lastItems = null;
  let lastType = null;
  let currentVisibility = null;
  let selection = null;
  // 独立 3D 模型（STEP / STL / 3MF）的网格。与 PCB 走不同的场景来源：
  // 它们没有 pcbnew 元素模型，也没有 2D 视图，加载后直接进 3D。
  let modelMesh = null;

  // PCB 上各元件已解析到的模型几何：Map<items.models 下标, 网格>
  let boardModelMeshes = null;

  // ---------- 模型库 ----------
  // 拖进来的目录会成为"库路径"，只在解析 .kicad_pcb 里 (model ...) 引用时使用；
  // 直接拖单个 3D 文件进来时不查库。索引与解析逻辑在 render3d-models.js 里，
  // 那部分是纯逻辑、可单测。
  const modLib = Models3D ? Models3D.createLibrary() : null;

  function updateLibBar() {
    if (!libInput) return;
    if (!modLib || !modLib.roots.length) {
      libInput.value = '';
      libInput.placeholder = '把 3dmodels 目录或项目目录拖进来，作为元件模型库（可拖多个）';
      return;
    }
    libInput.value = modLib.roots.map(r => r.name + '（' + r.count + ' 个文件）').join('  +  ');
  }

  // 递归遍历拖入的目录项。readEntries 每次最多返回 100 条，必须反复读到空。
  function collectEntries(entry, prefix, out) {
    return new Promise(resolve => {
      if (!entry) { resolve(); return; }
      if (entry.isFile) {
        entry.file(f => { out.push({ path: prefix + entry.name, file: f }); resolve(); },
                   () => resolve());
        return;
      }
      const reader = entry.createReader();
      const all = [];
      const readBatch = () => {
        reader.readEntries(batch => {
          if (!batch.length) {
            Promise.all(all.map(en => collectEntries(en, prefix + entry.name + '/', out)))
              .then(resolve);
            return;
          }
          for (const en of batch) all.push(en);
          readBatch();
        }, () => resolve());
      };
      readBatch();
    });
  }

  function addLibraryRoot(name, files) {
    if (!modLib) return;
    const n = modLib.addRoot(name, files);
    if (!n) return;
    updateLibBar();
    console.info('[KiPreview] 已登记模型库「' + name + '」：' + n +
      ' 个文件，累计 ' + modLib.size() + ' 个');
  }

  function resolveModelRef(ref) {
    return modLib ? modLib.resolve(ref) : null;
  }

  // 已解析过的模型文件缓存（同一模型常被引用几十次）
  const modelFileCache = new Map();

  function parserForName(name) {
    const n = name.toLowerCase();
    if (n.endsWith('.step') || n.endsWith('.stp')) return ParserStep;
    if (n.endsWith('.wrl')) return ParserWrl;
    if (n.endsWith('.stl')) return ParserStl;
    if (n.endsWith('.3mf')) return Parser3mf;
    return null;
  }

  function loadModelMesh(file, key) {
    if (modelFileCache.has(key)) return modelFileCache.get(key);
    const p = file.arrayBuffer().then(buf => {
      const parser = parserForName(key);
      if (!parser || parser.implemented === false) return null;
      return Promise.resolve(parser.parse(buf));
    }).catch(e => {
      console.warn('[KiPreview] 模型解析失败 ' + key + '：' + e.message);
      return null;
    });
    modelFileCache.set(key, p);
    return p;
  }

  // 为一块 PCB 解析并加载全部元件模型
  function loadBoardModels(items) {
    return new Promise(resolve => {
      const out = new Map();
      if (!items.models || !items.models.length || !modLib || !modLib.size()) {
        resolve({ meshes: out, total: items.models ? items.models.length : 0, missing: [] });
        return;
      }
      const missing = [];
      const jobs = items.models.map((m, i) => {
        const r = resolveModelRef(m.path);
        if (!r) { if (missing.length < 12) missing.push(m.path); return null; }
        return loadModelMesh(r.file, r.path).then(mesh => {
          if (mesh && mesh.count) out.set(i, mesh);
          else if (missing.length < 12) missing.push(m.path);
        });
      }).filter(Boolean);
      Promise.all(jobs).then(() => resolve({
        meshes: out,
        total: items.models.length,
        missing
      }));
    });
  }

  // 视图模式：'2d' 走原有的 Canvas 2D 渲染，'3d' 走 WebGL。
  // 两套渲染互不干扰，2D 路径完全没有改动。
  let viewMode = '2d';
  let cam3d = null;
  let glReady = false;
  let glFailed = false;
  let sceneRevision = 0;      // 每次加载新板子自增，用于判定 3D 网格是否要重建
  const has3D = !!(Camera3D && Mesh3D && Pick3D && GlRenderer && viewBtn && glCanvas);

  // ---------- 画布尺寸 ----------
  function resizeCanvas() {
    const rect = content.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.round(rect.width * dpr));
    canvas.height = Math.max(1, Math.round(rect.height * dpr));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  // ---------- 包围盒 ----------
  function collectPoints(items, type) {
    const pts = [];
    if (type === 'pcb') {
      items.edges.forEach(e => { pts.push({x:e.x1,y:e.y1}, {x:e.x2,y:e.y2}); });
      (items.arcs || []).forEach(a => {
        pts.push({x:a.x1,y:a.y1}, {x:a.x2,y:a.y2});
        a.points.forEach(p => pts.push({x:p[0], y:p[1]}));
      });
      items.circles.forEach(c => { pts.push({x:c.x-c.r,y:c.y-c.r}, {x:c.x+c.r,y:c.y+c.r}); });
      items.segments.forEach(s => { pts.push({x:s.x1,y:s.y1}, {x:s.x2,y:s.y2}); });
      items.pads.forEach(p => { pts.push({x:p.x,y:p.y}); });
      items.vias.forEach(v => { pts.push({x:v.x,y:v.y}); });
    } else {
      items.wires.forEach(w => { pts.push({x:w.x1,y:w.y1}, {x:w.x2,y:w.y2}); });
      items.junctions.forEach(j => pts.push({x:j.x,y:j.y}));
      items.labels.forEach(l => pts.push({x:l.x,y:l.y}));
      items.texts.forEach(t => pts.push({x:t.x,y:t.y}));
      items.symbols.forEach(s => {
        pts.push({x: s.x - 10, y: s.y - 10}, {x: s.x + 10, y: s.y + 10});
      });
    }
    return pts;
  }

  function computeBounds(points) {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const p of points) {
      if (p.x < minX) minX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.x > maxX) maxX = p.x;
      if (p.y > maxY) maxY = p.y;
    }
    if (!isFinite(minX)) return { minX: 0, minY: 0, maxX: 1, maxY: 1 };
    return { minX, minY, maxX, maxY };
  }

  // ---------- 渲染 ----------
  function redraw() {
    if (!lastItems || lastType === 'model') return;
    const rect = content.getBoundingClientRect();
    const w = rect.width, h = rect.height;
    try {
      if (lastType === 'pcb') {
        PcbRenderer.render(ctx, lastItems, view, currentBounds, currentVisibility, w, h, selection);
      } else if (lastType === 'sch') {
        SchRenderer.render(ctx, lastItems, view, currentBounds, currentVisibility, w, h, selection);
      }
    } catch (e) {
      console.error('[KiPreview] 渲染失败：', e);
    }
  }

  // ---------- 3D 视图 ----------

  // 3D 只对 PCB 有意义：原理图没有立体概念
  function is3DAvailable() {
    if (!has3D) return false;
    if (lastType === 'model') return !!modelMesh;   // 独立模型只有 3D
    return lastType === 'pcb' && !!lastItems;
  }

  function updateViewBtn() {
    if (!viewBtn) return;
    // 独立模型没有可切换的 2D 视图，按钮直接不出现
    if (!is3DAvailable() || lastType === 'model') {
      viewBtn.style.display = 'none';
      return;
    }
    viewBtn.style.display = '';
    viewBtn.disabled = viewMode === '3d' && !glReady && glFailed;
    viewBtn.classList.toggle('on', viewMode === '3d');
    viewBtn.textContent = glFailed ? '3D 不可用'
      : (viewMode === '3d' ? '2D 视图' : '3D 视图');
  }

  function render3D() {
    if (viewMode !== '3d' || !is3DAvailable()) return;
    const rect = content.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) return;

    if (!glReady) {
      glReady = GlRenderer.init(glCanvas);
      if (!glReady) {
        glFailed = true;
        updateViewBtn();
        return;
      }
    }
    if (lastType === 'model') {
      // 外部 parser 已经产出网格，直接投喂
      GlRenderer.setMesh(modelMesh, sceneRevision);
    } else {
      GlRenderer.updateScene(lastItems, currentVisibility, currentBounds, sceneRevision,
                             boardModelMeshes);
    }
    // 网格可能刚重建（元素序号变了），按引用重新解析高亮
    GlRenderer.setSelection(selection);
    if (!GlRenderer.render(cam3d, rect.width, rect.height)) {
      console.error('[KiPreview] 3D 渲染失败。');
    }
  }

  // 图层面板等状态变化后统一入口：按当前模式重新出图
  function refresh() {
    if (viewMode === '3d') render3D();
    else redraw();
  }

  function setViewMode(mode) {
    // 独立模型没有 2D 视图，恒为 3D
    if (lastType === 'model') mode = '3d';

    const next = (mode === '3d' && is3DAvailable()) ? '3d' : '2d';
    if (next === viewMode) { updateViewBtn(); return; }
    viewMode = next;

    if (viewMode === '3d') {
      // 切到 WebGL：隐藏 2D canvas，清掉 2D 的悬浮信息。
      // 详情面板不清空——它在 3D 下同样可用（拾取到元素就会显示）。
      canvas.style.display = 'none';
      canvas.classList.remove('dragging');
      coordTip.style.display = 'none';
      glCanvas.style.display = 'block';
      if (glTip) glTip.classList.add('visible');
      if (!cam3d) cam3d = Camera3D.create();
      // 模型的取景在加载时已按网格包围盒设好，切换模式时不动它
      if (lastType !== 'model') Camera3D.fit(cam3d, currentBounds, Mesh3D.T_DEFAULT);
      render3D();
    } else {
      glCanvas.style.display = 'none';
      glCanvas.classList.remove('dragging');
      if (glTip) glTip.classList.remove('visible');
      canvas.style.display = 'block';
      redraw();
    }
    syncProperties();
    updateViewBtn();
  }

  // ---------- 显示状态 ----------
  function showContent() {
    hint.style.display = 'none';
    content.classList.add('active');
    canvas.style.display = 'block';
  }

  function showMessage(msg) {
    content.classList.remove('active');
    canvas.style.display = 'none';
    layersEl.classList.remove('visible');
    layersEl.innerHTML = '';
    PropertiesPanel.hide(propertiesEl);
    hint.style.display = 'block';
    hint.innerHTML = '<div class="ico">⚠️</div><h2>加载失败</h2><p>' + msg + '</p>';
  }

  function resetHint() {
    hint.innerHTML = '<div class="ico">📁</div><h2>拖拽文件到这里</h2>' +
      '<p>KiCad：.kicad_pcb / .kicad_sch</p>' +
      '<p>3D 模型：.step / .stp / .wrl / .stl / .3mf</p>' +
      '<small>也可以把 3dmodels 或项目目录拖进来当模型库，' +
      '之后打开 PCB 就会自动摆放元件模型</small>';
  }

  // ---------- 关闭 / 重置 ----------
  function closeViewer() {
    // 独立模型（STEP/STL/3MF）没有 2D 视图，清掉网格即可
    modelMesh = null;
    boardModelMeshes = null;

    // 3D 状态复位：回到 2D 模式，等下一次加载再决定按钮是否出现
    viewMode = '2d';
    if (glCanvas) {
      glCanvas.style.display = 'none';
      glCanvas.classList.remove('dragging');
    }
    if (glTip) glTip.classList.remove('visible');

    lastItems = null;
    lastType = null;
    currentBounds = null;
    currentVisibility = null;
    selection = null;
    coordTip.style.display = 'none';

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    content.classList.remove('active');
    canvas.style.display = 'none';

    layersEl.classList.remove('visible');
    layersEl.innerHTML = '';

    PropertiesPanel.hide(propertiesEl);

    urlInput.value = '';
    delete urlInput.dataset.source;

    updateViewBtn();
    resetHint();
    hint.style.display = 'block';
  }

  // ---------- 文件类型 ----------
  function getFileKind(name) {
    const n = name.toLowerCase();
    if (n.endsWith('.kicad_pcb')) return 'pcb';
    if (n.endsWith('.kicad_sch')) return 'sch';
    if (n.endsWith('.step') || n.endsWith('.stp')) return 'step';
    if (n.endsWith('.wrl')) return 'wrl';
    if (n.endsWith('.stl')) return 'stl';
    if (n.endsWith('.3mf')) return '3mf';
    return null;
  }

  // 独立 3D 模型格式（非 PCB）走这一条：解析成网格后直接进 3D 视图
  const MODEL_PARSERS = {
    step: () => ParserStep,
    wrl: () => ParserWrl,
    stl: () => ParserStl,
    '3mf': () => Parser3mf
  };

  function loadModelFile(file, kind) {
    const parser = MODEL_PARSERS[kind] && MODEL_PARSERS[kind]();
    if (!parser) {
      showMessage('缺少 ' + kind.toUpperCase() + ' 解析器。');
      return;
    }
    if (parser.implemented === false) {
      showMessage(kind.toUpperCase() + ' 解析尚未实现。' +
        '<br><small>解析器接口已就位，等待补实现</small>');
      return;
    }

    file.arrayBuffer().then(buf => {
      // 统一入口：parser.parse(source) → 网格（3MF 之类需要解压的可以是 Promise）
      return Promise.resolve(parser.parse(buf));
    }).then(mesh => {
      if (!mesh || !mesh.count) throw new Error('解析结果为空');
      showModel(mesh, file.name);
    }).catch(e => {
      console.error('[KiPreview] ' + kind + ' 解析失败：', e);
      showMessage('解析失败：' + e.message);
    });
  }

  // 展示一个独立 3D 模型：没有 2D 视图，直接进 3D
  function showModel(mesh, name) {
    closeViewer();

    modelMesh = mesh;
    lastType = 'model';
    sceneRevision++;
    cam3d = null;

    // 相机按网格自身的世界坐标包围盒取景
    if (mesh.bounds && Camera3D) {
      cam3d = Camera3D.create();
      Camera3D.fit3D(cam3d, mesh.bounds.min, mesh.bounds.max);
    }

    showContent();
    layersEl.classList.remove('visible');   // 模型没有图层概念
    propertiesEl && PropertiesPanel.hide(propertiesEl);

    urlInput.value = 'file://' + name;
    urlInput.dataset.source = 'file';

    setViewMode('3d');
    // 各格式的 stats 字段不同（STEP 有面数与平面覆盖率，STL 有 format/着色面数），
    // 所以只拼实际存在的项，避免打印 undefined
    const st = mesh.stats;
    if (st) {
      const bits = [];
      if (st.format) bits.push(st.format);
      bits.push('三角 ' + (mesh.count / 3));
      if (st.faces) bits.push('面 ' + st.faces + '（平面 ' + st.planar + '）');
      if (st.polygons) bits.push('多边形 ' + st.polygons);
      if (st.colored) bits.push('着色面 ' + st.colored);
      if (st.skipped && Object.keys(st.skipped).length) {
        bits.push('跳过 ' + JSON.stringify(st.skipped));
      }
      console.info('[KiPreview] ' + name + '：' + bits.join('，'));
    }
    updateViewBtn();
  }

  // ---------- 选中与详情面板 ----------
  function getSelectedElement() {
    if (!selection || !lastItems) return null;
    const { kind, index } = selection;
    if (kind === 'segment') return lastItems.segments[index];
    if (kind === 'pad') return lastItems.pads[index];
    if (kind === 'via') return lastItems.vias[index];
    if (kind === 'edge') return lastItems.edges[index];
    if (kind === 'circle') return lastItems.circles[index];
    if (kind === 'arc') return lastItems.arcs[index];
    return null;
  }

  // 详情面板与渲染后端无关：2D / 3D 共用同一套，只要有 selection 就能显示
  function syncProperties() {
    const element = getSelectedElement();
    const parser = lastType === 'pcb' ? ParserKicadPcb : ParserKicadSch;
    if (!element || !parser || !parser.describe) {
      PropertiesPanel.hide(propertiesEl);
      return;
    }
    PropertiesPanel.show(propertiesEl, parser.describe(element), () => {
      setSelection(null);
    });
  }

  // 选中状态的唯一入口：同时更新 3D 高亮、重绘、详情面板
  function setSelection(sel) {
    selection = sel || null;
    if (viewMode === '3d') {
      if (glReady) GlRenderer.setSelection(selection);
      render3D();
    } else {
      redraw();
    }
    syncProperties();
  }

  // ---------- 加载：本地文件 ----------
  function loadFromFile(file) {
    const name = file.name;
    const kind = getFileKind(name);
    if (!kind) {
      showMessage('不支持的文件格式：' + name);
      return;
    }

    if (kind === 'step' || kind === 'wrl' || kind === 'stl' || kind === '3mf') {
      loadModelFile(file, kind);
      return;
    }

    file.text().then(text => {
      const ast = parse(text);
      let items, type;
      if (kind === 'pcb') {
        items = ParserKicadPcb.parse(ast);
        type = 'pcb';
      } else {
        items = ParserKicadSch.parse(ast);
        type = 'sch';
      }
      // 只有 PCB 会去查模型库；原理图没有元件模型
      const pending = (type === 'pcb') ? loadBoardModels(items) : Promise.resolve(null);
      return pending.then(res => ({ items, type, res }));
    }).then(({ items, type, res }) => {
      closeViewer();

      boardModelMeshes = res ? res.meshes : null;
      lastItems = items;
      lastType = type;
      currentBounds = computeBounds(collectPoints(items, type));
      currentVisibility = Layers.createVisibility(type);
      Layers.buildPanel(layersEl, type, currentVisibility, refresh);
      sceneRevision++;

      if (res && res.total) {
        console.info('[KiPreview] 元件模型命中 ' + res.meshes.size + ' / ' + res.total +
          (res.missing.length ? '，未命中示例：' + res.missing.slice(0, 3).join(' | ') : ''));
      }

      urlInput.value = 'file://' + name;
      urlInput.dataset.source = 'file';

      showContent();
      resizeCanvas();
      const rect = content.getBoundingClientRect();
      fit(view, currentBounds, rect.width, rect.height, 30);
      redraw();
      updateViewBtn();
    }).catch(e => {
      console.error('[KiPreview] 解析失败：', e);
      showMessage('解析失败：' + e.message);
    });
  }

  // ---------- 加载：网络 URL ----------
  function loadFromURL(url) {
    const path = url.split('?')[0].split('#')[0];
    const name = path.substring(path.lastIndexOf('/') + 1);
    const kind = getFileKind(name);
    const isModel = kind === 'step' || kind === 'wrl' || kind === 'stl' || kind === '3mf';

    // 先判类型再决定读取方式：3D 模型要 ArrayBuffer，别把二进制当文本读
    fetch(url).then(resp => {
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return isModel ? resp.arrayBuffer() : resp.text();
    }).then(data => {
      if (!kind) throw new Error('无法从 URL 判断文件类型：' + name);

      if (isModel) {
        const parser = MODEL_PARSERS[kind] && MODEL_PARSERS[kind]();
        if (!parser) throw new Error('缺少 ' + kind.toUpperCase() + ' 解析器');
        if (parser.implemented === false) {
          throw new Error(kind.toUpperCase() + ' 解析尚未实现');
        }
        return Promise.resolve(parser.parse(data)).then(mesh => {
          if (!mesh || !mesh.count) throw new Error('解析结果为空');
          showModel(mesh, name);
          urlInput.value = url;
          delete urlInput.dataset.source;
          updateViewBtn();
        });
      }

      const ast = parse(data);
      let items, type;
      if (kind === 'pcb') {
        items = ParserKicadPcb.parse(ast);
        type = 'pcb';
      } else {
        items = ParserKicadSch.parse(ast);
        type = 'sch';
      }

      closeViewer();

      lastItems = items;
      lastType = type;
      currentBounds = computeBounds(collectPoints(items, type));
      currentVisibility = Layers.createVisibility(type);
      Layers.buildPanel(layersEl, type, currentVisibility, refresh);
      sceneRevision++;

      urlInput.value = url;
      delete urlInput.dataset.source;

      showContent();
      resizeCanvas();
      const rect = content.getBoundingClientRect();
      fit(view, currentBounds, rect.width, rect.height, 30);
      redraw();
      updateViewBtn();
    }).catch(e => {
      console.error('[KiPreview] 加载失败：', e);
      showMessage('加载失败：' + e.message +
        '<br><small>可能是格式不支持、CORS 限制或网络错误</small>');
    });
  }

  // ---------- URL 输入框 ----------
  urlInput.addEventListener('input', () => {
    delete urlInput.dataset.source;
  });

  urlBtn.addEventListener('click', () => {
    const val = urlInput.value.trim();
    if (!val) return;
    if (urlInput.dataset.source === 'file') return;

    if (val.startsWith('http://') || val.startsWith('https://')) {
      loadFromURL(val);
    } else if (val.startsWith('file://') || /^[a-zA-Z]:[\\/]/.test(val)) {
      showMessage('浏览器不允许直接读取本地路径。<br>请将文件拖拽到下方区域。');
    } else {
      showMessage('无法识别的地址格式。请输入 http:// 或 https:// 开头的 URL，或拖拽本地文件。');
    }
  });

  urlInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') urlBtn.click();
  });

  // ---------- 关闭按钮 ----------
  closeBtn.addEventListener('click', closeViewer);

  // ---------- 2D / 3D 切换按钮 ----------
  if (viewBtn) {
    viewBtn.addEventListener('click', () => {
      if (viewBtn.disabled) return;
      setViewMode(viewMode === '3d' ? '2d' : '3d');
    });
  }

  // ---------- 拖拽 ----------
  // 拖入目录 → 登记为模型库（供 PCB 里的 (model ...) 引用解析）
  // 拖入单个文件 → 按格式加载（这条路径不查库）
  //
  // 取值顺序很关键：普通文件一律优先用 dataTransfer.files，
  // 它同步、直接、各浏览器都可靠；webkitGetAsEntry 只用来判断"是不是目录"。
  // 之前用 FileSystemFileEntry.file() 的异步回调取文件，一旦回调没触发
  // 就静默什么都不做（Mac 上拖拽没反应就是这个原因），而且错误被吞掉。
  function handleDrop(dt) {
    if (!dt) return;

    // 1) 只有 items 能区分目录
    const dirs = [];
    const items = dt.items;
    if (items && items.length) {
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        if (it.kind && it.kind !== 'file') continue;
        let en = null;
        try { en = it.webkitGetAsEntry ? it.webkitGetAsEntry() : null; } catch (e) { en = null; }
        if (en && en.isDirectory) dirs.push(en);
      }
    }

    // 2) 目录 → 登记为库（递归是异步的，登记完成后刷新底部工具条）
    if (dirs.length) {
      dirs.forEach(en => {
        const out = [];
        collectEntries(en, '', out)
          .then(() => addLibraryRoot(en.name, out))
          .catch(e => console.warn('[KiPreview] 读取目录失败：', e));
      });
    }

    // 3) 普通文件：优先 dt.files
    const files = dt.files ? Array.prototype.slice.call(dt.files) : [];
    if (files.length) { loadFromFile(files[0]); return; }

    // 4) dt.files 为空的极少数情况才退回 entry，并且不再吞错误
    if (items && items.length && !dirs.length) {
      for (let i = 0; i < items.length; i++) {
        let en = null;
        try { en = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null; } catch (e) { en = null; }
        if (en && en.isFile) {
          en.file(
            f => loadFromFile(f),
            err => {
              console.warn('[KiPreview] 读取拖入文件失败：', err);
              showMessage('读取拖入的文件失败，请改用点击选择文件。');
            });
          return;
        }
      }
    }

    if (!dirs.length) showMessage('没有识别到可处理的文件。');
  }

  // 落点用整个文档：拖到哪都能接住，也避免子元素挡住 drop
  ['dragenter', 'dragover'].forEach(t => {
    document.addEventListener(t, e => {
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
      hint.classList.add('over');
      if (libBar) libBar.classList.add('over');
    });
  });
  document.addEventListener('dragleave', e => {
    // 真正离开窗口时才取消高亮（relatedTarget 为空表示离开文档）
    if (!e.relatedTarget) {
      hint.classList.remove('over');
      if (libBar) libBar.classList.remove('over');
    }
  });
  document.addEventListener('drop', e => {
    e.preventDefault();
    hint.classList.remove('over');
    if (libBar) libBar.classList.remove('over');
    handleDrop(e.dataTransfer);
  });

  // ---------- 模型库工具条 ----------
  if (libBtn) {
    libBtn.addEventListener('click', () => {
      const input = document.createElement('input');
      input.type = 'file';
      input.webkitdirectory = true;      // 选整个目录
      input.multiple = true;
      input.onchange = () => {
        const files = Array.from(input.files || []);
        if (!files.length) return;
        // webkitRelativePath 形如 "3dmodels/Resistor_SMD.3dshapes/R_0805.wrl"
        const rel = files[0].webkitRelativePath || files[0].name;
        const rootName = rel.split('/')[0] || '目录';
        addLibraryRoot(rootName, files.map(f => ({
          path: f.webkitRelativePath || f.name,
          file: f
        })));
      };
      input.click();
    });
  }

  if (libClear) {
    libClear.addEventListener('click', () => {
      if (modLib) modLib.clear();
      modelFileCache.clear();
      updateLibBar();
    });
  }
  updateLibBar();

  hint.addEventListener('click', () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.kicad_pcb,.kicad_sch,.step,.stp,.wrl,.stl,.3mf';
    input.onchange = () => {
      if (input.files.length) loadFromFile(input.files[0]);
    };
    input.click();
  });

// ---------- 画布交互 ----------
let isDragging = false;
let dragStart = null;
let pendingClick = false;
let clickStart = null;

function handleClick(e) {
  // TODO: 原理图元素选中暂未实现
  if (lastType !== 'pcb') {
    setSelection(null);
    return;
  }
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(view, mx, my, currentBounds);
  const tol = 5 / view.scale;
  const hit = HitTest.hitTest(
    lastItems, lastType, world.x, world.y, tol,
    currentVisibility, Layers.isVisible
  );
  setSelection(hit);
}

// 3D 拾取：屏幕点 → 世界射线 → 命中的 PCB 元素
function handleClick3D(e) {
  if (viewMode !== '3d' || !cam3d || !is3DAvailable()) return;
  const rect = glCanvas.getBoundingClientRect();
  let hit = null;
  try {
    hit = Pick3D.pick(
      GlRenderer.getMesh(), cam3d,
      e.clientX - rect.left, e.clientY - rect.top,
      rect.width, rect.height
    );
  } catch (err) {
    console.error('[KiPreview] 3D 拾取失败：', err);
  }
  setSelection(hit);
}

// ---- canvas 上的事件 ----

canvas.addEventListener('mousedown', e => {
  if (!lastItems || lastType === 'model') return;
  isDragging = true;
  pendingClick = true;
  clickStart = { x: e.clientX, y: e.clientY };
  canvas.classList.add('dragging');
  dragStart = { x: e.clientX, y: e.clientY, panX: view.panX, panY: view.panY };
});

canvas.addEventListener('mousemove', e => {
  if (!lastItems || lastType === 'model') return;
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(view, mx, my, currentBounds);
  coordTip.textContent = '(' + world.x.toFixed(3) + ', ' + world.y.toFixed(3) + ') mm';
  coordTip.style.left = (mx + 14) + 'px';
  coordTip.style.top = (my + 14) + 'px';
  coordTip.style.display = 'block';
});

canvas.addEventListener('mouseleave', () => {
  coordTip.style.display = 'none';
});

canvas.addEventListener('wheel', e => {
  if (!lastItems || lastType === 'model') return;
  e.preventDefault();
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
  zoomAt(view, mx, my, factor, currentBounds);
  redraw();
}, { passive: false });

canvas.addEventListener('dblclick', () => {
  if (!lastItems || lastType === 'model' || !currentBounds) return;
  const rect = content.getBoundingClientRect();
  fit(view, currentBounds, rect.width, rect.height, 30);
  redraw();
});

// ---- window 上的事件 ----

window.addEventListener('mousemove', e => {
  if (!isDragging) return;
  // 超过 4px 视为拖拽，不再当作点击
  if (pendingClick &&
      Math.hypot(e.clientX - clickStart.x, e.clientY - clickStart.y) > 4) {
    pendingClick = false;
  }
  view.panX = dragStart.panX + (e.clientX - dragStart.x);
  view.panY = dragStart.panY + (e.clientY - dragStart.y);
  redraw();
});

window.addEventListener('mouseup', e => {
  if (!isDragging) return;
  isDragging = false;
  canvas.classList.remove('dragging');
  // 位移没超过阈值才算点击
  if (pendingClick) {
    handleClick(e);
  }
  pendingClick = false;
});

// ---------- 3D 画布交互 ----------
// 只在 3D 模式下生效，与上面 2D canvas 的事件互不干扰（两个 canvas 互斥显示）

let glDragging = false;
let glDragMode = null;      // 'orbit' | 'pan'
let glPendingClick = false; // 位移没超过阈值才算点击（与 2D 一致的 4px 阈值）
let glClickStart = null;
let glLastX = 0;
let glLastY = 0;

if (glCanvas) {
  glCanvas.addEventListener('mousedown', e => {
    if (viewMode !== '3d' || !cam3d) return;
    glDragging = true;
    glPendingClick = true;
    glClickStart = { x: e.clientX, y: e.clientY };
    glDragMode = (e.button === 2 || e.shiftKey) ? 'pan' : 'orbit';
    glLastX = e.clientX;
    glLastY = e.clientY;
    glCanvas.classList.add('dragging');
    e.preventDefault();
  });

  // 右键用来平移，屏蔽系统菜单
  glCanvas.addEventListener('contextmenu', e => e.preventDefault());

  glCanvas.addEventListener('wheel', e => {
    if (viewMode !== '3d' || !cam3d) return;
    e.preventDefault();
    Camera3D.zoom(cam3d, e.deltaY < 0 ? 1 / 1.12 : 1.12);
    render3D();
  }, { passive: false });

  glCanvas.addEventListener('dblclick', () => {
    if (viewMode !== '3d' || !cam3d) return;
    Camera3D.fit(cam3d, currentBounds, Mesh3D.T_DEFAULT);
    render3D();
  });

  window.addEventListener('mousemove', e => {
    if (!glDragging || viewMode !== '3d' || !cam3d) return;
    if (glPendingClick && glClickStart &&
        Math.hypot(e.clientX - glClickStart.x, e.clientY - glClickStart.y) > 4) {
      glPendingClick = false;
    }
    const dx = e.clientX - glLastX;
    const dy = e.clientY - glLastY;
    glLastX = e.clientX;
    glLastY = e.clientY;
    if (glDragMode === 'pan') {
      Camera3D.pan(cam3d, dx, dy, content.getBoundingClientRect().height);
    } else {
      Camera3D.orbit(cam3d, dx, dy);
    }
    render3D();
  });

  window.addEventListener('mouseup', e => {
    if (!glDragging) return;
    glDragging = false;
    glCanvas.classList.remove('dragging');
    if (glPendingClick) handleClick3D(e);
    glPendingClick = false;
  });
}

// ---------- 窗口尺寸变化 ----------
let resizeTimer = null;
window.addEventListener('resize', () => {
  if (!lastItems || lastType === 'model') return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (viewMode === '3d') {
      render3D();
    } else {
      resizeCanvas();
      redraw();
    }
  }, 120);
});

  updateViewBtn();
  resetHint();
})(window);