(function (global) {
  'use strict';

  // PCB 上元件 3D 模型的摆放（变换链）与实际几何装配。
  //
  // 每个 (model ...) 引用有两种呈现：
  //   已解析到模型文件 → 把真实几何按变换链摆上去
  //   没解析到         → 画一个占位方块（尺寸用该封装焊盘的局部范围近似）
  //
  // ── 变换链 ───────────────────────────────────────────────
  // 顺序固定为：缩放 → 旋转（XYZ 欧拉角，单位度）→ 平移，
  // 得到封装局部 3D 坐标；再套封装自身的摆放。
  //
  // 两点关键：
  // 1) 模型局部 X/Y 与封装局部（pcbnew，Y 朝下）一致，因此可以直接套用
  //    本项目已校验过的焊盘摆放公式
  //        world = T(fp.x, -fp.y) · Rz(θ) · (qx, qy)
  //    展开即 [[cosθ, sinθ],[sinθ, -cosθ]]，行列式 -1，是一次反射 ——
  //    这正是"板面 3D 的 Y 朝上、pcbnew 的 Y 朝下"带来的。
  // 2) 欧拉角取负。实测把 (rotate) 的角度直接代入 Rz·Ry·Rx 时，
  //    带旋转的模型只有 1 个能对齐；取负后 U3 / J14 / J12 三个都对齐了
  //    （判据：模型在封装局部坐标系里的 XY 范围必须盖住焊盘范围）。
  //    取负等价于旋转矩阵转置，即 KiCad 用的是 R⁻¹。
  //
  // 背面封装（B.Cu）：等效于绕 X 轴再转 180°，Z 取反。
  // 目前手上的板子里背面封装都没有 3D 模型，这一段没有样本可验证。

  const DEFAULT_COLOR = [0.55, 0.55, 0.95];   // 占位方块：淡紫
  const BOX_H = 1.0;                          // 占位高度（真实高度未知）
  const MIN_SIZE = 0.4;

  // 行主序 3x3：R = Rz·Ry·Rx（先施加 X，再 Y，最后 Z）
  function eulerXYZ(rxDeg, ryDeg, rzDeg) {
    const d = Math.PI / 180;
    const cx = Math.cos(rxDeg * d), sx = Math.sin(rxDeg * d);
    const cy = Math.cos(ryDeg * d), sy = Math.sin(ryDeg * d);
    const cz = Math.cos(rzDeg * d), sz = Math.sin(rzDeg * d);
    return [
      cz * cy, cz * sy * sx - sz * cx, cz * sy * cx + sz * sx,
      sz * cy, sz * sy * sx + cz * cx, sz * sy * cx - cz * sx,
      -sy,     cy * sx,                cy * cx
    ];
  }

  // 返回一个映射对象：w(p) 变换点，w.dir(v) 只走线性部分（法线用）
  function modelToWorld(m) {
    const R = eulerXYZ(-m.rotate[0], -m.rotate[1], -m.rotate[2]);
    const sc = m.scale, off = m.offset;
    const fx = m.fp.x, fy = m.fp.y;
    const back = !!m.fp.back;

    const th = back ? -m.fp.rot : m.fp.rot;
    const c = Math.cos(th), s = Math.sin(th);
    const zs = back ? -1 : 1;

    // 线性部分：模型旋转 → 封装那一步反射/旋转
    function lin(p) {
      const x0 = p[0] * sc[0], y0 = p[1] * sc[1], z0 = p[2] * sc[2];
      const qx = R[0] * x0 + R[1] * y0 + R[2] * z0;
      const qy = R[3] * x0 + R[4] * y0 + R[5] * z0;
      const qz = R[6] * x0 + R[7] * y0 + R[8] * z0;
      return [qx, qy, qz];
    }

    function w(p) {
      const q = lin(p);
      // 平移在封装摆放之前施加，三个分量都要加
      const qx = q[0] + off[0];
      const qy = q[1] + off[1];
      const qz = q[2] + off[2];
      return [
        fx + qx * c + qy * s,
        -fy + qx * s - qy * c,
        zs * qz
      ];
    }

    // 法线只走线性部分。这里的线性映射是正交的（旋转 + 一次反射），
    // 所以法线可以直接用同一矩阵变换，不需要逆转置。
    w.dir = function (v) {
      const q = lin(v);
      return [
        q[0] * c + q[1] * s,
        q[0] * s - q[1] * c,
        zs * q[2]
      ];
    };

    // 模型原点在世界里的位置（用于"是否落到板外"的检查）
    w.origin = function () { return w([0, 0, 0]); };

    return w;
  }

  // 把一份已解析的模型几何按变换链摆上去
  function appendTransformed(b, mesh, src, w) {
    const P = src.pos, N = src.nrm, C = src.col;
    const hasN = N && N.length === P.length;
    const hasC = C && C.length === P.length;

    for (let i = 0; i < P.length; i += 3) {
      const p = w([P[i], P[i + 1], P[i + 2]]);
      let n = [0, 0, 1];
      if (hasN) n = w.dir([N[i], N[i + 1], N[i + 2]]);
      const c = hasC ? [C[i], C[i + 1], C[i + 2]] : DEFAULT_COLOR;
      mesh.pushVert(b, p, n, c);
    }
  }

  // 占位方块：沿局部盒子 8 个角走一遍变换，再连成 6 个面
  function appendBox(b, mesh, w, x1, y1, z1, x2, y2, z2, color) {
    const c = [];
    for (let i = 0; i < 8; i++) {
      c.push(w([
        (i & 1) ? x2 : x1,
        (i & 2) ? y2 : y1,
        (i & 4) ? z2 : z1
      ]));
    }
    const F = [
      [0, 1, 3, 2], [4, 5, 7, 6],
      [0, 1, 5, 4], [2, 3, 7, 6],
      [0, 2, 6, 4], [1, 3, 7, 5]
    ];
    for (const f of F) {
      mesh.addQuad(b, c[f[0]], c[f[1]], c[f[2]], c[f[3]], color);
    }
  }

  function appendModels(b, items, visibility, opts) {
    const stats = {
      count: 0, resolved: 0, placeholder: 0,
      offBoard: 0, offList: [], triangles: 0
    };
    const models = items && items.models;
    if (!models || !models.length) return stats;

    const isVisible = global.KiPreview.Layers.isVisible;
    if (visibility && !isVisible(visibility, 'Models')) return stats;

    const mesh = global.KiPreview.Mesh3D;
    const bx = opts && opts.bounds;
    const srcs = (opts && opts.modelMeshes) || null;   // Map<模型序号, 网格>

    for (let i = 0; i < models.length; i++) {
      const m = models[i];

      // 方块尺寸：优先用封装局部焊盘范围，没有就给个最小值
      const pb = m.fp.padBox;
      let w0 = pb ? Math.abs(pb.x2 - pb.x1) : MIN_SIZE;
      let h0 = pb ? Math.abs(pb.y2 - pb.y1) : MIN_SIZE;
      if (!(w0 > 0.01)) w0 = MIN_SIZE;
      if (!(h0 > 0.01)) h0 = MIN_SIZE;

      const w = modelToWorld(m);
      mesh.beginElement(b, null);        // 模型暂不参与拾取

      const src = srcs ? srcs.get(i) : null;
      if (src && src.count) {
        appendTransformed(b, mesh, src, w);
        stats.resolved++;
        stats.triangles += src.count / 3;
      } else {
        appendBox(b, mesh, w, -w0 / 2, -h0 / 2, 0, w0 / 2, h0 / 2, BOX_H, DEFAULT_COLOR);
        stats.placeholder++;
      }

      stats.count++;
      const c0 = w.origin();
      if (bx) {
        const pad = Math.max(w0, h0);
        if (c0[0] < bx.minX - pad || c0[0] > bx.maxX + pad ||
            c0[1] > -bx.minY + pad || c0[1] < -bx.maxY - pad) {
          stats.offBoard++;
          if (stats.offList.length < 8) {
            stats.offList.push((m.fp.ref || '(无位号)') + ' @(' +
              c0[0].toFixed(1) + ', ' + c0[1].toFixed(1) + ', ' + c0[2].toFixed(1) + ')');
          }
        }
      }
    }
    return stats;
  }

  // ── 模型库索引与路径解析 ─────────────────────────────────
  //
  // 只服务 .kicad_pcb 里 (model ...) 的引用解析；直接拖单个 3D 文件时不查库。
  //
  // 为什么不做成"填一个本地路径"：浏览器读不到任意文件系统路径，
  // 文本框最多拿到字符串，拿去 fetch('file:///...') 会被 CORS 挡掉。
  // 所以本地文件只能靠拖目录/选目录拿到 File 对象。
  //
  // 解析策略：KiCad 的引用去掉 ${变量} 前缀后，形态固定是
  //     <库名>.3dshapes/<模型名>.<后缀>
  // 所以按"末两段路径"建索引就能对上，完全不需要用户配置环境变量。
  // 实测 CM5IO 的 66 个引用去掉前缀后得到 28 个唯一路径，无冲突。
  //
  // 官方库对同一模型同时发布 .wrl 与 .step，而 KiCad 9 的安装库已经是
  // STEP-only，所以按原后缀找不到时要换后缀再试 —— 这一条能把
  // CM5IO 里 54 个 .wrl 引用全部救回来。

  const EXT_SWAP = {
    '.wrl': ['.step', '.stp', '.stl'],
    '.step': ['.wrl', '.stl', '.stp'],
    '.stp': ['.wrl', '.step', '.stl'],
    '.stl': ['.wrl', '.step', '.stp'],
    '.3mf': ['.stl', '.step', '.stp']
  };

  function createLibrary() {
    const lib = {
      roots: [],
      byTail2: new Map(),
      byBase: new Map()
    };

    lib.size = function () {
      return lib.roots.reduce((n, r) => n + r.count, 0);
    };

    // files: [{ path, file }]
    lib.addRoot = function (name, files) {
      if (!files || !files.length) return 0;
      for (const it of files) {
        const low = String(it.path).toLowerCase().replace(/\\/g, '/');
        const segs = low.split('/');
        const base = segs[segs.length - 1];
        if (segs.length >= 2) {
          const tail2 = segs.slice(-2).join('/');
          if (!lib.byTail2.has(tail2)) lib.byTail2.set(tail2, it.file);
        }
        if (!lib.byBase.has(base)) lib.byBase.set(base, it.file);
      }
      lib.roots.push({ name, count: files.length });
      return files.length;
    };

    lib.clear = function () {
      lib.roots.length = 0;
      lib.byTail2.clear();
      lib.byBase.clear();
    };

    // ref: "(model ...)" 里的原始字符串 → { file, path, substituted } | null
    lib.resolve = function (ref) {
      if (!lib.size()) return null;
      const rel = String(ref).replace(/^\$\{[^}]+\}[\\/]?/, '').replace(/\\/g, '/');
      const dot = rel.lastIndexOf('.');
      const ext = dot > 0 ? rel.slice(dot).toLowerCase() : '';

      const cands = [rel];
      for (const s of (EXT_SWAP[ext] || [])) cands.push(rel.slice(0, dot) + s);

      for (const c of cands) {
        const low = c.toLowerCase();
        const segs = low.split('/');
        if (segs.length >= 2) {
          const f = lib.byTail2.get(segs.slice(-2).join('/'));
          if (f) return { file: f, path: c, substituted: c !== rel };
        }
        const f2 = lib.byBase.get(segs[segs.length - 1]);
        if (f2) return { file: f2, path: c, substituted: c !== rel };
      }
      return null;
    };

    return lib;
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Models3D = {
    modelToWorld,
    eulerXYZ,
    appendModels,
    appendTransformed,
    createLibrary,
    EXT_SWAP,
    BOX_H,
    DEFAULT_COLOR
  };
})(window);
