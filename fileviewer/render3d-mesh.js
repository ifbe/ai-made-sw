(function (global) {
  'use strict';

  // PCB → 3D 三角网格。
  //
  // 坐标映射：pcbnew 的 Y 轴向下，3D 空间 Z 轴向上，所以统一映射为
  //     W(x, y, z) = [x, -y, z]
  // 板面位于 XY 平面，板厚沿 +Z。板体 z ∈ [0, T]。
  //
  // 输出是非索引的三角形汤（position / normal / color 各一个 Float32Array），
  // 渲染端直接 drawArrays，法线在顶点处由叉积算出，配合双面光照，
  // 所以绕序不需要严格正确。
  //
  // 同时记录"三角形 → 原 PCB 元素"的归属（elem / elems）：
  // 每个元素贡献的三角形是连续的，因此只需存 [triStart, triEnd) 区间，
  // 拾取时先用元素 AABB 粗筛，再只对候选元素的三角形做射线求交。

  const { groupRings, triangulateRings } = global.KiPreview.Triangulate;

  const T_DEFAULT = 1.6;        // 板厚 mm
  const CU_DEPTH = 0.035;       // 铜箔显示厚度
  const PAD_H = 0.06;           // 焊盘凸起高度
  const VIA_OVER = 0.04;        // 过孔露出板面的量
  const CIRCLE_SEG = 32;

  const COL = {
    top:        [0.13, 0.34, 0.16],   // 顶层阻焊（绿）
    bottom:     [0.11, 0.27, 0.14],   // 底层阻焊
    edge:       [0.60, 0.52, 0.28],   // 板边 FR4
    fcu:        [0.78, 0.22, 0.22],   // F.Cu 走线
    bcu:        [0.18, 0.44, 0.18],   // B.Cu 走线
    pad:        [0.83, 0.69, 0.38],   // 贴片焊盘
    padThrough: [0.72, 0.72, 0.72],   // 通孔焊盘
    via:        [0.62, 0.62, 0.62]
  };

  function W(x, y, z) { return [x, -y, z]; }

  // ---------- builder ----------

  function createBuilder() {
    return {
      pos: [], nrm: [], col: [],
      elem: [],        // 每个顶点一个元素序号，-1 表示不可拾取（板体）
      elems: [],       // { kind, index, triStart, triEnd, min, max }
      curElem: -1
    };
  }

  // 开始记录一个新元素。kind 传 null 表示这段几何不参与拾取。
  function beginElement(b, kind, index) {
    const tri = b.pos.length / 9;              // 已有三角形数
    if (b.curElem >= 0) b.elems[b.curElem].triEnd = tri;
    b.curElem = -1;
    if (!kind) return;
    b.elems.push({
      id: b.elems.length,
      kind, index,
      triStart: tri, triEnd: tri,
      min: [Infinity, Infinity, Infinity],
      max: [-Infinity, -Infinity, -Infinity]
    });
    b.curElem = b.elems.length - 1;
  }

  function pushVert(b, p, n, c) {
    b.pos.push(p[0], p[1], p[2]);
    b.nrm.push(n[0], n[1], n[2]);
    b.col.push(c[0], c[1], c[2]);
    b.elem.push(b.curElem);
    if (b.curElem >= 0) {
      const e = b.elems[b.curElem];
      for (let i = 0; i < 3; i++) {
        if (p[i] < e.min[i]) e.min[i] = p[i];
        if (p[i] > e.max[i]) e.max[i] = p[i];
      }
    }
  }

  function addTriangle(b, p0, p1, p2, color) {
    const ux = p1[0] - p0[0], uy = p1[1] - p0[1], uz = p1[2] - p0[2];
    const vx = p2[0] - p0[0], vy = p2[1] - p0[1], vz = p2[2] - p0[2];
    let nx = uy * vz - uz * vy;
    let ny = uz * vx - ux * vz;
    let nz = ux * vy - uy * vx;
    const l = Math.hypot(nx, ny, nz);
    if (l < 1e-12) { nx = 0; ny = 0; nz = 1; }
    else { nx /= l; ny /= l; nz /= l; }
    const n = [nx, ny, nz];
    pushVert(b, p0, n, color);
    pushVert(b, p1, n, color);
    pushVert(b, p2, n, color);
  }

  function addQuad(b, p0, p1, p2, p3, color) {
    addTriangle(b, p0, p1, p2, color);
    addTriangle(b, p0, p2, p3, color);
  }

  function finish(b) {
    const total = b.pos.length / 9;
    if (b.curElem >= 0) b.elems[b.curElem].triEnd = total;
    for (const e of b.elems) {
      e.triCount = e.triEnd - e.triStart;
      if (!isFinite(e.min[0])) e.triCount = 0;   // 没有产出几何的空元素
    }
    return {
      pos: new Float32Array(b.pos),
      nrm: new Float32Array(b.nrm),
      col: new Float32Array(b.col),
      elem: new Float32Array(b.elem),
      elems: b.elems,
      count: b.pos.length / 3
    };
  }

  // ---------- 环的构造（都在 pcb 二维坐标下，不重复首点） ----------

  // 旋转矩形：与 2D 渲染端 ctx.rotate(-rot) 的约定保持一致
  function rotRectRing(cx, cy, w, h, rot) {
    const c = Math.cos(rot), s = Math.sin(rot);
    const hw = w / 2, hh = h / 2;
    const loc = [[-hw, -hh], [hw, -hh], [hw, hh], [-hw, hh]];
    return loc.map(([lx, ly]) => [
      cx + lx * c + ly * s,
      cy - lx * s + ly * c
    ]);
  }

  // 旋转椭圆（圆是 rx == ry 的特例）
  function ellipseRing(cx, cy, rx, ry, rot, seg) {
    const n = seg || CIRCLE_SEG;
    const c = Math.cos(rot), s = Math.sin(rot);
    const out = [];
    for (let i = 0; i < n; i++) {
      const a = (i / n) * Math.PI * 2;
      const lx = Math.cos(a) * rx;
      const ly = Math.sin(a) * ry;
      out.push([cx + lx * c + ly * s, cy - lx * s + ly * c]);
    }
    return out;
  }

  function segmentRing(s) {
    const dx = s.x2 - s.x1, dy = s.y2 - s.y1;
    const len = Math.hypot(dx, dy) || 1;
    const nx = -dy / len * (s.w / 2);
    const ny = dx / len * (s.w / 2);
    return [
      [s.x1 + nx, s.y1 + ny],
      [s.x2 + nx, s.y2 + ny],
      [s.x2 - nx, s.y2 - ny],
      [s.x1 - nx, s.y1 - ny]
    ];
  }

  // 单组环（一个外环 + 若干洞）的三角化
  function ringTris(outer, holes) {
    if (!holes || !holes.length) {
      const n = outer.length;
      if (n === 3) return { verts: outer, tris: [[0, 1, 2]] };
      if (n === 4) return { verts: outer, tris: [[0, 1, 2], [0, 2, 3]] };
    }
    return triangulateRings(outer, holes);
  }

  // 把一组组环沿 Z 挤出成实体
  function extrude(b, groups, z0, z1, topColor, botColor, sideColor) {
    for (const g of groups) {
      const { verts, tris } = ringTris(g.outer, g.holes);

      for (const t of tris) {
        const a = verts[t[0]], c = verts[t[1]], d = verts[t[2]];
        addTriangle(b, W(a[0], a[1], z1), W(c[0], c[1], z1), W(d[0], d[1], z1), topColor);
        addTriangle(b, W(a[0], a[1], z0), W(c[0], c[1], z0), W(d[0], d[1], z0), botColor);
      }

      const rings = [g.outer].concat(g.holes || []);
      for (const ring of rings) {
        for (let i = 0; i < ring.length; i++) {
          const p = ring[i], q = ring[(i + 1) % ring.length];
          addQuad(b,
            W(p[0], p[1], z0), W(q[0], q[1], z0),
            W(q[0], q[1], z1), W(p[0], p[1], z1),
            sideColor);
        }
      }
    }
  }

  function extrudeRing(b, ring, z0, z1, topColor, botColor, sideColor) {
    extrude(b, [{ outer: ring, holes: [] }], z0, z1, topColor, botColor, sideColor);
  }

  // ---------- 板框 ----------

  // 把若干条开放折线串成闭合环。
  // 直线段是 2 点折线，板框圆弧是采样后的 N 点折线，两者一视同仁。
  function chainPolylines(polys) {
    if (!polys.length) return [];
    const tol = 0.01;
    const key = p => Math.round(p[0] / tol) + ',' + Math.round(p[1] / tol);

    const adj = new Map();
    polys.forEach((pl, i) => {
      for (const p of [pl[0], pl[pl.length - 1]]) {
        const k = key(p);
        if (!adj.has(k)) adj.set(k, []);
        const list = adj.get(k);
        if (list.indexOf(i) < 0) list.push(i);
      }
    });

    const used = new Array(polys.length).fill(false);
    const loops = [];

    for (let seed = 0; seed < polys.length; seed++) {
      if (used[seed]) continue;
      const startKey = key(polys[seed][0]);
      const loop = [];
      let nodeKey = startKey;
      let cur = seed;
      let closed = false;
      let guard = 0;

      while (cur >= 0 && guard++ <= polys.length + 1) {
        used[cur] = true;
        const pl = polys[cur];
        const kStart = key(pl[0]);
        const kEnd = key(pl[pl.length - 1]);

        let pts;
        if (kStart === nodeKey) { pts = pl; nodeKey = kEnd; }
        else if (kEnd === nodeKey) { pts = pl.slice().reverse(); nodeKey = kStart; }
        else break;                                  // 断开的链

        // 末点留给下一段作为起点（或正好回到闭环起点），不重复压入
        for (let i = 0; i < pts.length - 1; i++) loop.push([pts[i][0], pts[i][1]]);

        if (nodeKey === startKey) { closed = true; break; }

        const cands = adj.get(nodeKey) || [];
        let next = -1;
        for (const j of cands) { if (!used[j]) { next = j; break; } }
        cur = next;
      }

      // 只有真正闭环的链才算板框；开放折线宁可丢弃，也不要造出假板形
      if (closed && loop.length >= 3) loops.push(loop);
    }
    return loops;
  }

  // 兼容旧接口：只吃直线段
  function chainEdges(edges) {
    return chainPolylines(edges.map(e => [[e.x1, e.y1], [e.x2, e.y2]]));
  }

  // 板框环：线段 + 圆弧串成的闭合环，再加上 Edge.Cuts 上的圆（安装孔等）
  function outlineRings(items) {
    const polys = (items.edges || []).map(e => [[e.x1, e.y1], [e.x2, e.y2]]);
    (items.arcs || []).forEach(a => {
      if (a.points && a.points.length >= 2) polys.push(a.points);
    });

    const rings = chainPolylines(polys);
    (items.circles || []).forEach(c => {
      if (c.r > 0.001) rings.push(ellipseRing(c.x, c.y, c.r, c.r, 0, CIRCLE_SEG));
    });
    return rings;
  }

  function boundsRect(bounds, pad) {
    const p = pad || 0;
    return [
      [bounds.minX - p, bounds.minY - p],
      [bounds.maxX + p, bounds.minY - p],
      [bounds.maxX + p, bounds.maxY + p],
      [bounds.minX - p, bounds.maxY + p]
    ];
  }

  // ---------- 主入口 ----------

  function buildBoard(items, visibility, opts) {
    opts = opts || {};
    const T = opts.thickness || T_DEFAULT;
    const isVisible = global.KiPreview.Layers.isVisible;
    const b = createBuilder();

    // 板体：板框挤出；板框不闭合时退化成包围盒，保证 3D 里总有东西可看。
    // 板体不参与拾取（beginElement(b, null)）：它是"整个板框"挤出的，
    // 一块顶面无法对应到某一条 Edge.Cuts。拾取留给焊盘/过孔/走线这些有明细的元素。
    beginElement(b, null);
    if (isVisible(visibility, 'Edge.Cuts')) {
      const groups = groupRings(outlineRings(items));
      if (groups.length) {
        extrude(b, groups, 0, T, COL.top, COL.bottom, COL.edge);
      } else if (opts.bounds) {
        extrudeRing(b, boundsRect(opts.bounds, 0), 0, T, COL.top, COL.bottom, COL.edge);
      }
    }

    // 走线：F.Cu 贴上表面，B.Cu 贴下表面
    (items.segments || []).forEach((s, i) => {
      if (!isVisible(visibility, s.layer)) return;
      const ring = segmentRing(s);
      if (s.layer === 'B.Cu' || s.layer === 'F.Cu') {
        beginElement(b, 'segment', i);
        if (s.layer === 'B.Cu') {
          extrudeRing(b, ring, 0.02, 0.02 + CU_DEPTH, COL.bcu, COL.bcu, COL.bcu);
        } else {
          extrudeRing(b, ring, T - CU_DEPTH - 0.02, T - 0.02, COL.fcu, COL.fcu, COL.fcu);
        }
      }
    });

    // 焊盘
    if (isVisible(visibility, 'Pads')) {
      (items.pads || []).forEach((p, i) => {
        const color = p.through ? COL.padThrough : COL.pad;
        let ring;
        if (p.shape === 'circle') {
          const r = Math.min(p.w, p.h) / 2;
          if (r <= 0.001) return;
          ring = ellipseRing(p.x, p.y, r, r, p.rot, CIRCLE_SEG);
        } else if (p.shape === 'oval') {
          if (p.w <= 0.001 || p.h <= 0.001) return;
          ring = ellipseRing(p.x, p.y, p.w / 2, p.h / 2, p.rot, CIRCLE_SEG);
        } else {
          if (p.w <= 0.001 || p.h <= 0.001) return;
          ring = rotRectRing(p.x, p.y, p.w, p.h, p.rot);
        }

        beginElement(b, 'pad', i);
        if (p.through) {
          extrudeRing(b, ring, -PAD_H, T + PAD_H, color, color, color);
        } else if (p.back && !p.front) {
          extrudeRing(b, ring, -PAD_H, 0.02, color, color, color);
        } else {
          extrudeRing(b, ring, T - 0.02, T + PAD_H, color, color, color);
        }
      });
    }

    // 过孔
    if (isVisible(visibility, 'Vias')) {
      (items.vias || []).forEach((v, i) => {
        if (v.r <= 0.001) return;
        beginElement(b, 'via', i);
        const ring = ellipseRing(v.x, v.y, v.r, v.r, 0, CIRCLE_SEG);
        extrudeRing(b, ring, -VIA_OVER, T + VIA_OVER, COL.via, COL.via, COL.via);
      });
    }

    // 丝印文字（items.texts）暂不渲染：需要字体轮廓转三角面，
    // 留到后续与 STEP/VRML 一起处理。

    // 元件 3D 模型：已解析到文件的摆真实几何，没解析到的画占位方块
    const Models3D = global.KiPreview.Models3D;
    let modelStats = null;
    if (Models3D && items.models && items.models.length) {
      modelStats = Models3D.appendModels(b, items, visibility, {
        bounds: opts.bounds,
        modelMeshes: opts.modelMeshes
      });
    }

    const out = finish(b);
    if (modelStats) out.models = modelStats;
    return out;
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Mesh3D = {
    COL,
    T_DEFAULT,
    buildBoard,
    chainEdges,
    chainPolylines,
    outlineRings,
    rotRectRing,
    ellipseRing,
    segmentRing,
    // 通用 builder：STL / 3MF / STEP 等 parser 复用它产出同一种网格格式。
    // beginElement(b, null) 表示不做元素归属（这些格式没有可拾取的元素概念）。
    createBuilder,
    beginElement,
    pushVert,
    addTriangle,
    addQuad,
    finish
  };
})(window);
