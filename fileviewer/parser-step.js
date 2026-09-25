(function (global) {
  'use strict';

  // STEP (ISO 10303-21, AP203/AP214/AP242) 解析器 —— 零依赖纯 JS 实现。
  //
  // 分两个层次：
  //   1) 语法层：Part 21 exchange structure（#id = ENTITY(args); ）→ 实体表
  //   2) 几何层：B-rep 拓扑遍历 → 三角网格
  //
  // 几何层目前只做解析曲面里的 PLANE（平面面）。
  // 实测 KiCad 官方 3D 库采样 300 个文件、105623 个面：
  //     PLANE                 83.3%
  //     CYLINDRICAL_SURFACE    7.8%
  //     SPHERICAL_SURFACE      1.4%
  //     B_SPLINE_SURFACE       0.6%
  //     锥/环/旋转面/拉伸面     0.6%
  // 所以平面面能覆盖绝大多数可见几何；其余曲面先以"边界线框"呈现，
  // 后续阶段再补参数曲面求值与裁剪。
  //
  // 输出与 Mesh3D.buildBoard 完全相同的网格格式，直接交给 render3d-webgl.js。

  const { triangulateRings } = global.KiPreview.Triangulate;

  const COL_SOLID = [0.72, 0.73, 0.77];   // 实体面
  const COL_WIRE  = [0.30, 0.78, 0.95];   // 未支持曲面的边界线框
  const WIRE_R    = 0.0012;               // 线框粗细（相对模型对角线）

  const DERIVED = { derived: true };
  const EPS = 1e-9;

  // ============ 1. Part 21 词法 ============

  function tokenize(src) {
    const toks = [];
    const n = src.length;
    let i = 0;

    while (i < n) {
      const c = src[i];

      if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }

      // /* 注释 */
      if (c === '/' && src[i + 1] === '*') {
        const e = src.indexOf('*/', i + 2);
        i = e < 0 ? n : e + 2;
        continue;
      }

      // '字符串'，内部 '' 表示一个单引号
      if (c === "'") {
        let j = i + 1, out = '';
        while (j < n) {
          if (src[j] === "'") {
            if (src[j + 1] === "'") { out += "'"; j += 2; continue; }
            break;
          }
          out += src[j++];
        }
        toks.push({ t: 'str', v: out });
        i = j + 1;
        continue;
      }

      if (c === '#') {
        let j = i + 1, d = '';
        while (j < n && src[j] >= '0' && src[j] <= '9') d += src[j++];
        toks.push({ t: 'ref', v: parseInt(d, 10) });
        i = j;
        continue;
      }

      // .ENUM. 形式，注意要与 ".5" 这种数字区分开
      if (c === '.') {
        const m = /^\.([A-Za-z0-9_]+)\./.exec(src.slice(i, i + 64));
        if (m) { toks.push({ t: 'enum', v: m[1] }); i += m[0].length; continue; }
      }

      if (c === '(' || c === ')' || c === ',' || c === ';' || c === '=') {
        toks.push({ t: c }); i++; continue;
      }
      if (c === '$') { toks.push({ t: 'unset' }); i++; continue; }
      if (c === '*') { toks.push({ t: 'derived' }); i++; continue; }

      // 实体名（含 ISO 10303 的 !USER_DEFINED 形式）
      const id = /^[A-Za-z_!][A-Za-z0-9_]*/.exec(src.slice(i, i + 128));
      if (id) { toks.push({ t: 'ident', v: id[0] }); i += id[0].length; continue; }

      // 数字：1.  1.5  .5  2.E-05  -3
      const nm = /^[-+]?(?:\d+\.?\d*|\.\d+)(?:[Ee][-+]?\d+)?/.exec(src.slice(i, i + 64));
      if (nm) { toks.push({ t: 'num', v: parseFloat(nm[0]) }); i += nm[0].length; continue; }

      i++;   // 无法识别，跳过
    }
    return toks;
  }

  // ============ 2. Part 21 语法 → 实体表 ============

  function parsePart21(src) {
    const toks = tokenize(src);
    const ents = new Map();
    let p = 0;

    function value() {
      const t = toks[p];
      if (!t) return null;
      p++;
      switch (t.t) {
        case 'num': return t.v;
        case 'str': return t.v;
        case 'ref': return { ref: t.v };
        case 'enum': return { enum: t.v };
        case 'unset': return null;
        case 'derived': return DERIVED;
        case 'ident': {
          // 带类型参数：IDENT(args)
          if (toks[p] && toks[p].t === '(') return { type: t.v, args: value() };
          return t.v;
        }
        case '(': {
          const list = [];
          if (toks[p] && toks[p].t === ')') { p++; return list; }
          for (;;) {
            list.push(value());
            const c = toks[p];
            if (!c || c.t === ')') { p++; break; }
            p++;                                  // 吃掉 ','
          }
          return list;
        }
        default: return null;
      }
    }

    while (p < toks.length) {
      const t = toks[p];
      if (!t || t.t !== 'ref') { p++; continue; }
      const id = t.v;
      p++;
      if (!toks[p] || toks[p].t !== '=') continue;
      p++;

      const first = toks[p];
      if (first && first.t === '(') {
        // 复合实体：(A(...)B(...)C(...))
        p++;
        const parts = [];
        while (toks[p] && toks[p].t !== ')') {
          const it = toks[p];
          if (it.t === 'ident') {
            p++;
            const args = (toks[p] && toks[p].t === '(') ? value() : [];
            parts.push({ type: it.v, args });
          } else {
            p++;
          }
        }
        p++;
        const head = parts[0] || { type: '', args: [] };
        ents.set(id, { id, type: head.type, args: head.args, parts });
      } else if (first && first.t === 'ident') {
        const type = first.v;
        p++;
        const args = (toks[p] && toks[p].t === '(') ? value() : [];
        ents.set(id, { id, type, args });
      }

      while (toks[p] && toks[p].t !== ';') p++;
      p++;
    }
    return ents;
  }

  // ============ 3. 向量小工具 ============

  function sub(a, b) { return [a[0] - b[0], a[1] - b[1], a[2] - b[2]]; }
  function dot(a, b) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; }
  function cross(a, b) {
    return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
  }
  function norm(a) {
    const l = Math.hypot(a[0], a[1], a[2]) || 1;
    return [a[0] / l, a[1] / l, a[2] / l];
  }
  function d2(a, b) {
    const dx = a[0] - b[0], dy = a[1] - b[1], dz = a[2] - b[2];
    return dx * dx + dy * dy + dz * dz;
  }

  // ============ 4. 几何解析 ============

  function buildMesh(src, opts) {
    opts = opts || {};
    const wantWire = opts.wireframe !== false;

    const ents = parsePart21(src);
    const b = global.KiPreview.Mesh3D.createBuilder();
    global.KiPreview.Mesh3D.beginElement(b, null);

    const stats = {
      entities: ents.size, faces: 0, planar: 0, skipped: {},
      edges: 0, wireEdges: 0, curveFallback: 0,
      triFallback: 0, planarFail: {},
      // 自检用：平面面在参数域内的多边形面积 vs 实际三角化的面积总和。
      // 两者应当相等；若三角化退化（耳切卡住走了扇形兜底），后者会明显偏大。
      polyArea: 0, triArea: 0
    };

    const get = v => (v && v.ref !== undefined) ? (ents.get(v.ref) || null) : null;
    const arg = (rec, i) => (rec && rec.args) ? rec.args[i] : undefined;
    const num = v => (typeof v === 'number' && isFinite(v)) ? v : 0;

    // ---- 单位 → mm ----
    let scale = 1;
    for (const e of ents.values()) {
      if (!e.parts) continue;
      if (!e.parts.some(x => x.type === 'LENGTH_UNIT')) continue;
      const si = e.parts.find(x => x.type === 'SI_UNIT');
      if (!si) continue;
      const pref = si.args[0], name = si.args[1];
      if (name && name.enum === 'METRE') {
        if (!pref || pref === null || pref.derived) scale = 1000;
        else if (pref.enum === 'MILLI') scale = 1;
        else if (pref.enum === 'CENTI') scale = 10;
        else if (pref.enum === 'MICRO') scale = 0.001;
        else if (pref.enum === 'KILO') scale = 1e6;
        else scale = 1;
      } else if (name && name.enum === 'INCH') {
        scale = 25.4;
      }
      break;
    }
    stats.unitScale = scale;

    // ---- 基础取值 ----
    function coordList(rec) {
      const a = arg(rec, 1);
      return Array.isArray(a) ? [num(a[0]), num(a[1]), num(a[2])] : null;
    }
    function pointOf(rec) {
      const c = coordList(rec);
      return c ? [c[0] * scale, c[1] * scale, c[2] * scale] : [0, 0, 0];
    }
    function dirOf(rec) {
      const c = coordList(rec);
      return c ? norm(c) : null;
    }

    // AXIS2_PLACEMENT_3D('',#origin,#z,#x)
    function axis2(rec) {
      if (!rec) return { o: [0, 0, 0], x: [1, 0, 0], y: [0, 1, 0], z: [0, 0, 1] };
      const o = pointOf(get(arg(rec, 1)));
      let z = dirOf(get(arg(rec, 2)));
      if (!z) z = [0, 0, 1];
      let x = dirOf(get(arg(rec, 3)));
      if (!x) x = Math.abs(z[0]) > 0.9 ? [0, 1, 0] : [1, 0, 0];
      // 把 X 对 Z 正交化
      const d = dot(x, z);
      x = norm(sub(x, [z[0] * d, z[1] * d, z[2] * d]));
      return { o, x, y: cross(z, x), z };
    }

    // ---- 曲线采样：返回从 from 到 to 的折线（含两端） ----

    // 采样段数按弦高容差定，而不是固定角度：
    //   弦高 sagitta = r * (1 - cos(Δθ/2)) ≤ CHORD_TOL
    // 小半径（元件圆角）自动降到几段，大半径（安装孔）自动加密。
    // 同一个圆在任何面里半径相同，所以各面采出的点数一致，不会产生裂缝。
    const CHORD_TOL = 0.02;      // mm
    function arcSteps(r, sweep) {
      const rr = Math.max(r, 1e-6);
      let dth;
      if (rr <= CHORD_TOL) dth = Math.PI / 2;
      else dth = 2 * Math.acos(Math.max(-1, 1 - CHORD_TOL / rr));
      if (!isFinite(dth) || dth <= 1e-6) dth = Math.PI / 8;
      return Math.max(2, Math.min(64, Math.ceil(Math.abs(sweep) / dth)));
    }

    // ccw 表示沿曲线参数增大的方向行进；圆/椭圆按参数增大方向定义，
    // 方向不由起止点决定，所以必须由调用方给出。
    function sampleArc(O, X, Y, a, b2, from, to, ccw) {
      const ang = p => {
        const d = sub(p, O);
        return Math.atan2(dot(d, Y) / (b2 || 1), dot(d, X) / (a || 1));
      };
      const t0 = ang(from), t1 = ang(to);
      let sweep = t1 - t0;
      if (ccw) {
        while (sweep < -EPS) sweep += Math.PI * 2;
        while (sweep >= Math.PI * 2 - EPS) sweep -= Math.PI * 2;
      } else {
        while (sweep > EPS) sweep -= Math.PI * 2;
        while (sweep <= -Math.PI * 2 + EPS) sweep += Math.PI * 2;
      }
      if (Math.abs(sweep) < 1e-7 && d2(from, to) < 1e-12) {
        sweep = ccw ? Math.PI * 2 : -Math.PI * 2;    // 起止重合 → 整圆
      }
      const steps = arcSteps(Math.max(a, b2), sweep);
      const out = [];
      for (let i = 0; i <= steps; i++) {
        const t = t0 + sweep * (i / steps);
        out.push([
          O[0] + a * Math.cos(t) * X[0] + b2 * Math.sin(t) * Y[0],
          O[1] + a * Math.cos(t) * X[1] + b2 * Math.sin(t) * Y[1],
          O[2] + a * Math.cos(t) * X[2] + b2 * Math.sin(t) * Y[2]
        ]);
      }
      return out;
    }

    function sampleCurve(curve, from, to, ccw, depth) {
      if (!curve || (depth || 0) > 4) return [from, to];
      const t = curve.type;

      if (t === 'LINE') return [from, to];

      if (t === 'CIRCLE') {
        const ax = axis2(get(arg(curve, 1)));
        const r = num(arg(curve, 2)) * scale;
        return r > EPS ? sampleArc(ax.o, ax.x, ax.y, r, r, from, to, ccw) : [from, to];
      }
      if (t === 'ELLIPSE') {
        const ax = axis2(get(arg(curve, 1)));
        const a = num(arg(curve, 2)) * scale;
        const b2 = num(arg(curve, 3)) * scale;
        return (a > EPS && b2 > EPS)
          ? sampleArc(ax.o, ax.x, ax.y, a, b2, from, to, ccw) : [from, to];
      }
      // 复合/包络曲线：向里追一层
      if (t === 'SURFACE_CURVE' || t === 'SEAM_CURVE' || t === 'INTERSECTION_CURVE') {
        return sampleCurve(get(arg(curve, 1)), from, to, ccw, (depth || 0) + 1);
      }
      if (t === 'TRIMMED_CURVE') {
        const basis = get(arg(curve, 1));
        const p1 = pointOf(get(arg(curve, 2)));
        const p2 = pointOf(get(arg(curve, 3)));
        return sampleCurve(basis, p1, p2, ccw, (depth || 0) + 1);
      }
      // B_SPLINE_CURVE 等：先用弦代替（会损失圆角精度，已计入统计）
      stats.curveFallback++;
      return [from, to];
    }

    function vertexPoint(vp) {
      return pointOf(get(arg(vp, 1)));
    }

    // EDGE_CURVE('',#v1,#v2,#curve,.T.)
    // 圆弧的行进方向由两个布尔量共同决定：
    //   ORIENTED_EDGE 的 orientation —— 这条边相对 EDGE_CURVE 的 v1→v2 是否正向
    //   EDGE_CURVE 的 same_sense    —— v1→v2 是否等于曲线参数增大的方向
    // 两者相同则沿参数增大方向走，不同则反向（异或）。
    // 忽略 same_sense 会让圆弧绕远路，几何被撑得很大。
    function edgePolyline(edge, orient) {
      const p1 = vertexPoint(get(arg(edge, 1)));
      const p2 = vertexPoint(get(arg(edge, 2)));
      const curve = get(arg(edge, 3));
      const ss = arg(edge, 4);
      const sameSense = !(ss && ss.enum === 'F');

      const from = orient ? p1 : p2;
      const to = orient ? p2 : p1;
      const ccw = (orient === sameSense);
      return sampleCurve(curve, from, to, ccw, 0);
    }

    // EDGE_LOOP('',(#oriented_edge,...)) → 有序 3D 点环
    function loopPoints(loop) {
      const refs = arg(loop, 1);
      const out = [];
      if (!Array.isArray(refs)) return out;

      for (const r of refs) {
        const oe = get(r);
        if (!oe || oe.type !== 'ORIENTED_EDGE') continue;
        const edge = get(arg(oe, 3));
        if (!edge) continue;
        const ori = arg(oe, 4);
        const forward = !(ori && ori.enum === 'F');
        for (const p of edgePolyline(edge, forward)) {
          const last = out[out.length - 1];
          if (last && d2(last, p) < 1e-14) continue;
          out.push(p);
        }
      }
      if (out.length > 1 && d2(out[0], out[out.length - 1]) < 1e-14) out.pop();
      return out;
    }

    // ---- 把闭合环投影到平面坐标 ----
    function to2D(pts, ax) {
      return pts.map(p => {
        const d = sub(p, ax.o);
        return [dot(d, ax.x), dot(d, ax.y)];
      });
    }

    // ---- 面 ----
    function emitPlanarFace(face, surf, ax) {
      const boundRefs = arg(face, 1);
      if (!Array.isArray(boundRefs)) { stats.planarFail.noBound = (stats.planarFail.noBound || 0) + 1; return false; }

      const loops = [];
      for (const br of boundRefs) {
        const bound = get(br);
        if (!bound) continue;
        const pts = loopPoints(get(arg(bound, 1)));
        if (pts.length >= 3) loops.push(pts);
      }
      if (!loops.length) { stats.planarFail.shortLoop = (stats.planarFail.shortLoop || 0) + 1; return false; }

      // 面积最大的当外环，其余当洞。用解析出的 2D 有向面积判断。
      let outer2D = null, outerArea = -1, hole2D = [];
      const flat = loops.map(pts => to2D(pts, ax));
      for (const r2 of flat) {
        let a2 = 0;
        for (let i = 0; i < r2.length; i++) {
          const p = r2[i], q = r2[(i + 1) % r2.length];
          a2 += p[0] * q[1] - q[0] * p[1];
        }
        a2 = Math.abs(a2) / 2;
        if (a2 > outerArea) {
          if (outer2D) hole2D.push(outer2D);
          outerArea = a2;
          outer2D = r2;
        } else {
          hole2D.push(r2);
        }
      }
      if (!outer2D || outer2D.length < 3) { stats.planarFail.degenerate = (stats.planarFail.degenerate || 0) + 1; return false; }

      // 自检：参数域内的净面积（外环 - 各洞），应与三角化面积相吻合
      const ringArea = r => {
        let a2 = 0;
        for (let i = 0; i < r.length; i++) {
          const p = r[i], q = r[(i + 1) % r.length];
          a2 += p[0] * q[1] - q[0] * p[1];
        }
        return Math.abs(a2) / 2;
      };
      let net = ringArea(outer2D);
      for (const h of hole2D) net -= ringArea(h);
      stats.polyArea += Math.max(net, 0);

      const tri = triangulateRings(outer2D, hole2D);
      if (tri.fallback) {
        stats.triFallback++;      // 耳切卡住走了扇形兜底 → 面积会偏大
        if (opts.onFallback) opts.onFallback(outer2D, hole2D);
      }
      if (!tri.tris.length) { stats.planarFail.noTri = (stats.planarFail.noTri || 0) + 1; return false; }

      const mesh = global.KiPreview.Mesh3D;
      for (const t of tri.tris) {
        const a2 = tri.verts[t[0]], b2 = tri.verts[t[1]], c2 = tri.verts[t[2]];
        stats.triArea += Math.abs(
          (b2[0] - a2[0]) * (c2[1] - a2[1]) - (b2[1] - a2[1]) * (c2[0] - a2[0])) / 2;
        mesh.addTriangle(b,
          planeTo3D(a2, ax), planeTo3D(b2, ax), planeTo3D(c2, ax), COL_SOLID);
      }
      return true;
    }

    function planeTo3D(p, ax) {
      return [
        ax.o[0] + p[0] * ax.x[0] + p[1] * ax.y[0],
        ax.o[1] + p[0] * ax.x[1] + p[1] * ax.y[1],
        ax.o[2] + p[0] * ax.x[2] + p[1] * ax.y[2]
      ];
    }

    function emitWireLoop(loop) {
      const pts = loop;
      if (pts.length < 2) return;
      const mesh = global.KiPreview.Mesh3D;
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i], c = pts[(i + 1) % pts.length];
        if (d2(a, c) < 1e-14) continue;
        mesh.addQuad(b,
          [a[0], a[1] + WIRE_R, a[2]], [c[0], c[1] + WIRE_R, c[2]],
          [c[0], c[1] - WIRE_R, c[2]], [a[0], a[1] - WIRE_R, a[2]], COL_WIRE);
        mesh.addQuad(b,
          [a[0] + WIRE_R, a[1], a[2]], [c[0] + WIRE_R, c[1], c[2]],
          [c[0] - WIRE_R, c[1], c[2]], [a[0] - WIRE_R, a[1], a[2]], COL_WIRE);
        stats.wireEdges++;
      }
    }

    // ---- 遍历所有面 ----
    for (const e of ents.values()) {
      if (e.type !== 'ADVANCED_FACE' && e.type !== 'FACE_SURFACE') continue;
      stats.faces++;

      const surf = get(arg(e, 2));
      const st = surf ? surf.type : '(无)';

      if (st === 'PLANE') {
        const ax = axis2(get(arg(surf, 1)));
        if (emitPlanarFace(e, surf, ax)) stats.planar++;
        else stats.skipped[st] = (stats.skipped[st] || 0) + 1;
      } else {
        stats.skipped[st] = (stats.skipped[st] || 0) + 1;
        if (wantWire) {
          const boundRefs = arg(e, 1);
          if (Array.isArray(boundRefs)) {
            for (const br of boundRefs) {
              const bound = get(br);
              if (!bound) continue;
              const pts = loopPoints(get(arg(bound, 1)));
              if (pts.length >= 2) emitWireLoop(pts);
            }
          }
        }
      }
    }

    const mesh = global.KiPreview.Mesh3D.finish(b);
    mesh.bounds = computeBounds(mesh.pos);
    mesh.stats = stats;
    return mesh;
  }

  function computeBounds(pos) {
    const min = [Infinity, Infinity, Infinity];
    const max = [-Infinity, -Infinity, -Infinity];
    for (let i = 0; i < pos.length; i += 3) {
      for (let k = 0; k < 3; k++) {
        const v = pos[i + k];
        if (v < min[k]) min[k] = v;
        if (v > max[k]) max[k] = v;
      }
    }
    if (!isFinite(min[0])) return { min: [0, 0, 0], max: [0, 0, 0] };
    return { min, max };
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.ParserStep = {
    // 统一入口（所有 parser 同一签名）：string 或 ArrayBuffer → 网格
    parse: function (source) {
      const text = (typeof source === 'string')
        ? source
        : new TextDecoder('utf-8').decode(source);
      return buildMesh(text);
    },
    // 低层接口，便于测试与复用
    parsePart21,
    tokenize,
    buildMesh,
    computeBounds,
    implemented: true
  };
})(window);
