(function (global) {
  'use strict';

  // VRML 2.0 (.wrl) 解析器 —— KiCad 旧版 3D 模型格式，零依赖纯 JS。
  //
  // 实测 KiCad 官方库 6189 个 .wrl：
  //   全部是 "#VRML V2.0 utf8"，0 个用 VRML 1.0 语法（Separator/Coordinate3）
  //   0 个含 Normal 节点      → 法线要按 creaseAngle 自己算平滑
  //   3 个含 Transform 节点   → 几何基本已在模型本地坐标系，变换只是兜底
  //   全部大量使用 DEF/USE    → 材质节点被复用上万次，必须支持节点引用
  //
  // 结构与 STEP 相比简单得多：IndexedFaceSet 里 coordIndex 已经是三角形
  // （-1 是面结束符），所以不需要 B-rep、曲面求值或三角化。
  //
  // 单位：KiCad 的 VRML 模型以 0.1 英寸为单位，乘 2.54 才是 mm。
  // （把同一模型的 .wrl 与 .step 包围盒对比，12 个模型的比例全部精确等于 2.54）

  const SCALE = 2.54;
  const DEFAULT_COLOR = [0.72, 0.73, 0.77];

  // ============ 1. 词法 ============

  function tokenize(src) {
    const toks = [];
    const n = src.length;
    let i = 0;

    while (i < n) {
      const c = src[i];

      // 空白与逗号（VRML 里逗号只是分隔符，不需要保留）
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === ',') { i++; continue; }

      // # 注释到行尾（首行的 "#VRML V2.0 utf8" 也是注释）
      if (c === '#') { while (i < n && src[i] !== '\n') i++; continue; }

      if (c === '{' || c === '}' || c === '[' || c === ']') { toks.push(c); i++; continue; }

      if (c === '"') {
        let j = i + 1, out = '';
        while (j < n && src[j] !== '"') out += src[j++];
        toks.push({ str: out });
        i = j + 1;
        continue;
      }

      // 数字（含 -1 这类面结束符）
      const num = /^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?/.exec(src.slice(i, i + 64));
      if (num) { toks.push(parseFloat(num[0])); i += num[0].length; continue; }

      // 标识符。官方规范是 [A-Za-z_][A-Za-z0-9_]*，但真实文件里
      // 出现了 "DEF MET-01 Material" 这种带连字符的名字，所以允许连字符。
      const id = /^[A-Za-z_][A-Za-z0-9_\-]*/.exec(src.slice(i, i + 128));
      if (id) { toks.push(id[0]); i += id[0].length; continue; }

      i++;   // 无法识别，跳过
    }
    return toks;
  }

  // ============ 2. 语法 → 节点树 ============

  function parseVrml(toks) {
    let p = 0;
    const defs = Object.create(null);

    const peek = k => toks[p + (k || 0)];
    const next = () => toks[p++];
    const isName = t => typeof t === 'string' && t !== '{' && t !== '}' && t !== '[' && t !== ']';
    const isNodeStart = () => {
      const t = peek();
      return t === 'DEF' || t === 'USE' || t === 'NULL' ||
             (isName(t) && peek(1) === '{');
    };

    function parseNode() {
      const t = peek();
      if (t === 'DEF') {
        next();
        const name = next();
        const node = parseNode();
        if (name) defs[name] = node;
        return node;
      }
      if (t === 'USE') { next(); return defs[next()] || null; }
      if (t === 'NULL') { next(); return null; }
      if (!isName(t)) { next(); return null; }

      const type = next();
      if (peek() !== '{') return null;
      next();

      const node = { type, fields: Object.create(null) };
      while (p < toks.length && peek() !== '}') {
        const fname = next();
        if (!isName(fname)) break;
        node.fields[fname] = parseValue();
      }
      if (peek() === '}') next();
      return node;
    }

    function parseValue() {
      const t = peek();
      if (t === '[') return parseList();
      if (isNodeStart()) return parseNode();

      // 标量序列：读到下一个字段名/括号为止
      const out = [];
      for (;;) {
        const v = peek();
        if (typeof v === 'number') { out.push(next()); continue; }
        if (v === 'TRUE') { next(); out.push(true); continue; }
        if (v === 'FALSE') { next(); out.push(false); continue; }
        if (v && typeof v === 'object' && 'str' in v) { out.push(next().str); continue; }
        break;
      }
      return out.length === 1 ? out[0] : out;
    }

    function parseList() {
      next();                                  // '['
      const out = [];
      while (p < toks.length && peek() !== ']') {
        const t = peek();
        if (t === 'DEF' || t === 'USE' || t === 'NULL' || (isName(t) && peek(1) === '{')) {
          out.push(parseNode());
        } else if (typeof t === 'number') {
          out.push(next());
        } else if (t === 'TRUE' || t === 'FALSE') {
          out.push(next() === 'TRUE');
        } else {
          next();                              // 跳过无法识别的记号
        }
      }
      if (peek() === ']') next();
      return out;
    }

    const roots = [];
    let guard = 0;
    while (p < toks.length && guard++ < toks.length + 8) {
      const before = p;
      const node = parseNode();
      if (node) roots.push(node);
      if (p === before) p++;                   // 防止死循环
    }
    return roots;
  }

  // ============ 3. 变换 ============

  const M3 = global.KiPreview.Math3D;

  // Transform 节点的 translation / rotation(轴角) / scale → 4x4
  function trsMatrix(t, r, s) {
    const tx = t || [0, 0, 0];
    const sc = s || [1, 1, 1];
    let ax = 0, ay = 0, az = 1, ang = 0;
    if (Array.isArray(r) && r.length >= 4) { ax = r[0]; ay = r[1]; az = r[2]; ang = r[3]; }
    const l = Math.hypot(ax, ay, az) || 1;
    ax /= l; ay /= l; az /= l;

    const c = Math.cos(ang), si = Math.sin(ang), q = 1 - c;
    // 行主序的旋转块
    const R = [
      q * ax * ax + c,      q * ax * ay - si * az, q * ax * az + si * ay,
      q * ax * ay + si * az, q * ay * ay + c,      q * ay * az - si * ax,
      q * ax * az - si * ay, q * ay * az + si * ax, q * az * az + c
    ];
    const out = new Float32Array(16);           // 列主序
    out[0] = R[0] * sc[0]; out[1] = R[3] * sc[0]; out[2] = R[6] * sc[0];
    out[4] = R[1] * sc[1]; out[5] = R[4] * sc[1]; out[6] = R[7] * sc[1];
    out[8] = R[2] * sc[2]; out[9] = R[5] * sc[2]; out[10] = R[10] * sc[2];
    out[12] = tx[0]; out[13] = tx[1]; out[14] = tx[2]; out[15] = 1;
    return out;
  }

  function applyM(m, p) {
    if (!m) return [p[0] * SCALE, p[1] * SCALE, p[2] * SCALE];
    const q = M3.transformPoint(m, [p[0] * SCALE, p[1] * SCALE, p[2] * SCALE]);
    return q;
  }

  // ============ 4. 场景遍历 → 三角形 ============

  function buildMesh(source) {
    const src = (typeof source === 'string')
      ? source : new TextDecoder('utf-8').decode(source);
    const roots = parseVrml(tokenize(src));

    const stats = {
      shapes: 0, faceSets: 0, polygons: 0, triangles: 0,
      vertices: 0, materials: 0, transforms: 0, useNodes: 0,
      skipped: {}, maxPolygon: 0
    };

    // pass 1：收集三角形（世界坐标、面法线、材质色、creaseAngle）
    const tris = [];

    function collect(shape, m) {
      stats.shapes++;
      const app = shape.fields.appearance;
      const geom = shape.fields.geometry;

      let color = DEFAULT_COLOR;
      if (app && app.fields && app.fields.material) {
        const mat = app.fields.material;
        const dc = mat.fields && mat.fields.diffuseColor;
        if (Array.isArray(dc) && dc.length >= 3) {
          color = [dc[0], dc[1], dc[2]];
          stats.materials++;
        }
      }

      if (!geom || geom.type !== 'IndexedFaceSet') {
        const t = geom ? geom.type : '(无几何)';
        stats.skipped[t] = (stats.skipped[t] || 0) + 1;
        return;
      }
      stats.faceSets++;

      const coordNode = geom.fields.coord;
      const pts = (coordNode && coordNode.fields && Array.isArray(coordNode.fields.point))
        ? coordNode.fields.point : null;
      const idx = geom.fields.coordIndex;
      if (!pts || !Array.isArray(idx)) {
        stats.skipped['缺 coordIndex/point'] = (stats.skipped['缺 coordIndex/point'] || 0) + 1;
        return;
      }

      const crease = (typeof geom.fields.creaseAngle === 'number') ? geom.fields.creaseAngle : 0;
      const nv = Math.floor(pts.length / 3);
      stats.vertices += nv;

      // 世界坐标顶点表（变换 + 单位换算只做一次）
      const world = new Array(nv);
      for (let i = 0; i < nv; i++) {
        world[i] = applyM(m, [pts[i * 3], pts[i * 3 + 1], pts[i * 3 + 2]]);
      }

      // coordIndex 按 -1 切分成多边形
      let face = [];
      const flush = () => {
        if (face.length >= 3) {
          stats.polygons++;
          if (face.length > stats.maxPolygon) stats.maxPolygon = face.length;
          // 面法线用 Newell 法，对非平面多边形也稳
          let nx = 0, ny = 0, nz = 0;
          for (let k = 0; k < face.length; k++) {
            const a = world[face[k]], b = world[face[(k + 1) % face.length]];
            if (!a || !b) continue;
            nx += (a[1] - b[1]) * (a[2] + b[2]);
            ny += (a[2] - b[2]) * (a[0] + b[0]);
            nz += (a[0] - b[0]) * (a[1] + b[1]);
          }
          const l = Math.hypot(nx, ny, nz);
          if (l > 1e-12) {
            const nrm = [nx / l, ny / l, nz / l];
            for (let k = 1; k + 1 < face.length; k++) {
              const a = world[face[0]], b = world[face[k]], c = world[face[k + 1]];
              if (!a || !b || !c) continue;
              tris.push({ a, b, c, n: nrm, crease, color });
            }
          }
        }
        face = [];
      };
      for (const v of idx) {
        if (typeof v !== 'number') continue;
        if (v < 0) flush();
        else face.push(v);
      }
      flush();
    }

    function walk(node, m, depth) {
      if (!node || (depth || 0) > 64) return;
      const t = node.type;

      if (t === 'Shape') { collect(node, m); return; }

      if (t === 'Transform') {
        stats.transforms++;
        const local = trsMatrix(node.fields.translation, node.fields.rotation, node.fields.scale);
        const mm = m ? M3.multiply(m, local) : local;
        for (const c of (node.fields.children || [])) walk(c, mm, (depth || 0) + 1);
        return;
      }

      if (t === 'Group' || t === 'Anchor' || t === 'Collision' ||
          t === 'Switch' || t === 'Billboard' || t === 'StaticGroup') {
        for (const c of (node.fields.children || [])) walk(c, m, (depth || 0) + 1);
        return;
      }

      if (t === 'LOD') {
        const lv = node.fields.level;
        if (Array.isArray(lv) && lv.length) walk(lv[0], m, (depth || 0) + 1);
        return;
      }

      // 顶层的 Inline / WorldInfo / Viewpoint 等忽略
    }

    for (const r of roots) walk(r, null, 0);

    // pass 2：按 creaseAngle 做法线平滑，然后输出
    // 位置 → 该处出现过的面法线集合（按法线去重）
    const posNormals = new Map();
    const keyOf = p => p[0].toFixed(4) + '|' + p[1].toFixed(4) + '|' + p[2].toFixed(4);

    for (const t of tris) {
      const nk = t.n[0].toFixed(3) + ',' + t.n[1].toFixed(3) + ',' + t.n[2].toFixed(3);
      for (const p of [t.a, t.b, t.c]) {
        const k = keyOf(p);
        let e = posNormals.get(k);
        if (!e) { e = new Map(); posNormals.set(k, e); }
        if (!e.has(nk)) e.set(nk, t.n);
      }
    }

    function smoothNormal(p, faceN, crease) {
      if (!(crease > 0)) return faceN;
      const e = posNormals.get(keyOf(p));
      if (!e || e.size < 2) return faceN;
      const cosLimit = Math.cos(crease);
      let sx = 0, sy = 0, sz = 0;
      for (const nn of e.values()) {
        if (nn[0] * faceN[0] + nn[1] * faceN[1] + nn[2] * faceN[2] >= cosLimit) {
          sx += nn[0]; sy += nn[1]; sz += nn[2];
        }
      }
      const l = Math.hypot(sx, sy, sz);
      if (l < 1e-9) return faceN;
      return [sx / l, sy / l, sz / l];
    }

    const mesh = global.KiPreview.Mesh3D;
    const b = mesh.createBuilder();
    mesh.beginElement(b, null);

    for (const t of tris) {
      mesh.pushVert(b, t.a, smoothNormal(t.a, t.n, t.crease), t.color);
      mesh.pushVert(b, t.b, smoothNormal(t.b, t.n, t.crease), t.color);
      mesh.pushVert(b, t.c, smoothNormal(t.c, t.n, t.crease), t.color);
    }
    stats.triangles = tris.length;

    const out = mesh.finish(b);
    out.bounds = computeBounds(out.pos);
    out.stats = stats;
    return out;
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
  global.KiPreview.ParserWrl = {
    // 统一入口：string 或 ArrayBuffer → 网格
    parse: buildMesh,
    buildMesh,
    tokenize,
    parseVrml,
    computeBounds,
    SCALE,
    implemented: true
  };
})(window);
