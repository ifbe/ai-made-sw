(function (global) {
  'use strict';

  // 二维多边形三角化（支持洞）。
  // 目前服务于 PCB 板框挤出，后续 STEP 的平面面（PLANE + FACE_BOUND/EDGE_LOOP）
  // 也走这里，所以这一层不包含任何 KiCad 相关知识，只处理 [[x,y], ...]。
  //
  // 输入 rings: 任意顺序的环数组，每个环是 [[x,y], ...]（不重复首点）
  // 输出 { verts: [[x,y],...], tris: [[i,j,k],...] }，索引指向 verts

  const EPS = 1e-9;

  function signedArea(ring) {
    let a = 0;
    const n = ring.length;
    for (let i = 0; i < n; i++) {
      const p = ring[i], q = ring[(i + 1) % n];
      a += p[0] * q[1] - q[0] * p[1];
    }
    return a / 2;
  }

  // 返回 X 最大的顶点下标
  function ringMaxX(ring) {
    let m = -Infinity, idx = 0;
    for (let i = 0; i < ring.length; i++) {
      if (ring[i][0] > m) { m = ring[i][0]; idx = i; }
    }
    return idx;
  }

  function pointInTriangle(px, py, ax, ay, bx, by, cx, cy) {
    const d1 = (px - bx) * (ay - by) - (ax - bx) * (py - by);
    const d2 = (px - cx) * (by - cy) - (bx - cx) * (py - cy);
    const d3 = (px - ax) * (cy - ay) - (cx - ax) * (py - ay);
    const neg = d1 < 0 || d2 < 0 || d3 < 0;
    const pos = d1 > 0 || d2 > 0 || d3 > 0;
    return !(neg && pos);
  }

  // 射线法，用于判断环的包含关系（区分外框与洞）
  function pointInRing(px, py, ring) {
    let inside = false;
    const n = ring.length;
    for (let i = 0, j = n - 1; i < n; j = i++) {
      const xi = ring[i][0], yi = ring[i][1];
      const xj = ring[j][0], yj = ring[j][1];
      if ((yi > py) !== (yj > py) &&
          px < (xj - xi) * (py - yi) / (yj - yi) + xi) {
        inside = !inside;
      }
    }
    return inside;
  }

  // 把 poly 按包含关系分组：每组一个外环 + 若干洞（按奇偶嵌套深度判定）
  function groupRings(rings) {
    const clean = rings.filter(r => r && r.length >= 3);
    const groups = [];
    if (!clean.length) return groups;

    const info = clean.map((r, i) => ({
      i,
      ring: r,
      area: Math.abs(signedArea(r)),
      parent: -1,
      depth: 0
    }));

    // 为每个环找最小的包含它的环作为父环
    for (const a of info) {
      let best = -1, bestArea = Infinity;
      const probe = a.ring[0];
      for (const b of info) {
        if (a === b) continue;
        if (b.area <= a.area) continue;
        if (!pointInRing(probe[0], probe[1], b.ring)) continue;
        if (b.area < bestArea) { bestArea = b.area; best = b.i; }
      }
      a.parent = best;
    }

    // 深度 = 祖先数量
    for (const a of info) {
      let d = 0, p = a.parent, guard = 0;
      while (p >= 0 && guard++ < info.length) {
        d++;
        p = info.find(x => x.i === p).parent;
      }
      a.depth = d;
    }

    for (const a of info) {
      if (a.depth % 2 !== 0) continue;   // 奇数深度是洞，由父组吸收
      const holes = info
        .filter(b => b.depth === a.depth + 1 && b.parent === a.i)
        .map(b => b.ring);
      groups.push({ outer: a.ring, holes, area: a.area });
    }
    groups.sort((x, y) => y.area - x.area);
    return groups;
  }

  // 从洞的最高点向右投射，找到外环上可见的顶点，把洞"焊"进外环。
  //
  // 单洞的面上朴素射线法就够了；但 STEP 里常见一个平面带 8~24 个洞
  // （引脚阵列、过孔阵列），朴素做法会挑到与已有边交叉的桥接点，
  // 拼出来的多边形自交，耳切随即卡住并退化成扇形兜底（面积虚高、洞被填掉）。
  // 所以这里对桥接边做可见性校验，不通过就换候选。

  function samePt(a, b) {
    return Math.abs(a[0] - b[0]) < 1e-12 && Math.abs(a[1] - b[1]) < 1e-12;
  }

  // 两线段是否真交叉（共享端点不算）
  function segCross(a, b, c, d) {
    if (samePt(a, c) || samePt(a, d) || samePt(b, c) || samePt(b, d)) return false;
    const side = (p, q, r) =>
      (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0]);
    const s1 = side(a, b, c), s2 = side(a, b, d);
    const s3 = side(c, d, a), s4 = side(c, d, b);
    return (s1 > 0) !== (s2 > 0) && (s3 > 0) !== (s4 > 0);
  }

  // M→poly[pIdx] 这条桥接边是否与现有边相交
  function bridgeClear(poly, hole, M, pIdx) {
    const P = poly[pIdx];
    for (let i = 0; i < poly.length; i++) {
      const a = poly[i], b = poly[(i + 1) % poly.length];
      if (samePt(a, P) || samePt(b, P)) continue;
      if (segCross(M, P, a, b)) return false;
    }
    for (let i = 0; i < hole.length; i++) {
      const a = hole[i], b = hole[(i + 1) % hole.length];
      if (samePt(a, M) || samePt(b, M)) continue;
      if (segCross(M, P, a, b)) return false;
    }
    return true;
  }

  function spliceHole(poly, hole, mi, pIdx) {
    return poly.slice(0, pIdx + 1)
      .concat(hole.slice(mi))
      .concat(hole.slice(0, mi + 1))
      .concat([poly[pIdx]])
      .concat(poly.slice(pIdx + 1));
  }

  // 标准射线法：向右投射，取命中边中 x 较大的端点，再用凹顶点细化
  function rayCastCandidate(poly, M) {
    const n = poly.length;
    let bestT = Infinity, bestEdge = -1;
    for (let i = 0; i < n; i++) {
      const a = poly[i], b = poly[(i + 1) % n];
      if ((a[1] > M[1]) === (b[1] > M[1])) continue;
      const t = a[0] + (b[0] - a[0]) * (M[1] - a[1]) / (b[1] - a[1]);
      if (t >= M[0] - EPS && t < bestT) { bestT = t; bestEdge = i; }
    }
    if (bestEdge < 0) return -1;

    const e0 = bestEdge, e1 = (bestEdge + 1) % n;
    let pIdx = poly[e0][0] > poly[e1][0] ? e0 : e1;

    const I = [bestT, M[1]];
    let bestAng = Infinity;
    for (let i = 0; i < n; i++) {
      if (i === pIdx) continue;
      const v = poly[i];
      if (!pointInTriangle(v[0], v[1], M[0], M[1], I[0], I[1],
                           poly[pIdx][0], poly[pIdx][1])) continue;
      const prev = poly[(i - 1 + n) % n], next = poly[(i + 1) % n];
      const cross = (v[0] - prev[0]) * (next[1] - v[1]) -
                    (v[1] - prev[1]) * (next[0] - v[0]);
      if (cross >= 0) continue;           // 只考虑凹顶点
      const ang = Math.abs(Math.atan2(v[1] - M[1], v[0] - M[0]));
      if (ang < bestAng) { bestAng = ang; pIdx = i; }
    }
    return pIdx;
  }

  function bridgeHole(poly, hole) {
    const mi = ringMaxX(hole);
    const M = hole[mi];

    // 快路径：单洞或布局简单的面走这里，结果通常就对
    const fast = rayCastCandidate(poly, M);
    if (fast >= 0 && bridgeClear(poly, hole, M, fast)) {
      return spliceHole(poly, hole, mi, fast);
    }

    // 慢路径：所有可见顶点里挑方向最接近 +X 的
    let bestP = -1, bestAng = Infinity;
    for (let i = 0; i < poly.length; i++) {
      if (!bridgeClear(poly, hole, M, i)) continue;
      const v = poly[i];
      const dx = v[0] - M[0], dy = v[1] - M[1];
      let ang = Math.abs(Math.atan2(dy, dx));
      if (dx < 0) ang = Math.PI + ang;    // 优先朝向 +X
      if (ang < bestAng) { bestAng = ang; bestP = i; }
    }
    if (bestP < 0) return poly;           // 找不到可见点，放弃该洞
    return spliceHole(poly, hole, mi, bestP);
  }

  function eliminateHoles(outer, holes) {
    let poly = signedArea(outer) < 0 ? outer.slice().reverse() : outer.slice();
    const hs = holes
      .filter(h => h && h.length >= 3)
      .map(h => (signedArea(h) > 0 ? h.slice().reverse() : h.slice()));  // 洞取反向
    hs.sort((a, b) => b[ringMaxX(b)][0] - a[ringMaxX(a)][0]);
    for (const h of hs) poly = bridgeHole(poly, h);
    return poly;
  }

  // 桥接会在多边形里留下位置完全重合的重复顶点（洞的接缝）。
  // 做内点测试时必须跳过它们，否则这些"贴在自己边界上"的点会把合法的耳全部堵死，
  // 导致 earClip 卡住并退化成扇形兜底（面积虚高、洞也扣不掉）。
  function samePoint(p, q) {
    return Math.abs(p[0] - q[0]) < 1e-12 && Math.abs(p[1] - q[1]) < 1e-12;
  }

  // 严格内部判定，只用于卡住时给候选打分
  function strictlyInside(px, py, ax, ay, bx, by, cx, cy) {
    const d1 = (px - bx) * (ay - by) - (ax - bx) * (py - by);
    const d2 = (px - cx) * (by - cy) - (bx - cx) * (py - cy);
    const d3 = (px - ax) * (cy - ay) - (cx - ax) * (py - ay);
    return d1 > 0 && d2 > 0 && d3 > 0;
  }

  function earClip(poly) {
    const n = poly.length;
    const tris = [];
    let fallback = false;
    if (n < 3) return { tris, fallback };

    const idx = [];
    for (let i = 0; i < n; i++) idx.push(i);

    // 每个顶点被多少条边"看到"，用来给卡住时的候选打分
    function insideCount(ia, ib, ic) {
      const a = poly[ia], b = poly[ib], c = poly[ic];
      let cnt = 0;
      for (let j = 0; j < idx.length; j++) {
        const ij = idx[j];
        if (ij === ia || ij === ib || ij === ic) continue;
        const p = poly[ij];
        if (samePoint(p, a) || samePoint(p, b) || samePoint(p, c)) continue;
        if (strictlyInside(p[0], p[1], a[0], a[1], b[0], b[1], c[0], c[1])) cnt++;
      }
      return cnt;
    }

    let guard = 0;
    const maxGuard = n * n + 100;
    while (idx.length > 3 && guard++ < maxGuard) {
      let found = false;
      for (let i = 0; i < idx.length; i++) {
        const ia = idx[(i - 1 + idx.length) % idx.length];
        const ib = idx[i];
        const ic = idx[(i + 1) % idx.length];
        const a = poly[ia], b = poly[ib], c = poly[ic];
        // 只剪凸角
        const cross = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]);
        if (cross <= EPS) continue;
        let ok = true;
        for (let j = 0; j < idx.length; j++) {
          const ij = idx[j];
          if (ij === ia || ij === ib || ij === ic) continue;
          const p = poly[ij];
          if (samePoint(p, a) || samePoint(p, b) || samePoint(p, c)) continue;
          if (pointInTriangle(p[0], p[1], a[0], a[1], b[0], b[1], c[0], c[1])) {
            ok = false;
            break;
          }
        }
        if (!ok) continue;
        tris.push([ia, ib, ic]);
        idx.splice(i, 1);
        found = true;
        break;
      }

      if (!found) {
        // 卡住。多洞面经桥接后会出现"零宽缝"，缝两侧的顶点会让所有候选耳都被判掉。
        // 这时不再整块退化成扇形（那是全局重叠、面积能差一倍以上），
        // 而是挑一个"最不坏"的凸角剪掉：被最少顶点挡住、面积最大者。
        // 代价只落在局部，而且保证一定推进，不会死锁。
        fallback = true;
        let bestI = -1, bestCnt = Infinity, bestCross = -1;
        for (let i = 0; i < idx.length; i++) {
          const ia = idx[(i - 1 + idx.length) % idx.length];
          const ib = idx[i];
          const ic = idx[(i + 1) % idx.length];
          const a = poly[ia], b = poly[ib], c = poly[ic];
          const cross = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]);
          if (cross <= EPS) continue;
          const cnt = insideCount(ia, ib, ic);
          if (cnt < bestCnt || (cnt === bestCnt && cross > bestCross)) {
            bestCnt = cnt; bestCross = cross; bestI = i;
          }
        }
        if (bestI < 0) break;              // 只剩共线点，交给下面的收尾
        const ia = idx[(bestI - 1 + idx.length) % idx.length];
        const ib = idx[bestI];
        const ic = idx[(bestI + 1) % idx.length];
        tris.push([ia, ib, ic]);
        idx.splice(bestI, 1);
      }
    }

    if (idx.length === 3) {
      tris.push([idx[0], idx[1], idx[2]]);
    } else if (idx.length > 3) {
      // 兜底：扇形补齐，宁可多画也别留空洞。
      // 凹多边形上这会产出重叠三角形，面积随之偏大，所以如实上报。
      for (let i = 1; i + 1 < idx.length; i++) tris.push([idx[0], idx[i], idx[i + 1]]);
      fallback = true;
    }
    return { tris, fallback };
  }

  // 梯形扫描线三角化：带洞多边形的稳健兜底。
  //
  // 多洞面经桥接后会出现"零宽缝"，缝两侧顶点会把所有候选耳都判掉，
  // 耳切必然死锁。这时改成沿 x 切竖条，每条里求所有边与中线的交点、
  // 按 y 排序后按奇偶配对成梯形（even-odd 填充，外环与洞自动处理）。
  // 取中线判"哪些边跨过本竖条"是关键：竖条内部没有顶点，
  // 所以跨过中线的边一定贯穿整条，端点处的退化情形自然被避开。
  // 代价是同一个面会产生更多三角形，但结果一定正确。
  function slabTriangulate(rings) {
    const valid = rings.filter(r => r && r.length >= 3);
    if (!valid.length) return { verts: [], tris: [] };

    const xs = [];
    for (const r of valid) for (const p of r) xs.push(p[0]);
    xs.sort((a, b) => a - b);

    const ux = [];
    for (const x of xs) if (!ux.length || x - ux[ux.length - 1] > 1e-12) ux.push(x);
    if (ux.length < 2) return { verts: [], tris: [] };

    const verts = [];
    const tris = [];
    const push = p => { verts.push(p); return verts.length - 1; };

    for (let s = 0; s + 1 < ux.length; s++) {
      const xl = ux[s], xr = ux[s + 1];
      const xm = (xl + xr) / 2;

      const cross = [];
      for (const r of valid) {
        for (let k = 0; k < r.length; k++) {
          const a = r[k], b = r[(k + 1) % r.length];
          if ((a[0] <= xm) === (b[0] <= xm)) continue;   // 没跨过中线
          if (a[0] === b[0]) continue;
          cross.push({ a, b });
        }
      }
      if (cross.length < 2) continue;

      for (const e of cross) {
        const dx = e.b[0] - e.a[0];
        e.yl = e.a[1] + (e.b[1] - e.a[1]) * (xl - e.a[0]) / dx;
        e.yr = e.a[1] + (e.b[1] - e.a[1]) * (xr - e.a[0]) / dx;
      }
      cross.sort((p, q) => p.yl - q.yl);

      for (let k = 0; k + 1 < cross.length; k += 2) {
        const lo = cross[k], hi = cross[k + 1];
        if (Math.abs(hi.yl - lo.yl) < 1e-12 && Math.abs(hi.yr - lo.yr) < 1e-12) continue;
        const i0 = push([xl, lo.yl]);
        const i1 = push([xr, lo.yr]);
        const i2 = push([xr, hi.yr]);
        const i3 = push([xl, hi.yl]);
        tris.push([i0, i1, i2], [i0, i2, i3]);
      }
    }
    return { verts, tris };
  }

  // 单组：一个外环 + 若干洞 → { verts, tris, fallback }
  function triangulateRings(outer, holes) {
    if (!outer || outer.length < 3) return { verts: [], tris: [], fallback: false };
    const hs = holes || [];
    const poly = eliminateHoles(outer, hs);
    const r = earClip(poly);
    if (!r.fallback) return { verts: poly, tris: r.tris, fallback: false };

    // 耳切死锁 → 换扫描线，保证几何正确
    const slab = slabTriangulate([outer].concat(hs));
    if (slab.tris.length) {
      return { verts: slab.verts, tris: slab.tris, fallback: true, slab: true };
    }
    return { verts: poly, tris: r.tris, fallback: true };
  }

  // 多组：自动按包含关系分组后逐组三角化
  function triangulate(rings) {
    const groups = groupRings(rings);
    const verts = [], tris = [];
    for (const g of groups) {
      const r = triangulateRings(g.outer, g.holes);
      const base = verts.length;
      for (const v of r.verts) verts.push(v);
      for (const t of r.tris) tris.push([t[0] + base, t[1] + base, t[2] + base]);
    }
    return { verts, tris };
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Triangulate = {
    signedArea,
    pointInRing,
    groupRings,
    triangulateRings,
    triangulate
  };
})(window);
