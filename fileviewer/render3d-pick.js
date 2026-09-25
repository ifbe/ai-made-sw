(function (global) {
  'use strict';

  // 3D 拾取：屏幕点 → 世界射线 → 命中哪个 PCB 元素。
  //
  // 用 CPU 射线求交而不是 GPU 颜色拾取（readPixels）：后者要额外的 FBO 和
  // 一套 id 着色器，而 CPU 这条路只需要网格里已有的数据，且能和渲染共用
  // 同一份三角形，命中结果与看到的几何完全一致。
  //
  // 性能关键在于先做粗筛：网格把每个元素的三角形存成连续区间（并带 AABB），
  // 一次点击只需对几百个元素做 AABB 测试，再对少数候选元素做三角形求交，
  // 不必遍历十几万个三角形。

  const { normalize3 } = global.KiPreview.Math3D;

  // sx / sy 是相对 canvas 左上角的 CSS 像素，w / h 是 canvas 的 CSS 尺寸
  // （与渲染时的宽高比一致）。
  function screenRay(cam, basis, sx, sy, w, h) {
    const ndcX = (sx / w) * 2 - 1;
    const ndcY = 1 - (sy / h) * 2;
    const tanHalf = Math.tan(cam.fov / 2);
    const aspect = w / h;
    const { forward, right, up } = basis;

    const kx = ndcX * aspect * tanHalf;
    const ky = ndcY * tanHalf;
    return {
      origin: basis.eye,
      dir: normalize3([
        forward[0] + right[0] * kx + up[0] * ky,
        forward[1] + right[1] * kx + up[1] * ky,
        forward[2] + right[2] * kx + up[2] * ky
      ])
    };
  }

  // 射线与 AABB（slab 法），返回入射距离，未命中返回 -1
  function rayAABB(ro, rd, min, max) {
    let t0 = 0, t1 = Infinity;
    for (let i = 0; i < 3; i++) {
      if (Math.abs(rd[i]) < 1e-12) {
        if (ro[i] < min[i] || ro[i] > max[i]) return -1;
      } else {
        const inv = 1 / rd[i];
        let a = (min[i] - ro[i]) * inv;
        let b = (max[i] - ro[i]) * inv;
        if (a > b) { const tmp = a; a = b; b = tmp; }
        if (a > t0) t0 = a;
        if (b < t1) t1 = b;
        if (t0 > t1) return -1;
      }
    }
    return t0;
  }

  // Möller–Trumbore，双面求交（与渲染端关闭背面剔除保持一致）
  function rayTriangle(ro, rd, ax, ay, az, bx, by, bz, cx, cy, cz) {
    const e1x = bx - ax, e1y = by - ay, e1z = bz - az;
    const e2x = cx - ax, e2y = cy - ay, e2z = cz - az;

    const px = rd[1] * e2z - rd[2] * e2y;
    const py = rd[2] * e2x - rd[0] * e2z;
    const pz = rd[0] * e2y - rd[1] * e2x;

    const det = e1x * px + e1y * py + e1z * pz;
    if (Math.abs(det) < 1e-12) return -1;          // 射线与三角形几乎平行
    const inv = 1 / det;

    const tx = ro[0] - ax, ty = ro[1] - ay, tz = ro[2] - az;
    const u = (tx * px + ty * py + tz * pz) * inv;
    if (u < 0 || u > 1) return -1;

    const qx = ty * e1z - tz * e1y;
    const qy = tz * e1x - tx * e1z;
    const qz = tx * e1y - ty * e1x;

    const v = (rd[0] * qx + rd[1] * qy + rd[2] * qz) * inv;
    if (v < 0 || u + v > 1) return -1;

    const t = (e2x * qx + e2y * qy + e2z * qz) * inv;
    return t > 1e-6 ? t : -1;
  }

  // 返回 { kind, index, elemId }，未命中返回 null
  function pick(mesh, cam, sx, sy, w, h) {
    if (!mesh || !mesh.count || !mesh.elems || !mesh.elems.length) return null;
    if (w < 1 || h < 1) return null;

    const basis = global.KiPreview.Camera3D.basis(cam);
    const ray = screenRay(cam, basis, sx, sy, w, h);
    const ro = ray.origin, rd = ray.dir;
    const pos = mesh.pos;

    // 粗筛：AABB 命中才进入三角形求交
    const cand = [];
    for (let i = 0; i < mesh.elems.length; i++) {
      const e = mesh.elems[i];
      if (!e.triCount) continue;
      const t = rayAABB(ro, rd, e.min, e.max);
      if (t >= 0) cand.push({ e, t });
    }
    if (!cand.length) return null;

    // 按 AABB 入射距离升序：一旦拿到命中，后面更远的元素可以直接跳过
    cand.sort((a, b) => a.t - b.t);

    let best = null;
    let bestT = Infinity;
    for (let ci = 0; ci < cand.length; ci++) {
      const e = cand[ci].e;
      if (cand[ci].t >= bestT) break;

      for (let t = e.triStart; t < e.triEnd; t++) {
        const o = t * 9;
        const hit = rayTriangle(ro, rd,
          pos[o], pos[o + 1], pos[o + 2],
          pos[o + 3], pos[o + 4], pos[o + 5],
          pos[o + 6], pos[o + 7], pos[o + 8]);
        if (hit > 0 && hit < bestT) { bestT = hit; best = e; }
      }
    }

    return best ? { kind: best.kind, index: best.index, elemId: best.id } : null;
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Pick3D = { pick, screenRay, rayAABB, rayTriangle };
})(window);
