(function (global) {
  'use strict';

  // STL 解析器 —— 零依赖纯 JS，二进制与 ASCII 两种都支持。
  //
  // 二进制：80 字节头 + uint32 三角面数，之后每面 50 字节
  //         （3 个 float 法线 + 9 个 float 顶点 + uint16 属性）
  // ASCII ：solid / facet normal / outer loop / vertex ×3 / endloop / endfacet
  //
  // 判别方式：不能只看是否以 "solid " 开头——二进制文件也可能这么写。
  // 先用长度关系 84 + 50 * n === byteLength 判二进制，否则按 ASCII 处理。
  //
  // STL 没有材质概念，统一用金属灰；个别工具会把颜色塞进二进制那个
  // uint16 属性字段（VisCAM / SolidView 约定），这里只在最高位标记有效时采用。
  //
  // 单位：STL 不自带单位，按 3D 打印惯例视为毫米。
  // 法线：按面绕序重新算，不直接信文件里的（很多文件写 0 0 0 或未归一化）。
  // STL 本质是分面几何，所以用平面着色，不做平滑。

  const DEFAULT_COLOR = [0.62, 0.64, 0.68];

  // 二进制判定：只有长度关系完全吻合才算
  function isBinary(buf) {
    if (!buf || buf.byteLength < 84) return false;
    const n = new DataView(buf).getUint32(80, true);
    return 84 + 50 * n === buf.byteLength;
  }

  function toArrayBuffer(source) {
    if (source instanceof ArrayBuffer) return source;
    if (ArrayBuffer.isView(source)) {
      return source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength);
    }
    return null;
  }

  // 用绕序算面法线；退化时退回文件给的法线，再不行给 +Z
  function faceNormal(ax, ay, az, bx, by, bz, cx, cy, cz, fx, fy, fz) {
    const ux = bx - ax, uy = by - ay, uz = bz - az;
    const vx = cx - ax, vy = cy - ay, vz = cz - az;
    let nx = uy * vz - uz * vy;
    let ny = uz * vx - ux * vz;
    let nz = ux * vy - uy * vx;
    const l = Math.hypot(nx, ny, nz);
    if (l > 1e-12) return [nx / l, ny / l, nz / l];

    const fl = Math.hypot(fx, fy, fz);
    if (fl > 1e-12) return [fx / fl, fy / fl, fz / fl];
    return [0, 0, 1];
  }

  function emptyResult() {
    return {
      pos: new Float32Array(0), nrm: new Float32Array(0), col: new Float32Array(0),
      elems: [], count: 0,
      bounds: { min: [0, 0, 0], max: [0, 0, 0] },
      stats: { format: '?', triangles: 0, colored: 0 }
    };
  }

  function parseBinary(buf, opts, countOverride) {
    const dv = new DataView(buf);
    const n = (countOverride !== undefined) ? countOverride : dv.getUint32(80, true);

    // 三角形数已知，直接按最终尺寸分配，避免用 JS 数组中转（大文件两三倍内存）
    const pos = new Float32Array(n * 9);
    const nrm = new Float32Array(n * 9);
    const col = new Float32Array(n * 9);

    const min = [Infinity, Infinity, Infinity];
    const max = [-Infinity, -Infinity, -Infinity];
    let colored = 0;
    const base = opts && opts.color ? opts.color : DEFAULT_COLOR;

    let off = 84;
    for (let i = 0; i < n; i++) {
      const fx = dv.getFloat32(off, true);
      const fy = dv.getFloat32(off + 4, true);
      const fz = dv.getFloat32(off + 8, true);
      const p = off + 12;

      const ax = dv.getFloat32(p, true), ay = dv.getFloat32(p + 4, true), az = dv.getFloat32(p + 8, true);
      const bx = dv.getFloat32(p + 12, true), by = dv.getFloat32(p + 16, true), bz = dv.getFloat32(p + 20, true);
      const cx = dv.getFloat32(p + 24, true), cy = dv.getFloat32(p + 28, true), cz = dv.getFloat32(p + 32, true);
      const attr = dv.getUint16(p + 36, true);
      off += 50;

      // VisCAM / SolidView：最高位为 1 时低 15 位是 5-5-5 的 RGB
      let c = base;
      if (attr & 0x8000) {
        c = [
          ((attr >> 10) & 0x1f) / 31,
          ((attr >> 5) & 0x1f) / 31,
          (attr & 0x1f) / 31
        ];
        colored++;
      }

      const nv = faceNormal(ax, ay, az, bx, by, bz, cx, cy, cz, fx, fy, fz);
      const o = i * 9;
      const xs = [ax, bx, cx], ys = [ay, by, cy], zs = [az, bz, cz];
      for (let k = 0; k < 3; k++) {
        pos[o + k * 3] = xs[k]; pos[o + k * 3 + 1] = ys[k]; pos[o + k * 3 + 2] = zs[k];
        nrm[o + k * 3] = nv[0]; nrm[o + k * 3 + 1] = nv[1]; nrm[o + k * 3 + 2] = nv[2];
        col[o + k * 3] = c[0]; col[o + k * 3 + 1] = c[1]; col[o + k * 3 + 2] = c[2];
        if (xs[k] < min[0]) min[0] = xs[k];
        if (ys[k] < min[1]) min[1] = ys[k];
        if (zs[k] < min[2]) min[2] = zs[k];
        if (xs[k] > max[0]) max[0] = xs[k];
        if (ys[k] > max[1]) max[1] = ys[k];
        if (zs[k] > max[2]) max[2] = zs[k];
      }
    }

    return {
      pos, nrm, col, elems: [], count: n * 3,
      bounds: isFinite(min[0]) ? { min, max } : { min: [0, 0, 0], max: [0, 0, 0] },
      stats: { format: 'binary', triangles: n, colored }
    };
  }

  const VERTEX_RE_SRC = 'vertex\\s+([-+0-9.eE]+)[\\s,]+([-+0-9.eE]+)[\\s,]+([-+0-9.eE]+)';

  function parseAscii(text, opts) {
    // 先数一遍顶点，好按最终尺寸分配（正则用局部实例，避免 lastIndex 串扰）
    let count = 0;
    let re = new RegExp(VERTEX_RE_SRC, 'g');
    while (re.exec(text)) count++;
    const n = Math.floor(count / 3);
    if (!n) return emptyResult();

    const pos = new Float32Array(n * 9);
    const nrm = new Float32Array(n * 9);
    const col = new Float32Array(n * 9);
    const min = [Infinity, Infinity, Infinity];
    const max = [-Infinity, -Infinity, -Infinity];
    const base = opts && opts.color ? opts.color : DEFAULT_COLOR;

    const v = new Float32Array(9);
    let vi = 0, ti = 0;
    re = new RegExp(VERTEX_RE_SRC, 'g');
    let m;
    while ((m = re.exec(text))) {
      v[vi * 3] = parseFloat(m[1]);
      v[vi * 3 + 1] = parseFloat(m[2]);
      v[vi * 3 + 2] = parseFloat(m[3]);
      vi++;
      if (vi === 3) {
        const nv = faceNormal(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], 0, 0, 0);
        const o = ti * 9;
        for (let k = 0; k < 3; k++) {
          const x = v[k * 3], y = v[k * 3 + 1], z = v[k * 3 + 2];
          pos[o + k * 3] = x; pos[o + k * 3 + 1] = y; pos[o + k * 3 + 2] = z;
          nrm[o + k * 3] = nv[0]; nrm[o + k * 3 + 1] = nv[1]; nrm[o + k * 3 + 2] = nv[2];
          col[o + k * 3] = base[0]; col[o + k * 3 + 1] = base[1]; col[o + k * 3 + 2] = base[2];
          if (x < min[0]) min[0] = x;
          if (y < min[1]) min[1] = y;
          if (z < min[2]) min[2] = z;
          if (x > max[0]) max[0] = x;
          if (y > max[1]) max[1] = y;
          if (z > max[2]) max[2] = z;
        }
        vi = 0;
        ti++;
      }
    }

    return {
      pos, nrm, col, elems: [], count: ti * 3,
      bounds: { min, max },
      stats: { format: 'ascii', triangles: ti, colored: 0 }
    };
  }

  // 统一入口：ArrayBuffer / TypedArray / string → 网格
  function parse(source, opts) {
    if (typeof source === 'string') {
      // 字符串只可能是 ASCII STL
      return parseAscii(source, opts);
    }
    const buf = toArrayBuffer(source);
    if (!buf) throw new Error('STL 输入必须是 ArrayBuffer 或字符串');

    if (isBinary(buf)) return parseBinary(buf, opts);

    // 长度关系不吻合：可能是 ASCII，也可能是带尾随字节的二进制
    const head = new TextDecoder('utf-8').decode(new Uint8Array(buf, 0, Math.min(1024, buf.byteLength)));
    if (/^\s*solid/.test(head) && /vertex/i.test(head)) {
      return parseAscii(new TextDecoder('utf-8').decode(buf), opts);
    }
    // 兜底：按二进制读，三角面数由长度反推（不修改调用方传进来的 buffer）
    const n = Math.floor((buf.byteLength - 84) / 50);
    if (n > 0) {
      const r = parseBinary(buf, opts, n);
      r.stats.format = 'binary(按长度推测)';
      return r;
    }
    return emptyResult();
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.ParserStl = {
    parse,
    isBinary,
    parseBinary,
    parseAscii,
    implemented: true
  };
})(window);
