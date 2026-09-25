(function (global) {
  'use strict';

  // 4x4 矩阵（列主序，与 WebGL 的 uniformMatrix4fv 一致）与少量 vec3 helper。
  // 几何一律在世界空间里直接构建，所以这里只需要 投影 / 视图 两类矩阵。

  function identity() {
    return new Float32Array([
      1, 0, 0, 0,
      0, 1, 0, 0,
      0, 0, 1, 0,
      0, 0, 0, 1
    ]);
  }

  function multiply(a, b) {
    const out = new Float32Array(16);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        out[c * 4 + r] =
          a[0 * 4 + r] * b[c * 4 + 0] +
          a[1 * 4 + r] * b[c * 4 + 1] +
          a[2 * 4 + r] * b[c * 4 + 2] +
          a[3 * 4 + r] * b[c * 4 + 3];
      }
    }
    return out;
  }

  function perspective(fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2);
    const nf = 1 / (near - far);
    const out = new Float32Array(16);
    out[0] = f / aspect;
    out[5] = f;
    out[10] = (far + near) * nf;
    out[11] = -1;
    out[14] = 2 * far * near * nf;
    return out;
  }

  function lookAt(eye, center, up) {
    // z 轴指向相机背后
    let zx = eye[0] - center[0], zy = eye[1] - center[1], zz = eye[2] - center[2];
    let zl = Math.hypot(zx, zy, zz);
    if (zl < 1e-9) { zx = 0; zy = 0; zz = 1; zl = 1; }
    zx /= zl; zy /= zl; zz /= zl;

    // x = normalize(cross(up, z))
    let xx = up[1] * zz - up[2] * zy;
    let xy = up[2] * zx - up[0] * zz;
    let xz = up[0] * zy - up[1] * zx;
    let xl = Math.hypot(xx, xy, xz);
    if (xl < 1e-9) {
      // up 与视线平行时的退化处理：换一个参考轴
      xx = 1; xy = 0; xz = 0; xl = 1;
    }
    xx /= xl; xy /= xl; xz /= xl;

    // y = cross(z, x)
    const yx = zy * xz - zz * xy;
    const yy = zz * xx - zx * xz;
    const yz = zx * xy - zy * xx;

    const out = new Float32Array(16);
    out[0] = xx; out[4] = xy; out[8] = xz;
    out[12] = -(xx * eye[0] + xy * eye[1] + xz * eye[2]);
    out[1] = yx; out[5] = yy; out[9] = yz;
    out[13] = -(yx * eye[0] + yy * eye[1] + yz * eye[2]);
    out[2] = zx; out[6] = zy; out[10] = zz;
    out[14] = -(zx * eye[0] + zy * eye[1] + zz * eye[2]);
    out[3] = 0; out[7] = 0; out[11] = 0; out[15] = 1;
    return out;
  }

  // 取 4x4 左上 3x3 作为 mat3。视图矩阵是刚体变换（无缩放），
  // 所以法线直接用它变换即可，不需要逆转置。
  function upper3(m) {
    return new Float32Array([
      m[0], m[1], m[2],
      m[4], m[5], m[6],
      m[8], m[9], m[10]
    ]);
  }

  function transformPoint(m, p) {
    const x = p[0], y = p[1], z = p[2];
    const w = m[3] * x + m[7] * y + m[11] * z + m[15];
    const iw = w === 0 ? 1 : 1 / w;
    return [
      (m[0] * x + m[4] * y + m[8] * z + m[12]) * iw,
      (m[1] * x + m[5] * y + m[9] * z + m[13]) * iw,
      (m[2] * x + m[6] * y + m[10] * z + m[14]) * iw
    ];
  }

  // 把世界坐标投影到屏幕像素（含 Y 翻转），用于坐标提示等叠加信息
  function projectToScreen(mvp, p, w, h) {
    const c = transformPoint(mvp, p);
    return {
      x: (c[0] * 0.5 + 0.5) * w,
      y: (1 - (c[1] * 0.5 + 0.5)) * h,
      depth: c[2]
    };
  }

  function normalize3(v) {
    const l = Math.hypot(v[0], v[1], v[2]) || 1;
    return [v[0] / l, v[1] / l, v[2] / l];
  }

  function cross3(a, b) {
    return [
      a[1] * b[2] - a[2] * b[1],
      a[2] * b[0] - a[0] * b[2],
      a[0] * b[1] - a[1] * b[0]
    ];
  }

  function sub3(a, b) {
    return [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Math3D = {
    identity,
    multiply,
    perspective,
    lookAt,
    upper3,
    transformPoint,
    projectToScreen,
    normalize3,
    cross3,
    sub3
  };
})(window);
