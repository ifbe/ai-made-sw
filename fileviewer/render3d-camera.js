(function (global) {
  'use strict';

  // Z 轴朝上的轨道相机（KiCad 的 3D 空间就是 Z-up：板子在 XY 平面，Z 是高度）。
  // 注意 pcbnew 文件里的 Y 轴向下，几何构建阶段已经统一映射成 (x, -y, z)，
  // 所以这里的 target 用的是映射之后的世界坐标。
  const { lookAt, perspective, normalize3, cross3, sub3 } = global.KiPreview.Math3D;

  const FOV = 45 * Math.PI / 180;
  const ELEV_LIMIT = Math.PI / 2 - 0.02;

  function create() {
    return {
      target: [0, 0, 0],
      distance: 100,
      azimuth: -Math.PI / 4,   // 绕 Z 轴
      elevation: 0.62,         // 与 XY 平面的夹角
      fov: FOV,
      near: 0.05,
      far: 100000
    };
  }

  function eye(cam) {
    const ce = Math.cos(cam.elevation);
    const se = Math.sin(cam.elevation);
    return [
      cam.target[0] + cam.distance * ce * Math.cos(cam.azimuth),
      cam.target[1] + cam.distance * ce * Math.sin(cam.azimuth),
      cam.target[2] + cam.distance * se
    ];
  }

  function viewMatrix(cam) {
    return lookAt(eye(cam), cam.target, [0, 0, 1]);
  }

  function projMatrix(cam, aspect) {
    return perspective(cam.fov, aspect || 1, cam.near, cam.far);
  }

  function mvp(cam, aspect, w, h) {
    const m = global.KiPreview.Math3D;
    return m.multiply(projMatrix(cam, aspect), viewMatrix(cam));
  }

  function orbit(cam, dxPx, dyPx) {
    cam.azimuth -= dxPx * 0.008;
    if (cam.azimuth > Math.PI) cam.azimuth -= Math.PI * 2;
    if (cam.azimuth < -Math.PI) cam.azimuth += Math.PI * 2;
    let e = cam.elevation + dyPx * 0.008;
    if (e > ELEV_LIMIT) e = ELEV_LIMIT;
    if (e < -ELEV_LIMIT) e = -ELEV_LIMIT;
    cam.elevation = e;
  }

  function zoom(cam, factor) {
    let d = cam.distance * factor;
    if (d < 0.5) d = 0.5;
    if (d > 200000) d = 200000;
    cam.distance = d;
  }

  // 相机基向量。射线拾取要把屏幕点转成世界射线，同样需要这套基。
  function basis(cam) {
    const e = eye(cam);
    const forward = normalize3(sub3(cam.target, e));
    let right = cross3(forward, [0, 0, 1]);
    if (Math.hypot(right[0], right[1], right[2]) < 1e-6) right = [1, 0, 0];
    right = normalize3(right);
    return { eye: e, forward, right, up: cross3(right, forward) };
  }

  // 沿相机的右/上方向平移 target，屏幕像素位移与视觉位移一致
  function pan(cam, dxPx, dyPx, viewportH) {
    const { right, up } = basis(cam);
    const k = cam.distance * Math.tan(cam.fov / 2) * 2 / Math.max(viewportH, 1);
    for (let i = 0; i < 3; i++) {
      cam.target[i] += (-right[i] * dxPx + up[i] * dyPx) * k;
    }
  }

  const FILL = 0.95;    // 视口垂直方向上想占的比例

  // 世界坐标系的包围盒 fit（独立模型用，min/max 是 [x,y,z]）
  function fit3D(cam, min, max) {
    cam.target = [
      (min[0] + max[0]) / 2,
      (min[1] + max[1]) / 2,
      (min[2] + max[2]) / 2
    ];
    // 按"包围球"定距离而不是按最长边：模型是斜着看的，最长边估算会明显偏小；
    // 包围球与视角无关，任意轨道角度都不会把模型裁掉。
    const r = 0.5 * Math.hypot(max[0] - min[0], max[1] - min[1], max[2] - min[2]) || 1;
    cam.distance = r / Math.sin(cam.fov / 2 * FILL);
    cam.near = Math.max(0.01, cam.distance / 2000);
    cam.far = cam.distance * 200;
    return cam;
  }

  // bounds 是 pcbnew 坐标下的包围盒（与 2D 视图共用）。
  // pcbnew 的 Y 轴向下，世界坐标是 (x, -y, z)，这里换算后复用 fit3D。
  function fit(cam, bounds, thickness) {
    const t = thickness || 0;
    return fit3D(cam,
      [bounds.minX, -bounds.maxY, 0],
      [bounds.maxX, -bounds.minY, t]);
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Camera3D = {
    create,
    eye,
    basis,
    viewMatrix,
    projMatrix,
    mvp,
    orbit,
    zoom,
    pan,
    fit,
    fit3D
  };
})(window);
