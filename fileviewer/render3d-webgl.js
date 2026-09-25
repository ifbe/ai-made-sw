(function (global) {
  'use strict';

  // 3D 视图的 WebGL 后端。
  // 只负责把 Mesh3D 生成的三角形汤画出来，不关心 KiCad 语义。
  //
  // 光照说明：几何与法线都在世界空间构建，所以法线不做任何变换，
  // 光照方向由 CPU 按相机位置算好传进来（相当于挂在相机上的头灯）。
  // 双面光照 + 关闭背面剔除，因此三角面绕序不影响可见性。

  const Math3D = global.KiPreview.Math3D;
  const Camera3D = global.KiPreview.Camera3D;
  const Mesh3D = global.KiPreview.Mesh3D;

  const VERT_SRC = [
    'attribute vec3 aPos;',
    'attribute vec3 aNormal;',
    'attribute vec3 aColor;',
    'uniform mat4 uMVP;',
    'varying vec3 vNormal;',
    'varying vec3 vColor;',
    'void main() {',
    '  vNormal = aNormal;',
    '  vColor = aColor;',
    '  gl_Position = uMVP * vec4(aPos, 1.0);',
    '}'
  ].join('\n');

  const FRAG_SRC = [
    'precision mediump float;',
    'varying vec3 vNormal;',
    'varying vec3 vColor;',
    'uniform vec3 uLightDir;',
    'uniform float uAmbient;',
    'void main() {',
    '  vec3 n = normalize(vNormal);',
    '  vec3 l = normalize(uLightDir);',
    '  float front = max(dot(n, l), 0.0);',
    '  float back = max(dot(-n, l), 0.0) * 0.75;',
    '  float diff = max(front, back);',
    '  gl_FragColor = vec4(vColor * (uAmbient + (1.0 - uAmbient) * diff), 1.0);',
    '}'
  ].join('\n');

  let gl = null;
  let canvas = null;
  let program = null;
  let buffers = null;
  let loc = null;

  let mesh = null;         // 当前上传到 GPU 的网格
  let sceneKey = null;     // 用于判断是否需要重建网格
  let uploaded = false;

  // 选中高亮：与 2D 渲染端的 HIGHLIGHT 用同一个青色，切模式时观感一致
  const HILITE = [0, 0.88, 1];
  const HILITE_MIX = 0.7;

  let selectedRef = null;  // {kind, index}
  let selectedElem = -1;   // 解析后的元素序号，-1 表示无选中

  function compile(type, src) {
    const sh = gl.createShader(type);
    gl.shaderSource(sh, src);
    gl.compileShader(sh);
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
      const log = gl.getShaderInfoLog(sh);
      gl.deleteShader(sh);
      throw new Error('着色器编译失败：' + log);
    }
    return sh;
  }

  function init(canvasEl) {
    if (gl && canvas === canvasEl) return true;
    canvas = canvasEl;

    const opts = { alpha: false, antialias: true, depth: true, preserveDrawingBuffer: false };
    gl = canvas.getContext('webgl', opts) || canvas.getContext('experimental-webgl', opts);
    if (!gl) {
      console.error('[KiPreview] 当前浏览器不支持 WebGL，3D 视图不可用。');
      return false;
    }

    const vs = compile(gl.VERTEX_SHADER, VERT_SRC);
    const fs = compile(gl.FRAGMENT_SHADER, FRAG_SRC);
    program = gl.createProgram();
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    gl.deleteShader(vs);
    gl.deleteShader(fs);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      const log = gl.getProgramInfoLog(program);
      program = null;
      console.error('[KiPreview] 着色器链接失败：' + log);
      return false;
    }

    loc = {
      aPos: gl.getAttribLocation(program, 'aPos'),
      aNormal: gl.getAttribLocation(program, 'aNormal'),
      aColor: gl.getAttribLocation(program, 'aColor'),
      uMVP: gl.getUniformLocation(program, 'uMVP'),
      uLightDir: gl.getUniformLocation(program, 'uLightDir'),
      uAmbient: gl.getUniformLocation(program, 'uAmbient')
    };

    buffers = {
      pos: gl.createBuffer(),
      nrm: gl.createBuffer(),
      col: gl.createBuffer()
    };

    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.disable(gl.CULL_FACE);         // 绕序不作为可见性依据
    gl.clearColor(0.07, 0.07, 0.12, 1.0);

    canvas.addEventListener('webglcontextlost', e => {
      e.preventDefault();
      uploaded = false;
      console.warn('[KiPreview] WebGL 上下文丢失。');
    });
    canvas.addEventListener('webglcontextrestored', () => {
      gl = null; program = null; buffers = null;
      console.warn('[KiPreview] WebGL 上下文已恢复，请重新进入 3D 视图。');
    });

    return true;
  }

  function isReady() {
    return !!(gl && program && buffers);
  }

  // revision 由 app.js 在每次加载新文件时自增，visibility 变化也会体现出来。
  // 只靠"元素个数"做键是不够的：两块不同板子可能恰好有同样多的走线/焊盘。
  function updateScene(items, visibility, bounds, revision, modelMeshes) {
    const key = (revision || 0) + '|' + JSON.stringify(visibility || {}) +
                '|' + (modelMeshes ? modelMeshes.size : 0);
    if (key === sceneKey && mesh) return;
    sceneKey = key;
    mesh = Mesh3D.buildBoard(items, visibility, {
      bounds, thickness: Mesh3D.T_DEFAULT, modelMeshes
    });
    // 高亮是在颜色缓冲上就地改写的，所以留一份未被改动的基色用于还原
    mesh.baseCol = Float32Array.from(mesh.col);
    selectedElem = -1;
    uploaded = false;
  }

  function invalidate() {
    uploaded = false;
  }

  // 直接投喂外部 parser（STEP / STL / 3MF）产出的网格，
  // 绕开 Mesh3D.buildBoard —— 这些格式没有"PCB 元素"的概念。
  function setMesh(m, key) {
    const k = 'mesh|' + (key || 0);
    if (k === sceneKey && mesh === m) return;
    sceneKey = k;
    mesh = m;
    mesh.baseCol = Float32Array.from(mesh.col);
    selectedElem = -1;
    uploaded = false;
  }

  function upload() {
    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.pos);
    gl.bufferData(gl.ARRAY_BUFFER, mesh.pos, gl.STATIC_DRAW);
    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.nrm);
    gl.bufferData(gl.ARRAY_BUFFER, mesh.nrm, gl.STATIC_DRAW);
    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.col);
    gl.bufferData(gl.ARRAY_BUFFER, mesh.col, gl.STATIC_DRAW);
    uploaded = true;
    // 刚上传的是干净基色，高亮需要重新施加
    selectedElem = -1;
    applySelection();
  }

  // ---------- 选中高亮 ----------
  // 只改写选中元素那一段颜色（元素三角形是连续的），用 bufferSubData 局部上传。
  // 154k 三角形全量重传要 1.85MB，点一下会明显卡；局部改写只有几百个浮点。

  function paintRange(id, on) {
    const e = mesh.elems[id];
    if (!e || !e.triCount) return;
    const from = e.triStart * 9;
    const to = e.triEnd * 9;
    const dst = mesh.col;
    const src = mesh.baseCol;

    for (let i = from; i < to; i += 3) {
      if (on) {
        for (let k = 0; k < 3; k++) {
          dst[i + k] = src[i + k] * (1 - HILITE_MIX) + HILITE[k] * HILITE_MIX;
        }
      } else {
        for (let k = 0; k < 3; k++) dst[i + k] = src[i + k];
      }
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.col);
    gl.bufferSubData(gl.ARRAY_BUFFER, from * 4, dst.subarray(from, to));
  }

  function resolveSelectedElem() {
    if (!selectedRef || !mesh || !mesh.elems) return -1;
    for (let i = 0; i < mesh.elems.length; i++) {
      const e = mesh.elems[i];
      if (e.kind === selectedRef.kind && e.index === selectedRef.index) return i;
    }
    return -1;
  }

  function applySelection() {
    if (!gl || !mesh || !uploaded) return;
    const want = resolveSelectedElem();
    if (want === selectedElem) return;
    if (selectedElem >= 0) paintRange(selectedElem, false);
    selectedElem = want;
    if (selectedElem >= 0) paintRange(selectedElem, true);
  }

  // ref 形如 {kind, index}，传 null 取消选中。
  // 这里存的是引用而不是元素序号：网格重建后序号会变，引用不会。
  function setSelection(ref) {
    selectedRef = ref || null;
    applySelection();
  }

  function resize(wCss, hCss) {
    if (!gl || !canvas) return { w: 0, h: 0 };
    const dpr = Math.min(global.devicePixelRatio || 1, 2);
    const w = Math.max(1, Math.round(wCss * dpr));
    const h = Math.max(1, Math.round(hCss * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    return { w, h, dpr };
  }

  function render(cam, viewW, viewH) {
    if (!isReady()) return false;

    const size = resize(viewW, viewH);
    if (!size.w || !size.h) return false;

    gl.viewport(0, 0, size.w, size.h);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    if (!mesh || !mesh.count) return true;
    if (!uploaded) upload();

    const aspect = size.w / size.h;
    const m = Camera3D.mvp(cam, aspect, size.w, size.h);

    // 头灯：从相机指向目标，再偏一点避免正面平光
    const e = Camera3D.eye(cam);
    let ld = Math3D.normalize3(Math3D.sub3(e, cam.target));
    ld = Math3D.normalize3([ld[0] + 0.35, ld[1] - 0.22, ld[2] + 0.55]);

    gl.useProgram(program);
    gl.uniformMatrix4fv(loc.uMVP, false, m);
    gl.uniform3fv(loc.uLightDir, new Float32Array(ld));
    gl.uniform1f(loc.uAmbient, 0.32);

    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.pos);
    gl.enableVertexAttribArray(loc.aPos);
    gl.vertexAttribPointer(loc.aPos, 3, gl.FLOAT, false, 0, 0);

    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.nrm);
    gl.enableVertexAttribArray(loc.aNormal);
    gl.vertexAttribPointer(loc.aNormal, 3, gl.FLOAT, false, 0, 0);

    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.col);
    gl.enableVertexAttribArray(loc.aColor);
    gl.vertexAttribPointer(loc.aColor, 3, gl.FLOAT, false, 0, 0);

    gl.drawArrays(gl.TRIANGLES, 0, mesh.count);
    return true;
  }

  function stats() {
    return {
      triangles: mesh ? mesh.count / 3 : 0,
      ready: isReady()
    };
  }

  // 供拾取模块使用（CPU 射线求交需要三角形数据）
  function getMesh() {
    return mesh;
  }

  function dispose() {
    mesh = null;
    sceneKey = null;
    uploaded = false;
    selectedRef = null;
    selectedElem = -1;
    // 上下文由浏览器回收，这里只丢弃引用
    gl = null;
    program = null;
    buffers = null;
    canvas = null;
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.GlRenderer = {
    init,
    isReady,
    updateScene,
    setMesh,
    invalidate,
    setSelection,
    render,
    stats,
    getMesh,
    dispose
  };
})(window);
