(function (global) {
  'use strict';

  // 3MF 解析器 —— 占位，尚未实现。
  //
  // 3MF 是个 ZIP 容器，解压用浏览器 / Node 都自带的
  // DecompressionStream('deflate-raw')，不需要引第三方库。
  //
  // 计划：
  //   1) 读 ZIP 中央目录（EOCD → central directory → local header → inflate）
  //   2) 从 _rels/.rels 找 3dmodel 关系拿到主模型路径，
  //      拿不到就退回约定路径 3D/3dmodel.model
  //   3) 解析 XML：<resources> 里的 <object>（含 <mesh> 或 <components>）
  //      与 <build><item>，写的是 4x3 变换矩阵（m00..m32 十二个数）
  //   4) Bambu Studio / PrusaSlicer 会把每个对象拆到
  //      3D/Objects/*.model，靠 production 扩展的
  //      <component p:path="..." objectid="..."/> 跨文件引用，需要递归解析
  //   5) 单位取自根节点 unit 属性（默认 millimeter）
  //
  // 产出与 Mesh3D.buildBoard 相同的网格格式，交给 render3d-webgl.js 渲染。

  const NOT_IMPLEMENTED = '3MF 解析尚未实现';

  // input: ArrayBuffer → Promise<{ pos, nrm, col, count, bounds }>
  // 3MF 需要解压，接口是异步的。
  function parse() {
    return Promise.reject(new Error(NOT_IMPLEMENTED));
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Parser3mf = { parse, implemented: false };
})(window);
