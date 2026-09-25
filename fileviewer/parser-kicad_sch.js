(function (global) {
  'use strict';
  const { find, findAll, safeNum, stringifySexpr } = global.KiPreview.Sexpr;

  function parse(ast) {
    const items = { wires: [], junctions: [], labels: [], texts: [], symbols: [], libSymbols: {} };

    const libNode = find(ast, 'lib_symbols');
    if (libNode) {
      for (const sym of findAll(libNode, 'symbol')) {
        if (typeof sym[1] === 'string') {
          items.libSymbols[sym[1]] = parseLibSymbol(sym);
        }
      }
    }

    function walk(node) {
      if (!Array.isArray(node)) return;
      const tag = node[0];

      if (tag === 'wire') {
        const pts = find(node, 'pts');
        if (pts) {
          const xy = findAll(pts, 'xy');
          for (let i = 0; i < xy.length - 1; i++) {
            items.wires.push({
              kind: 'wire',
              x1: safeNum(xy[i][1]), y1: safeNum(xy[i][2]),
              x2: safeNum(xy[i+1][1]), y2: safeNum(xy[i+1][2]),
              _raw: node
            });
          }
        }
      }
      if (tag === 'junction') {
        const a = find(node, 'at');
        if (a) items.junctions.push({
          kind: 'junction',
          x: safeNum(a[1]), y: safeNum(a[2]),
          _raw: node
        });
      }
      if (tag === 'label' || tag === 'global_label' || tag === 'hierarchical_label') {
        const a = find(node, 'at');
        const txt = typeof node[1] === 'string' ? node[1] : '';
        if (a && txt) items.labels.push({
          kind: 'label',
          x: safeNum(a[1]), y: safeNum(a[2]), text: txt,
          rot: safeNum(a[3]), type: tag,
          _raw: node
        });
      }
      if (tag === 'text') {
        const a = find(node, 'at');
        const txt = typeof node[1] === 'string' ? node[1] : '';
        if (a && txt) items.texts.push({
          kind: 'text',
          x: safeNum(a[1]), y: safeNum(a[2]), text: txt,
          rot: safeNum(a[3]),
          _raw: node
        });
      }
      if (tag === 'symbol' && typeof node[1] === 'string' && items.libSymbols[node[1]]) {
        const lib = items.libSymbols[node[1]];
        const a = find(node, 'at');
        const mirror = find(node, 'mirror');
        const unit = find(node, 'unit');
        items.symbols.push({
          kind: 'symbol',
          lib,
          x: safeNum(a ? a[1] : 0),
          y: safeNum(a ? a[2] : 0),
          rot: ((safeNum(a ? a[3] : 0) * Math.PI) / 180),
          mirror: mirror ? mirror[1] : null,
          unit: unit ? unit[1] : 1,
          _raw: node
        });
      }
      for (const c of node) if (Array.isArray(c)) walk(c);
    }
    walk(ast);
    return items;
  }

  function parseLibSymbol(sym) {
    const def = { graphics: [], pins: [] };
    function collect(node, unit) {
      if (!Array.isArray(node)) return;
      const tag = node[0];

      if (tag === 'symbol') {
        const name = typeof node[1] === 'string' ? node[1] : '';
        let u = unit;
        if (name.includes('_')) {
          const parts = name.split('_');
          const n = parseInt(parts[parts.length - 1]);
          if (!isNaN(n)) u = n;
        }
        for (const c of node) collect(c, u);
        return;
      }
      if (tag === 'rectangle') {
        const s = find(node, 'start'), e = find(node, 'end');
        const fill = find(node, 'fill');
        if (s && e) def.graphics.push({
          type: 'rect',
          x1: safeNum(s[1]), y1: safeNum(s[2]),
          x2: safeNum(e[1]), y2: safeNum(e[2]),
          fill: fill ? fill[1] : 'none', unit
        });
      }
      if (tag === 'polyline') {
        const pts = find(node, 'pts');
        if (pts) {
          const xy = findAll(pts, 'xy').map(p => ({ x: safeNum(p[1]), y: safeNum(p[2]) }));
          def.graphics.push({ type: 'poly', pts: xy, unit });
        }
      }
      if (tag === 'circle') {
        const c = find(node, 'center'), r = find(node, 'radius');
        if (c && r) def.graphics.push({
          type: 'circle', x: safeNum(c[1]), y: safeNum(c[2]),
          r: Math.abs(safeNum(r[1])), unit
        });
      }
      if (tag === 'arc') {
        const s = find(node, 'start'), m = find(node, 'mid'), e = find(node, 'end');
        if (s && m && e) def.graphics.push({
          type: 'arc',
          sx: safeNum(s[1]), sy: safeNum(s[2]),
          mx: safeNum(m[1]), my: safeNum(m[2]),
          ex: safeNum(e[1]), ey: safeNum(e[2]), unit
        });
      }
      if (tag === 'pin') {
        const a = find(node, 'at'), len = find(node, 'length');
        const name = find(node, 'name'), num = find(node, 'number');
        def.pins.push({
          x: safeNum(a ? a[1] : 0),
          y: safeNum(a ? a[2] : 0),
          rot: safeNum(a ? a[3] : 0),
          len: Math.abs(safeNum(len ? len[1] : 0)),
          name: name ? name[1] : '',
          number: num ? num[1] : '',
          unit
        });
      }
      for (const c of node) if (Array.isArray(c)) collect(c, unit);
    }
    for (const c of sym) if (Array.isArray(c)) collect(c, undefined);
    return def;
  }

  // TODO: 原理图元素详情暂未实现
  function describe(element) {
    return {
      title: '原理图元素',
      rows: [['提示', '详情功能暂未实现']],
      source: element && element._raw ? stringifySexpr(element._raw) : ''
    };
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.ParserKicadSch = { parse, describe };
})(window);