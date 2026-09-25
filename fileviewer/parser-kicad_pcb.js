(function (global) {
  'use strict';
  const { find, safeNum, stringifySexpr } = global.KiPreview.Sexpr;

  // 由 start / mid / end 三点还原圆弧，并采样成折线。
  // KiCad 的板框圆角就是 gr_arc，不还原的话板框永远串不成闭环。
  function buildArc(x1, y1, mx, my, x2, y2) {
    const d = 2 * (x1 * (my - y2) + mx * (y2 - y1) + x2 * (y1 - my));
    if (Math.abs(d) < 1e-9) {
      // 三点共线，退化成折线
      return { points: [[x1, y1], [mx, my], [x2, y2]], cx: 0, cy: 0, r: 0, sweep: 0 };
    }
    const s1 = x1 * x1 + y1 * y1;
    const s2 = mx * mx + my * my;
    const s3 = x2 * x2 + y2 * y2;
    const cx = (s1 * (my - y2) + s2 * (y2 - y1) + s3 * (y1 - my)) / d;
    const cy = (s1 * (x2 - mx) + s2 * (x1 - x2) + s3 * (mx - x1)) / d;
    const r = Math.hypot(x1 - cx, y1 - cy);

    const norm = a => {
      while (a < 0) a += Math.PI * 2;
      while (a >= Math.PI * 2) a -= Math.PI * 2;
      return a;
    };
    const a0 = Math.atan2(y1 - cy, x1 - cx);
    const a1 = Math.atan2(y2 - cy, x2 - cx);
    const am = Math.atan2(my - cy, mx - cx);

    const ccwSweep = norm(a1 - a0);
    const ccwMid = norm(am - a0);
    const ccw = ccwMid <= ccwSweep;                 // mid 落在逆时针区间内
    const sweep = ccw ? ccwSweep : ccwSweep - Math.PI * 2;

    const steps = Math.max(4, Math.min(64, Math.ceil(Math.abs(sweep) / (Math.PI / 36))));
    const points = [];
    for (let i = 0; i <= steps; i++) {
      const a = a0 + sweep * (i / steps);
      points.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
    }
    return { points, cx, cy, r, a0, a1, sweep };
  }

  // (offset (xyz x y z)) / (scale (xyz ...)) / (rotate (xyz ...))
  function xyzVec(node, fallback) {
    if (!Array.isArray(node)) return fallback.slice();
    const xyz = find(node, 'xyz');
    if (!xyz) return fallback.slice();
    return [safeNum(xyz[1], fallback[0]),
            safeNum(xyz[2], fallback[1]),
            safeNum(xyz[3], fallback[2])];
  }

  function parse(ast) {
    const items = {
      edges: [], arcs: [], circles: [], segments: [], vias: [], pads: [], texts: [],
      models: []          // 封装引用的 3D 模型（含摆放变换）
    };

    function walk(node, fp) {
      if (!Array.isArray(node)) return;
      const tag = node[0];

      if (tag === 'gr_line') {
        const layer = find(node, 'layer');
        if (layer && layer[1] === 'Edge.Cuts') {
          const s = find(node, 'start'), e = find(node, 'end');
          if (s && e) items.edges.push({
            kind: 'edge',
            x1: safeNum(s[1]), y1: safeNum(s[2]),
            x2: safeNum(e[1]), y2: safeNum(e[2]),
            _raw: node
          });
        }
      }
      if (tag === 'gr_arc') {
        const layer = find(node, 'layer');
        if (layer && layer[1] === 'Edge.Cuts') {
          const s = find(node, 'start'), m = find(node, 'mid'), e = find(node, 'end');
          if (s && m && e) {
            const arc = buildArc(safeNum(s[1]), safeNum(s[2]),
                                 safeNum(m[1]), safeNum(m[2]),
                                 safeNum(e[1]), safeNum(e[2]));
            items.arcs.push({
              kind: 'arc',
              x1: safeNum(s[1]), y1: safeNum(s[2]),
              mx: safeNum(m[1]), my: safeNum(m[2]),
              x2: safeNum(e[1]), y2: safeNum(e[2]),
              cx: arc.cx, cy: arc.cy, r: arc.r,
              points: arc.points,
              _raw: node
            });
          }
        }
      }
      if (tag === 'gr_circle') {
        const layer = find(node, 'layer');
        if (layer && layer[1] === 'Edge.Cuts') {
          const c = find(node, 'center'), e = find(node, 'end');
          if (c && e) {
            const r = Math.hypot(safeNum(e[1]) - safeNum(c[1]), safeNum(e[2]) - safeNum(c[2]));
            items.circles.push({
              kind: 'circle',
              x: safeNum(c[1]), y: safeNum(c[2]),
              r: Math.abs(r),
              _raw: node
            });
          }
        }
      }
      if (tag === 'segment') {
        const s = find(node, 'start'), e = find(node, 'end'), w = find(node, 'width');
        const layer = find(node, 'layer');
        const net = find(node, 'net');
        if (s && e) items.segments.push({
          kind: 'segment',
          x1: safeNum(s[1]), y1: safeNum(s[2]),
          x2: safeNum(e[1]), y2: safeNum(e[2]),
          w: Math.abs(safeNum(w ? w[1] : 0.2, 0.2)),
          layer: layer ? layer[1] : 'F.Cu',
          net: net ? net[1] : '',
          _raw: node
        });
      }
      if (tag === 'via') {
        const a = find(node, 'at'), s = find(node, 'size');
        const drill = find(node, 'drill');
        const net = find(node, 'net');
        if (a && typeof a[1] === 'number' && typeof a[2] === 'number') {
          const size = (s && typeof s[1] === 'number') ? s[1] : 1.6;
          const drillVal = (drill && typeof drill[1] === 'number') ? drill[1] : 0;
          items.vias.push({
            kind: 'via',
            x: a[1], y: a[2],
            r: Math.abs(size) / 2,
            size: Math.abs(size),
            drill: drillVal,
            net: net ? net[1] : '',
            _raw: node
          });
        }
      }
      if (tag === 'footprint') {
        const at = find(node, 'at');
        const layerNode = find(node, 'layer');
        const layer = (layerNode && typeof layerNode[1] === 'string') ? layerNode[1] : 'F.Cu';
        const refProp = findAll(node, 'property').find(p => p[1] === 'Reference');
        const valProp = findAll(node, 'property').find(p => p[1] === 'Value');
        const fpAt = at
          ? {
              x: safeNum(at[1]), y: safeNum(at[2]),
              rot: ((safeNum(at[3]) * Math.PI) / 180),
              layer: layer,
              back: layer === 'B.Cu',
              ref: refProp ? refProp[2] : '',
              value: valProp ? valProp[2] : '',
              name: typeof node[1] === 'string' ? node[1] : ''
            }
          : { x: 0, y: 0, rot: 0, layer: layer, back: layer === 'B.Cu',
              ref: '', value: '', name: '' };

        // 封装引用的 3D 模型。摆放变换由三段组成：
        //   scale → rotate（XYZ 欧拉角，度）→ offset
        // 之后再叠加封装自身的 (at) 与正反面翻转。
        for (const c of node) {
          if (!Array.isArray(c) || c[0] !== 'model' || typeof c[1] !== 'string') continue;
          items.models.push({
            kind: 'model',
            path: c[1],
            offset: xyzVec(find(c, 'offset'), [0, 0, 0]),
            scale: xyzVec(find(c, 'scale'), [1, 1, 1]),
            rotate: xyzVec(find(c, 'rotate'), [0, 0, 0]),
            fp: fpAt,
            fpIndex: items.models.length,
            _raw: c
          });
        }

        for (const c of node) walk(c, fpAt);
        return;
      }
      if (tag === 'pad' && fp) {
        const a = find(node, 'at'), s = find(node, 'size');
        const layers = find(node, 'layers');
        const net = find(node, 'net');
        const pinfunc = find(node, 'pinfunction');
        if (a && s && typeof s[1] === 'number' && typeof s[2] === 'number') {
          // 顺便累计封装局部的焊盘范围：3D 占位方块用它当元件尺寸的近似
          const lx = safeNum(a[1]), ly = safeNum(a[2]);
          if (!fp.padBox) fp.padBox = { x1: Infinity, y1: Infinity, x2: -Infinity, y2: -Infinity };
          fp.padBox.x1 = Math.min(fp.padBox.x1, lx - Math.abs(s[1]) / 2);
          fp.padBox.x2 = Math.max(fp.padBox.x2, lx + Math.abs(s[1]) / 2);
          fp.padBox.y1 = Math.min(fp.padBox.y1, ly - Math.abs(s[2]) / 2);
          fp.padBox.y2 = Math.max(fp.padBox.y2, ly + Math.abs(s[2]) / 2);

          const cos = Math.cos(fp.rot), sin = Math.sin(fp.rot);
          const px = safeNum(a[1]) * cos + safeNum(a[2]) * sin;
          const py = -safeNum(a[1]) * sin + safeNum(a[2]) * cos;
          const shape = node[3];
          const layerNames = layers ? layers.slice(1) : [];
          items.pads.push({
            kind: 'pad',
            x: fp.x + px, y: fp.y + py,
            w: Math.abs(s[1]), h: Math.abs(s[2]),
            rot: ((safeNum(a[3]) * Math.PI) / 180) + fp.rot,
            shape: typeof shape === 'string' ? shape : 'rect',
            number: typeof node[1] === 'string' ? node[1] : '',
            type: typeof node[2] === 'string' ? node[2] : '',
            net: net ? net[1] : '',
            pinfunction: pinfunc ? pinfunc[1] : '',
            front: layerNames.some(l => typeof l === 'string' && l.startsWith('F.')),
            back: layerNames.some(l => typeof l === 'string' && l.startsWith('B.')),
            through: layerNames.some(l => l === '*.Cu'),
            fpRef: fp.ref,
            fpValue: fp.value,
            fpName: fp.name,
            _raw: node
          });
        }
      }
      if (tag === 'gr_text') {
        const a = find(node, 'at'), layer = find(node, 'layer');
        if (a && layer && (layer[1] === 'F.SilkS' || layer[1] === 'B.SilkS')) {
          const txt = typeof node[1] === 'string' ? node[1] : '';
          const eff = find(node, 'effects');
          const font = eff ? find(eff, 'font') : null;
          const sz = font ? find(font, 'size') : null;
          if (txt) items.texts.push({
            kind: 'text',
            x: safeNum(a[1]), y: safeNum(a[2]), text: txt,
            size: Math.abs(safeNum(sz ? sz[1] : 1, 1)),
            rot: safeNum(a[3]),
            layer: layer[1],
            _raw: node
          });
        }
      }
      // 兼容 findAll 在 walk 里的局部引用
      function findAll(n, t) {
        return n.filter(c => Array.isArray(c) && c[0] === t);
      }
      for (const c of node) if (Array.isArray(c)) walk(c, fp);
    }
    walk(ast, null);
    return items;
  }

  // ---------- describe ----------
  function fmt(n, digits) {
    if (typeof n !== 'number') return String(n);
    if (digits === undefined) digits = 4;
    const s = n.toFixed(digits);
    return s.replace(/\.?0+$/, '') || '0';
  }

  function pt(x, y) {
    return '(' + fmt(x) + ', ' + fmt(y) + ')';
  }

  function describe(element) {
    const kind = element.kind;
    const info = { title: '', rows: [], source: stringifySexpr(element._raw) };

    if (kind === 'segment') {
      info.title = '走线';
      info.rows = [
        ['图层', element.layer],
        ['网络', element.net || '(无)'],
        ['起点', pt(element.x1, element.y1)],
        ['终点', pt(element.x2, element.y2)],
        ['宽度', fmt(element.w) + ' mm']
      ];
    } else if (kind === 'pad') {
      info.title = '焊盘 ' + (element.number || '(无编号)');
      info.rows = [
        ['类型', element.type],
        ['形状', element.shape],
        ['所属封装', (element.fpRef || '') + (element.fpName ? ' (' + element.fpName + ')' : '')],
        ['值', element.fpValue || '(无)'],
        ['位置', pt(element.x, element.y)],
        ['尺寸', fmt(element.w) + ' × ' + fmt(element.h) + ' mm'],
        ['旋转', fmt(element.rot * 180 / Math.PI, 2) + '°'],
        ['网络', element.net || '(无)'],
        ['引脚功能', element.pinfunction || '(无)']
      ];
    } else if (kind === 'via') {
      info.title = '过孔';
      info.rows = [
        ['位置', pt(element.x, element.y)],
        ['外径', fmt(element.size) + ' mm'],
        ['钻孔', fmt(element.drill) + ' mm'],
        ['网络', element.net || '(无)']
      ];
    } else if (kind === 'edge') {
      info.title = '板框线段';
      info.rows = [
        ['图层', 'Edge.Cuts'],
        ['起点', pt(element.x1, element.y1)],
        ['终点', pt(element.x2, element.y2)]
      ];
    } else if (kind === 'circle') {
      info.title = '板框圆';
      info.rows = [
        ['图层', 'Edge.Cuts'],
        ['圆心', pt(element.x, element.y)],
        ['半径', fmt(element.r) + ' mm']
      ];
    } else if (kind === 'arc') {
      info.title = '板框圆弧';
      info.rows = [
        ['图层', 'Edge.Cuts'],
        ['起点', pt(element.x1, element.y1)],
        ['中点', pt(element.mx, element.my)],
        ['终点', pt(element.x2, element.y2)],
        ['圆心', pt(element.cx, element.cy)],
        ['半径', fmt(element.r) + ' mm']
      ];
    } else {
      info.title = '元素';
      info.rows = [['类型', kind || '(未知)']];
    }
    return info;
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.ParserKicadPcb = { parse, describe, buildArc };
})(window);