(function (global) {
  'use strict';
  const { makeTransform } = global.KiPreview.Viewport;

  function safeArc(ctx, cx, cy, r, a0, a1) {
    const radius = Math.abs(r);
    if (!isFinite(radius) || radius < 0.01) return;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, a0 === undefined ? 0 : a0, a1 === undefined ? Math.PI * 2 : a1);
  }

  // TODO: 原理图元素的选中高亮（selection 参数接收但暂未使用）
  function render(ctx, items, view, bounds, visibility, w, h, selection) {
    const isVisible = global.KiPreview.Layers.isVisible;
    const vis = visibility;

    const pts = [];
    items.wires.forEach(w2 => { pts.push({x:w2.x1,y:w2.y1}, {x:w2.x2,y:w2.y2}); });
    items.junctions.forEach(j => pts.push({x:j.x,y:j.y}));
    items.labels.forEach(l => pts.push({x:l.x,y:l.y}));
    items.texts.forEach(t => pts.push({x:t.x,y:t.y}));
    items.symbols.forEach(s => {
      pts.push({x: s.x - 10, y: s.y - 10}, {x: s.x + 10, y: s.y + 10});
    });

    ctx.clearRect(0, 0, w, h);
    if (!pts.length) return;

    const T = makeTransform(view, bounds, w, h);

    if (isVisible(vis, 'Wires')) {
      ctx.strokeStyle = '#3a9a3a';
      ctx.lineWidth = 1.5;
      ctx.lineCap = 'round';
      items.wires.forEach(w2 => {
        const a = T.toS(w2.x1, w2.y1), b = T.toS(w2.x2, w2.y2);
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      });
    }

    if (isVisible(vis, 'Symbols')) {
      items.symbols.forEach(sym => {
        ctx.save();
        const p = T.toS(sym.x, sym.y);
        ctx.translate(p.sx, p.sy);
        ctx.scale(1, -1);
        ctx.rotate(sym.rot);
        if (sym.mirror === 'x') ctx.scale(1, -1);
        if (sym.mirror === 'y') ctx.scale(-1, 1);

        const k = T.scale;

        sym.lib.graphics.forEach(g => {
          if (g.unit && sym.unit && g.unit !== sym.unit) return;
          ctx.strokeStyle = '#c83232';
          ctx.lineWidth = Math.max(1.5, 0.2 * k);
          if (g.type === 'rect') {
            const x1 = g.x1 * k, y1 = g.y1 * k, x2 = g.x2 * k, y2 = g.y2 * k;
            const rx = Math.min(x1, x2), ry = Math.min(y1, y2);
            const rw = Math.abs(x2 - x1), rh = Math.abs(y2 - y1);
            if (g.fill === 'background') {
              ctx.fillStyle = '#3a2a1a';
              ctx.fillRect(rx, ry, rw, rh);
            }
            ctx.strokeRect(rx, ry, rw, rh);
          } else if (g.type === 'poly') {
            ctx.beginPath();
            g.pts.forEach((pt, i) => {
              const x = pt.x * k, y = pt.y * k;
              i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
            });
            ctx.stroke();
          } else if (g.type === 'circle') {
            safeArc(ctx, g.x * k, g.y * k, g.r * k);
            ctx.stroke();
          } else if (g.type === 'arc') {
            ctx.beginPath();
            ctx.moveTo(g.sx * k, g.sy * k);
            ctx.quadraticCurveTo(g.mx * k, g.my * k, g.ex * k, g.ey * k);
            ctx.stroke();
          }
        });

        sym.lib.pins.forEach(pin => {
          if (pin.unit && sym.unit && pin.unit !== sym.unit) return;
          const rad = (pin.rot * Math.PI) / 180;
          const x1 = pin.x * k, y1 = pin.y * k;
          const x2 = (pin.x + pin.len * Math.cos(rad)) * k;
          const y2 = (pin.y + pin.len * Math.sin(rad)) * k;
          ctx.strokeStyle = '#c83232';
          ctx.lineWidth = Math.max(1, 0.15 * k);
          ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();

          ctx.save();
          ctx.scale(1, -1);
          ctx.fillStyle = '#d0d0d0';
          ctx.font = Math.max(8, 0.9 * k) + 'px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(pin.number, (x1 + x2) / 2, -(y1 + y2) / 2 + 3);
          ctx.restore();
        });

        ctx.restore();
      });
    }

    if (isVisible(vis, 'Junctions')) {
      ctx.fillStyle = '#3a9a3a';
      items.junctions.forEach(j => {
        const p = T.toS(j.x, j.y);
        safeArc(ctx, p.sx, p.sy, 3);
        ctx.fill();
      });
    }

    if (isVisible(vis, 'Labels')) {
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      items.labels.forEach(l => {
        const p = T.toS(l.x, l.y);
        if (l.type === 'global_label') {
          ctx.fillStyle = '#e94560';
          ctx.strokeStyle = '#e94560';
          ctx.lineWidth = 1;
          const tw = ctx.measureText(l.text).width + 10;
          ctx.strokeRect(p.sx, p.sy - 9, tw, 18);
          ctx.fillText(l.text, p.sx + 5, p.sy);
        } else {
          ctx.fillStyle = '#60a0e0';
          ctx.fillText(l.text, p.sx + 3, p.sy - 8);
        }
      });
    }

    if (isVisible(vis, 'Texts')) {
      ctx.fillStyle = '#888';
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      items.texts.forEach(t => {
        const p = T.toS(t.x, t.y);
        ctx.fillText(t.text, p.sx, p.sy);
      });
    }
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.SchRenderer = { render };
})(window);