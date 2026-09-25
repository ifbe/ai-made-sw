(function (global) {
  'use strict';
  const { makeTransform } = global.KiPreview.Viewport;

  const HIGHLIGHT = '#00e0ff';

  function safeArc(ctx, cx, cy, r, a0, a1) {
    const radius = Math.abs(r);
    if (!isFinite(radius) || radius < 0.01) return;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, a0 === undefined ? 0 : a0, a1 === undefined ? Math.PI * 2 : a1);
  }

  function isSelected(selection, kind, index) {
    return selection && selection.kind === kind && selection.index === index;
  }

  function render(ctx, items, view, bounds, visibility, w, h, selection) {
    const isVisible = global.KiPreview.Layers.isVisible;
    const vis = visibility;

    const pts = [];
    items.edges.forEach(e => { pts.push({x:e.x1,y:e.y1}, {x:e.x2,y:e.y2}); });
    (items.arcs || []).forEach(a => { pts.push({x:a.x1,y:a.y1}, {x:a.x2,y:a.y2}); });
    items.circles.forEach(c => { pts.push({x:c.x-c.r,y:c.y-c.r}, {x:c.x+c.r,y:c.y+c.r}); });
    items.segments.forEach(s => { pts.push({x:s.x1,y:s.y1}, {x:s.x2,y:s.y2}); });
    items.pads.forEach(p => { pts.push({x:p.x,y:p.y}); });
    items.vias.forEach(v => { pts.push({x:v.x,y:v.y}); });

    ctx.clearRect(0, 0, w, h);
    if (!pts.length) return;

    const T = makeTransform(view, bounds, w, h);

    // ---------- 板框 ----------
    if (isVisible(vis, 'Edge.Cuts')) {
      ctx.strokeStyle = '#f0c040';
      ctx.lineWidth = 1.5;
      items.edges.forEach((e, i) => {
        const a = T.toS(e.x1, e.y1), b = T.toS(e.x2, e.y2);
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      });
      items.circles.forEach((c, i) => {
        const p = T.toS(c.x, c.y);
        safeArc(ctx, p.sx, p.sy, c.r * T.scale);
        ctx.stroke();
      });
      (items.arcs || []).forEach(a => {
        if (!a.points || a.points.length < 2) return;
        ctx.beginPath();
        for (let i = 0; i < a.points.length; i++) {
          const q = T.toS(a.points[i][0], a.points[i][1]);
          if (i === 0) ctx.moveTo(q.sx, q.sy); else ctx.lineTo(q.sx, q.sy);
        }
        ctx.stroke();
      });
    }

    // ---------- 走线 ----------
    ctx.lineCap = 'round';
    if (isVisible(vis, 'B.Cu')) {
      ctx.strokeStyle = '#2a6a2a';
      items.segments.forEach((s, i) => {
        if (s.layer !== 'B.Cu') return;
        const a = T.toS(s.x1, s.y1), b = T.toS(s.x2, s.y2);
        ctx.lineWidth = Math.max(Math.abs(s.w) * T.scale, 0.5);
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      });
    }
    if (isVisible(vis, 'F.Cu')) {
      ctx.strokeStyle = '#c83232';
      items.segments.forEach((s, i) => {
        if (s.layer !== 'F.Cu') return;
        const a = T.toS(s.x1, s.y1), b = T.toS(s.x2, s.y2);
        ctx.lineWidth = Math.max(Math.abs(s.w) * T.scale, 0.5);
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      });
    }

    // ---------- 焊盘 ----------
    if (isVisible(vis, 'Pads')) {
      items.pads.forEach(p => {
        const c = T.toS(p.x, p.y);
        ctx.save();
        ctx.translate(c.sx, c.sy);
        ctx.rotate(-p.rot);
        const pw = Math.abs(p.w) * T.scale, ph = Math.abs(p.h) * T.scale;
        ctx.fillStyle = p.through ? '#b0b0b0' : (p.back && !p.front ? '#4a8a4a' : '#d4b060');
        if (p.shape === 'circle') {
          safeArc(ctx, 0, 0, Math.min(pw, ph) / 2);
          ctx.fill();
        } else if (p.shape === 'oval') {
          ctx.beginPath();
          ctx.ellipse(0, 0, Math.abs(pw/2), Math.abs(ph/2), 0, 0, Math.PI * 2);
          ctx.fill();
        } else {
          ctx.fillRect(-pw / 2, -ph / 2, pw, ph);
        }
        ctx.restore();
      });
    }

    // ---------- 过孔 ----------
    if (isVisible(vis, 'Vias')) {
      ctx.fillStyle = '#999';
      items.vias.forEach(v => {
        const p = T.toS(v.x, v.y);
        safeArc(ctx, p.sx, p.sy, v.r * T.scale);
        ctx.fill();
      });
    }

    // ---------- 丝印文字 ----------
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    items.texts.forEach(t => {
      if (!isVisible(vis, t.layer)) return;
      const p = T.toS(t.x, t.y);
      const fs = Math.max(Math.abs(t.size) * T.scale, 6);
      ctx.save();
      ctx.translate(p.sx, p.sy);
      ctx.rotate((-t.rot * Math.PI) / 180);
      ctx.font = fs + 'px sans-serif';
      ctx.fillStyle = t.layer === 'B.SilkS' ? '#a0a0a0' : '#e0e0e0';
      ctx.fillText(t.text, 0, 0);
      ctx.restore();
    });

    // ---------- 选中高亮 ----------
    if (!selection) return;
    const { kind, index } = selection;

    ctx.strokeStyle = HIGHLIGHT;
    ctx.lineWidth = 2;
    ctx.setLineDash([]);

    if (kind === 'segment') {
      const s = items.segments[index];
      if (s) {
        const a = T.toS(s.x1, s.y1), b = T.toS(s.x2, s.y2);
        ctx.lineWidth = Math.max(Math.abs(s.w) * T.scale, 0.5) + 3;
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      }
    } else if (kind === 'edge') {
      const e = items.edges[index];
      if (e) {
        const a = T.toS(e.x1, e.y1), b = T.toS(e.x2, e.y2);
        ctx.lineWidth = 4;
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      }
    } else if (kind === 'circle') {
      const c = items.circles[index];
      if (c) {
        const p = T.toS(c.x, c.y);
        ctx.lineWidth = 3;
        safeArc(ctx, p.sx, p.sy, c.r * T.scale + 2);
        ctx.stroke();
      }
    } else if (kind === 'arc') {
      const a = (items.arcs || [])[index];
      if (a && a.points && a.points.length >= 2) {
        ctx.lineWidth = 4;
        ctx.beginPath();
        for (let i = 0; i < a.points.length; i++) {
          const q = T.toS(a.points[i][0], a.points[i][1]);
          if (i === 0) ctx.moveTo(q.sx, q.sy); else ctx.lineTo(q.sx, q.sy);
        }
        ctx.stroke();
      }
    } else if (kind === 'via') {
      const v = items.vias[index];
      if (v) {
        const p = T.toS(v.x, v.y);
        ctx.lineWidth = 3;
        safeArc(ctx, p.sx, p.sy, v.r * T.scale + 3);
        ctx.stroke();
      }
    } else if (kind === 'pad') {
      const p = items.pads[index];
      if (p) {
        const c = T.toS(p.x, p.y);
        ctx.save();
        ctx.translate(c.sx, c.sy);
        ctx.rotate(-p.rot);
        const pw = Math.abs(p.w) * T.scale + 4;
        const ph = Math.abs(p.h) * T.scale + 4;
        ctx.lineWidth = 2;
        if (p.shape === 'circle') {
          safeArc(ctx, 0, 0, Math.min(pw, ph) / 2);
          ctx.stroke();
        } else if (p.shape === 'oval') {
          ctx.beginPath();
          ctx.ellipse(0, 0, Math.abs(pw/2), Math.abs(ph/2), 0, 0, Math.PI * 2);
          ctx.stroke();
        } else {
          ctx.strokeRect(-pw / 2, -ph / 2, pw, ph);
        }
        ctx.restore();
      }
    }
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.PcbRenderer = { render };
})(window);