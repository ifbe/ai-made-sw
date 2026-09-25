(function (global) {
    'use strict';
  
    // 点到线段的最短距离
    function distToSegment(px, py, x1, y1, x2, y2) {
      const dx = x2 - x1, dy = y2 - y1;
      const len2 = dx * dx + dy * dy;
      if (len2 === 0) return Math.hypot(px - x1, py - y1);
      let t = ((px - x1) * dx + (py - y1) * dy) / len2;
      t = Math.max(0, Math.min(1, t));
      const cx = x1 + t * dx, cy = y1 + t * dy;
      return Math.hypot(px - cx, py - cy);
    }
  
    // 点到旋转矩形的距离（把点逆旋转到矩形局部坐标，再算到 AABB 的距离）
    function distToRect(px, py, cx, cy, w, h, rot) {
      const cos = Math.cos(-rot), sin = Math.sin(-rot);
      const dx = px - cx, dy = py - cy;
      const lx = dx * cos - dy * sin;
      const ly = dx * sin + dy * cos;
      const hw = w / 2, hh = h / 2;
      const ox = Math.max(Math.abs(lx) - hw, 0);
      const oy = Math.max(Math.abs(ly) - hh, 0);
      return Math.hypot(ox, oy);
    }
  
    // 点到旋转椭圆的距离（近似：把点逆旋转，再按椭圆半径归一化）
    function distToEllipse(px, py, cx, cy, rx, ry, rot) {
      const cos = Math.cos(-rot), sin = Math.sin(-rot);
      const dx = px - cx, dy = py - cy;
      const lx = dx * cos - dy * sin;
      const ly = dx * sin + dy * cos;
      if (rx <= 0 || ry <= 0) return Math.hypot(lx, ly);
      const nx = lx / rx, ny = ly / ry;
      const d = Math.hypot(nx, ny);
      // 近似：把归一化距离映射回世界坐标距离
      return Math.abs(d - 1) * Math.min(rx, ry);
    }
  
    // 点到折线的最短距离。板框圆弧在解析时已采样成折线，直接复用这些点。
    function distToPolyline(px, py, pts) {
      if (!pts || pts.length < 2) return Infinity;
      let best = Infinity;
      for (let i = 0; i < pts.length - 1; i++) {
        const d = distToSegment(px, py, pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1]);
        if (d < best) best = d;
      }
      return best;
    }

    function hitTest(items, type, wx, wy, tol, visibility, isVisible) {
      if (type !== 'pcb') return null;
  
      let best = null;
      let bestDist = Infinity;
  
      function consider(kind, index, dist, priority) {
        if (dist > tol) return;
        // 优先级数字越大越优先；同优先级比距离
        if (!best ||
            priority > best.priority ||
            (priority === best.priority && dist < bestDist)) {
          best = { kind, index, priority };
          bestDist = dist;
        }
      }
  
      // 焊盘（优先级 3）
      if (isVisible(visibility, 'Pads')) {
        items.pads.forEach((p, i) => {
          let d;
          const r = p.rot;
          if (p.shape === 'circle') {
            const rad = Math.min(p.w, p.h) / 2;
            d = Math.abs(Math.hypot(wx - p.x, wy - p.y) - rad);
          } else if (p.shape === 'oval') {
            d = distToEllipse(wx, wy, p.x, p.y, p.w / 2, p.h / 2, r);
          } else {
            d = distToRect(wx, wy, p.x, p.y, p.w, p.h, r);
          }
          consider('pad', i, d, 3);
        });
      }
  
      // 过孔（优先级 3）
      if (isVisible(visibility, 'Vias')) {
        items.vias.forEach((v, i) => {
          const d = Math.max(Math.hypot(wx - v.x, wy - v.y) - v.r, 0);
          consider('via', i, d, 3);
        });
      }
  
      // 走线（优先级 2）
      if (isVisible(visibility, 'F.Cu')) {
        items.segments.forEach((s, i) => {
          if (s.layer !== 'F.Cu') return;
          const d = Math.max(distToSegment(wx, wy, s.x1, s.y1, s.x2, s.y2) - s.w / 2, 0);
          consider('segment', i, d, 2);
        });
      }
      if (isVisible(visibility, 'B.Cu')) {
        items.segments.forEach((s, i) => {
          if (s.layer !== 'B.Cu') return;
          const d = Math.max(distToSegment(wx, wy, s.x1, s.y1, s.x2, s.y2) - s.w / 2, 0);
          consider('segment', i, d, 2);
        });
      }
  
      // 板框线（优先级 1）
      if (isVisible(visibility, 'Edge.Cuts')) {
        items.edges.forEach((e, i) => {
          const d = distToSegment(wx, wy, e.x1, e.y1, e.x2, e.y2);
          consider('edge', i, d, 1);
        });
        items.circles.forEach((c, i) => {
          const d = Math.abs(Math.hypot(wx - c.x, wy - c.y) - c.r);
          consider('circle', i, d, 1);
        });
        (items.arcs || []).forEach((a, i) => {
          consider('arc', i, distToPolyline(wx, wy, a.points), 1);
        });
      }
  
      // TODO: 文字（gr_text / fp_text）的命中测试
  
      return best ? { kind: best.kind, index: best.index } : null;
    }
  
    global.KiPreview = global.KiPreview || {};
    global.KiPreview.HitTest = { hitTest };
  })(window);