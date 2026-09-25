(function (global) {
    'use strict';
  
    function create() {
      return { panX: 0, panY: 0, scale: 1 };
    }
  
    function fit(view, bounds, w, h, padding) {
      padding = padding || 30;
      const bw = bounds.maxX - bounds.minX || 1;
      const bh = bounds.maxY - bounds.minY || 1;
      view.scale = Math.min((w - padding * 2) / bw, (h - padding * 2) / bh);
      view.panX = (w - bw * view.scale) / 2;
      view.panY = (h - bh * view.scale) / 2;
    }
  
    // KiCad 坐标系 Y 轴向下，和 Canvas 一致，直接线性映射
    function makeTransform(view, bounds, w, h) {
      return {
        scale: view.scale,
        toS(x, y) {
          return {
            sx: (x - bounds.minX) * view.scale + view.panX,
            sy: (y - bounds.minY) * view.scale + view.panY
          };
        }
      };
    }
  
    function screenToWorld(view, sx, sy, bounds) {
      return {
        x: (sx - view.panX) / view.scale + bounds.minX,
        y: (sy - view.panY) / view.scale + bounds.minY
      };
    }
  
    function zoomAt(view, mx, my, factor, bounds) {
      const world = screenToWorld(view, mx, my, bounds);
      view.scale = Math.max(0.1, Math.min(view.scale * factor, 500));
      view.panX = mx - (world.x - bounds.minX) * view.scale;
      view.panY = my - (world.y - bounds.minY) * view.scale;
    }
  
    global.KiPreview = global.KiPreview || {};
    global.KiPreview.Viewport = { create, fit, makeTransform, screenToWorld, zoomAt };
  })(window);