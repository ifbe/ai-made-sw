(function (global) {
    'use strict';
  
    const STORAGE_KEY = 'kipreview.propertiesWidth';
    const MIN_W = 200;
    const MAX_W = 600;
    const DEFAULT_W = 280;
  
    let resizeState = null;
  
    function getStoredWidth() {
      try {
        const v = parseInt(localStorage.getItem(STORAGE_KEY), 10);
        if (!isNaN(v) && v >= MIN_W && v <= MAX_W) return v;
      } catch (e) {}
      return DEFAULT_W;
    }
  
    function saveWidth(w) {
      try { localStorage.setItem(STORAGE_KEY, String(w)); } catch (e) {}
    }
  
    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }
  
    function show(container, info, onClose) {
      const width = getStoredWidth();
      let html = '';
      html += '<div class="pp-header">';
      html += '<span class="pp-title">' + escapeHtml(info.title || '详情') + '</span>';
      html += '<button class="pp-close" title="取消选中">×</button>';
      html += '</div>';
      html += '<div class="pp-rows">';
      for (const row of (info.rows || [])) {
        html += '<div class="pp-row">';
        html += '<span class="pp-key">' + escapeHtml(row[0]) + '</span>';
        html += '<span class="pp-val">' + escapeHtml(row[1]) + '</span>';
        html += '</div>';
      }
      html += '</div>';
      if (info.source) {
        html += '<div class="pp-source-title">S-expression</div>';
        html += '<pre class="pp-source">' + escapeHtml(info.source) + '</pre>';
      }
      html += '<div class="pp-resize"></div>';
  
      container.innerHTML = html;
      container.style.width = width + 'px';
      container.classList.add('visible');
  
      // 关闭按钮
      const closeBtn = container.querySelector('.pp-close');
      if (closeBtn && onClose) {
        closeBtn.addEventListener('click', onClose);
      }
  
      // 拖拽调整宽度
      const handle = container.querySelector('.pp-resize');
      if (handle) {
        handle.addEventListener('mousedown', e => {
          e.preventDefault();
          e.stopPropagation();
          resizeState = {
            startX: e.clientX,
            startWidth: container.getBoundingClientRect().width
          };
          document.body.style.cursor = 'col-resize';
          document.body.style.userSelect = 'none';
        });
      }
    }
  
    function hide(container) {
      container.classList.remove('visible');
      container.innerHTML = '';
      container.style.width = '';
    }
  
    // 全局监听 resize 拖拽
    window.addEventListener('mousemove', e => {
      if (!resizeState) return;
      const container = document.getElementById('properties');
      if (!container) return;
      let w = resizeState.startWidth + (e.clientX - resizeState.startX);
      w = Math.max(MIN_W, Math.min(MAX_W, w));
      container.style.width = w + 'px';
    });
  
    window.addEventListener('mouseup', () => {
      if (!resizeState) return;
      const container = document.getElementById('properties');
      if (container) {
        const w = Math.round(container.getBoundingClientRect().width);
        saveWidth(w);
      }
      resizeState = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    });
  
    global.KiPreview = global.KiPreview || {};
    global.KiPreview.PropertiesPanel = { show, hide };
  })(window);