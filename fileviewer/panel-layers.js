(function (global) {
    'use strict';
  
    const PCB_LAYERS = [
      { id: 'Edge.Cuts', name: '板框',     color: '#f0c040' },
      { id: 'B.Cu',      name: '底层铜',   color: '#2a6a2a' },
      { id: 'F.Cu',      name: '顶层铜',   color: '#c83232' },
      { id: 'Pads',      name: '焊盘',     color: '#d4b060' },
      { id: 'Vias',      name: '过孔',     color: '#999999' },
      { id: 'F.SilkS',   name: '顶层丝印', color: '#e0e0e0' },
      { id: 'B.SilkS',   name: '底层丝印', color: '#a0a0a0' },
      { id: 'Models',    name: '元件模型', color: '#8c8cf5' }
    ];
  
    const SCH_LAYERS = [
      { id: 'Wires',     name: '导线',     color: '#3a9a3a' },
      { id: 'Symbols',   name: '符号',     color: '#c83232' },
      { id: 'Labels',    name: '标签',     color: '#60a0e0' },
      { id: 'Junctions', name: '节点',     color: '#3a9a3a' },
      { id: 'Texts',     name: '注释',     color: '#888888' }
    ];
  
    function createVisibility(type) {
      const vis = {};
      const defs = type === 'pcb' ? PCB_LAYERS : SCH_LAYERS;
      for (const d of defs) vis[d.id] = true;
      return vis;
    }
  
    function isVisible(vis, id) {
      return vis[id] !== false;
    }
  
    function buildPanel(container, type, vis, onChange) {
      const defs = type === 'pcb' ? PCB_LAYERS : SCH_LAYERS;
      let html = '<div class="title">图层</div>';
      for (const d of defs) {
        html += '<label>' +
          '<input type="checkbox" data-layer="' + d.id + '"' + (isVisible(vis, d.id) ? ' checked' : '') + '>' +
          '<span class="swatch" style="background:' + d.color + '"></span>' +
          '<span>' + d.name + '</span>' +
          '</label>';
      }
      html += '<div class="actions">' +
        '<button data-act="all">全选</button>' +
        '<button data-act="none">全不选</button>' +
        '</div>';
      container.innerHTML = html;
      container.classList.add('visible');
  
      container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', () => {
          vis[cb.dataset.layer] = cb.checked;
          onChange();
        });
      });
      container.querySelectorAll('button[data-act]').forEach(btn => {
        btn.addEventListener('click', () => {
          const on = btn.dataset.act === 'all';
          container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.checked = on;
            vis[cb.dataset.layer] = on;
          });
          onChange();
        });
      });
    }
  
    global.KiPreview = global.KiPreview || {};
    global.KiPreview.Layers = { PCB_LAYERS, SCH_LAYERS, createVisibility, isVisible, buildPanel };
  })(window);