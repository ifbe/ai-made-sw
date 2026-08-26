// script.js
// 全局工具函数

// 显示通知
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 2rem;
        background-color: ${type === 'error' ? '#e74c3c' : type === 'success' ? '#2ecc71' : '#3498db'};
        color: white;
        border-radius: 4px;
        z-index: 2000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// 添加动画样式
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// 文件大小格式化
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 加载可选转换方法到下拉框（/api/methods/<type>），并记住用户选择
// 用法：loadMethodSelect('ttsMethod', 'tts', 'ttsMethod')
async function loadMethodSelect(selectId, methodType, storageKey) {
    const sel = document.getElementById(selectId);
    if (!sel) return;
    try {
        const res = await fetch('/api/methods/' + methodType);
        const data = await res.json();
        if (!data.methods || !data.methods.length) return;
        sel.innerHTML = '';
        for (const m of data.methods) {
            const opt = document.createElement('option');
            opt.value = m.model;
            opt.textContent = m.name;
            sel.appendChild(opt);
        }
        const saved = localStorage.getItem(storageKey);
        if (saved && [...sel.options].some(o => o.value === saved)) {
            sel.value = saved;
        }
        sel.addEventListener('change', function() {
            localStorage.setItem(storageKey, this.value);
        });
    } catch (e) { /* 忽略 */ }
}

// ===== 方法参数区：openai 类型方法显示可编辑连接参数（地址/端口/API路径/密码/音调）=====
// usage: initMethodParams('ttsMethod', 'ttsParams', 'tts')
// 参数区 div 初始 display:none；非 openai 方法保持隐藏
async function initMethodParams(selectId, paramsId, methodType) {
    const sel = document.getElementById(selectId);
    const box = document.getElementById(paramsId);
    if (!sel || !box) return;
    let methods = [];
    try {
        const res = await fetch('/api/methods/' + methodType);
        const data = await res.json();
        methods = data.methods || [];
    } catch (e) { return; }
    if (!methods.length) return;

    sel.innerHTML = '';
    for (const m of methods) {
        const opt = document.createElement('option');
        opt.value = m.model;
        opt.textContent = m.name;
        sel.appendChild(opt);
    }
    const saved = localStorage.getItem(selectId);
    if (saved && [...sel.options].some(o => o.value === saved)) sel.value = saved;
    sel.addEventListener('change', function() {
        localStorage.setItem(selectId, this.value);
        renderParams();
    });

    function renderParams() {
        const m = methods.find(x => x.model === sel.value);
        const isOpenai = m && m.api && String(m.api).toLowerCase().includes('openai');
        box.innerHTML = '';
        if (!isOpenai) { box.style.display = 'none'; return; }
        box.style.display = 'flex';
        box.style.flexDirection = 'column';
        box.style.gap = '0.3rem';
        box.style.width = '100%';

        // 通用字段：地址/端口/API路径/密码；音调（voice）仅当方法配置里有该字段时显示（如 TTS 服务）
        const fieldKeys = [
            ['addr', '地址'], ['port', '端口'], ['api_path', 'API路径'],
            ['password', '密码/Key'],
        ];
        if (m.voice !== undefined) fieldKeys.push(['voice', '音调']);

        const values = {
            addr: m.addr || '',
            port: m.port || '',
            api_path: m.api_path || '',
            password: m.api_key || '',
            voice: m.voice || '',
        };
        let row = document.createElement('div');
        row.style.cssText = 'display:flex; gap:0.3rem; width:100%;';
        fieldKeys.forEach(function(pair, i) {
            const key = pair[0], label = pair[1];
            const inp = document.createElement('input');
            inp.dataset.param = key;
            inp.placeholder = label;
            inp.value = values[key] || '';
            if (key === 'password') inp.type = 'password';
            inp.style.cssText = 'padding:0.35rem 0.4rem; border:1px solid #ddd; border-radius:4px; font-size:0.8rem; flex:1; min-width:55px;';
            row.appendChild(inp);
            // 每行最多 3 个，满了换行
            if ((i + 1) % 3 === 0 && i < fieldKeys.length - 1) {
                box.appendChild(row);
                row = document.createElement('div');
                row.style.cssText = 'display:flex; gap:0.3rem; width:100%;';
            }
        });
        if (row.children.length) box.appendChild(row);
    }
    renderParams();
}

// 收集方法参数区当前值（openai 方法显示时），返回 {addr, port, api_path, password, voice, ...}
function collectMethodParams(paramsId) {
    const box = document.getElementById(paramsId);
    const out = {};
    if (!box || box.style.display === 'none') return out;
    box.querySelectorAll('[data-param]').forEach(function(inp) {
        const v = inp.value.trim();
        if (v) out[inp.dataset.param] = v;
    });
    return out;
}

// ===== 悬浮矩形拖动：按住矩形空白处（非输入控件）可移动位置 =====
function makeDraggable(rect) {
    if (!rect || rect.dataset.draggable) return;
    rect.dataset.draggable = '1';
    let dragging = false, startX = 0, startY = 0, origLeft = 0, origTop = 0;

    rect.addEventListener('mousedown', function(e) {
        if (e.target.closest('input, select, button, textarea, a')) return;
        dragging = true;
        startX = e.clientX;
        startY = e.clientY;
        const cs = window.getComputedStyle(rect);
        origLeft = parseFloat(cs.left) || 0;
        origTop = parseFloat(cs.top) || 0;
        rect.style.cursor = 'grabbing';
        e.preventDefault();
    });

    document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        rect.style.left = (origLeft + (e.clientX - startX)) + 'px';
        rect.style.top = (origTop + (e.clientY - startY)) + 'px';
    });

    document.addEventListener('mouseup', function() {
        if (dragging) { dragging = false; rect.style.cursor = 'move'; }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.media-rect').forEach(makeDraggable);
});
