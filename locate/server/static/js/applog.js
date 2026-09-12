// ========== 应用内日志缓冲 + 左下角日志矩形 ==========
//
// 对应 Android 的 AppLog.kt / LogPanel，以及 iOS 的 AppLog.swift / LogPanel.swift。
// 只记录「本程序自己想在界面上告诉用户」的消息，不是 console 的镜像；
// 缓冲区是页面级的，所以准备页写的日志进地图页也还能看到。

const AppLog = (() => {
    const MAX_ENTRIES = 200;
    const PREFS_KEY = 'locate.logPanel';

    const listeners = [];
    const buffer = [];

    function pad2(n) {
        return n < 10 ? '0' + n : '' + n;
    }

    function nowText() {
        const d = new Date();
        return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    }

    function notify() {
        listeners.forEach((fn) => {
            try {
                fn();
            } catch (e) {
                console.error('日志监听回调出错', e);
            }
        });
    }

    function append(level, text) {
        buffer.push({ time: nowText(), level: level, text: text });
        while (buffer.length > MAX_ENTRIES) buffer.shift();
        notify();
    }

    return {
        entries: buffer,

        i(text) { console.log(text); append('info', String(text)); },
        w(text) { console.warn(text); append('warn', String(text)); },
        e(text) { console.error(text); append('error', String(text)); },

        clear() {
            buffer.length = 0;
            notify();
        },

        subscribe(fn) {
            listeners.push(fn);
        },

        // 日志矩形的展开状态和用户拖出来的尺寸；记在 localStorage 里，刷新后保持原样
        prefs: {
            expanded: false,
            rows: 10,
            width: 0
        },

        loadPrefs() {
            try {
                const raw = localStorage.getItem(PREFS_KEY);
                if (!raw) return;
                const saved = JSON.parse(raw);
                this.prefs.expanded = saved.expanded === true;
                if (typeof saved.rows === 'number' && saved.rows > 0) this.prefs.rows = saved.rows;
                if (typeof saved.width === 'number' && saved.width > 0) this.prefs.width = saved.width;
            } catch (e) {
                console.warn('日志面板设置读取失败', e);
            }
        },

        savePrefs() {
            try {
                localStorage.setItem(PREFS_KEY, JSON.stringify(this.prefs));
            } catch (e) {
                // 隐私模式下写不进去，忽略
            }
        }
    };
})();


// ─── 日志矩形（左下角） ─────────────────────────────────────────────

const LogPanel = (() => {
    // 尺寸常量，和 Android / iOS 保持一致
    const ROW_PITCH = 14;          // 每行日志的行距
    const STRIP_HEIGHT = 30;       // 底部把手条高度（折叠时只有它）
    const ROWS_TOP = 3;
    const MIN_ROWS = 3;
    const MAX_ROWS_CAP = 30;
    const DEFAULT_WIDTH = 300;
    const MIN_PANEL_WIDTH = 140;
    const TAB_MIN_WIDTH = 40;      // 折叠小方块的最小宽度（箭头 + 日志N）
    const RESIZE_ZONE = 26;        // 右上角缩放热区大小
    const LONG_PRESS_MS = 600;
    const DRAG_SLOP = 6;

    let scrollLines = 0;           // 距最新一行上滚了多少行，0 = 贴住最新
    let lastCount = 0;
    let ready = false;

    const measureCanvas = document.createElement('canvas').getContext('2d');

    function stripText() {
        return '日志 ' + AppLog.entries.length;
    }

    function maxRows() {
        const usable = window.innerHeight / 2 - (STRIP_HEIGHT + ROWS_TOP + 1);
        return Math.min(MAX_ROWS_CAP, Math.max(MIN_ROWS, Math.floor(usable / ROW_PITCH)));
    }

    function capacity() {
        return Math.min(Math.max(AppLog.prefs.rows, MIN_ROWS), maxRows());
    }

    function maxScroll() {
        return Math.max(0, AppLog.entries.length - capacity());
    }

    /** 折叠态宽度：按把手条文字实测，仍比展开时短得多 */
    function tabWidth() {
        measureCanvas.font = "10px 'Segoe UI', Roboto, system-ui, sans-serif";
        const textWidth = measureCanvas.measureText(stripText()).width;
        return Math.max(TAB_MIN_WIDTH, Math.ceil(24 + textWidth + 10));
    }

    function panelWidth() {
        if (!AppLog.prefs.expanded) return tabWidth();
        const stored = AppLog.prefs.width > 0 ? AppLog.prefs.width : Math.min(DEFAULT_WIDTH, window.innerWidth - 48);
        return Math.min(Math.max(stored, MIN_PANEL_WIDTH), window.innerWidth - 16);
    }

    /** 当前视口里的日志：末尾是 entries.length - scrollLines */
    function visibleEntries() {
        const all = AppLog.entries;
        const end = Math.min(Math.max(all.length - scrollLines, 0), all.length);
        const start = Math.max(0, end - capacity());
        return all.slice(start, end);
    }

    // ─── 绘制 ──────────────────────────────────────────────────────

    function render() {
        if (!ready) return;

        const expanded = AppLog.prefs.expanded;
        DOM.logPanel.classList.toggle('expanded', expanded);
        DOM.logTriangle.className = 'log-triangle ' + (expanded ? 'down' : 'up');
        DOM.logStripText.textContent = stripText();
        DOM.logStripText.classList.toggle('scrolled', expanded && scrollLines > 0);
        DOM.logPanel.style.width = panelWidth() + 'px';

        if (!expanded) {
            DOM.logRows.style.display = 'none';
            DOM.logGrip.classList.remove('show');
            return;
        }

        const rows = capacity();
        DOM.logRows.style.display = 'block';
        DOM.logRows.style.height = (ROWS_TOP + rows * ROW_PITCH) + 'px';
        DOM.logGrip.classList.add('show');

        const visible = visibleEntries();
        if (visible.length === 0) {
            DOM.logLines.innerHTML = '<div class="log-empty">暂无日志</div>';
        } else {
            // 每行固定 14px，超出视口的行本来就不在 visible 里，不用滚动容器
            DOM.logLines.innerHTML = visible.map((entry) => {
                const cls = entry.level === 'info' ? 'log-row' : 'log-row ' + entry.level;
                return '<div class="' + cls + '">' +
                    '<span class="t">' + escapeHtml(entry.time) + '</span>' +
                    '<span class="m">' + escapeHtml(entry.text) + '</span>' +
                    '</div>';
            }).join('');
        }

        // 终端式滚动条：显示当前窗口在全部日志里的位置
        const total = AppLog.entries.length;
        if (total > rows) {
            const end = Math.min(Math.max(total - scrollLines, 0), total);
            const start = Math.max(0, end - rows);
            DOM.logScrollbar.classList.add('show');
            const trackHeight = DOM.logScrollbar.clientHeight;
            DOM.logThumb.style.height = Math.max(10, trackHeight * rows / total) + 'px';
            DOM.logThumb.style.marginTop = (trackHeight * start / total) + 'px';
        } else {
            DOM.logScrollbar.classList.remove('show');
        }
    }

    function escapeHtml(text) {
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    // ─── 交互 ──────────────────────────────────────────────────────

    function toggle() {
        AppLog.prefs.expanded = !AppLog.prefs.expanded;
        if (!AppLog.prefs.expanded) scrollLines = 0;
        AppLog.savePrefs();
        render();
    }

    function clearAndReset() {
        AppLog.clear();
        scrollLines = 0;
        render();
    }

    /** 有的浏览器在指针已经不是活动状态时会抛错，捕获掉即可（拖动照样能用） */
    function capturePointer(el, e) {
        try {
            if (el.setPointerCapture) el.setPointerCapture(e.pointerId);
        } catch (err) {
            // 忽略
        }
    }

    function bindStrip() {
        let pressStart = 0;
        let moved = false;
        let downY = 0;

        DOM.logStrip.addEventListener('pointerdown', (e) => {
            pressStart = Date.now();
            downY = e.clientY;
            moved = false;
            capturePointer(DOM.logStrip, e);
        });

        DOM.logStrip.addEventListener('pointermove', (e) => {
            if (pressStart === 0) return;
            if (Math.abs(e.clientY - downY) > DRAG_SLOP) moved = true;
        });

        const finish = () => {
            if (pressStart === 0) return;      // 不是在这个元素上按下的，不处理
            const duration = Date.now() - pressStart;
            pressStart = 0;
            if (duration >= LONG_PRESS_MS) {
                clearAndReset();               // 长按清空
            } else if (!moved) {
                toggle();                      // 短按切换展开/折叠
            }
        };

        DOM.logStrip.addEventListener('pointerup', finish);
        DOM.logStrip.addEventListener('pointercancel', () => { pressStart = 0; });
    }

    function bindRows() {
        let pressStart = 0;
        let downY = 0;
        let lastY = 0;
        let dragging = false;

        DOM.logRows.addEventListener('pointerdown', (e) => {
            pressStart = Date.now();
            downY = e.clientY;
            lastY = e.clientY;
            dragging = false;
            capturePointer(DOM.logRows, e);
        });

        DOM.logRows.addEventListener('pointermove', (e) => {
            if (pressStart === 0) return;
            if (!dragging && Math.abs(e.clientY - downY) > DRAG_SLOP) dragging = true;
            if (!dragging) return;
            const lines = Math.trunc((e.clientY - lastY) / ROW_PITCH);
            if (lines !== 0) {
                scrollLines = Math.min(Math.max(scrollLines + lines, 0), maxScroll());
                lastY += lines * ROW_PITCH;
                render();
            }
        });

        const finish = () => {
            if (pressStart === 0) return;
            const duration = Date.now() - pressStart;
            const wasDragging = dragging;
            pressStart = 0;
            dragging = false;
            if (!wasDragging && duration >= LONG_PRESS_MS) {
                clearAndReset();
            }
        };

        DOM.logRows.addEventListener('pointerup', finish);
        DOM.logRows.addEventListener('pointercancel', () => { pressStart = 0; dragging = false; });
    }

    function bindGrip() {
        let resizing = false;
        let startX = 0;
        let startY = 0;
        let startWidth = 0;
        let startRows = 0;

        DOM.logGrip.addEventListener('pointerdown', (e) => {
            e.preventDefault();
            e.stopPropagation();
            resizing = true;
            startX = e.clientX;
            startY = e.clientY;
            startWidth = panelWidth();
            startRows = capacity();
            capturePointer(DOM.logGrip, e);
        });

        DOM.logGrip.addEventListener('pointermove', (e) => {
            if (!resizing) return;
            // 左下角固定，所以往右上拖变大
            const newWidth = Math.min(
                Math.max(startWidth + (e.clientX - startX), MIN_PANEL_WIDTH),
                window.innerWidth - 16
            );
            const deltaRows = Math.trunc(-(e.clientY - startY) / ROW_PITCH);
            const newRows = Math.min(Math.max(startRows + deltaRows, MIN_ROWS), maxRows());

            AppLog.prefs.width = newWidth;
            AppLog.prefs.rows = newRows;
            scrollLines = Math.min(scrollLines, Math.max(0, AppLog.entries.length - newRows));
            render();
        });

        DOM.logGrip.addEventListener('pointerup', () => {
            if (!resizing) return;
            resizing = false;
            AppLog.savePrefs();
        });
    }

    function init() {
        if (ready) return;

        AppLog.loadPrefs();
        lastCount = AppLog.entries.length;

        bindStrip();
        bindRows();
        bindGrip();

        AppLog.subscribe(() => {
            const newCount = AppLog.entries.length;
            // 正在翻历史时来了新日志：滚动量一起前推，视口保持不动
            if (scrollLines > 0 && newCount > lastCount) {
                scrollLines += newCount - lastCount;
            }
            lastCount = newCount;
            scrollLines = Math.min(Math.max(scrollLines, 0), maxScroll());
            render();
        });

        ready = true;
        render();
    }

    return { init, render, capacity, maxRows, ROW_PITCH, STRIP_HEIGHT, ROWS_TOP };
})();
