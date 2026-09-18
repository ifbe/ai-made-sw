/**
 * 页面外壳：左上角标签栏、右上角重置、左下角联机条、右下角日志框。
 * 对应 Android 的 MainActivity.kt + res/layout/activity_main.xml。
 *
 * 和 Android 的区别（浏览器里没法监听端口，服/客二合一没有意义）：
 * 左下角联机条只有 [地址][开始/状态]，永远是「客」——连的是 python server.py
 * （或者 Android 端开的「服」）。地址默认就是打开这个页面的 host:port。
 */
var Chrome = (function () {
    'use strict';

    var DEFAULT_PORT = 8765;
    var STORAGE_ADDRESS = 'chess.net.address';
    var STORAGE_WANTED = 'chess.net.wanted';

    /** 左上角标签栏：主页 + 四种棋（四种棋的顺序和 Android 的标签栏一致）。 */
    var PAGES = [
        {id: 'index', label: '主页', href: 'index.html'},
        {id: 'xiangqi', label: '象棋', href: 'xiangqi.html'},
        {id: 'intl_chess', label: '国际象棋', href: 'intl_chess.html'},
        {id: 'weiqi', label: '围棋', href: 'weiqi.html'},
        {id: 'wuziqi', label: '五子棋', href: 'wuziqi.html'}
    ];

    var session = null;
    var linkState = 'idle';
    var statusDetail = '';
    var remoteHandler = null;
    var lastViewState = null;
    var nodes = {};

    // ------------------------------------------------------------------ 小工具

    function store(key, value) {
        try {
            sessionStorage.setItem(key, value);
        } catch (e) {
            // 忽略
        }
    }

    function read(key, fallback) {
        try {
            var value = sessionStorage.getItem(key);
            return value === null ? fallback : value;
        } catch (e) {
            return fallback;
        }
    }

    function make(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text) node.textContent = text;
        return node;
    }

    /**
     * 用户输入 → ws 地址。允许省略 `ws://`，也允许不写端口（补默认端口）；
     * 顺手把从浏览器地址栏复制过来的 `http(s)://` 换成 `ws(s)://`。不合法返回 null。
     */
    function toWsUrl(text) {
        var raw = (text || '').trim();
        if (!raw) return null;
        if (/^https:\/\//i.test(raw)) {
            raw = 'wss://' + raw.substring(8);
        } else if (/^http:\/\//i.test(raw)) {
            raw = 'ws://' + raw.substring(7);
        } else if (!/^wss?:\/\//i.test(raw)) {
            raw = 'ws://' + raw;
        }

        var url;
        try {
            url = new URL(raw);
        } catch (e) {
            return null;
        }
        if (!url.hostname) return null;
        if (!url.port) url.port = String(DEFAULT_PORT);
        return url.toString();
    }

    // ------------------------------------------------------------------ 联机

    function createSession() {
        var created = new WsClient({
            onState: function (kind, message) {
                // 已经换了一条连接 / 已经断开，旧连接的回调就丢掉
                if (session !== created) return;
                setLinkState(kind, message);
            },
            onEvent: function (event) {
                if (remoteHandler) remoteHandler(event);
            }
        });
        session = created;
        return created;
    }

    function startSession(url) {
        createSession().start(url);
    }

    function closeSession() {
        var current = session;
        session = null;
        if (current) current.close();
        linkState = 'idle';
        statusDetail = '';
        refreshAction();
    }

    function toggleSession() {
        if (session) {
            store(STORAGE_WANTED, '0');
            closeSession();
            return;
        }

        var address = nodes.address.value.trim();
        var url = toWsUrl(address);
        if (!url) {
            AppLog.log('地址不合法：' + address);
            setLinkState('failed', '地址不对');
            return;
        }
        store(STORAGE_ADDRESS, address);
        store(STORAGE_WANTED, '1');
        startSession(url);
    }

    function setLinkState(kind, message) {
        linkState = kind;
        statusDetail = message || '';
        refreshAction();
    }

    /** 按钮文字 = 当前状态 + 下一步动作（跟 Android 的 refreshNetAction 一样）。 */
    function refreshAction() {
        var text;
        if (session) {
            if (statusDetail) text = statusDetail;
            else if (linkState === 'starting') text = '连接中…';
            else if (linkState === 'online') text = '已连接';
            else text = '连接失败';
        } else if (linkState === 'failed' && statusDetail) {
            // Android 这里会被 session == null 覆盖成「开始连接」，只剩日志能看；
            // 网页上直接把「地址不对」写在按钮上，点一下还能重试。
            text = statusDetail;
        } else {
            text = '开始连接';
        }
        nodes.action.textContent = text;
    }

    // ------------------------------------------------------------------ 全屏 / 方向

    function fullscreenElement() {
        return document.fullscreenElement || document.webkitFullscreenElement || null;
    }

    function fullscreenSupported() {
        var root = document.documentElement;
        return !!(root && (root.requestFullscreen || root.webkitRequestFullscreen));
    }

    function describeError(error) {
        if (!error) return '未知原因';
        return error.message || String(error);
    }

    /** 全屏 / 正常 切换（必须由用户点出来，浏览器只认用户手势）。 */
    function toggleFullscreen() {
        if (fullscreenElement()) {
            var exit = document.exitFullscreen || document.webkitExitFullscreen;
            if (!exit) return;
            try {
                var exited = exit.call(document);
                if (exited && exited.catch) {
                    exited.catch(function (error) {
                        AppLog.log('退出全屏失败：' + describeError(error));
                    });
                }
            } catch (e) {
                AppLog.log('退出全屏失败：' + describeError(e));
            }
            return;
        }

        var root = document.documentElement;
        var request = root && (root.requestFullscreen || root.webkitRequestFullscreen);
        if (!request) {
            AppLog.log('这个浏览器不支持全屏 API');
            return;
        }
        try {
            var requested = request.call(root);
            if (requested && requested.catch) {
                requested.catch(function (error) {
                    AppLog.log('全屏被拒绝：' + describeError(error));
                });
            }
        } catch (e) {
            AppLog.log('全屏失败：' + describeError(e));
        }
    }

    function refreshFullscreenLabel() {
        if (!nodes.fullscreen) return;
        nodes.fullscreen.textContent = fullscreenElement() ? '⛶ 正常' : '⛶ 全屏';
    }

    function onFullscreenChange() {
        refreshFullscreenLabel();
        AppLog.log(fullscreenElement() ? '进入全屏' : '退出全屏');
        // 全屏会把视口变大 / 变小，页面要不要转可能得重算
        Draw.applyOrientation();
        refreshViewState();
        layoutTabs();
    }

    /** 横屏 / 竖屏 切换：玩家左右 ↔ 玩家上下。 */
    function toggleOrientation() {
        var next = Draw.effectiveOrientation() === 'landscape' ? 'portrait' : 'landscape';
        Draw.setOrientation(next);
        refreshOrientationLabel();
        refreshViewState();
        layoutTabs();
        AppLog.log(next === 'landscape'
            ? '切换为横屏（两个玩家左右分坐）'
            : '切换为竖屏（两个玩家上下分坐）');
    }

    function refreshOrientationLabel() {
        if (!nodes.orientation) return;
        // 按钮上写的是「点一下会变成什么」
        nodes.orientation.textContent = Draw.effectiveOrientation() === 'landscape'
            ? '⟳ 竖屏'
            : '⟳ 横屏';
    }

    /**
     * 右上角那行小字：把「全屏 / 窗口」和「横屏 / 竖屏」两个状态一起显示出来，
     * 比如「全屏且竖屏」。状态一变就往日志里也记一行。
     */
    function viewStateText() {
        return (fullscreenElement() ? '全屏' : '窗口') + '且' +
            (Draw.effectiveOrientation() === 'landscape' ? '横屏' : '竖屏');
    }

    function refreshViewState() {
        var text = viewStateText();
        if (nodes.viewState) nodes.viewState.textContent = text;
        if (text === lastViewState) return;
        lastViewState = text;
        AppLog.log('当前显示：' + text);
    }

    /** 窗口尺寸 / 设备方向变了：重新对一遍（页面要不要转跟着屏幕方向走）。 */
    function onViewportChange() {
        Draw.applyOrientation();
        refreshOrientationLabel();
        refreshViewState();
        layoutTabs();
    }

    /**
     * 标签栏要让开右上角那组按钮。按钮宽度跟页面文字有关，用 JS 量一下再设，
     * 比在 CSS 里写死一个宽度靠谱（主页只有两个按钮，棋盘页有三个）。
     */
    function layoutTabs() {
        if (!nodes.tabs) return;
        var reserved = nodes.tools ? (nodes.tools.offsetWidth + 20) : 0;
        nodes.tabs.style.maxWidth = 'calc(100% - ' + reserved + 'px)';
    }

    // ------------------------------------------------------------------ 日志框

    function renderLog(lines) {
        nodes.logText.textContent = lines.join('\n');
        if (nodes.logPanel.classList.contains('open')) {
            nodes.logPanel.scrollTop = nodes.logPanel.scrollHeight;
        }
    }

    function toggleLog() {
        var open = !nodes.logPanel.classList.contains('open');
        nodes.logPanel.classList.toggle('open', open);
        nodes.logToggle.textContent = open ? '收起' : '日志';
        if (open) {
            renderLog(AppLog.snapshot());
            nodes.logPanel.scrollTop = nodes.logPanel.scrollHeight;
        }
    }

    // ------------------------------------------------------------------ 搭建

    function build(opts) {
        var page = opts.page;

        // 左上角：标签栏
        var tabs = make('div', 'chrome-tabs');
        for (var i = 0; i < PAGES.length; i++) {
            var item = PAGES[i];
            var tab = make('a', 'chrome-btn' + (item.id === page ? ' active' : ''), item.label);
            tab.href = item.href;
            tabs.appendChild(tab);
        }
        document.body.appendChild(tabs);

        // 右上角：重置（只有真正有棋盘的页面才给）+ 全屏 / 正常 + 横屏 / 竖屏，
        // 下面再挂一行小字显示当前状态（比如「全屏且竖屏」）。
        var tools = make('div', 'chrome-tools');
        var toolsRow = make('div', 'chrome-tools-row');
        if (opts.onReset) {
            var reset = make('div', 'chrome-btn chrome-reset', '↺ 重置');
            reset.addEventListener('click', function () {
                opts.onReset();
            });
            toolsRow.appendChild(reset);
        }
        var fullscreen = null;
        if (fullscreenSupported()) {
            fullscreen = make('div', 'chrome-btn', '⛶ 全屏');
            fullscreen.addEventListener('click', toggleFullscreen);
            toolsRow.appendChild(fullscreen);
        } else {
            // 比如 iPhone 上的 Safari 不支持给普通元素开全屏，那就不放这个按钮
            AppLog.log('这个浏览器不支持全屏 API，右上角不放「全屏」按钮');
        }
        var orientation = make('div', 'chrome-btn', '⟳ 横屏');
        orientation.addEventListener('click', toggleOrientation);
        toolsRow.appendChild(orientation);
        var viewState = make('div', 'chrome-tools-state', '窗口且竖屏');
        tools.appendChild(toolsRow);
        tools.appendChild(viewState);
        document.body.appendChild(tools);

        // 左下角：联机条 [地址][开始/状态]
        var net = make('div', 'chrome-net');
        var address = make('input', 'chrome-address');
        address.type = 'text';
        address.spellcheck = false;
        address.setAttribute('autocomplete', 'off');
        address.placeholder = '192.168.1.7:' + DEFAULT_PORT;
        address.value = read(STORAGE_ADDRESS, window.location.host || ('127.0.0.1:' + DEFAULT_PORT));
        var action = make('div', 'chrome-btn', '开始连接');
        net.appendChild(address);
        net.appendChild(action);
        document.body.appendChild(net);

        // 右下角：日志框（默认折叠成一个按钮）
        var logBox = make('div', 'chrome-log');
        var logPanel = make('div', 'chrome-log-panel');
        var logText = make('div', 'chrome-log-text');
        logPanel.appendChild(logText);
        var logToggle = make('div', 'chrome-btn', '日志');
        logBox.appendChild(logPanel);
        logBox.appendChild(logToggle);
        document.body.appendChild(logBox);

        // 中间的提示文字（主页、以及还没做的棋种）
        if (opts.hint) {
            document.body.appendChild(make('div', 'chrome-hint', opts.hint));
        }

        nodes = {
            tabs: tabs,
            tools: tools,
            viewState: viewState,
            fullscreen: fullscreen,
            orientation: orientation,
            address: address,
            action: action,
            logPanel: logPanel,
            logText: logText,
            logToggle: logToggle
        };

        action.addEventListener('click', toggleSession);
        address.addEventListener('change', function () {
            store(STORAGE_ADDRESS, address.value.trim());
        });
        address.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                address.blur();
                if (!session) toggleSession();
            }
        });
        logToggle.addEventListener('click', toggleLog);
        AppLog.addListener(renderLog);

        // 系统栏 / 设备方向变化：重算方向 + 标签栏让位的宽度
        document.addEventListener('fullscreenchange', onFullscreenChange);
        document.addEventListener('webkitfullscreenchange', onFullscreenChange);
        window.addEventListener('resize', onViewportChange);
        window.addEventListener('orientationchange', onViewportChange);

        AppLog.log('页面加载：' + page + '，本机地址 ' + (window.location.host || '(未知)'));

        refreshFullscreenLabel();
        refreshOrientationLabel();
        refreshViewState();
        layoutTabs();

        // 上个页面连着的时候，切过来自动接上（浏览器换页一定会断一次 socket）
        if (read(STORAGE_WANTED, '0') === '1') {
            var url = toWsUrl(address.value);
            if (url) {
                AppLog.log('自动恢复连接：' + address.value);
                startSession(url);
            }
        }
    }

    return {
        /** 挂载外壳。opts = {page, onReset, hint} */
        mount: function (opts) {
            build(opts || {});
        },

        /** 页面收到对端事件时交给谁（只有象棋页会挂）。 */
        setRemoteHandler: function (handler) {
            remoteHandler = handler;
        },

        /** 棋盘产生本地事件 → 当前连接（没连上就等于丢掉，跟 Android 一样）。 */
        sendLocal: function (events) {
            if (session) session.send(events);
        }
    };
})();
