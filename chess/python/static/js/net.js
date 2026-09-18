/**
 * WebSocket 客户端，对应 Android 的 net/ws/WsSession.kt（只保留「客」这一半）。
 *
 *  - 本地事件按 `Envelope` 编码后发给服务端；
 *  - 高频的位置流（drag_move）只留最新一条、按 30Hz 发送；发关键事件前先把它冲掉，
 *    保证「先动、后落」；
 *  - 收到对端事件就回调 onEvent，交给对应棋种的页面去 apply。
 *
 * 服务端只转发、不缓存，所以断线重连后要等下一次 board 包才能对齐盘面（跟 Android 一样）。
 */
function WsClient(handlers) {
    this.handlers = handlers || {};
    this.socket = null;
    this.url = null;
    this.closing = false;
    this.pendingDrag = null;
    this.dragTimer = null;
}

/** 位置流的发送间隔：30Hz 足够跟手，再快只是浪费带宽。 */
WsClient.DRAG_INTERVAL_MS = 33;

WsClient.prototype.start = function (url) {
    var self = this;
    this.closing = false;
    this.url = url;

    AppLog.log('开始连接：' + url);
    this.emitState('starting', '连接中…');

    var socket;
    try {
        socket = new WebSocket(url);
    } catch (e) {
        AppLog.log('连接失败：地址没法解析（' + url + '）');
        this.emitState('failed', '地址不对');
        return;
    }
    this.socket = socket;

    socket.onopen = function () {
        if (self.closing) {
            try {
                socket.close();
            } catch (e) {
                // 忽略
            }
            return;
        }
        var shown = url;
        try {
            var parsed = new URL(url);
            shown = parsed.host || url;
        } catch (e) {
            // 忽略
        }
        AppLog.log('已连接：' + shown);
        self.emitState('online', '已连接');
    };

    socket.onmessage = function (messageEvent) {
        if (self.closing) return;
        // 协议只有文本帧，二进制一律不当报文处理。
        if (typeof messageEvent.data !== 'string') return;
        var event = Envelope.decode(messageEvent.data);
        if (event && self.handlers.onEvent) self.handlers.onEvent(event);
    };

    socket.onclose = function (closeEvent) {
        self.stopDragTimer();
        self.socket = null;
        if (self.closing) return;
        AppLog.log(
            '连接断开（code=' + closeEvent.code +
            '，reason=' + (closeEvent.reason || '') +
            '，remote=' + (closeEvent.wasClean ? 'false' : 'true') + '）'
        );
        self.emitState('failed', '连接已断开');
    };

    socket.onerror = function () {
        if (self.closing) return;
        AppLog.log('连接失败：WebSocket 出错（服务端没在监听 / 地址不通 / 不是 ws 服务端）');
        self.emitState('failed', '连接失败');
    };
};

/** 本地事件 → 服务端。没连上就丢掉（跟 Android 的 sendNow 一样）。 */
WsClient.prototype.send = function (events) {
    if (!events || !events.length) return;
    for (var i = 0; i < events.length; i++) {
        var event = events[i];
        if (event.t === 'drag_move') {
            this.pendingDrag = event;
            this.ensureDragTimer();
            continue;
        }
        // 关键事件之前先把攒着的位置发掉，保证「先动、后落」
        this.flushDrag();
        var line = Envelope.encode(event);
        if (line) this.sendLine(line);
    }
};

WsClient.prototype.sendLine = function (line) {
    var socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    try {
        socket.send(line);
    } catch (e) {
        AppLog.log('发送失败：' + e.message);
    }
};

WsClient.prototype.ensureDragTimer = function () {
    if (this.dragTimer !== null) return;
    var self = this;
    this.dragTimer = setInterval(function () {
        self.flushDrag();
    }, WsClient.DRAG_INTERVAL_MS);
};

WsClient.prototype.stopDragTimer = function () {
    if (this.dragTimer === null) return;
    clearInterval(this.dragTimer);
    this.dragTimer = null;
};

WsClient.prototype.flushDrag = function () {
    var event = this.pendingDrag;
    this.pendingDrag = null;
    if (!event) return;
    var line = Envelope.encode(event);
    if (line) this.sendLine(line);
};

WsClient.prototype.isOpen = function () {
    return !!this.socket && this.socket.readyState === WebSocket.OPEN;
};

/** 用户主动断开：不再把 onclose / onerror 报成故障。 */
WsClient.prototype.close = function () {
    this.closing = true;
    this.stopDragTimer();
    this.pendingDrag = null;
    var socket = this.socket;
    this.socket = null;
    if (socket) {
        try {
            socket.close();
        } catch (e) {
            // 忽略
        }
    }
    AppLog.log('已断开连接');
};

WsClient.prototype.emitState = function (kind, detail) {
    if (this.handlers.onState) this.handlers.onState(kind, detail);
};
