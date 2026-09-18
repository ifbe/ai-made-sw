/**
 * 右下角「特殊日志」缓冲，对应 Android 的 log/AppLog.kt：
 * 只记连接 / 断开 / 出错这类值得看一眼的事，不记高频动作。
 *
 *  - 最多留 200 行，超了丢最旧的；
 *  - 存在 sessionStorage 里，所以在一个标签页里切来切去（每次都是一次新的页面加载）
 *    日志不会断，跟 Android 四个页面一直活着是一样的效果；
 *  - 同时往 console 打一份（相当于 Android 那边的 logcat）。
 */
var AppLog = (function () {
    'use strict';

    var MAX_LINES = 200;
    var STORAGE_KEY = 'chess.log';

    var lines = [];
    var listeners = [];

    try {
        var saved = sessionStorage.getItem(STORAGE_KEY);
        if (saved) {
            var parsed = JSON.parse(saved);
            if (Object.prototype.toString.call(parsed) === '[object Array]') lines = parsed;
        }
    } catch (e) {
        lines = [];
    }

    function pad(value) {
        return value < 10 ? '0' + value : String(value);
    }

    function stamp() {
        var now = new Date();
        return pad(now.getHours()) + ':' + pad(now.getMinutes()) + ':' + pad(now.getSeconds());
    }

    function persist() {
        try {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(lines));
        } catch (e) {
            // 存不下就算了，日志不值得打断棋局
        }
    }

    function notify() {
        var snapshot = lines.slice();
        for (var i = 0; i < listeners.length; i++) {
            try {
                listeners[i](snapshot);
            } catch (e) {
                // 单个监听器出错不影响其它监听器
            }
        }
    }

    return {
        /** 记一行：`HH:mm:ss  消息`（跟 Android 的格式一样，时间是两个空格）。 */
        log: function (message) {
            lines.push(stamp() + '  ' + message);
            while (lines.length > MAX_LINES) lines.shift();
            persist();
            try {
                console.log('[ChessApp] ' + message);
            } catch (e) {
                // 忽略
            }
            notify();
        },

        /** 当前全部日志（最多 200 行）。 */
        snapshot: function () {
            return lines.slice();
        },

        /** 挂一个监听器；挂上时立刻回调一次当前内容（跟 Android 的 addListener 一致）。 */
        addListener: function (listener) {
            listeners.push(listener);
            try {
                listener(lines.slice());
            } catch (e) {
                // 忽略
            }
        },

        removeListener: function (listener) {
            var index = listeners.indexOf(listener);
            if (index >= 0) listeners.splice(index, 1);
        },

        clear: function () {
            lines = [];
            persist();
            notify();
        }
    };
})();
