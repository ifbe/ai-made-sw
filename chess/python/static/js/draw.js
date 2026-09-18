/**
 * 画布、文字、以及方向模式的小工具，给四个棋盘页共用
 * （象棋页 xiangqi.js 的字体和基线也走这里）。
 *
 * 文字基线的算法跟 Android 的 `Paint.FontMetrics` 对齐：
 *   baseline = cy - (ascent + descent) / 2   （Android 的 ascent 是负数）
 * 画布这边 ascent / descent 都是正数，所以等价于 cy + (ascent - descent) / 2。
 *
 * 方向：`portrait`（默认）/ `landscape` 是 **App 自己的一个模式，跟屏幕长宽比无关**：
 *   - portrait：两个玩家上下分坐，棋盘竖着摆；
 *   - landscape：两个玩家左右分坐，棋盘横着摆。
 *
 * 只让**棋盘自己**转 90°，**不转整个页面**：页面一转，屏幕上看到的就是「整体歪了、
 * 双方又变成上下」（因为人的头没跟着转），而且又高又窄的窗口上还会把棋盘挤到屏幕外。
 * 代价是窄屏上横屏棋盘会小一些（10 路只能铺在窄边上），把窗口 / 设备横过来就大了。
 */
var Draw = (function () {
    'use strict';

    /** App 的方向模式：'portrait'（默认，玩家上下） / 'landscape'（玩家左右）。 */
    var ORIENTATION_KEY = 'chess.view.orientation';
    var DEFAULT_ORIENTATION = 'portrait';

    /**
     * 画布里的字体栈。**必须显式列出字体族**：画布不像 DOM 文字那样会自动逐字回退，
     * 只写 `sans-serif` 时如果系统默认字体（比如 Noto Sans CJK）没有棋子字形，
     * 画出来就是一串「26 5A」的十六进制方框。先把中文字体排前面，再挂符号字体。
     */
    var FONT_STACK = '"Noto Sans CJK SC", "Source Han Sans SC", "PingFang SC", "Microsoft YaHei", ' +
        '"DejaVu Sans", "Noto Sans Symbols 2", "Segoe UI Symbol", "Apple Symbols", sans-serif';

    var orientation = readOrientation();

    /** 上一次同步过的布局状态（棋盘是左右还是上下），用来判断要不要通知棋盘重新量尺寸。 */
    var lastLayoutSignature = null;

    // ------------------------------------------------------------------ 方向

    function readOrientation() {
        try {
            var value = sessionStorage.getItem(ORIENTATION_KEY);
            return value === 'landscape' ? 'landscape' : DEFAULT_ORIENTATION;
        } catch (e) {
            return DEFAULT_ORIENTATION;
        }
    }

    /** App 当前的方向模式。 */
    function effectiveOrientation() {
        return orientation;
    }

    /** 棋盘要不要左右放两个玩家：横屏模式就是左右，竖屏模式就是上下。 */
    function boardRotated() {
        return orientation === 'landscape';
    }

    /** 视口尺寸（页面不转，所以就是窗口尺寸）。 */
    function viewportWidth() {
        return window.innerWidth;
    }

    function viewportHeight() {
        return window.innerHeight;
    }

    /** 通知棋盘重新量尺寸（切模式不会触发浏览器的 resize）。 */
    function notifyResize() {
        try {
            if (!window.dispatchEvent) return;
            var event;
            try {
                event = new Event('resize');
            } catch (e) {
                event = document.createEvent('Event');
                event.initEvent('resize', true, true);
            }
            window.dispatchEvent(event);
        } catch (e) {
            // 忽略
        }
    }

    /** 影响棋盘布局的状态。变了才派发 resize，否则「resize → 重新同步 → 再派发」会转圈。 */
    function layoutSignature() {
        return boardRotated() ? 'board-rot' : 'board-flat';
    }

    function applyOrientation() {
        var signature = layoutSignature();
        var changed = signature !== lastLayoutSignature;
        lastLayoutSignature = signature;
        if (changed) notifyResize();
        return changed;
    }

    /** 设置方向模式：'landscape'（玩家左右）/ 'portrait'（玩家上下，默认）。记进 sessionStorage。 */
    function setOrientation(value) {
        orientation = value === 'landscape' ? 'landscape' : DEFAULT_ORIENTATION;
        try {
            sessionStorage.setItem(ORIENTATION_KEY, orientation);
        } catch (e) {
            // 忽略
        }
        applyOrientation();
    }

    // ------------------------------------------------------------------ 画布 / 文字

    /** 按视口 + devicePixelRatio 调好画布，之后都用 CSS 像素画。 */
    function setup(canvas) {
        var dpr = window.devicePixelRatio || 1;
        var width = viewportWidth();
        var height = viewportHeight();
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';
        var ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return {ctx: ctx, width: width, height: height};
    }

    function font(size) {
        return size + 'px ' + FONT_STACK;
    }

    /** 量一个字的 ascent / descent（正数）；拿不到就用 0.8em / 0.2em 兜底。 */
    function metrics(ctx, text, fontSpec) {
        ctx.font = fontSpec;
        var measured = ctx.measureText(text);
        var size = parseFloat(fontSpec) || 10;
        var ascent = measured.actualBoundingBoxAscent;
        var descent = measured.actualBoundingBoxDescent;
        if (typeof ascent !== 'number' || !isFinite(ascent) || ascent <= 0) ascent = size * 0.8;
        if (typeof descent !== 'number' || !isFinite(descent)) descent = size * 0.2;
        return {ascent: ascent, descent: descent};
    }

    /** 让文字视觉上正好居中在 cy 上，返回基线的偏移量。 */
    function centeredBaseline(ctx, text, fontSpec) {
        var measured = metrics(ctx, text, fontSpec);
        return (measured.ascent - measured.descent) / 2;
    }

    /** 清成纯黑，跟 Android 那边棋盘 View 的黑底一样。 */
    function clear(ctx, width, height) {
        ctx.clearRect(0, 0, width, height);
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, width, height);
    }

    // 载入时就把存过的方向应用上，棋盘一创建量到的就是对的布局。
    applyOrientation();

    return {
        setup: setup,
        font: font,
        metrics: metrics,
        centeredBaseline: centeredBaseline,
        clear: clear,

        setOrientation: setOrientation,
        applyOrientation: applyOrientation,
        getOrientation: function () {
            return orientation;
        },
        effectiveOrientation: effectiveOrientation,
        /** 棋盘要不要左右放两个玩家。 */
        boardRotated: boardRotated,
        viewportWidth: viewportWidth,
        viewportHeight: viewportHeight
    };
})();
