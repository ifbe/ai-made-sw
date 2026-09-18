/**
 * 围棋页：标准 19 路。
 * 棋盘、托盘、拖拽落子、吃子（把子拖出棋盘）等逻辑全在 stone.js / 五子棋共用。
 */
var Weiqi = (function () {
    'use strict';

    return {
        create: function (canvas) {
            return Stone.create(canvas, {lines: 19, kind: 'weiqi'});
        },
        /** 围棋棋盘：19 路 × 19 路。 */
        LINES: 19
    };
})();
