/**
 * 五子棋页：标准 15 路（连珠棋盘），星位也按 15 路取。
 * 棋盘、托盘、拖拽落子、吃子（把子拖出棋盘）等逻辑全在 stone.js / 围棋共用。
 */
var Wuziqi = (function () {
    'use strict';

    return {
        create: function (canvas) {
            return Stone.create(canvas, {lines: 15, kind: 'wuziqi'});
        },
        /** 五子棋棋盘：15 路 × 15 路。 */
        LINES: 15
    };
})();
