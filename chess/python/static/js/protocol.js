/**
 * 报文的「信封」编解码，对应 Android 的 game/share/protocol/EnvelopeCodec.kt。
 *
 * 一行文本、一个 WebSocket text 帧一条：
 *
 *     v1|game=xiangqi|seq=12|t=drag_move|side=0|name=车|id=54|x=1280|y=-1152
 *     v1|game=xiangqi|seq=13|t=board|board=..b.w..|turn=1|counts=
 *
 * 字段顺序、字段名、解析规则都跟 Android 完全一致，所以网页端和 Android 端能直接对下。
 */
var Envelope = (function () {
    'use strict';

    var VERSION = 'v1';
    var GAMES = ['xiangqi', 'intl_chess', 'weiqi', 'wuziqi'];

    function intOr(value, fallback) {
        return /^-?\d+$/.test(value) ? parseInt(value, 10) : fallback;
    }

    return {
        VERSION: VERSION,

        /** 事件对象 → 一行报文。事件对象形状见 xiangqi.js 里产生事件的地方。 */
        encode: function (event) {
            var parts = [VERSION, 'game=' + event.game, 'seq=' + event.seq];

            switch (event.t) {
                case 'drag_start':
                    parts.push(
                        't=drag_start',
                        'side=' + event.piece.side,
                        'name=' + event.piece.name,
                        'id=' + event.piece.id,
                        'from=' + event.from,
                        'x=' + event.pos.x,
                        'y=' + event.pos.y
                    );
                    break;
                case 'drag_move':
                    parts.push(
                        't=drag_move',
                        'side=' + event.piece.side,
                        'name=' + event.piece.name,
                        'id=' + event.piece.id,
                        'x=' + event.pos.x,
                        'y=' + event.pos.y
                    );
                    break;
                case 'drag_end':
                    parts.push(
                        't=drag_end',
                        'side=' + event.piece.side,
                        'name=' + event.piece.name,
                        'id=' + event.piece.id,
                        'x=' + event.pos.x,
                        'y=' + event.pos.y,
                        'committed=' + (event.committed ? 1 : 0)
                    );
                    break;
                case 'board':
                    parts.push(
                        't=board',
                        'board=' + event.board,
                        'turn=' + event.turn,
                        'counts=' + (event.counts || []).join(',')
                    );
                    break;
                case 'reset':
                    parts.push('t=reset');
                    break;
                default:
                    return null;
            }
            return parts.join('|');
        },

        /** 一行报文 → 事件对象；版本不对、字段缺失、脏数据都返回 null（不抛异常）。 */
        decode: function (line) {
            if (typeof line !== 'string') return null;
            var parts = line.split('|');
            if (!parts.length || parts[0] !== VERSION) return null;

            var fields = {};
            for (var i = 1; i < parts.length; i++) {
                var eq = parts[i].indexOf('=');
                if (eq <= 0) continue;
                fields[parts[i].substring(0, eq)] = parts[i].substring(eq + 1);
            }

            if (GAMES.indexOf(fields.game) < 0) return null;
            if (!/^-?\d+$/.test(fields.seq)) return null;

            var event = {
                game: fields.game,
                seq: parseInt(fields.seq, 10),
                piece: {
                    side: intOr(fields.side, 0),
                    name: fields.name || '',
                    id: intOr(fields.id, -1)
                },
                pos: {
                    x: intOr(fields.x, 0),
                    y: intOr(fields.y, 0)
                }
            };
            event.pos.cellX = event.pos.x / 256;
            event.pos.cellY = event.pos.y / 256;

            switch (fields.t) {
                case 'drag_start':
                    event.t = 'drag_start';
                    event.from = intOr(fields.from, -1);
                    return event;
                case 'drag_move':
                    event.t = 'drag_move';
                    return event;
                case 'drag_end':
                    event.t = 'drag_end';
                    event.committed = fields.committed === '1';
                    return event;
                case 'board':
                    event.t = 'board';
                    event.board = fields.board || '';
                    event.turn = intOr(fields.turn, 0);
                    event.counts = (fields.counts || '')
                        .split(',')
                        .filter(function (item) {
                            return item.length > 0;
                        })
                        .map(function (item) {
                            return parseInt(item, 10);
                        })
                        .filter(function (value) {
                            return isFinite(value);
                        });
                    return event;
                case 'reset':
                    event.t = 'reset';
                    return event;
                default:
                    return null;
            }
        }
    };
})();
