/**
 * 围棋 / 五子棋共用的「石头棋盘」页：盘面数据 + 逻辑 + 棋盘绘制 + 托盘 / 拖拽手势。
 * 对应 Android 的 share/stone/StoneGame.kt、StoneProtocol.kt、BoardGeometry.kt、
 * StoneBoardView.kt；两种棋只有路数不同（围棋 19 路、五子棋 15 路），
 * 具体某种棋看 weiqi.js / wuziqi.js 两个薄壳。
 *
 * 布局（BoardGeometry）：
 *  - 页面底色纯黑；棋盘是边长 = min(宽, 高)、中心 = 屏幕中心的正方形；
 *  - 正方形等分成 (lines+1) × (lines+1) 个格子，格子正中心就是落点；
 *  - 正方形外剩下的两侧余量放黑 / 白棋子托盘（圆形 + 剩余数量文字）。
 *
 * 规则（StoneGame）：不做吃子 / 提子 / 连五判断，只判断轮次；
 * 盘上的子谁都能拿起来拖，把子拖出棋盘 = 被吃直接消失；托盘只有该走的一方能用，
 * 落到盘上空位就落子并把数量 -1。
 */
var Stone = (function () {
    'use strict';

    var EMPTY = 0;
    var BLACK = 1;
    var WHITE = 2;
    var FIRST_SIDE = 0;

    var UNITS_PER_CELL = 256;

    /** 每色棋子初始数量。 */
    var INITIAL_STONES = 180;

    /** 各尺寸棋盘的传统星位，[col0, row0, col1, row1, ...]。 */
    var STAR_POINTS = {
        19: [3, 3, 9, 3, 15, 3, 3, 9, 9, 9, 15, 9, 3, 15, 9, 15, 15, 15],
        15: [3, 3, 11, 3, 3, 11, 11, 11, 7, 7],
        13: [3, 3, 9, 3, 3, 9, 9, 9, 6, 6],
        9: [2, 2, 6, 2, 2, 6, 6, 6, 4, 4]
    };

    // ------------------------------------------------------------------ 纯函数

    function sideOf(color) {
        return color === BLACK ? FIRST_SIDE : 1;
    }

    function colorOf(side) {
        return side === FIRST_SIDE ? BLACK : WHITE;
    }

    function makePos(cellX, cellY) {
        var x = Math.round(cellX * UNITS_PER_CELL);
        var y = Math.round(cellY * UNITS_PER_CELL);
        return {x: x, y: y, cellX: x / UNITS_PER_CELL, cellY: y / UNITS_PER_CELL};
    }

    function samePiece(a, b) {
        return !!a && !!b && a.side === b.side && a.name === b.name && a.id === b.id;
    }

    function starPoints(lines) {
        return STAR_POINTS[lines] || [];
    }

    // ------------------------------------------------------------------ 盘面数据

    function Game(lines, kind) {
        this.lines = lines;
        this.kind = kind;
        this.grid = new Array(lines * lines).fill(EMPTY);
        this.ids = new Array(lines * lines).fill(0);
        this.blackToMove = true;
        this.blackRemaining = INITIAL_STONES;
        this.whiteRemaining = INITIAL_STONES;
        this.drag = null;
        this.dragFrom = -1;
        this.dragColor = EMPTY;
        this.dragRef = null;
        this.dragFromTray = false;
        this.nextStoneId = 1;
        this.seq = 0;
        this.setup();
    }

    Game.prototype.turn = function () {
        return this.blackToMove ? FIRST_SIDE : 1;
    };

    Game.prototype.remaining = function (side) {
        return side === FIRST_SIDE ? this.blackRemaining : this.whiteRemaining;
    };

    Game.prototype.remainingOf = function (color) {
        return color === BLACK ? this.blackRemaining : this.whiteRemaining;
    };

    Game.prototype.setup = function () {
        this.grid.fill(EMPTY);
        this.ids.fill(0);
        this.blackToMove = true;
        this.blackRemaining = INITIAL_STONES;
        this.whiteRemaining = INITIAL_STONES;
        this.clearDrag();
    };

    Game.prototype.clearDrag = function () {
        this.drag = null;
        this.dragFrom = -1;
        this.dragColor = EMPTY;
        this.dragRef = null;
        this.dragFromTray = false;
    };

    Game.prototype.hasPieceAt = function (index) {
        return index >= 0 && index < this.grid.length && this.grid[index] !== EMPTY;
    };

    /** 盘面 → lines² 个字符：'.' 空、'b' 黑、'w' 白。 */
    Game.prototype.encode = function () {
        var out = '';
        for (var index = 0; index < this.grid.length; index++) {
            var cell = this.grid[index];
            out += cell === BLACK ? 'b' : (cell === WHITE ? 'w' : '.');
        }
        return out;
    };

    Game.prototype.decode = function (board) {
        if (typeof board !== 'string' || board.length !== this.grid.length) return false;
        for (var index = 0; index < this.grid.length; index++) {
            var ch = board.charAt(index);
            if (ch === 'b') {
                this.grid[index] = BLACK;
            } else if (ch === 'w') {
                this.grid[index] = WHITE;
            } else if (ch === '.') {
                this.grid[index] = EMPTY;
            } else {
                return false;
            }
        }
        return true;
    };

    Game.prototype.snapshot = function () {
        return {
            board: this.encode(),
            turn: this.turn(),
            counts: [this.blackRemaining, this.whiteRemaining]
        };
    };

    /** 落点下标 → 棋盘语义坐标（相对棋盘中心，单位 1/256 格）。 */
    Game.prototype.posOf = function (index) {
        var lines = this.lines;
        return makePos(index % lines - (lines - 1) / 2, Math.floor(index / lines) - (lines - 1) / 2);
    };

    // ------------------------------------------------------------------ 手势

    Game.prototype.pickUp = function (index) {
        if (!this.hasPieceAt(index)) return [];
        var color = this.grid[index];
        this.dragFrom = index;
        this.dragColor = color;
        this.dragFromTray = false;
        var ref = {side: sideOf(color), name: '', id: this.ids[index]};
        this.dragRef = ref;
        var pos = this.posOf(index);
        this.drag = {piece: ref, from: index, cellX: pos.cellX, cellY: pos.cellY, byMe: true};
        return [{
            t: 'drag_start', game: this.kind, seq: ++this.seq,
            piece: ref, from: index, pos: pos
        }];
    };

    /** 从托盘拿一颗新子（只有该走的那一方能拿）。 */
    Game.prototype.pickUpNew = function (side, cellX, cellY) {
        if (side !== this.turn()) return [];
        if (this.remaining(side) <= 0) return [];

        var ref = {side: side, name: '', id: this.nextStoneId++};
        this.dragFrom = -1;
        this.dragColor = colorOf(side);
        this.dragFromTray = true;
        this.dragRef = ref;
        var pos = makePos(cellX, cellY);
        this.drag = {piece: ref, from: -1, cellX: pos.cellX, cellY: pos.cellY, byMe: true};
        return [{
            t: 'drag_start', game: this.kind, seq: ++this.seq,
            piece: ref, from: -1, pos: pos
        }];
    };

    Game.prototype.dragTo = function (cellX, cellY) {
        var current = this.drag;
        if (!current) return [];
        current.cellX = cellX;
        current.cellY = cellY;
        return [{
            t: 'drag_move', game: this.kind, seq: ++this.seq,
            piece: current.piece, pos: makePos(cellX, cellY)
        }];
    };

    Game.prototype.drop = function (cellX, cellY, targetIndex) {
        var current = this.drag;
        if (!current) return [];
        var from = this.dragFrom;
        var color = this.dragColor;
        var ref = this.dragRef;
        var fromTray = this.dragFromTray;
        this.clearDrag();

        var pos = makePos(cellX, cellY);
        var events = [];
        if (!ref) return [];

        // 从盘上拿起来的子
        if (!fromTray) {
            // 拖出棋盘 = 被吃，直接消失（不回托盘、不换手）
            if (targetIndex < 0) {
                if (from >= 0 && from < this.grid.length) {
                    this.grid[from] = EMPTY;
                    this.ids[from] = 0;
                }
                events.push(this.dragEnded(ref, pos, false));
                events.push(this.boardChanged());
                return events;
            }
            var blocked = targetIndex === from ||
                sideOf(color) !== this.turn() ||
                this.grid[targetIndex] !== EMPTY;
            if (blocked) {
                events.push(this.dragEnded(ref, pos, false));
                return events;
            }
            this.grid[targetIndex] = color;
            this.ids[targetIndex] = this.ids[from];
            this.grid[from] = EMPTY;
            this.ids[from] = 0;
            this.blackToMove = !this.blackToMove;
            events.push(this.dragEnded(ref, pos, true));
            events.push(this.boardChanged());
            return events;
        }

        // 从托盘拖出来的新子：落不到盘上就相当于放回托盘
        if (targetIndex < 0 || this.grid[targetIndex] !== EMPTY) {
            events.push(this.dragEnded(ref, pos, false));
            return events;
        }
        this.grid[targetIndex] = color;
        this.ids[targetIndex] = ref.id;
        if (color === BLACK) {
            this.blackRemaining--;
        } else {
            this.whiteRemaining--;
        }
        this.blackToMove = !this.blackToMove;
        events.push(this.dragEnded(ref, pos, true));
        events.push(this.boardChanged());
        return events;
    };

    Game.prototype.dragEnded = function (piece, pos, committed) {
        return {
            t: 'drag_end', game: this.kind, seq: ++this.seq,
            piece: piece, pos: pos, committed: committed
        };
    };

    Game.prototype.cancel = function () {
        var current = this.drag;
        if (!current) return [];
        var pos = current.from >= 0
            ? this.posOf(current.from)
            : makePos(current.cellX, current.cellY);
        var ref = current.piece;
        this.clearDrag();
        return [this.dragEnded(ref, pos, false)];
    };

    Game.prototype.boardChanged = function () {
        return {
            t: 'board', game: this.kind, seq: ++this.seq,
            board: this.encode(), turn: this.turn(),
            counts: [this.blackRemaining, this.whiteRemaining]
        };
    };

    Game.prototype.reset = function () {
        this.setup();
        return [
            {t: 'reset', game: this.kind, seq: ++this.seq},
            this.boardChanged()
        ];
    };

    Game.prototype.apply = function (event) {
        if (event.game !== this.kind) return;
        if (event.seq > this.seq) this.seq = event.seq;

        switch (event.t) {
            case 'drag_start': {
                // 从托盘拿的新子（from < 0）没法校验，直接显示；盘上的子要确认还在原地
                if (event.from >= 0) {
                    if (!this.hasPieceAt(event.from)) return;
                    if (sideOf(this.grid[event.from]) !== event.piece.side) return;
                }
                this.drag = {
                    piece: event.piece, from: event.from,
                    cellX: event.pos.cellX, cellY: event.pos.cellY, byMe: false
                };
                return;
            }
            case 'drag_move': {
                if (!this.drag || !samePiece(this.drag.piece, event.piece)) return;
                this.drag.cellX = event.pos.cellX;
                this.drag.cellY = event.pos.cellY;
                return;
            }
            case 'drag_end': {
                if (this.drag && samePiece(this.drag.piece, event.piece)) this.drag = null;
                return;
            }
            case 'board': {
                if (this.decode(event.board)) {
                    this.blackToMove = event.turn === FIRST_SIDE;
                    if (event.counts.length >= 2) {
                        this.blackRemaining = event.counts[0];
                        this.whiteRemaining = event.counts[1];
                    }
                }
                this.clearDrag();
                return;
            }
            case 'reset': {
                this.setup();
                return;
            }
            default:
                return;
        }
    };

    // ------------------------------------------------------------------ 存档

    Game.prototype.storageKey = function () {
        return 'chess.' + this.kind;
    };

    Game.prototype.save = function () {
        try {
            sessionStorage.setItem(this.storageKey(), JSON.stringify(this.snapshot()));
        } catch (e) {
            // 忽略
        }
    };

    Game.prototype.load = function () {
        var raw = null;
        try {
            raw = sessionStorage.getItem(this.storageKey());
        } catch (e) {
            return false;
        }
        if (!raw) return false;
        try {
            var data = JSON.parse(raw);
            if (!data || typeof data.board !== 'string') return false;
            if (!this.decode(data.board)) return false;
            this.blackToMove = data.turn === FIRST_SIDE;
            if (data.counts && data.counts.length >= 2) {
                this.blackRemaining = data.counts[0];
                this.whiteRemaining = data.counts[1];
            }
            this.clearDrag();
            return true;
        } catch (e) {
            return false;
        }
    };

    // ------------------------------------------------------------------ 几何

    /**
     * [rotated] 由「横屏 / 竖屏」模式决定（不再看屏幕长宽比）：
     *  - false（默认，玩家上下）：黑托盘在上、白托盘在下；
     *  - true （玩家左右）：黑托盘在左、白托盘在右。
     * 棋盘永远是 min(宽, 高) 的正方形；放托盘的那条边留 20%（不然托盘会贴到屏幕边上）。
     */
    function Geometry(width, height, lines, rotated) {
        this.width = width;
        this.height = height;
        this.lines = lines;
        this.subdivisions = lines + 1;
        this.trayOnSides = !!rotated;
        this.boardSize = this.trayOnSides
            ? Math.min(width * 0.8, height)
            : Math.min(width, height * 0.8);
        this.boardLeft = (width - this.boardSize) / 2;
        this.boardTop = (height - this.boardSize) / 2;
        this.cell = this.boardSize / this.subdivisions;
        this.stoneRadius = this.cell * 0.46;
        this.pieceRadius = this.stoneRadius * 1.08;
    }

    Geometry.prototype.gridX = function (col) {
        return this.boardLeft + (col + 1) * this.cell;
    };

    Geometry.prototype.gridY = function (row) {
        return this.boardTop + (row + 1) * this.cell;
    };

    Geometry.prototype.cellXAt = function (px) {
        return (px - this.boardLeft - this.boardSize / 2) / this.cell;
    };

    Geometry.prototype.cellYAt = function (py) {
        return (py - this.boardTop - this.boardSize / 2) / this.cell;
    };

    Geometry.prototype.pxOfCell = function (cellX) {
        return this.boardLeft + this.boardSize / 2 + cellX * this.cell;
    };

    Geometry.prototype.pyOfCell = function (cellY) {
        return this.boardTop + this.boardSize / 2 + cellY * this.cell;
    };

    Geometry.prototype.isInsideBoard = function (x, y) {
        return x >= this.boardLeft && x <= this.boardLeft + this.boardSize &&
            y >= this.boardTop && y <= this.boardTop + this.boardSize;
    };

    /** 手指吸附到最近的落点，返回下标（row * lines + col）；不在棋盘内返回 -1。 */
    Geometry.prototype.indexAt = function (x, y) {
        if (!this.isInsideBoard(x, y)) return -1;
        var col = Math.round((x - this.boardLeft) / this.cell - 1);
        var row = Math.round((y - this.boardTop) / this.cell - 1);
        col = Math.max(0, Math.min(this.lines - 1, col));
        row = Math.max(0, Math.min(this.lines - 1, row));
        return row * this.lines + col;
    };

    Geometry.prototype.trayCenterX = function (black) {
        if (this.trayOnSides) {
            return black ? this.boardLeft / 2 : this.width - this.boardLeft / 2;
        }
        return this.width / 2;
    };

    Geometry.prototype.trayCenterY = function (black) {
        if (this.trayOnSides) return this.height / 2;
        return black ? this.boardTop / 2 : this.height - this.boardTop / 2;
    };

    // ------------------------------------------------------------------ 配色

    var PALETTE = {
        boardFill: '#FFE999',
        boardBorder: '#E0C67E',
        line: '#3A3226',
        blackStone: '#0A0A0A',
        whiteStone: '#F2F2F2',
        blackRim: '#3A3A3A',
        whiteRim: '#9E9E9E',
        text: '#FFFFFF',
        active: '#E6B24C',
        hover: '#3A3226',
        blocked: '#C62828'
    };

    // ------------------------------------------------------------------ 棋盘视图

    function Board(canvas, lines, kind) {
        this.canvas = canvas;
        this.lines = lines;
        this.kind = kind;
        this.starPoints = starPoints(lines);
        this.game = new Game(lines, kind);
        this.game.load();
        this.geo = null;
        this.width = 0;
        this.height = 0;
        this.dragging = false;
        this.hoverIndex = -1;
        this.drawScheduled = false;
        this.trayStoneCx = 0;
        this.trayStoneCy = 0;
        this.trayTextLeft = 0;
        this.trayTextBaseline = 0;

        var initial = Draw.setup(canvas);
        this.ctx = initial.ctx;
        this.applySize(initial.width, initial.height);

        this.bindEvents();
        this.persist();
        this.scheduleDraw();
    }

    Board.prototype.applySize = function (width, height) {
        this.width = width;
        this.height = height;
        this.geo = new Geometry(width, height, this.lines, Draw.boardRotated());
    };

    Board.prototype.resize = function () {
        var sized = Draw.setup(this.canvas);
        this.applySize(sized.width, sized.height);
        this.scheduleDraw();
    };

    Board.prototype.scheduleDraw = function () {
        if (this.drawScheduled) return;
        this.drawScheduled = true;
        var self = this;
        window.requestAnimationFrame(function () {
            self.drawScheduled = false;
            self.draw();
        });
    };

    Board.prototype.persist = function () {
        this.game.save();
    };

    Board.prototype.emit = function (events) {
        if (!events || !events.length) return;
        Chrome.sendLocal(events);
    };

    Board.prototype.applyRemote = function (event) {
        if (event.game !== this.kind) return;
        this.game.apply(event);
        this.persist();
        this.scheduleDraw();
    };

    Board.prototype.reset = function () {
        var events = this.game.reset();
        this.dragging = false;
        this.hoverIndex = -1;
        this.emit(events);
        this.persist();
        this.scheduleDraw();
    };

    Board.prototype.draw = function () {
        var ctx = this.ctx;
        var g = this.geo;
        if (!g) return;

        Draw.clear(ctx, this.width, this.height);
        this.drawBoardSurface(ctx, g);
        this.drawGrid(ctx, g);
        this.drawPlacedStones(ctx, g);
        this.drawHover(ctx, g);
        this.drawTray(ctx, g, BLACK);
        this.drawTray(ctx, g, WHITE);
        this.drawDraggedStone(ctx, g);
    };

    Board.prototype.drawBoardSurface = function (ctx, g) {
        ctx.fillStyle = PALETTE.boardFill;
        ctx.fillRect(g.boardLeft, g.boardTop, g.boardSize, g.boardSize);

        var borderWidth = Math.max(1, g.cell * 0.05);
        var inset = borderWidth / 2;
        ctx.strokeStyle = PALETTE.boardBorder;
        ctx.lineWidth = borderWidth;
        ctx.strokeRect(
            g.boardLeft + inset,
            g.boardTop + inset,
            g.boardSize - borderWidth,
            g.boardSize - borderWidth
        );
    };

    Board.prototype.drawGrid = function (ctx, g) {
        var last = this.lines - 1;
        ctx.strokeStyle = PALETTE.line;
        ctx.lineWidth = Math.max(1, g.cell * 0.035);
        ctx.lineCap = 'round';
        ctx.beginPath();
        for (var i = 0; i < this.lines; i++) {
            var x = g.gridX(i);
            ctx.moveTo(x, g.gridY(0));
            ctx.lineTo(x, g.gridY(last));
            var y = g.gridY(i);
            ctx.moveTo(g.gridX(0), y);
            ctx.lineTo(g.gridX(last), y);
        }
        ctx.stroke();

        var starRadius = Math.max(2.5, g.cell * 0.11);
        ctx.fillStyle = PALETTE.line;
        for (var p = 0; p + 1 < this.starPoints.length; p += 2) {
            ctx.beginPath();
            ctx.arc(g.gridX(this.starPoints[p]), g.gridY(this.starPoints[p + 1]), starRadius, 0, Math.PI * 2);
            ctx.fill();
        }
    };

    Board.prototype.drawPlacedStones = function (ctx, g) {
        // 正在被拖（本地或对端）的那颗，原位不画，画在浮层上。
        var draggingFrom = this.game.drag ? this.game.drag.from : -1;
        for (var index = 0; index < this.game.grid.length; index++) {
            if (index === draggingFrom) continue;
            var color = this.game.grid[index];
            if (color === EMPTY) continue;
            this.drawStone(
                ctx, g,
                g.gridX(index % this.lines),
                g.gridY(Math.floor(index / this.lines)),
                g.stoneRadius,
                color
            );
        }
    };

    Board.prototype.drawStone = function (ctx, g, cx, cy, radius, color) {
        var fill = color === BLACK ? PALETTE.blackStone : PALETTE.whiteStone;
        var rim = color === BLACK ? PALETTE.blackRim : PALETTE.whiteRim;
        var rimWidth = Math.max(1, g.cell * 0.05);

        ctx.fillStyle = fill;
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = rim;
        ctx.lineWidth = rimWidth;
        ctx.beginPath();
        ctx.arc(cx, cy, Math.max(0.5, radius - rimWidth / 2), 0, Math.PI * 2);
        ctx.stroke();
    };

    Board.prototype.drawHover = function (ctx, g) {
        if (!this.dragging || this.hoverIndex < 0) return;
        // 该自己走、且落点是空的 ⇒ 能落下；其余情况松手会弹回。
        var overlay = this.game.drag;
        var canDrop = !!overlay &&
            overlay.piece.side === this.game.turn() &&
            this.game.grid[this.hoverIndex] === EMPTY;
        ctx.strokeStyle = canDrop ? PALETTE.hover : PALETTE.blocked;
        ctx.lineWidth = Math.max(2, g.cell * 0.06);
        ctx.beginPath();
        ctx.arc(
            g.gridX(this.hoverIndex % this.lines),
            g.gridY(Math.floor(this.hoverIndex / this.lines)),
            g.stoneRadius * 1.15,
            0,
            Math.PI * 2
        );
        ctx.stroke();
    };

    Board.prototype.drawTray = function (ctx, g, color) {
        var isActive = (color === BLACK ? FIRST_SIDE : 1) === this.game.turn();
        var label = 'x' + this.game.remainingOf(color);
        var radius = g.pieceRadius;

        // 先算好棋子圆和数量文字的位置，顺手拿到「棋子 + 数字」的包围盒。
        var bounds = this.trayLayout(ctx, g, color, label);

        // 该走的那一方：用黄色方框把棋子和数量一起圈起来
        if (isActive) {
            ctx.strokeStyle = PALETTE.active;
            ctx.lineWidth = 2;
            ctx.strokeRect(bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top);
        }

        this.drawStone(ctx, g, this.trayStoneCx, this.trayStoneCy, radius, color);

        var fontSpec = Draw.font(Math.max(15, g.cell * 0.5));
        ctx.font = fontSpec;
        ctx.fillStyle = PALETTE.text;
        ctx.textAlign = g.trayOnSides ? 'center' : 'left';
        ctx.textBaseline = 'alphabetic';
        ctx.fillText(label, this.trayTextLeft, this.trayTextBaseline);
    };

    /**
     * 算出一方托盘的排版：棋子圆心、数量文字的左端 / 基线，以及把两者都包住的矩形。
     * 结果写到 this.tray* 上（跟 Android 复用字段的做法一样）。
     */
    Board.prototype.trayLayout = function (ctx, g, color, label) {
        var black = color === BLACK;
        var radius = g.pieceRadius;
        var gap = radius * 0.45;
        var fontSpec = Draw.font(Math.max(15, g.cell * 0.5));
        ctx.font = fontSpec;
        var textWidth = ctx.measureText(label).width;
        var m = Draw.metrics(ctx, label, fontSpec);

        var textLeft;
        var textBaseline;
        if (g.trayOnSides) {
            // 左右余量很窄：圆放在空带正中间，数量写在圆的正下方并水平居中。
            this.trayStoneCx = g.trayCenterX(black);
            this.trayStoneCy = g.trayCenterY(black);
            textLeft = this.trayStoneCx - textWidth / 2;
            textBaseline = this.trayStoneCy + radius + gap + m.ascent;
        } else {
            // 上下余量很宽：数量写在圆的右侧，整组（圆 + 数字）水平居中。
            this.trayStoneCy = g.trayCenterY(black);
            var groupWidth = radius * 2 + gap + textWidth;
            this.trayStoneCx = this.width / 2 - groupWidth / 2 + radius;
            textLeft = this.trayStoneCx + radius + gap;
            textBaseline = this.trayStoneCy + (m.ascent - m.descent) / 2;
        }
        this.trayTextLeft = textLeft;
        this.trayTextBaseline = textBaseline;

        var bounds = {
            left: Math.min(this.trayStoneCx - radius, textLeft),
            top: Math.min(this.trayStoneCy - radius, textBaseline - m.ascent),
            right: Math.max(this.trayStoneCx + radius, textLeft + textWidth),
            bottom: Math.max(this.trayStoneCy + radius, textBaseline + m.descent)
        };
        // 方框比内容再大一圈
        var inflate = radius * 0.4;
        bounds.left -= inflate;
        bounds.top -= inflate;
        bounds.right += inflate;
        bounds.bottom += inflate;
        return bounds;
    };

    /** 拖动中的那颗子：位置来自 drag 浮层，本地和远端的画法完全一样。 */
    Board.prototype.drawDraggedStone = function (ctx, g) {
        var overlay = this.game.drag;
        if (!overlay) return;
        this.drawStone(
            ctx, g,
            g.pxOfCell(overlay.cellX),
            g.pyOfCell(overlay.cellY),
            g.pieceRadius,
            colorOf(overlay.piece.side)
        );
    };

    /**
     * 托盘的可点区域：就是那个「棋子 + 数字」的方框再往外放一点，
     * 所以手指按在黄框里任意位置都能开始拖。
     */
    Board.prototype.hitTray = function (ctx, g, color, x, y) {
        var bounds = this.trayLayout(ctx, g, color, 'x' + this.game.remainingOf(color));
        var slop = 12;
        return x >= bounds.left - slop && x <= bounds.right + slop &&
            y >= bounds.top - slop && y <= bounds.bottom + slop;
    };

    // ------------------------------------------------------------------ 触摸

    Board.prototype.bindEvents = function () {
        var self = this;
        var canvas = this.canvas;

        canvas.addEventListener('pointerdown', function (event) {
            var g = self.geo;
            if (!g) return;
            var x = event.offsetX;
            var y = event.offsetY;

            // 先看是不是按在盘上的棋子上：是的话谁都能拿起来（不看轮次）。
            var index = g.indexAt(x, y);
            if (index >= 0 && self.game.hasPieceAt(index)) {
                self.dragging = true;
                self.hoverIndex = index;
                self.emit(self.game.pickUp(index));
                self.afterPointerDown(event);
                return;
            }

            // 否则看是不是按在该走的那一方的托盘上。
            var side = self.game.turn();
            var color = colorOf(side);
            if (self.game.remaining(side) <= 0) return;
            if (!self.hitTray(self.ctx, g, color, x, y)) return;

            self.dragging = true;
            self.hoverIndex = -1;
            // 托盘中心换算成棋盘语义坐标（在棋盘外，对端照样看得见）
            var trayCx = self.trayStoneCx;
            var trayCy = self.trayStoneCy;
            self.emit(self.game.pickUpNew(side, g.cellXAt(trayCx), g.cellYAt(trayCy)));
            self.afterPointerDown(event);
        });

        canvas.addEventListener('pointermove', function (event) {
            if (!self.dragging) return;
            var g = self.geo;
            if (!g) return;
            self.hoverIndex = g.indexAt(event.offsetX, event.offsetY);
            self.emit(self.game.dragTo(g.cellXAt(event.offsetX), g.cellYAt(event.offsetY)));
            self.scheduleDraw();
            event.preventDefault();
        });

        canvas.addEventListener('pointerup', function (event) {
            if (!self.dragging) return;
            var g = self.geo;
            if (!g) return;
            self.emit(self.game.drop(
                g.cellXAt(event.offsetX),
                g.cellYAt(event.offsetY),
                g.indexAt(event.offsetX, event.offsetY)
            ));
            self.dragging = false;
            self.hoverIndex = -1;
            self.persist();
            self.scheduleDraw();
            event.preventDefault();
        });

        canvas.addEventListener('pointercancel', function () {
            if (!self.dragging) return;
            self.emit(self.game.cancel());
            self.dragging = false;
            self.hoverIndex = -1;
            self.persist();
            self.scheduleDraw();
        });

        window.addEventListener('resize', function () {
            self.resize();
        });
        window.addEventListener('orientationchange', function () {
            window.setTimeout(function () {
                self.resize();
            }, 120);
        });
    };

    Board.prototype.afterPointerDown = function (event) {
        this.persist();
        this.scheduleDraw();
        if (this.canvas.setPointerCapture) {
            try {
                this.canvas.setPointerCapture(event.pointerId);
            } catch (e) {
                // 忽略
            }
        }
        event.preventDefault();
    };

    return {
        create: function (canvas, options) {
            return new Board(canvas, options.lines, options.kind);
        },
        INITIAL_STONES: INITIAL_STONES,
        starPoints: starPoints
    };
})();
