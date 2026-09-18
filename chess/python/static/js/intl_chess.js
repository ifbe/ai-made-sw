/**
 * 国际象棋页：盘面数据 + 逻辑 + 棋盘绘制 + 拖拽手势。
 * 对应 Android 的 IntlChessGame.kt / IntlChessProtocol.kt / IntlChessGeometry.kt /
 * IntlChessBoardView.kt 四个文件，规则仍然只在浏览器里算。
 *
 * 布局（IntlChessGeometry）：棋盘是 min(w, h) 的正方形、居中、8 × 8 方格；
 * 竖屏白方在下黑方在上，横屏（宽 > 高）整块转 90°（黑方在左、白方在右）。
 * 棋盘坐标：file 0..7 = a..h，rank 0 = 黑方底线，rank 7 = 白方底线。
 *
 * 规则（IntlChessGame）：只判断轮次（白先），不做走法 / 将军 / 胜负校验；
 * 吃子 = 走到对方子上，拖出棋盘 = 被吃消失。
 */
var IntlChess = (function () {
    'use strict';

    var FILES = 8;
    var RANKS = 8;
    var SIZE = FILES * RANKS;

    var EMPTY = 0;
    var WHITE = 1;
    var BLACK = 2;
    var FIRST_SIDE = 0;

    var HALF = (FILES - 1) / 2;   // 3.5

    var UNITS_PER_CELL = 256;

    /** 底线从左到右：车 马 象 后 王 象 马 车。 */
    var BACK_RANK = ['R', 'N', 'B', 'Q', 'K', 'B', 'N', 'R'];

    var CODE_CHARS = 'KQRBNP';

    /** 棋子用实心字形，靠颜色区分黑白。 */
    var GLYPHS = {
        K: '\u265A',
        Q: '\u265B',
        R: '\u265C',
        B: '\u265D',
        N: '\u265E',
        P: '\u265F'
    };

    var STORAGE_KEY = 'chess.intl_chess';

    // ------------------------------------------------------------------ 纯函数

    function sideOf(color) {
        return color === WHITE ? FIRST_SIDE : 1;
    }

    function colorOf(side) {
        return side === FIRST_SIDE ? WHITE : BLACK;
    }

    function makePos(cellX, cellY) {
        var x = Math.round(cellX * UNITS_PER_CELL);
        var y = Math.round(cellY * UNITS_PER_CELL);
        return {x: x, y: y, cellX: x / UNITS_PER_CELL, cellY: y / UNITS_PER_CELL};
    }

    function samePiece(a, b) {
        return !!a && !!b && a.side === b.side && a.name === b.name && a.id === b.id;
    }

    // ------------------------------------------------------------------ 盘面数据

    function Game() {
        this.colors = new Array(SIZE).fill(EMPTY);
        this.types = new Array(SIZE).fill(null);
        this.whiteToMove = true;
        this.drag = null;
        this.dragFrom = -1;
        this.dragColor = EMPTY;
        this.dragCode = null;
        this.seq = 0;
        this.setup();
    }

    Game.prototype.turn = function () {
        return this.whiteToMove ? FIRST_SIDE : 1;
    };

    Game.prototype.put = function (file, rank, color, code) {
        var index = rank * FILES + file;
        this.colors[index] = color;
        this.types[index] = code;
    };

    /** 白方在下（rank 7）、黑方在上（rank 0），标准开局。 */
    Game.prototype.setup = function () {
        this.colors.fill(EMPTY);
        this.types.fill(null);
        for (var file = 0; file < FILES; file++) {
            this.put(file, 0, BLACK, BACK_RANK[file]);
            this.put(file, 1, BLACK, 'P');
            this.put(file, 6, WHITE, 'P');
            this.put(file, 7, WHITE, BACK_RANK[file]);
        }
        this.whiteToMove = true;
        this.clearDrag();
    };

    Game.prototype.clearDrag = function () {
        this.drag = null;
        this.dragFrom = -1;
        this.dragColor = EMPTY;
        this.dragCode = null;
    };

    Game.prototype.hasPieceAt = function (index) {
        return index >= 0 && index < SIZE && this.colors[index] !== EMPTY;
    };

    /** 盘面 → 64 个字符：'.' 空、白方大写 KQRBNP、黑方小写；行序 rank 0..7。 */
    Game.prototype.encode = function () {
        var out = '';
        for (var index = 0; index < SIZE; index++) {
            var color = this.colors[index];
            var code = this.types[index];
            if (color === EMPTY || !code) {
                out += '.';
                continue;
            }
            out += color === WHITE ? code.toUpperCase() : code.toLowerCase();
        }
        return out;
    };

    Game.prototype.decode = function (board) {
        if (typeof board !== 'string' || board.length !== SIZE) return false;
        for (var index = 0; index < SIZE; index++) {
            var ch = board.charAt(index);
            if (ch === '.') {
                this.colors[index] = EMPTY;
                this.types[index] = null;
                continue;
            }
            var code = ch.toUpperCase();
            if (CODE_CHARS.indexOf(code) < 0) return false;
            this.colors[index] = ch === code ? WHITE : BLACK;
            this.types[index] = code;
        }
        return true;
    };

    Game.prototype.snapshot = function () {
        return {board: this.encode(), turn: this.turn()};
    };

    /** 方格下标 → 棋盘语义坐标（相对棋盘中心，单位 1/256 格）。 */
    Game.prototype.posOf = function (index) {
        return makePos(index % FILES - HALF, Math.floor(index / FILES) - HALF);
    };

    // ------------------------------------------------------------------ 手势

    Game.prototype.pickUp = function (index) {
        if (!this.hasPieceAt(index)) return [];
        var color = this.colors[index];
        var code = this.types[index];
        this.dragFrom = index;
        this.dragColor = color;
        this.dragCode = code;

        var piece = {side: sideOf(color), name: code, id: index};
        var pos = this.posOf(index);
        this.drag = {piece: piece, from: index, cellX: pos.cellX, cellY: pos.cellY, byMe: true};
        return [{
            t: 'drag_start', game: 'intl_chess', seq: ++this.seq,
            piece: piece, from: index, pos: pos
        }];
    };

    Game.prototype.dragTo = function (cellX, cellY) {
        var current = this.drag;
        if (!current) return [];
        current.cellX = cellX;
        current.cellY = cellY;
        return [{
            t: 'drag_move', game: 'intl_chess', seq: ++this.seq,
            piece: current.piece, pos: makePos(cellX, cellY)
        }];
    };

    Game.prototype.drop = function (cellX, cellY, targetIndex) {
        var current = this.drag;
        if (!current) return [];
        var from = this.dragFrom;
        var color = this.dragColor;
        var code = this.dragCode;
        this.clearDrag();

        var pos = makePos(cellX, cellY);
        var events = [];

        // 拖出棋盘 = 被吃，直接消失（不换手）
        if (targetIndex < 0) {
            if (from >= 0 && from < SIZE) {
                this.colors[from] = EMPTY;
                this.types[from] = null;
            }
            events.push({
                t: 'drag_end', game: 'intl_chess', seq: ++this.seq,
                piece: current.piece, pos: pos, committed: false
            });
            events.push(this.boardChanged());
            return events;
        }

        // 点一下没动 / 不该自己走 / 走到自己子上 ⇒ 弹回原位
        var blocked = !code ||
            targetIndex === from ||
            sideOf(color) !== this.turn() ||
            this.colors[targetIndex] === color;
        if (blocked) {
            events.push({
                t: 'drag_end', game: 'intl_chess', seq: ++this.seq,
                piece: current.piece, pos: pos, committed: false
            });
            return events;
        }

        // 落到空格就是走子，落到对方子上就是把对方吃掉（直接覆盖）
        this.colors[targetIndex] = color;
        this.types[targetIndex] = code;
        this.colors[from] = EMPTY;
        this.types[from] = null;
        this.whiteToMove = !this.whiteToMove;

        events.push({
            t: 'drag_end', game: 'intl_chess', seq: ++this.seq,
            piece: current.piece, pos: pos, committed: true
        });
        events.push(this.boardChanged());
        return events;
    };

    Game.prototype.cancel = function () {
        var current = this.drag;
        if (!current) return [];
        var pos = current.from >= 0 ? this.posOf(current.from) : makePos(current.cellX, current.cellY);
        var piece = current.piece;
        this.clearDrag();
        return [{
            t: 'drag_end', game: 'intl_chess', seq: ++this.seq,
            piece: piece, pos: pos, committed: false
        }];
    };

    Game.prototype.boardChanged = function () {
        return {
            t: 'board', game: 'intl_chess', seq: ++this.seq,
            board: this.encode(), turn: this.turn(), counts: []
        };
    };

    Game.prototype.reset = function () {
        this.setup();
        return [
            {t: 'reset', game: 'intl_chess', seq: ++this.seq},
            this.boardChanged()
        ];
    };

    Game.prototype.apply = function (event) {
        if (event.game !== 'intl_chess') return;
        if (event.seq > this.seq) this.seq = event.seq;

        switch (event.t) {
            case 'drag_start': {
                var from = event.from;
                if (!(from >= 0 && from < SIZE)) return;
                var color = this.colors[from];
                if (color === EMPTY) return;
                var code = this.types[from];
                if (!code) return;
                if (code !== event.piece.name) return;
                this.drag = {
                    piece: event.piece, from: from,
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
                if (this.decode(event.board)) this.whiteToMove = event.turn === FIRST_SIDE;
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

    Game.prototype.save = function () {
        try {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(this.snapshot()));
        } catch (e) {
            // 忽略
        }
    };

    Game.prototype.load = function () {
        var raw = null;
        try {
            raw = sessionStorage.getItem(STORAGE_KEY);
        } catch (e) {
            return false;
        }
        if (!raw) return false;
        try {
            var data = JSON.parse(raw);
            if (!data || typeof data.board !== 'string') return false;
            if (!this.decode(data.board)) return false;
            this.whiteToMove = data.turn === FIRST_SIDE;
            this.clearDrag();
            return true;
        } catch (e) {
            return false;
        }
    };

    // ------------------------------------------------------------------ 几何

    /**
     * [rotated] 由「横屏 / 竖屏」模式决定（不再看屏幕长宽比）：
     *  - false（默认，玩家上下）：白方在下、黑方在上；
     *  - true （玩家左右）：棋盘转 90°，黑方在左、白方在右。
     * 棋盘永远是 min(宽, 高) 的正方形；只有放牌子的那条边留 20%（不然牌子会贴在屏幕边上）。
     */
    function Geometry(width, height, rotated) {
        this.width = width;
        this.height = height;
        this.rotated = !!rotated;
        this.boardSize = this.rotated
            ? Math.min(width * 0.8, height)
            : Math.min(width, height * 0.8);
        this.boardLeft = (width - this.boardSize) / 2;
        this.boardTop = (height - this.boardSize) / 2;
        this.cell = this.boardSize / FILES;
        this.badgeStrip = this.rotated ? this.boardLeft : this.boardTop;
    }

    /** 某个格子是不是深色格（a1 是深色，标准棋盘）。 */
    Geometry.prototype.isDarkSquare = function (file, rank) {
        return (file + rank) % 2 === 1;
    };

    Geometry.prototype.screenCol = function (file, rank) {
        return this.rotated ? rank : file;
    };

    Geometry.prototype.screenRow = function (file, rank) {
        return this.rotated ? file : rank;
    };

    Geometry.prototype.squareX = function (file, rank) {
        return this.boardLeft + (this.screenCol(file, rank) + 0.5) * this.cell;
    };

    Geometry.prototype.squareY = function (file, rank) {
        return this.boardTop + (this.screenRow(file, rank) + 0.5) * this.cell;
    };

    Geometry.prototype.squareLeft = function (file, rank) {
        return this.boardLeft + this.screenCol(file, rank) * this.cell;
    };

    Geometry.prototype.squareTop = function (file, rank) {
        return this.boardTop + this.screenRow(file, rank) * this.cell;
    };

    Geometry.prototype.cellXAt = function (px, py) {
        return this.rotated
            ? (py - this.boardTop - this.boardSize / 2) / this.cell
            : (px - this.boardLeft - this.boardSize / 2) / this.cell;
    };

    Geometry.prototype.cellYAt = function (px, py) {
        return this.rotated
            ? (px - this.boardLeft - this.boardSize / 2) / this.cell
            : (py - this.boardTop - this.boardSize / 2) / this.cell;
    };

    Geometry.prototype.pxOfCell = function (cellX, cellY) {
        return this.rotated
            ? this.boardLeft + this.boardSize / 2 + cellY * this.cell
            : this.boardLeft + this.boardSize / 2 + cellX * this.cell;
    };

    Geometry.prototype.pyOfCell = function (cellX, cellY) {
        return this.rotated
            ? this.boardTop + this.boardSize / 2 + cellX * this.cell
            : this.boardTop + this.boardSize / 2 + cellY * this.cell;
    };

    Geometry.prototype.isInsideBoard = function (x, y) {
        return x >= this.boardLeft && x <= this.boardLeft + this.boardSize &&
            y >= this.boardTop && y <= this.boardTop + this.boardSize;
    };

    /** 手指落在哪个格子上，返回下标（rank * FILES + file）；不在棋盘内返回 -1。 */
    Geometry.prototype.indexAt = function (x, y) {
        if (!this.isInsideBoard(x, y)) return -1;
        var col = Math.floor((x - this.boardLeft) / this.cell);
        var row = Math.floor((y - this.boardTop) / this.cell);
        col = Math.max(0, Math.min(FILES - 1, col));
        row = Math.max(0, Math.min(RANKS - 1, row));
        var file = this.rotated ? row : col;
        var rank = this.rotated ? col : row;
        return rank * FILES + file;
    };

    Geometry.prototype.sideAnchorX = function (black) {
        if (!this.rotated) return this.width / 2;
        return black ? this.boardLeft / 2 : this.width - this.boardLeft / 2;
    };

    Geometry.prototype.sideAnchorY = function (black) {
        if (this.rotated) return this.height / 2;
        return black ? this.boardTop / 2 : this.height - this.boardTop / 2;
    };

    /** 牌子上的字要转多少度才正对着那一端的玩家（和象棋页同一套规则）。 */
    Geometry.prototype.sideTextRotation = function (black) {
        if (!this.rotated) return black ? 180 : 0;
        return black ? 90 : -90;
    };

    /** 棋子上的字要转多少度：朝着当前该走的那一方（白先）。 */
    Geometry.prototype.pieceTextRotation = function (whiteToMove) {
        return this.sideTextRotation(!whiteToMove);
    };

    // ------------------------------------------------------------------ 配色

    var PALETTE = {
        light: '#F0D9B5',
        dark: '#B58863',
        border: '#6B4A2F',
        whiteFill: '#FFFFFF',
        whiteStroke: '#3A3226',
        blackFill: '#1B1B1B',
        blackStroke: '#EFE6D5',
        label: '#FFFFFF',
        active: '#E6B24C',
        hover: 'rgba(230, 178, 76, 0.251)',
        blocked: 'rgba(198, 40, 40, 0.251)'
    };

    // ------------------------------------------------------------------ 棋盘视图

    function Board(canvas) {
        this.canvas = canvas;
        this.game = new Game();
        this.game.load();
        this.geo = null;
        this.width = 0;
        this.height = 0;
        this.dragging = false;
        this.hoverIndex = -1;
        this.drawScheduled = false;

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
        this.geo = new Geometry(width, height, Draw.boardRotated());
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
        if (event.game !== 'intl_chess') return;
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

    Board.prototype.glyphSize = function () {
        return this.geo.cell * 0.8;
    };

    Board.prototype.draw = function () {
        var ctx = this.ctx;
        var g = this.geo;
        if (!g) return;

        Draw.clear(ctx, this.width, this.height);
        this.drawSquares(ctx, g);
        this.drawPieces(ctx, g);
        this.drawHover(ctx, g);
        this.drawSideBadge(ctx, g, true);
        this.drawSideBadge(ctx, g, false);
        this.drawDraggedPiece(ctx, g);
    };

    Board.prototype.drawSquares = function (ctx, g) {
        for (var rank = 0; rank < RANKS; rank++) {
            for (var file = 0; file < FILES; file++) {
                var left = g.squareLeft(file, rank);
                var top = g.squareTop(file, rank);
                ctx.fillStyle = g.isDarkSquare(file, rank) ? PALETTE.dark : PALETTE.light;
                ctx.fillRect(left, top, g.cell, g.cell);
            }
        }

        var borderWidth = Math.max(2, g.cell * 0.05);
        var inset = borderWidth / 2;
        ctx.strokeStyle = PALETTE.border;
        ctx.lineWidth = borderWidth;
        ctx.strokeRect(
            g.boardLeft + inset,
            g.boardTop + inset,
            g.boardSize - borderWidth,
            g.boardSize - borderWidth
        );
    };

    Board.prototype.drawPieces = function (ctx, g) {
        var rotation = g.pieceTextRotation(this.game.whiteToMove);
        var size = this.glyphSize();
        var draggingFrom = this.game.drag ? this.game.drag.from : -1;

        for (var index = 0; index < SIZE; index++) {
            if (index === draggingFrom) continue;
            var color = this.game.colors[index];
            if (color === EMPTY) continue;
            var code = this.game.types[index];
            if (!code) continue;
            this.drawGlyph(
                ctx, g,
                g.squareX(index % FILES, Math.floor(index / FILES)),
                g.squareY(index % FILES, Math.floor(index / FILES)),
                size, color, code, rotation
            );
        }
    };

    /** 画一枚棋子：先描边再填色，两种底色上都清楚。 */
    Board.prototype.drawGlyph = function (ctx, g, cx, cy, size, color, code, rotation) {
        var glyph = GLYPHS[code];
        if (!glyph) return;
        var fill = color === WHITE ? PALETTE.whiteFill : PALETTE.blackFill;
        var stroke = color === WHITE ? PALETTE.whiteStroke : PALETTE.blackStroke;
        var strokeWidth = color === WHITE
            ? Math.max(2, g.cell * 0.035)
            : Math.max(1.5, g.cell * 0.022);

        var fontSpec = Draw.font(size);
        var baseline = cy + Draw.centeredBaseline(ctx, glyph, fontSpec);
        ctx.font = fontSpec;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        ctx.lineJoin = 'round';
        ctx.lineWidth = strokeWidth;

        if (rotation) {
            ctx.save();
            ctx.translate(cx, cy);
            ctx.rotate(rotation * Math.PI / 180);
            ctx.strokeStyle = stroke;
            ctx.fillStyle = fill;
            ctx.strokeText(glyph, 0, baseline - cy);
            ctx.fillText(glyph, 0, baseline - cy);
            ctx.restore();
        } else {
            ctx.strokeStyle = stroke;
            ctx.fillStyle = fill;
            ctx.strokeText(glyph, cx, baseline);
            ctx.fillText(glyph, cx, baseline);
        }
    };

    Board.prototype.drawHover = function (ctx, g) {
        if (!this.dragging || this.hoverIndex < 0) return;
        var file = this.hoverIndex % FILES;
        var rank = Math.floor(this.hoverIndex / FILES);
        var left = g.squareLeft(file, rank);
        var top = g.squareTop(file, rank);
        // 该自己走、且落点不是自己的子（空格或对方子）⇒ 能落下；其余情况松手会弹回。
        var overlay = this.game.drag;
        var canDrop = !!overlay &&
            overlay.piece.side === this.game.turn() &&
            this.game.colors[this.hoverIndex] !== colorOf(overlay.piece.side);
        ctx.fillStyle = canDrop ? PALETTE.hover : PALETTE.blocked;
        ctx.fillRect(left, top, g.cell, g.cell);
    };

    /**
     * 棋盘外空出来的那一端挂一方的小牌子：一枚王 + 这一方的名字。
     * 轮到谁走，谁的牌子就被黄色方框圈住；牌子上的字朝着坐在那一端的玩家转。
     */
    Board.prototype.drawSideBadge = function (ctx, g, black) {
        var strip = g.badgeStrip;
        if (strip <= 0) return;

        var isActive = (colorOf(this.game.turn()) === BLACK) === black;
        var radius = Math.min(g.cell * 0.42, strip * 0.38);
        var label = black ? '黑方' : '白方';
        var gap = radius * 0.5;

        var textSize = Math.max(16, g.cell * 0.42);
        var textFont = Draw.font(textSize);
        ctx.font = textFont;
        var textWidth = ctx.measureText(label).width;
        var groupWidth = radius * 2 + gap + textWidth;

        var anchorX = g.sideAnchorX(black);
        var anchorY = g.sideAnchorY(black);

        ctx.save();
        ctx.translate(anchorX, anchorY);
        ctx.rotate(g.sideTextRotation(black) * Math.PI / 180);

        var left = -groupWidth / 2;
        var pieceCx = left + radius;
        var inflate = radius * 0.45;
        if (isActive) {
            ctx.strokeStyle = PALETTE.active;
            ctx.lineWidth = 2;
            ctx.strokeRect(
                left - inflate,
                -radius - inflate,
                groupWidth + inflate * 2,
                radius * 2 + inflate * 2
            );
        }

        this.drawGlyph(ctx, g, pieceCx, 0, radius * 2, black ? BLACK : WHITE, 'K', 0);

        ctx.fillStyle = PALETTE.label;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'alphabetic';
        ctx.font = textFont;
        ctx.fillText(label, pieceCx + radius + gap, Draw.centeredBaseline(ctx, label, textFont));

        ctx.restore();
    };

    Board.prototype.drawDraggedPiece = function (ctx, g) {
        var overlay = this.game.drag;
        if (!overlay) return;
        var code = overlay.piece.name ? overlay.piece.name.charAt(0) : '';
        if (!code) return;
        this.drawGlyph(
            ctx, g,
            g.pxOfCell(overlay.cellX, overlay.cellY),
            g.pyOfCell(overlay.cellX, overlay.cellY),
            this.glyphSize() * 1.1,
            colorOf(overlay.piece.side),
            code,
            g.pieceTextRotation(this.game.whiteToMove)
        );
    };

    // ------------------------------------------------------------------ 触摸

    Board.prototype.bindEvents = function () {
        var self = this;
        var canvas = this.canvas;

        canvas.addEventListener('pointerdown', function (event) {
            var g = self.geo;
            if (!g) return;
            var index = g.indexAt(event.offsetX, event.offsetY);
            if (index < 0 || !self.game.hasPieceAt(index)) return;

            self.dragging = true;
            self.hoverIndex = index;
            self.emit(self.game.pickUp(index));
            self.persist();
            self.scheduleDraw();

            if (canvas.setPointerCapture) {
                try {
                    canvas.setPointerCapture(event.pointerId);
                } catch (e) {
                    // 忽略
                }
            }
            event.preventDefault();
        });

        canvas.addEventListener('pointermove', function (event) {
            if (!self.dragging) return;
            var g = self.geo;
            if (!g) return;
            self.hoverIndex = g.indexAt(event.offsetX, event.offsetY);
            self.emit(self.game.dragTo(g.cellXAt(event.offsetX, event.offsetY), g.cellYAt(event.offsetX, event.offsetY)));
            self.scheduleDraw();
            event.preventDefault();
        });

        canvas.addEventListener('pointerup', function (event) {
            if (!self.dragging) return;
            var g = self.geo;
            if (!g) return;
            self.emit(self.game.drop(
                g.cellXAt(event.offsetX, event.offsetY),
                g.cellYAt(event.offsetX, event.offsetY),
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

    return {
        create: function (canvas) {
            return new Board(canvas);
        },
        FILES: FILES,
        RANKS: RANKS
    };
})();
