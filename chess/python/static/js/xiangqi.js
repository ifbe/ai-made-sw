/**
 * 象棋页：盘面数据 + 逻辑 + 棋盘绘制 + 拖拽手势。
 * 对应 Android 的 XiangqiGame.kt / XiangqiProtocol.kt / XiangqiGeometry.kt / XiangqiBoardView.kt
 * 四个文件，纯 JavaScript 一行不差地搬过来 —— 棋类规则只在浏览器里算，python 那边只转发。
 *
 * 布局规则（XiangqiGeometry）：
 *  - 9 路 × 10 路，格子 = min(短边 / 9, 长边 / 10 × 0.8)；
 *  - 细长屏（手机竖屏）格子由「占满短边」决定，棋盘居中、上下各留一条空带放双方牌子；
 *  - 横屏（平板）时棋盘转 90°（10 路沿屏幕横向走），协议里的坐标永远用棋盘语义坐标。
 *
 * 规则（XiangqiGame）：只判断轮次，不做走法 / 胜负校验。不该自己走时松手弹回原位；
 * 吃子 = 走到对方子上；拖出棋盘 = 这个子被吃掉，直接消失。
 */
var Xiangqi = (function () {
    'use strict';

    var FILES = 9;
    var RANKS = 10;
    var SIZE = FILES * RANKS;

    var EMPTY = 0;
    var RED = 1;
    var BLACK = 2;
    var FIRST_SIDE = 0;

    var HALF_FILES = (FILES - 1) / 2;   // 4
    var HALF_RANKS = (RANKS - 1) / 2;   // 4.5

    var UNITS_PER_CELL = 256;

    /** 底线从左到右的七种子（棋盘编码字符，红大写 / 黑小写）。 */
    var BACK_ROW = ['R', 'N', 'B', 'A', 'K', 'A', 'B', 'N', 'R'];

    /** 编码字符 → [红方显示名, 黑方显示名]（相/象、仕/士、帅/将）。 */
    var NAMES = {
        R: ['车', '车'],
        N: ['马', '马'],
        B: ['相', '象'],
        A: ['仕', '士'],
        K: ['帅', '将'],
        C: ['炮', '炮'],
        P: ['兵', '卒']
    };

    var CODE_CHARS = 'RNBAKCP';
    var STORAGE_KEY = 'chess.xiangqi';

    // ------------------------------------------------------------------ 纯函数

    function sideOf(color) {
        return color === RED ? FIRST_SIDE : 1;
    }

    function colorOf(side) {
        return side === FIRST_SIDE ? RED : BLACK;
    }

    function nameOf(code, color) {
        var pair = NAMES[code];
        if (!pair) return '';
        return color === RED ? pair[0] : pair[1];
    }

    /** 棋盘语义坐标（单位 1/256 格，原点 = 棋盘中心）—— 跟 Android 的 BoardPos 一样。 */
    function makePos(cellX, cellY) {
        var x = Math.round(cellX * UNITS_PER_CELL);
        var y = Math.round(cellY * UNITS_PER_CELL);
        return {x: x, y: y, cellX: x / UNITS_PER_CELL, cellY: y / UNITS_PER_CELL};
    }

    function posFromWire(x, y) {
        return {x: x, y: y, cellX: x / UNITS_PER_CELL, cellY: y / UNITS_PER_CELL};
    }

    function samePiece(a, b) {
        return !!a && !!b && a.side === b.side && a.name === b.name && a.id === b.id;
    }

    // ------------------------------------------------------------------ 盘面数据

    function Game() {
        this.colors = new Array(SIZE).fill(EMPTY);
        this.pieces = new Array(SIZE).fill(null);
        this.redToMove = true;
        this.drag = null;
        this.dragFrom = -1;
        this.dragColor = EMPTY;
        this.dragCode = null;
        this.seq = 0;
        this.setup();
    }

    Game.prototype.turn = function () {
        return this.redToMove ? FIRST_SIDE : 1;
    };

    Game.prototype.put = function (file, rank, color, code) {
        var index = rank * FILES + file;
        this.colors[index] = color;
        this.pieces[index] = code;
    };

    /** 摆回开局：红方在下（rank 9）、黑方在上（rank 0），中间楚河汉界。 */
    Game.prototype.setup = function () {
        this.colors.fill(EMPTY);
        this.pieces.fill(null);
        for (var file = 0; file < FILES; file++) {
            this.put(file, 0, BLACK, BACK_ROW[file]);
            this.put(file, 9, RED, BACK_ROW[file]);
        }
        this.put(1, 2, BLACK, 'C');
        this.put(7, 2, BLACK, 'C');
        this.put(1, 7, RED, 'C');
        this.put(7, 7, RED, 'C');
        for (var f = 0; f < FILES; f += 2) {
            this.put(f, 3, BLACK, 'P');
            this.put(f, 6, RED, 'P');
        }
        this.redToMove = true;
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

    /** 盘面 → 90 个字符：'.' 空、红大写 RNBAKCP、黑小写；行序 rank 0..9、列序 file 0..8。 */
    Game.prototype.encode = function () {
        var out = '';
        for (var index = 0; index < SIZE; index++) {
            var color = this.colors[index];
            var code = this.pieces[index];
            if (color === EMPTY || !code) {
                out += '.';
                continue;
            }
            out += color === RED ? code.toUpperCase() : code.toLowerCase();
        }
        return out;
    };

    Game.prototype.decode = function (board) {
        if (typeof board !== 'string' || board.length !== SIZE) return false;
        for (var index = 0; index < SIZE; index++) {
            var ch = board.charAt(index);
            if (ch === '.') {
                this.colors[index] = EMPTY;
                this.pieces[index] = null;
                continue;
            }
            var code = ch.toUpperCase();
            if (CODE_CHARS.indexOf(code) < 0) return false;
            this.colors[index] = ch === code ? RED : BLACK;
            this.pieces[index] = code;
        }
        return true;
    };

    Game.prototype.snapshot = function () {
        return {board: this.encode(), turn: this.turn()};
    };

    /** 落点下标 → 棋盘语义坐标。 */
    Game.prototype.posOf = function (index) {
        return makePos(index % FILES - HALF_FILES, Math.floor(index / FILES) - HALF_RANKS);
    };

    // ------------------------------------------------------------------ 手势

    Game.prototype.pickUp = function (index) {
        if (!this.hasPieceAt(index)) return [];
        var color = this.colors[index];
        var code = this.pieces[index];
        this.dragFrom = index;
        this.dragColor = color;
        this.dragCode = code;

        var piece = {side: sideOf(color), name: nameOf(code, color), id: index};
        var pos = this.posOf(index);
        this.drag = {piece: piece, from: index, cellX: pos.cellX, cellY: pos.cellY, byMe: true};
        return [{
            t: 'drag_start', game: 'xiangqi', seq: ++this.seq,
            piece: piece, from: index, pos: pos
        }];
    };

    Game.prototype.dragTo = function (cellX, cellY) {
        var current = this.drag;
        if (!current) return [];
        current.cellX = cellX;
        current.cellY = cellY;
        return [{
            t: 'drag_move', game: 'xiangqi', seq: ++this.seq,
            piece: current.piece, pos: makePos(cellX, cellY)
        }];
    };

    /** 松手：targetIndex < 0 表示落在棋盘外。 */
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
                this.pieces[from] = null;
            }
            events.push({
                t: 'drag_end', game: 'xiangqi', seq: ++this.seq,
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
                t: 'drag_end', game: 'xiangqi', seq: ++this.seq,
                piece: current.piece, pos: pos, committed: false
            });
            return events;
        }

        // 落到空格就是走子，落到对方子上就是把对方吃掉（直接覆盖）
        this.colors[targetIndex] = color;
        this.pieces[targetIndex] = code;
        this.colors[from] = EMPTY;
        this.pieces[from] = null;
        this.redToMove = !this.redToMove;

        events.push({
            t: 'drag_end', game: 'xiangqi', seq: ++this.seq,
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
            t: 'drag_end', game: 'xiangqi', seq: ++this.seq,
            piece: piece, pos: pos, committed: false
        }];
    };

    Game.prototype.boardChanged = function () {
        return {
            t: 'board', game: 'xiangqi', seq: ++this.seq,
            board: this.encode(), turn: this.turn(), counts: []
        };
    };

    Game.prototype.reset = function () {
        this.setup();
        return [
            {t: 'reset', game: 'xiangqi', seq: ++this.seq},
            this.boardChanged()
        ];
    };

    /** 对端事件 → 更新本地盘面（跟 Android 的 apply 一一对应）。 */
    Game.prototype.apply = function (event) {
        if (event.game !== 'xiangqi') return;
        if (event.seq > this.seq) this.seq = event.seq;

        switch (event.t) {
            case 'drag_start': {
                // 对端拿起一颗子：只有它确实还在那个位置、名字也对得上才开浮层。
                var from = event.from;
                if (!(from >= 0 && from < SIZE)) return;
                var color = this.colors[from];
                if (color === EMPTY) return;
                var code = this.pieces[from];
                if (!code) return;
                if (nameOf(code, color) !== event.piece.name) return;
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
                if (this.decode(event.board)) this.redToMove = event.turn === FIRST_SIDE;
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
            this.redToMove = data.turn === FIRST_SIDE;
            this.clearDrag();
            return true;
        } catch (e) {
            return false;
        }
    };

    // ------------------------------------------------------------------ 几何

    /**
     * [rotated] 由「横屏 / 竖屏」模式决定（不再看屏幕长宽比）：
     *  - false（默认，玩家上下）：9 路铺在屏幕横边、10 路铺在竖边；
     *  - true （玩家左右）：棋盘转 90°，9 路铺在竖边、10 路铺在横边。
     * 格子 = min(放 9 路那条边 / 9, 放 10 路那条边 / 10 × 0.8)，
     * 那个 0.8 就是给两端「黑方 / 红方」牌子留的两条空带。
     */
    function Geometry(width, height, rotated) {
        this.width = width;
        this.height = height;
        this.rotated = !!rotated;

        this.cols = this.rotated ? RANKS : FILES;
        this.rows = this.rotated ? FILES : RANKS;

        var fileExtent = this.rotated ? height : width;
        var rankExtent = this.rotated ? width : height;
        this.cell = Math.min(fileExtent / FILES, rankExtent / RANKS * 0.8);

        this.boardWidth = this.cols * this.cell;
        this.boardHeight = this.rows * this.cell;
        this.boardLeft = (width - this.boardWidth) / 2;
        this.boardTop = (height - this.boardHeight) / 2;

        // 楚河汉界那条带子的起止（屏幕坐标）
        this.riverStart = this.rotated ? this.gridX(4) : this.gridY(4);
        this.riverEnd = this.rotated ? this.gridX(5) : this.gridY(5);

        // 挂双方牌子的那条空带
        this.badgeStrip = this.rotated ? this.boardLeft : this.boardTop;
    }

    Geometry.prototype.gridX = function (col) {
        return this.boardLeft + (col + 0.5) * this.cell;
    };

    Geometry.prototype.gridY = function (row) {
        return this.boardTop + (row + 0.5) * this.cell;
    };

    Geometry.prototype.screenCol = function (file, rank) {
        return this.rotated ? rank : file;
    };

    Geometry.prototype.screenRow = function (file, rank) {
        return this.rotated ? file : rank;
    };

    Geometry.prototype.pieceX = function (file, rank) {
        return this.gridX(this.screenCol(file, rank));
    };

    Geometry.prototype.pieceY = function (file, rank) {
        return this.gridY(this.screenRow(file, rank));
    };

    Geometry.prototype.cellXAt = function (px, py) {
        return this.rotated
            ? (py - this.boardTop - this.boardHeight / 2) / this.cell
            : (px - this.boardLeft - this.boardWidth / 2) / this.cell;
    };

    Geometry.prototype.cellYAt = function (px, py) {
        return this.rotated
            ? (px - this.boardLeft - this.boardWidth / 2) / this.cell
            : (py - this.boardTop - this.boardHeight / 2) / this.cell;
    };

    Geometry.prototype.pxOfCell = function (cellX, cellY) {
        return this.rotated
            ? this.boardLeft + this.boardWidth / 2 + cellY * this.cell
            : this.boardLeft + this.boardWidth / 2 + cellX * this.cell;
    };

    Geometry.prototype.pyOfCell = function (cellX, cellY) {
        return this.rotated
            ? this.boardTop + this.boardHeight / 2 + cellX * this.cell
            : this.boardTop + this.boardHeight / 2 + cellY * this.cell;
    };

    Geometry.prototype.isInsideBoard = function (x, y) {
        return x >= this.boardLeft && x <= this.boardLeft + this.boardWidth &&
            y >= this.boardTop && y <= this.boardTop + this.boardHeight;
    };

    /** 手指位置吸附到最近的落点，返回下标（rank * FILES + file）；不在棋盘内返回 -1。 */
    Geometry.prototype.indexAt = function (x, y) {
        if (!this.isInsideBoard(x, y)) return -1;
        var col = Math.round((x - this.boardLeft) / this.cell - 0.5);
        var row = Math.round((y - this.boardTop) / this.cell - 0.5);
        col = Math.max(0, Math.min(this.cols - 1, col));
        row = Math.max(0, Math.min(this.rows - 1, row));
        var file = this.rotated ? row : col;
        var rank = this.rotated ? col : row;
        return rank * FILES + file;
    };

    /** 某一方的牌子挂在棋盘外哪一端（black = 棋盘 rank 0 那一端）。 */
    Geometry.prototype.sideAnchorX = function (black) {
        if (!this.rotated) return this.width / 2;
        return black ? this.boardLeft / 2 : this.width - this.boardLeft / 2;
    };

    Geometry.prototype.sideAnchorY = function (black) {
        if (this.rotated) return this.height / 2;
        return black ? this.boardTop / 2 : this.height - this.boardTop / 2;
    };

    /**
     * 牌子上的字要转多少度才正对着坐在那一端的玩家：
     * 正常方向时上方那家转 180°；棋盘转了 90° 时左边 +90°、右边 -90°。
     */
    Geometry.prototype.sideTextRotation = function (black) {
        if (!this.rotated) return black ? 180 : 0;
        return black ? 90 : -90;
    };

    /** 棋盘上棋子里的字要转多少度：朝着当前该走的那一方。 */
    Geometry.prototype.pieceTextRotation = function (redToMove) {
        return this.sideTextRotation(!redToMove);
    };

    // ------------------------------------------------------------------ 配色

    var PALETTE = {
        boardFill: '#FFE999',
        line: '#3A3226',
        river: '#8A7748',
        face: '#FFFBF0',
        red: '#C0392B',
        black: '#1F1F1F',
        active: '#E6B24C',
        blocked: '#C62828',
        indicator: '#FFFFFF'
    };

    var RIVER_TEXTS = ['楚 河', '汉 界'];
    var RIVER_POSITIONS = [0.25, 0.75];

    // ------------------------------------------------------------------ 绘制

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

        // 画布尺寸一律走 Draw.setup：它会按「逻辑视口」算（页面转 90° 时宽高对调），
        // 直接读 window.innerWidth/innerHeight 在横屏模式下会把棋盘画到屏幕外去。
        var initial = Draw.setup(canvas);
        this.ctx = initial.ctx;
        this.applySize(initial.width, initial.height);

        this.bindEvents();
        this.persist();
        this.scheduleDraw();
    }

    Board.prototype.persist = function () {
        this.game.save();
    };

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

    Board.prototype.emit = function (events) {
        if (!events || !events.length) return;
        Chrome.sendLocal(events);
    };

    Board.prototype.applyRemote = function (event) {
        if (event.game !== 'xiangqi') return;
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

    Board.prototype.pieceRadius = function () {
        return this.geo.cell * 0.42;
    };

    Board.prototype.draw = function () {
        var ctx = this.ctx;
        var g = this.geo;
        if (!g) return;
        var game = this.game;
        var cell = g.cell;

        ctx.setTransform(window.devicePixelRatio || 1, 0, 0, window.devicePixelRatio || 1, 0, 0);
        ctx.clearRect(0, 0, this.width, this.height);
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, this.width, this.height);

        // 棋盘底色：一整块鹅黄，比最外圈的线大出半格
        ctx.fillStyle = PALETTE.boardFill;
        ctx.fillRect(g.boardLeft, g.boardTop, g.boardWidth, g.boardHeight);

        this.drawGrid(ctx, g, Math.max(1, cell * 0.03));
        this.drawPalaces(ctx, g, Math.max(1, cell * 0.03));
        this.drawRiverText(ctx, g, cell * 0.42);
        this.drawPieces(ctx, g);
        this.drawHover(ctx, g);
        this.drawSideBadge(ctx, g, true);
        this.drawSideBadge(ctx, g, false);
        this.drawDraggedPiece(ctx, g);
    };

    Board.prototype.drawGrid = function (ctx, g, lineWidth) {
        var left = g.gridX(0);
        var right = g.gridX(g.cols - 1);
        var top = g.gridY(0);
        var bottom = g.gridY(g.rows - 1);
        var col;
        var row;
        var x;
        var y;

        ctx.strokeStyle = PALETTE.line;
        ctx.lineWidth = lineWidth;

        // 外框是完整的一圈，楚河汉界只打断里面的线。
        ctx.beginPath();
        ctx.rect(left, top, right - left, bottom - top);
        ctx.stroke();

        ctx.beginPath();
        for (col = 1; col < g.cols - 1; col++) {
            x = g.gridX(col);
            if (g.rotated) {
                ctx.moveTo(x, top);
                ctx.lineTo(x, bottom);
            } else {
                ctx.moveTo(x, top);
                ctx.lineTo(x, g.riverStart);
                ctx.moveTo(x, g.riverEnd);
                ctx.lineTo(x, bottom);
            }
        }
        for (row = 1; row < g.rows - 1; row++) {
            y = g.gridY(row);
            if (g.rotated) {
                ctx.moveTo(left, y);
                ctx.lineTo(g.riverStart, y);
                ctx.moveTo(g.riverEnd, y);
                ctx.lineTo(right, y);
            } else {
                ctx.moveTo(left, y);
                ctx.lineTo(right, y);
            }
        }
        ctx.stroke();
    };

    /** 两端的九宫斜线（file 3..5，rank 0..2 和 7..9）。 */
    Board.prototype.drawPalaces = function (ctx, g, lineWidth) {
        var bases = [0, 7];
        ctx.strokeStyle = PALETTE.line;
        ctx.lineWidth = lineWidth;
        ctx.beginPath();
        for (var i = 0; i < bases.length; i++) {
            var baseRank = bases[i];
            ctx.moveTo(g.pieceX(3, baseRank), g.pieceY(3, baseRank));
            ctx.lineTo(g.pieceX(5, baseRank + 2), g.pieceY(5, baseRank + 2));
            ctx.moveTo(g.pieceX(5, baseRank), g.pieceY(5, baseRank));
            ctx.lineTo(g.pieceX(3, baseRank + 2), g.pieceY(3, baseRank + 2));
        }
        ctx.stroke();
    };

    /** 楚河汉界四个字，跟着棋盘方向走。 */
    Board.prototype.drawRiverText = function (ctx, g, fontSize) {
        var font = Draw.font(fontSize);
        ctx.fillStyle = PALETTE.river;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';

        for (var i = 0; i < RIVER_TEXTS.length; i++) {
            var text = RIVER_TEXTS[i];
            var offset = Draw.centeredBaseline(ctx, text, font);

            if (g.rotated) {
                var x = (g.riverStart + g.riverEnd) / 2 + offset;
                var y = g.boardTop + g.boardHeight * RIVER_POSITIONS[i];
                ctx.save();
                ctx.translate(x, y);
                ctx.rotate(Math.PI / 2);
                ctx.fillText(text, 0, 0);
                ctx.restore();
            } else {
                var cx = g.boardLeft + g.boardWidth * RIVER_POSITIONS[i];
                var cy = (g.riverStart + g.riverEnd) / 2 + offset;
                ctx.fillText(text, cx, cy);
            }
        }
    };

    /**
     * 画一枚棋子：棋子面 + 圆环 + 名字。
     * 文字绕棋子中心转，所以转完还是正好居中在棋子上。
     */
    Board.prototype.drawPiece = function (ctx, cx, cy, radius, color, label, ringWidth, rotationDeg) {
        var ringColor = color === RED ? PALETTE.red : PALETTE.black;

        ctx.fillStyle = PALETTE.face;
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = ringColor;
        ctx.lineWidth = ringWidth;
        ctx.beginPath();
        ctx.arc(cx, cy, Math.max(0.5, radius - ringWidth / 2), 0, Math.PI * 2);
        ctx.stroke();

        var size = radius * 1.1;
        var font = Draw.font(size);
        ctx.fillStyle = ringColor;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        var baseline = cy + Draw.centeredBaseline(ctx, label, font);

        if (rotationDeg) {
            ctx.save();
            ctx.translate(cx, cy);
            ctx.rotate(rotationDeg * Math.PI / 180);
            ctx.fillText(label, 0, baseline - cy);
            ctx.restore();
        } else {
            ctx.fillText(label, cx, baseline);
        }
    };

    Board.prototype.drawPieces = function (ctx, g) {
        var game = this.game;
        var radius = this.pieceRadius();
        var ringWidth = Math.max(2, g.cell * 0.045);
        // 轮到谁走，整盘棋子的字就朝着谁（竖屏时就是 0° / 180°）。
        var rotation = g.pieceTextRotation(game.redToMove);
        var draggingFrom = game.drag ? game.drag.from : -1;

        for (var rank = 0; rank < RANKS; rank++) {
            for (var file = 0; file < FILES; file++) {
                var index = rank * FILES + file;
                if (index === draggingFrom) continue;
                var color = game.colors[index];
                if (color === EMPTY) continue;
                var code = game.pieces[index];
                if (!code) continue;
                this.drawPiece(
                    ctx,
                    g.pieceX(file, rank),
                    g.pieceY(file, rank),
                    radius,
                    color,
                    nameOf(code, color),
                    ringWidth,
                    rotation
                );
            }
        }
    };

    Board.prototype.drawHover = function (ctx, g) {
        if (!this.dragging || this.hoverIndex < 0) return;
        var overlay = this.game.drag;
        var canDrop = !!overlay &&
            overlay.piece.side === this.game.turn() &&
            this.game.colors[this.hoverIndex] !== colorOf(overlay.piece.side);
        var file = this.hoverIndex % FILES;
        var rank = Math.floor(this.hoverIndex / FILES);

        ctx.strokeStyle = canDrop ? PALETTE.line : PALETTE.blocked;
        ctx.lineWidth = Math.max(2, g.cell * 0.06);
        ctx.beginPath();
        ctx.arc(g.pieceX(file, rank), g.pieceY(file, rank), this.pieceRadius() * 1.12, 0, Math.PI * 2);
        ctx.stroke();
    };

    /**
     * 棋盘外空出来的那一端挂一方的小牌子：一枚棋子 + 这一方的名字。
     * 轮到谁走，谁的牌子就被黄色方框圈住；牌子上的字朝着坐在那一端的玩家转。
     */
    Board.prototype.drawSideBadge = function (ctx, g, black) {
        var strip = g.badgeStrip;
        if (strip <= 0) return;

        var radius = Math.min(g.cell * 0.42, strip * 0.38);
        var label = black ? '黑方' : '红方';
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
        if (this.game.turn() === (black ? 1 : 0)) {
            ctx.strokeStyle = PALETTE.active;
            ctx.lineWidth = 2;
            ctx.strokeRect(
                left - inflate,
                -radius - inflate,
                groupWidth + inflate * 2,
                radius * 2 + inflate * 2
            );
        }

        this.drawPiece(
            ctx,
            pieceCx,
            0,
            radius,
            black ? BLACK : RED,
            nameOf('K', black ? BLACK : RED),
            Math.max(2, g.cell * 0.045),
            0
        );

        ctx.fillStyle = PALETTE.indicator;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'alphabetic';
        ctx.font = textFont;
        ctx.fillText(label, pieceCx + radius + gap, Draw.centeredBaseline(ctx, label, textFont));

        ctx.restore();
    };

    /** 拖动中的那颗子：位置来自 drag 浮层，本地和远端的画法完全一样。 */
    Board.prototype.drawDraggedPiece = function (ctx, g) {
        var overlay = this.game.drag;
        if (!overlay) return;
        var label = overlay.piece.name ? overlay.piece.name.charAt(0) : '';
        if (!label) return;
        this.drawPiece(
            ctx,
            g.pxOfCell(overlay.cellX, overlay.cellY),
            g.pyOfCell(overlay.cellX, overlay.cellY),
            this.pieceRadius(),
            colorOf(overlay.piece.side),
            label,
            Math.max(2, g.cell * 0.045),
            g.pieceTextRotation(this.game.redToMove)
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
