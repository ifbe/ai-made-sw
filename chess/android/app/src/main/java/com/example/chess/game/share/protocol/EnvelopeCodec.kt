package com.example.chess.game.share.protocol

/**
 * 报文的「信封」编解码。格式是 `key=value` 拼起来的单行文本：
 *
 * ```
 * v1|game=xiangqi|seq=12|t=drag_move|side=0|name=车|id=54|x=1280|y=-1152
 * v1|game=weiqi|seq=13|t=board|board=..b.w..|turn=1|counts=179,180
 * ```
 *
 * 为什么不引 JSON 库：现在项目零依赖，手写这套不到一百行，而且
 * **纯 JVM 就能单测**（org.json 在单元测试里是空壳，得额外加依赖）。
 * 第一段是版本号，以后加字段不会打乱老客户端；值里不能出现 '|'（棋子名、盘面串都不含）。
 */
object EnvelopeCodec {

    const val VERSION = "v1"
    private const val SEP = '|'

    private const val T_START = "drag_start"
    private const val T_MOVE = "drag_move"
    private const val T_END = "drag_end"
    private const val T_BOARD = "board"
    private const val T_RESET = "reset"

    fun encode(event: MoveEvent): String {
        val parts = ArrayList<String>(12)
        parts += VERSION
        parts += "game=${event.game.id}"
        parts += "seq=${event.seq}"
        when (event) {
            is DragStarted -> {
                parts += "t=$T_START"
                parts += "side=${event.piece.side}"
                parts += "name=${event.piece.name}"
                parts += "id=${event.piece.id}"
                parts += "from=${event.from}"
                parts += "x=${event.pos.x}"
                parts += "y=${event.pos.y}"
            }

            is DragMoved -> {
                parts += "t=$T_MOVE"
                parts += "side=${event.piece.side}"
                parts += "name=${event.piece.name}"
                parts += "id=${event.piece.id}"
                parts += "x=${event.pos.x}"
                parts += "y=${event.pos.y}"
            }

            is DragEnded -> {
                parts += "t=$T_END"
                parts += "side=${event.piece.side}"
                parts += "name=${event.piece.name}"
                parts += "id=${event.piece.id}"
                parts += "x=${event.pos.x}"
                parts += "y=${event.pos.y}"
                parts += "committed=${if (event.committed) 1 else 0}"
            }

            is BoardChanged -> {
                parts += "t=$T_BOARD"
                parts += "board=${event.board}"
                parts += "turn=${event.turn}"
                parts += "counts=${event.counts.joinToString(",")}"
            }

            is GameReset -> {
                parts += "t=$T_RESET"
            }
        }
        return parts.joinToString(SEP.toString())
    }

    /** 解析一行报文；版本不对、字段缺失或脏数据都返回 null，不抛异常。 */
    fun decode(line: String): MoveEvent? {
        val parts = line.split(SEP)
        if (parts.isEmpty() || parts[0] != VERSION) return null

        val fields = HashMap<String, String>(parts.size * 2)
        for (i in 1 until parts.size) {
            val part = parts[i]
            val eq = part.indexOf('=')
            if (eq <= 0) continue
            fields[part.substring(0, eq)] = part.substring(eq + 1)
        }

        val game = fields["game"]?.let { GameKind.fromId(it) } ?: return null
        val seq = fields["seq"]?.toLongOrNull() ?: return null
        val piece = PieceRef(
            side = fields["side"]?.toIntOrNull() ?: 0,
            name = fields["name"].orEmpty(),
            id = fields["id"]?.toIntOrNull() ?: -1,
        )
        val pos = BoardPos(
            x = fields["x"]?.toIntOrNull() ?: 0,
            y = fields["y"]?.toIntOrNull() ?: 0,
        )

        return when (fields["t"]) {
            T_START -> DragStarted(game, seq, piece, fields["from"]?.toIntOrNull() ?: -1, pos)
            T_MOVE -> DragMoved(game, seq, piece, pos)
            T_END -> DragEnded(game, seq, piece, pos, fields["committed"] == "1")
            T_BOARD -> BoardChanged(
                game = game,
                seq = seq,
                board = fields["board"].orEmpty(),
                turn = fields["turn"]?.toIntOrNull() ?: 0,
                counts = fields["counts"].orEmpty()
                    .split(',')
                    .filter { it.isNotEmpty() }
                    .mapNotNull { it.toIntOrNull() },
            )

            T_RESET -> GameReset(game, seq)
            else -> null
        }
    }
}
