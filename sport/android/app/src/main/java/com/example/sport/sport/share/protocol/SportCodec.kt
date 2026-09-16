package com.example.sport.sport.share.protocol

/**
 * 报文的「信封」编解码。格式跟象棋那边一样，是 `key=value` 拼起来的单行文本：
 *
 * ```
 * v1|sport=football|seq=12|t=drag_move|side=-1|num=0|x=1234|y=-567
 * v1|sport=football|seq=13|t=state|ball=0,0|p=0:1:-50000:0;0:2:-35000:-22000;1:9:9500:0
 * v1|sport=football|seq=14|t=reset
 * ```
 *
 * 选择沿用象棋那套而不是引 JSON：零依赖、几十行手写完，而且**纯 JVM 就能单测**
 * （`org.json` 在单元测试里是空壳，得额外加依赖）。第一段是版本号，以后加字段
 * 不会打乱老客户端；值里不能出现 `|`，所以球员列表用 `;` 和 `:` 当分隔符。
 */
object SportCodec {

    const val VERSION = "v1"
    private const val SEP = '|'

    private const val T_START = "drag_start"
    private const val T_MOVE = "drag_move"
    private const val T_END = "drag_end"
    private const val T_STATE = "state"
    private const val T_RESET = "reset"

    /** 球的 side 哨兵值，跟 [PlayerRef.BALL] 一致。 */
    private const val BALL_SIDE = -1

    fun encode(event: SportEvent): String {
        val parts = ArrayList<String>(10)
        parts += VERSION
        parts += "sport=${event.sport.id}"
        parts += "seq=${event.seq}"
        when (event) {
            is DragStarted -> {
                parts += "t=$T_START"
                parts += refFields(event.ref)
                parts += "x=${event.from.x}"
                parts += "y=${event.from.y}"
            }

            is DragMoved -> {
                parts += "t=$T_MOVE"
                parts += refFields(event.ref)
                parts += "x=${event.pos.x}"
                parts += "y=${event.pos.y}"
            }

            is DragEnded -> {
                parts += "t=$T_END"
                parts += refFields(event.ref)
                parts += "x=${event.pos.x}"
                parts += "y=${event.pos.y}"
                parts += "committed=${if (event.committed) 1 else 0}"
            }

            is StateChanged -> {
                parts += "t=$T_STATE"
                parts += "ball=${event.state.ball.x},${event.state.ball.y}"
                parts += "p=${encodePlayers(event.state.players)}"
            }

            is BoardReset -> parts += "t=$T_RESET"
        }
        return parts.joinToString(SEP.toString())
    }

    /** 解析一行报文；版本不对、字段缺失或脏数据都返回 null，不抛异常。 */
    fun decode(line: String): SportEvent? {
        val parts = line.split(SEP)
        if (parts.isEmpty() || parts[0] != VERSION) return null

        val fields = HashMap<String, String>(parts.size * 2)
        for (i in 1 until parts.size) {
            val part = parts[i]
            val eq = part.indexOf('=')
            if (eq <= 0) continue
            fields[part.substring(0, eq)] = part.substring(eq + 1)
        }

        val sport = fields["sport"]?.let { SportKind.fromId(it) } ?: return null
        val seq = fields["seq"]?.toLongOrNull() ?: return null

        val x = fields["x"]?.toIntOrNull() ?: 0
        val y = fields["y"]?.toIntOrNull() ?: 0
        val pos = Coord(x, y)
        val side = fields["side"]?.toIntOrNull() ?: 0
        val number = fields["num"]?.toIntOrNull() ?: 0

        return when (fields["t"]) {
            T_START -> DragStarted(sport, seq, decodeRef(side, number), pos)
            T_MOVE -> DragMoved(sport, seq, decodeRef(side, number), pos)
            T_END -> DragEnded(sport, seq, decodeRef(side, number), pos, fields["committed"] == "1")

            T_STATE -> StateChanged(
                sport = sport,
                seq = seq,
                state = CourtState(
                    players = decodePlayers(fields["p"].orEmpty()),
                    ball = decodeCoord(fields["ball"]) ?: Coord.ORIGIN,
                ),
            )

            T_RESET -> BoardReset(sport, seq)
            else -> null
        }
    }

    // ------------------------------------------------------------------ 球员列表

    /** `side:num:x:y` 用 `;` 连起来。 */
    private fun encodePlayers(players: Map<PlayerRef, Coord>): String =
        players.entries.joinToString(";") { (ref, pos) ->
            "${ref.side}:${ref.number}:${pos.x}:${pos.y}"
        }

    private fun decodePlayers(raw: String): Map<PlayerRef, Coord> {
        if (raw.isEmpty()) return emptyMap()
        val result = LinkedHashMap<PlayerRef, Coord>()
        for (item in raw.split(';')) {
            if (item.isEmpty()) continue
            val f = item.split(':')
            if (f.size != 4) continue
            val side = f[0].toIntOrNull() ?: continue
            val number = f[1].toIntOrNull() ?: continue
            val x = f[2].toIntOrNull() ?: continue
            val y = f[3].toIntOrNull() ?: continue
            if (side == BALL_SIDE) continue
            result[PlayerRef(side, number)] = Coord(x, y)
        }
        return result
    }

    /** `x,y`。 */
    private fun decodeCoord(raw: String?): Coord? {
        val text = raw ?: return null
        val f = text.split(',')
        if (f.size != 2) return null
        val x = f[0].toIntOrNull() ?: return null
        val y = f[1].toIntOrNull() ?: return null
        return Coord(x, y)
    }

    /** `side=..` 和 `num=..` 两个字段；球用 side=-1 表示，号码固定 0。 */
    private fun refFields(ref: PlayerRef): List<String> = if (ref.isBall) {
        listOf("side=$BALL_SIDE", "num=0")
    } else {
        listOf("side=${ref.side}", "num=${ref.number}")
    }

    private fun decodeRef(side: Int, number: Int): PlayerRef =
        if (side == BALL_SIDE) PlayerRef.BALL_REF else PlayerRef(side, number)
}
