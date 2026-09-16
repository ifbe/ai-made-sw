package com.example.chess.game.share.protocol

/** 四种棋。id 是上线到报文里的稳定名字，不要随便改。 */
enum class GameKind(val id: String) {
    XIANGQI("xiangqi"),
    INTL_CHESS("intl_chess"),
    WEIQI("weiqi"),
    WUZIQI("wuziqi"),
    ;

    companion object {
        fun fromId(id: String): GameKind? = entries.firstOrNull { it.id == id }
    }
}
