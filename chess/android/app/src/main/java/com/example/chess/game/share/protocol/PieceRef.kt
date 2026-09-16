package com.example.chess.game.share.protocol

/**
 * 「哪颗子」。
 *
 *  - [name]：有名字的棋（象棋的车马炮、国际象棋的 K/Q/R…）直接用名字，人看着就懂；
 *  - [id]：唯一标识 —— 有名字的用「拿起来时所在的落点下标」（同名的两个车/马靠它区分），
 *    围棋/五子棋这种没名字的用自增的落子序号；
 *  - [side]：0 = 先手方（象棋红、国际象棋白、围棋/五子棋黑），1 = 后手方。
 */
data class PieceRef(val side: Int, val name: String, val id: Int)
