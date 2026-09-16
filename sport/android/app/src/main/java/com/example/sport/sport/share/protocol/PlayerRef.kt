package com.example.sport.sport.share.protocol

/**
 * 「哪个人 / 还是球」。
 *
 *  - **球员**：[side] 是 0（主队）或 1（客队），[number] 是号码。两个队号码不重复，
 *    所以 `(side, number)` 就能唯一认出一个人，比传内部下标稳（对端的阵型顺序不必一样）。
 *  - **球**：[side] = [BALL]，[number] 无意义。
 *
 * [id] 是球场上那个令牌的内部下标，只为本地渲染方便，**不参与报文的语义**。
 */
data class PlayerRef(
    val side: Int,
    val number: Int,
    val id: Int = -1,
) {
    /** true = 这是球，不是球员。 */
    val isBall: Boolean get() = side == BALL

    /** 给日志看的中文描述。 */
    fun label(): String = if (isBall) "球" else "${if (side == 0) "主队" else "客队"}$number 号"

    companion object {
        /** 球的 side 哨兵值。 */
        const val BALL = -1

        val BALL_REF = PlayerRef(BALL, 0)

        fun home(number: Int, id: Int = -1) = PlayerRef(0, number, id)

        fun away(number: Int, id: Int = -1) = PlayerRef(1, number, id)
    }
}
