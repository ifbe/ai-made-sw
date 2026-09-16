package com.example.chess.game.share.protocol

/**
 * 要广播出去的一件事，分成两类：
 *
 *  - **拖拽流** [DragStarted] / [DragMoved] / [DragEnded]：高频、可丢、纯装饰。
 *    它只是「让对方看见我在把子拿着走」，丢了、晚了、乱了都不影响棋局；
 *  - **状态流** [BoardChanged] / [GameReset]：低频、必须可靠，是唯一权威。
 *    接收方直接照抄盘面，不自己算走法，所以永远不会累积误差。
 */
sealed interface MoveEvent {
    val game: GameKind

    /** 发送方自己递增的序号：去重、丢弃过期包用；服务器可以重新盖章。 */
    val seq: Long
}

/** 从盘上拿起了一颗子（[from] = 它原来所在的落点/格子下标）。 */
data class DragStarted(
    override val game: GameKind,
    override val seq: Long,
    val piece: PieceRef,
    val from: Int,
    val pos: BoardPos,
) : MoveEvent

/** 拖动中的实时位置（高频、可丢）。 */
data class DragMoved(
    override val game: GameKind,
    override val seq: Long,
    val piece: PieceRef,
    val pos: BoardPos,
) : MoveEvent

/**
 * 松手。[committed] = true 表示这个位置被采纳（后面会跟一条 [BoardChanged]）；
 * false 表示弹回原位（点一下没动、不该自己走、被取消）。
 */
data class DragEnded(
    override val game: GameKind,
    override val seq: Long,
    val piece: PieceRef,
    val pos: BoardPos,
    val committed: Boolean,
) : MoveEvent

/**
 * 全量棋盘：落子 / 吃子 / 拖出棋盘 / 重开之后都发这一包。
 * [board] 是本棋种协议编码出来的盘面（见各棋种的 XxxProtocol），接收方直接照着还原。
 */
data class BoardChanged(
    override val game: GameKind,
    override val seq: Long,
    val board: String,
    /** 接下来该谁走：0 = 先手，1 = 后手。 */
    val turn: Int,
    /** 剩余棋子数量（围棋/五子棋的 x180），没有就是空表。 */
    val counts: List<Int>,
) : MoveEvent

/** 重开一局（双方各自 reset 出同一个开局，所以不需要传盘面）。 */
data class GameReset(
    override val game: GameKind,
    override val seq: Long,
) : MoveEvent
