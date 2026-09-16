package com.example.sport.sport.share.protocol

/**
 * 要广播出去的一件事。分两类，跟象棋那边一个思路：
 *
 *  - **拖动流** [DragStarted] / [DragMoved] / [DragEnded]：高频、可丢、纯装饰。
 *    它只是「让对方看见我在把球拿着走」，丢了、晚了、乱了都不影响球场上的人数；
 *  - **状态流** [StateChanged] / [BoardReset]：低频、必须可靠，是唯一权威。
 *    接收方直接照抄 33 个坐标，不自己算任何东西。
 *
 * 这里**没有任何规则判断**（本来就没有规则）：位置就是全部状态。
 */
sealed interface SportEvent {
    val sport: SportKind

    /** 发送方自己递增的序号：去重、丢弃过期包用；服务端可以重新盖章。 */
    val seq: Long
}

/** 从场上拿起了一个人 / 球。[from] 是它原来在哪，接收方用它画一个影子。 */
data class DragStarted(
    override val sport: SportKind,
    override val seq: Long,
    val ref: PlayerRef,
    val from: Coord,
) : SportEvent

/** 拖动中的实时位置（高频、可丢）。 */
data class DragMoved(
    override val sport: SportKind,
    override val seq: Long,
    val ref: PlayerRef,
    val pos: Coord,
) : SportEvent

/**
 * 松手。[committed] = true 表示落位被采纳（后面会跟一条 [StateChanged]）；
 * false 表示拖动被打断。这里的松手规则跟象棋一样松 —— 场上任何位置都算数。
 */
data class DragEnded(
    override val sport: SportKind,
    override val seq: Long,
    val ref: PlayerRef,
    val pos: Coord,
    val committed: Boolean,
) : SportEvent

/**
 * 全量状态：场上所有人的坐标 + 球的坐标。
 * 拖动落位、重置之后都发这一包，接收方直接照抄。
 */
data class StateChanged(
    override val sport: SportKind,
    override val seq: Long,
    val state: CourtState,
) : SportEvent

/** 把所有人 + 球摆回开球站位（双方各自算，所以不需要传坐标）。 */
data class BoardReset(
    override val sport: SportKind,
    override val seq: Long,
) : SportEvent

/**
 * 一片场地的全量状态。纯 Kotlin，不依赖 Android，JVM 可单测。
 *
 * @param players 每个 `PlayerRef` → 它在哪儿；顺序无所谓
 * @param ball 球在哪儿
 */
data class CourtState(
    val players: Map<PlayerRef, Coord>,
    val ball: Coord,
)

/** 本地事件的出口：WebSocket 的 Session 接在这里。 */
fun interface SportEventSink {
    fun onLocalEvents(events: List<SportEvent>)
}
