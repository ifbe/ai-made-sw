package com.example.chess.game.share.core

import com.example.chess.game.share.protocol.GameKind
import com.example.chess.game.share.protocol.MoveEvent
import com.example.chess.game.share.protocol.PieceRef

/**
 * 本地手势。View 负责把像素换算成**棋盘语义坐标**（x 沿 file、y 沿 rank，单位 = 格），
 * 再交给 [Game]；所以 Game 既不认识 Android，也不认识像素，纯 JVM 就能测。
 */
sealed interface Gesture {
    /** 拿起盘上某个落点/格子上的子。 */
    data class PickUp(val index: Int) : Gesture

    /**
     * 从托盘里拿一颗新子（只有围棋/五子棋用）。
     * [side] 0 = 先手，1 = 后手；[cellX]/[cellY] 是托盘那一点在棋盘语义坐标里的位置
     * （在棋盘外，对端照样能看见这颗子被拿着走）。
     */
    data class PickUpNew(val side: Int, val cellX: Float, val cellY: Float) : Gesture

    /** 拖动中。 */
    data class DragTo(val cellX: Float, val cellY: Float) : Gesture

    /** 松手：[targetIndex] 是吸附后的落点/格子下标，-1 表示落在棋盘外。 */
    data class Drop(val cellX: Float, val cellY: Float, val targetIndex: Int) : Gesture

    /** 手势被系统取消（比如被父容器拦截）。 */
    data object Cancel : Gesture
}

/** 正在被拖的那颗子（本地或远端），渲染用。 */
data class DragOverlay(
    val piece: PieceRef,
    /** 它原来在哪个落点/格子上 —— 渲染时要跳过这一格，免得画两遍。 */
    val from: Int,
    val cellX: Float,
    val cellY: Float,
    /** true = 本机玩家在拖；false = 对端在拖（这就是「看见对方乱动」）。 */
    val byMe: Boolean,
)

/** 全量棋盘快照。 */
data class BoardSnapshot(
    val game: GameKind,
    val board: String,
    /** 0 = 先手，1 = 后手。 */
    val turn: Int,
    val counts: List<Int>,
)

/**
 * 每种棋的共同门面：**数据 + 逻辑都在实现类里，View 只渲染和报手势**。
 *
 * 约定：`onGesture` 会先更新本地状态，再把「需要广播出去的事件」返回给调用方；
 * `apply` 只处理**对端**来的事件，不会把自己的事件回灌。
 */
interface Game {
    val kind: GameKind

    /** 接下来该谁走：0 = 先手，1 = 后手。 */
    val turn: Int

    /** 全量状态（落子后广播这一包）。 */
    fun snapshot(): BoardSnapshot

    /** 某个落点/格子上有没有子（View 用它决定按下去要不要接这个手势）。 */
    fun hasPieceAt(index: Int): Boolean

    /** 当前拖拽浮层，没有则 null。 */
    val drag: DragOverlay?

    /** 本地手势 → 要广播出去的事件（本地状态已经更新）。 */
    fun onGesture(gesture: Gesture): List<MoveEvent>

    /** 收到对端事件 → 更新本地状态。 */
    fun apply(event: MoveEvent)

    /** 重开一局，返回要广播的事件。 */
    fun reset(): List<MoveEvent>
}

/** 本地事件的出口：下一轮的 WebSocket Session 就接在这里。 */
fun interface MoveEventSink {
    fun onLocalEvents(events: List<MoveEvent>)
}
