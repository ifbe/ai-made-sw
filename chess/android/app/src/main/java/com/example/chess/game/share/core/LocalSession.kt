package com.example.chess.game.share.core

import com.example.chess.game.share.protocol.MoveEvent

/**
 * 不联网时的本地回环出口：接住本地事件并留一份流水。
 * 现在只是让「本地 → 事件」这条链跑通（也方便以后做存档、回放、悔棋），
 * 下一轮把 WebSocket 的 Session 接到同一个位置即可，游戏代码一行都不用动。
 */
class LocalSession : MoveEventSink {

    private val log = ArrayList<MoveEvent>()

    /** 到目前为止本机产生过的全部事件。 */
    val events: List<MoveEvent> get() = log

    override fun onLocalEvents(events: List<MoveEvent>) {
        log.addAll(events)
    }

    fun clear() {
        log.clear()
    }
}
