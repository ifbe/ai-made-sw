package com.example.sport.net

import com.example.sport.sport.share.protocol.SportEvent

/** 连接状态：左下角那个按钮上显示的就是它。 */
enum class LinkState {
    /** 还没开始。 */
    IDLE,

    /** 正在启动服务 / 正在连接。 */
    STARTING,

    /** 服务已启动 / 已经连上。 */
    ONLINE,

    /** 出错或断开了。 */
    FAILED,
}

/**
 * 一条「房间」连接：本地事件从这里出去，对端事件从 [listen] 进来。
 * 服务端和客户端是同一个接口，球场代码只认它，不关心底下是 WebSocket 还是别的。
 */
interface Session {
    /** 把本地产生的事件发出去（这些事件本机已经应用过了）。 */
    fun send(events: List<SportEvent>)

    /** 注册对端事件回调（**在网络线程上**回调，UI 那边要自己切线程）。 */
    fun listen(listener: (SportEvent) -> Unit)

    /** 关掉服务 / 断开连接。 */
    fun close()
}
