package com.example.sport.sport.share.protocol

/**
 * 四种球类。`id` 是上线到报文里的稳定名字，**不要随便改**。
 *
 * 现在只有足球和篮球是真的，排球 / 乒乓球是占位页；协议先留着位置，
 * 等它们做出来直接加几何和阵型就行。
 */
enum class SportKind(val id: String, val label: String) {
    FOOTBALL("football", "足球"),
    BASKETBALL("basketball", "篮球"),
    VOLLEYBALL("volleyball", "排球"),
    PINGPONG("pingpong", "乒乓球"),
    ;

    companion object {
        fun fromId(id: String): SportKind? = entries.firstOrNull { it.id == id }
    }
}
