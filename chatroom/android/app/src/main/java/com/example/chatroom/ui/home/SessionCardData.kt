package com.example.chatroom.ui.home

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * 菜单页的一张**一级卡片**（一个会话）。
 *
 * - `sessionId == null` → **草稿卡片**：还没真正建会话，参与者只在内存里，点卡片上的「创建」才落盘
 * - `sessionId != null` → **已有会话**：内容来自 `SessionManager`，表单改动即时回写
 *
 * 折叠状态不放在这里（那是每个菜单实例自己的 UI 状态）。
 */
class SessionCardData(
    /** 卡片自身 id（草稿期用它做 key；创建后改用 sessionId） */
    val cardId: String = UUID.randomUUID().toString(),
    var sessionId: String? = null,
    val participants: MutableList<EditingCardData> = mutableListOf()
) {
    val isDraft: Boolean get() = sessionId == null

    /** 展开态的 key：草稿用 cardId，已有会话用 sessionId（这样创建后展开态不会丢） */
    val expandKey: String get() = sessionId ?: cardId
}

/**
 * 草稿卡片的共享容器。
 *
 * 菜单页同时存在多份实例（主页那份 + 每个 ChatFragment 抽屉里那份），草稿还没进
 * `SessionManager`，所以必须放在共享的地方，否则「主页加了张草稿卡片、切到聊天页打开抽屉就没了」。
 *
 * 只放草稿；已有会话一律以 `SessionManager` 为准（每次显示时重建）。
 */
object SessionDraftStore {

    val drafts = mutableListOf<SessionCardData>()

    fun add(card: SessionCardData = SessionCardData()) {
        drafts.add(card)
    }

    fun remove(card: SessionCardData) {
        drafts.remove(card)
    }

    fun clear() {
        drafts.clear()
    }
}

/**
 * 会话显示名 = 创建时间 `YYMM-DDhh-mmss`（例 `2609-1301-4310`），纯文字、无 emoji。
 *
 * 从 sessionId 里的 epoch 毫秒解析（`SessionManager.createSession()` 生成的就是
 * `session_<epochMillis>`）；解析不出来（理论上不会）就用 0。
 * **菜单页卡片名和底部 tab 名共用这一个函数**，保证两处永远一致。
 */
fun sessionTimeLabel(sessionId: String): String {
    val millis = sessionId.removePrefix("session_").toLongOrNull() ?: 0L
    return timeLabelFormat.get()!!.format(Date(millis))
}

/** SimpleDateFormat 不是线程安全的，但这里只在主线程用；用 ThreadLocal 兜住万一 */
private val timeLabelFormat = object : ThreadLocal<SimpleDateFormat>() {
    override fun initialValue() = SimpleDateFormat("yyMM-ddHH-mmss", Locale.US)
}
