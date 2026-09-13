package com.example.chatroom.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * 会话持久化（SharedPreferences + JSON）。
 *
 * 解决的问题：SessionManager 是纯内存 object，进程被系统杀掉（后台 LMK / 用户强杀 /
 * 国内厂商省电策略）后重建时，所有会话 + 参与者配置全没了，用户之前的会话再也找不回来。
 *
 * 方案：每次会话 / 参与者变更时把「会话 id + 参与者配置」落盘，下次进程启动由
 * [SessionManager.restoreFromStore] 读回来。恢复出来的会话**一律是未连接状态**，
 * 参与者信息还在，用户点 tab 展开重连面板手动重连。
 *
 * 不落盘的：
 * - 聊天消息（imageBytes 体积不可控，等以后有磁盘缓存再说）
 * - 连接状态（重启后必然断开，恢复出来就是未连接）
 * - 输入模式 / 拖拽出来的输入区高度等 UI 状态
 */
object SessionStore {

    private const val PREFS_NAME = "chatroom_sessions"
    private const val KEY_SESSIONS = "sessions_json_v1"
    private const val KEY_CREATED_AT = "createdAt"

    private var appContext: Context? = null

    /** Application onCreate / MainActivity onCreate 调一次 */
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** 按传入顺序覆盖保存全部会话（顺序 = tab 顺序） */
    fun save(sessions: List<PersistedSession>) {
        val ctx = appContext ?: return
        val arr = JSONArray()
        sessions.forEach { s ->
            val obj = JSONObject()
            obj.put("id", s.id)
            obj.put(KEY_CREATED_AT, s.createdAt)
            val pArr = JSONArray()
            s.participants.forEach { p ->
                val pObj = JSONObject()
                pObj.put("id", p.id)
                pObj.put("type", p.type.name)
                pObj.put("name", p.name)
                val params = JSONObject()
                p.params.forEach { (k, v) -> params.put(k, v) }
                pObj.put("params", params)
                pArr.put(pObj)
            }
            obj.put("participants", pArr)
            arr.put(obj)
        }
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_SESSIONS, arr.toString())
            // 用 commit 而不是 apply：会话创建后进程可能马上被杀，要确保数据已经落盘
            .commit()
    }

    fun load(): List<PersistedSession> {
        val ctx = appContext ?: return emptyList()
        val raw = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_SESSIONS, null) ?: return emptyList()
        return try {
            parse(raw)
        } catch (e: Exception) {
            // 数据损坏 / 格式升级时不要让 app 起不来：当作没有历史会话
            emptyList()
        }
    }

    /** 清空历史（调试 / 未来"清空历史会话"入口用） */
    fun clear() {
        appContext?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            ?.edit()?.remove(KEY_SESSIONS)?.apply()
    }

    private fun parse(raw: String): List<PersistedSession> {
        val arr = JSONArray(raw)
        val out = mutableListOf<PersistedSession>()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val id = obj.optString("id", "")
            if (id.isBlank()) continue

            val participants = mutableListOf<ParticipantConfig>()
            val pArr = obj.optJSONArray("participants") ?: JSONArray()
            for (j in 0 until pArr.length()) {
                val pObj = pArr.optJSONObject(j) ?: continue
                val typeName = pObj.optString("type", "")
                // 未知类型（旧版本写过 / 枚举改名）直接跳过，不让整条会话丢
                val type = ParticipantType.entries.firstOrNull { it.name == typeName } ?: continue
                val params = mutableMapOf<String, String>()
                pObj.optJSONObject("params")?.let { paramsObj ->
                    paramsObj.keys().forEach { k -> params.put(k, paramsObj.optString(k, "")) }
                }
                participants.add(
                    ParticipantConfig(
                        id = pObj.optString("id").ifBlank { java.util.UUID.randomUUID().toString() },
                        type = type,
                        name = pObj.optString("name").ifBlank { type.name },
                        params = params
                    )
                )
            }
            out.add(
                PersistedSession(
                    id = id,
                    createdAt = obj.optLong(KEY_CREATED_AT, 0L),
                    participants = participants
                )
            )
        }
        return out
    }
}

/** 落盘用的会话快照（连接状态不存 —— 重启后一律未连接，等用户手动重连） */
data class PersistedSession(
    val id: String,
    val createdAt: Long = 0L,
    val participants: List<ParticipantConfig> = emptyList()
)
