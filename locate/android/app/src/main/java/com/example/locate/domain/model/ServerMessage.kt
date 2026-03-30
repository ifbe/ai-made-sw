package com.example.locate.domain.model

import org.json.JSONObject

/**
 * 服务器 WebSocket 消息解析
 */
sealed class ServerMessage {
    data class LoginSuccess(
        val token: String,
        val nickname: String
    ) : ServerMessage()

    data class UserList(val users: List<User>) : ServerMessage()

    data class UserJoined(val username: String) : ServerMessage()

    data class UserLeft(val username: String) : ServerMessage()

    data class TargetUpdate(
        val username: String,
        val targetLat: Double?,
        val targetLng: Double?
    ) : ServerMessage()

    data class PositionUpdate(
        val username: String,
        val lat: Double,
        val lng: Double,
        val heading: Float = 0f
    ) : ServerMessage()

    data class Error(val message: String) : ServerMessage()

    companion object {
        fun parse(json: String): ServerMessage? {
            return try {
                val obj = JSONObject(json)
                when (obj.getString("type")) {
                    "login_success" -> LoginSuccess(
                        token = obj.getString("token"),
                        nickname = obj.optString("nickname", "")
                    )
                    "user_list" -> {
                        val users = mutableListOf<User>()
                        val arr = obj.optJSONArray("users") ?: return UserList(emptyList())
                        for (i in 0 until arr.length()) {
                            val u = arr.getJSONObject(i)
                            users.add(User(
                                username = u.getString("username"),
                                lat = u.getDouble("lat"),
                                lng = u.getDouble("lng"),
                                heading = u.optDouble("heading", 0.0).toFloat(),
                                nickname = u.optString("nickname", "").takeIf { it.isNotEmpty() },
                                targetLat = u.optDouble("target_lat").takeIf { !u.isNull("target_lat") },
                                targetLng = u.optDouble("target_lng").takeIf { !u.isNull("target_lng") }
                            ))
                        }
                        UserList(users)
                    }
                    "user_joined" -> UserJoined(obj.getString("username"))
                    "user_left" -> UserLeft(obj.getString("username"))
                    "update_target" -> TargetUpdate(
                        username = obj.getString("username"),
                        targetLat = obj.optDouble("target_lat").takeIf { !obj.isNull("target_lat") },
                        targetLng = obj.optDouble("target_lng").takeIf { !obj.isNull("target_lng") }
                    )
                    "update_position" -> PositionUpdate(
                        username = obj.getString("username"),
                        lat = obj.getDouble("lat"),
                        lng = obj.getDouble("lng"),
                        heading = obj.optDouble("heading", 0.0).toFloat()
                    )
                    "error" -> Error(obj.optString("message", "未知错误"))
                    else -> null
                }
            } catch (e: Exception) {
                null
            }
        }
    }
}
