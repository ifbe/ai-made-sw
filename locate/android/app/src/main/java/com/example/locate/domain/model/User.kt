package com.example.locate.domain.model

/**
 * 用户模型
 */
data class User(
    val username: String,
    val lat: Double,
    val lng: Double,
    val heading: Float = 0f,
    val nickname: String? = null,
    val targetLat: Double? = null,
    val targetLng: Double? = null
)
