package com.example.locate.domain.model

/**
 * 位置信息
 */
data class Position(
    val lat: Double,
    val lng: Double,
    val accuracy: Float = 0f,
    val altitude: Double = 0.0,
    val speed: Float = 0f,
    val bearing: Float = 0f
)
