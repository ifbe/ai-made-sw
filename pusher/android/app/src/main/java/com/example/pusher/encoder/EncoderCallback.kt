package com.example.pusher.encoder

interface EncoderCallback {
    fun onVideoFrame(data: ByteArray, timestamp: Long, isKeyFrame: Boolean)
    fun onAudioFrame(data: ByteArray, timestamp: Long)
}
