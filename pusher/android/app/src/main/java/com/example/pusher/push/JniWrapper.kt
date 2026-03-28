package com.example.pusher.push

object JniWrapper {
    
    init {
        System.loadLibrary("pusher")
        android.util.Log.d("JniWrapper", "✅ libpusher.so loaded")
    }
    
    /**
     * 初始化推流器
     * @return Pair<Boolean, String> (是否成功, 错误信息)
     */
    external fun initPusher(
        url: String,
        protocol: String,
        format: String,
        videoWidth: Int,
        videoHeight: Int,
        sampleRate: Int,
        channelCount: Int
    ): Pair<Boolean, String>
    external fun setVideoExtradata(data: ByteArray): Boolean
    external fun setAvioCallback(listener: AvioDataListener)
    external fun writeVideoFrame(data: ByteArray, ptsMs: Long, isKeyFrame: Boolean): Boolean
    external fun writeAudioFrame(data: ByteArray, ptsMs: Long): Boolean
    external fun closePusher()
}

interface AvioDataListener {
    fun onSendData(data: ByteArray, timestamp: Long)
    fun onRecvData(data: ByteArray, timestamp: Long)
    fun onRtmpError(errorMsg: String)
}
