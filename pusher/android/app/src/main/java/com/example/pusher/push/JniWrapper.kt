package com.example.pusher.push

object JniWrapper {

    init {
        System.loadLibrary("pusher")
        android.util.Log.d("JniWrapper", "✅ libpusher.so loaded")
    }

    /**
     * 初始化推流器
     * @param videoCodec 0 = H.264(AVC)，1 = H.265(HEVC)
     * @return Pair<Boolean, String> (是否成功, 错误信息)；native 侧失败时可能返回 null
     */
    external fun initPusher(
        url: String,
        protocol: String,
        format: String,
        videoWidth: Int,
        videoHeight: Int,
        sampleRate: Int,
        channelCount: Int,
        fps: Int,
        videoBitrate: Int,
        audioBitrate: Int,
        videoCodec: Int,
        enableSubtitle: Boolean
    ): Pair<Boolean, String>?

    external fun setAvioCallback(listener: AvioDataListener)

    /** 当前 FFmpeg 库支持的输出协议（逗号分隔，如 "rtmp,rtmpt,rtsp,tcp,srt,file"） */
    external fun nativeGetOutputProtocols(): String

    /** 本地录制：把已经 detach 的文件描述符交给 native（-1 = 关闭录制） */
    external fun nativeStartRecord(fd: Int)

    /** 本地录制：停止并关闭 fd，返回写入的总字节数 */
    external fun nativeStopRecord(): Long

    /**
     * 写入视频帧
     * @param isCsd true 表示这是编码器输出的 CSD（SPS/PPS 或 VPS/SPS/PPS），native 用它构造 extradata
     */
    external fun writeVideoFrame(data: ByteArray, ptsMs: Long, isKeyFrame: Boolean, isCsd: Boolean): Boolean

    external fun writeAudioFrame(data: ByteArray, ptsMs: Long): Boolean

    /**
     * 设置要显示的字幕文本（只有 mp4/fMP4 容器有独立字幕轨）。
     * native 会在**视频关键帧**处写入样本 —— 这样和 fMP4 的分片边界对齐，
     * 否则稀疏文本轨遇上分片截断会让 movenc 的 av_assert0 直接 abort。
     */
    external fun setSubtitleText(text: String)

    /** 写一条字幕样本（tx3g），一般不用直接调，native 在关键帧处会自己写 */
    external fun writeSubtitleFrame(text: String, ptsMs: Long, durationMs: Long): Boolean

    external fun closePusher()

    /** 最近一次 FFmpeg 失败的真实原因（可能为空） */
    external fun getLastError(): String
}

interface AvioDataListener {
    /**
     * 每次写出的封装字节。
     *
     * @param data      最多前 16 字节（供预览/自检，不跨 JNI 拷全量）
     * @param totalSize 这次写入的**真实长度**（data.size 只是它的前 16 字节）
     */
    fun onSendData(data: ByteArray, timestamp: Long, totalSize: Int)

    /** 交给封装器（muxer）的包，用于“封装数据预览” */
    fun onMuxData(data: ByteArray, timestamp: Long)

    fun onRtmpError(errorMsg: String)
}
