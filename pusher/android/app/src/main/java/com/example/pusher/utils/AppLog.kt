package com.example.pusher.utils

import android.util.Log

/**
 * 应用“特殊日志”：只记录关键事件（会话生命周期、连接结果、编解码/相机/音频设备参数、
 * 错误），不是 Android 的 logcat 全量日志。
 *
 * - 同时镜像一份到 logcat（tag = AppLog），方便用 adb 抓；
 * - 保留最近 [MAX_HISTORY] 条历史，这样“特殊日志”面板打开时能看到之前发生的事；
 * - 通过 [setSink] 把新日志推给 UI（由 Activity 注册/注销，避免内存泄漏）。
 */
object AppLog {

    private const val TAG = "AppLog"
    private const val MAX_HISTORY = 200

    private val history = ArrayDeque<String>()

    @Volatile
    private var sink: ((String) -> Unit)? = null

    fun log(message: String) {
        Log.d(TAG, message)
        val currentSink: ((String) -> Unit)?
        synchronized(this) {
            history.addLast(message)
            while (history.size > MAX_HISTORY) {
                history.removeFirst()
            }
            currentSink = sink
        }
        // 在锁外回调，避免 UI 线程回进来时互相等待
        currentSink?.invoke(message)
    }

    fun setSink(newSink: ((String) -> Unit)?) {
        synchronized(this) {
            sink = newSink
        }
    }

    fun snapshot(): List<String> = synchronized(this) { history.toList() }

    fun clear() {
        synchronized(this) { history.clear() }
    }
}
