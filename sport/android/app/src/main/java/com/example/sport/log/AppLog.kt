package com.example.sport.log

import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * app 内的「特殊日志」：启动、切页、重置、拖动落位这类值得看一眼的事，不记高频动作。
 *
 * 留一份环形缓冲（默认 200 行），并推给监听者（右下角那个日志框）。
 * **监听回调在调用线程上**（以后接联网时很可能是网络线程），界面那边自己切主线程。
 *
 * 纯 JVM：不 import android，所以能直接单测（见 AppLogTest）。
 */
object AppLog {

    private const val MAX_LINES = 200
    private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss")

    private val lines = ArrayDeque<String>()
    private val listeners = LinkedHashSet<(List<String>) -> Unit>()
    private val sinks = LinkedHashSet<(String) -> Unit>()

    /** 额外的输出目的地（Android 上会挂一个写 logcat 的 sink，方便 adb 抓日志）。 */
    fun addSink(sink: (String) -> Unit) {
        synchronized(this) { sinks += sink }
    }

    fun removeSink(sink: (String) -> Unit) {
        synchronized(this) { sinks -= sink }
    }

    fun log(message: String) {
        val snapshot: List<String>
        synchronized(this) {
            lines.addLast("${LocalTime.now().format(timeFormat)}  $message")
            while (lines.size > MAX_LINES) lines.removeFirst()
            snapshot = lines.toList()
        }
        val currentSinks = synchronized(this) { sinks.toList() }
        currentSinks.forEach { sink -> runCatching { sink(message) } }
        notifyListeners(snapshot)
    }

    fun snapshot(): List<String> = synchronized(this) { lines.toList() }

    fun addListener(listener: (List<String>) -> Unit) {
        val snapshot: List<String>
        synchronized(this) {
            listeners += listener
            snapshot = lines.toList()
        }
        if (snapshot.isNotEmpty()) runCatching { listener(snapshot) }
    }

    fun removeListener(listener: (List<String>) -> Unit) {
        synchronized(this) { listeners -= listener }
    }

    fun clear() {
        val snapshot: List<String>
        synchronized(this) {
            lines.clear()
            snapshot = emptyList()
        }
        notifyListeners(snapshot)
    }

    private fun notifyListeners(snapshot: List<String>) {
        val current = synchronized(this) { listeners.toList() }
        current.forEach { listener -> runCatching { listener(snapshot) } }
    }
}
