package com.example.locate.util

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 应用内日志缓冲。
 *
 * 只记录「本程序自己想在界面上告诉用户」的消息，不是系统 logcat 的镜像。
 * 由地图页左下角的日志矩形渲染；缓冲区是进程级的，所以启动页写的日志
 * 在地图页也能看到，Activity 重建也不会丢。
 */
object AppLog {

    enum class Level { INFO, WARN, ERROR }

    data class Entry(val time: String, val level: Level, val text: String)

    private const val MAX_ENTRIES = 200
    private const val LOGCAT_TAG = "AppLog"

    /** 日志矩形的展开状态和用户拖出来的尺寸。放在这里是为了 Activity 重建（旋转）后保持原样。 */
    @Volatile
    var panelExpanded: Boolean = false

    /** 展开后显示多少行日志（用户拖出来的） */
    @Volatile
    var panelRows: Int = 10

    /** 用户拖出来的宽度（dp），0 = 用默认宽度 */
    @Volatile
    var panelWidthDp: Int = 0

    private val mainHandler = Handler(Looper.getMainLooper())

    // 只在主线程访问
    private val buffer = ArrayDeque<Entry>()
    private val listeners = mutableSetOf<(List<Entry>) -> Unit>()
    private val formatter = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun i(text: String) = append(Level.INFO, text)

    fun w(text: String) = append(Level.WARN, text)

    fun e(text: String) = append(Level.ERROR, text)

    fun clear() {
        mainHandler.post {
            buffer.clear()
            notifyListeners()
        }
    }

    /**
     * 监听日志变化，注册时会立刻回调一次当前快照。
     */
    fun addListener(listener: (List<Entry>) -> Unit) {
        mainHandler.post {
            listeners.add(listener)
            listener(buffer.toList())
        }
    }

    fun removeListener(listener: (List<Entry>) -> Unit) {
        mainHandler.post { listeners.remove(listener) }
    }

    private fun append(level: Level, text: String) {
        // 同时打到 logcat，方便连 adb 排查；界面只显示应用自己写的消息
        val priority = if (level == Level.ERROR) Log.ERROR else Log.DEBUG
        Log.println(priority, LOGCAT_TAG, text)

        mainHandler.post {
            buffer.addLast(Entry(formatter.format(Date()), level, text))
            while (buffer.size > MAX_ENTRIES) buffer.removeFirst()
            notifyListeners()
        }
    }

    private fun notifyListeners() {
        val snapshot = buffer.toList()
        listeners.toList().forEach { it(snapshot) }
    }
}
