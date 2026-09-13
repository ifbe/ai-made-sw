package com.example.pusher.ui

import com.example.pusher.utils.*
import android.content.Context
import android.graphics.Typeface
import android.util.AttributeSet
import android.widget.ScrollView
import android.widget.TextView
import android.widget.LinearLayout
import android.widget.LinearLayout.LayoutParams
import androidx.core.widget.TextViewCompat

class PreviewLogView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : ScrollView(context, attrs, defStyleAttr) {

    private val container = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        layoutParams = LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT)
    }
    private val entries = mutableListOf<PreviewEntry>()
    private var maxEntries = 20

    // 复用的行视图：刷新时只改文本，不再整段重建（视觉完全一致）
    private val rowViews = mutableListOf<TextView>()

    // Batching: accumulate entries, refresh at most every FLUSH_INTERVAL_MS or when batch is full
    private val pendingEntries = mutableListOf<PreviewEntry>()
    private var pendingFlushRunnable: Runnable? = null
    private val pendingLock = Any()
    private companion object {
        private const val FLUSH_INTERVAL_MS = 1000L
        private const val BATCH_SIZE = 10

        // toShortString() 只展示前 16 字节
        private const val LOG_HEX_BYTES = 16

        // 日志行文字大小（sp）
        private const val ROW_TEXT_SIZE_SP = 11f
    }

    init {
        addView(container)
        isVerticalScrollBarEnabled = true
        isFillViewport = true
    }

    /** 面板最多保留多少行（默认 20；日志类面板可以调大） */
    fun setMaxEntries(max: Int) {
        maxEntries = max
        trimEntries()
    }

    /**
     * 日志只展示前 16 字节，没必要把整帧编码数据一直留在列表里
     * （视频帧可能几十 KB，20+40 条常驻会造成持续的 GC 压力）。
     */
    private fun normalized(entry: PreviewEntry): PreviewEntry =
        if (entry.data.size > LOG_HEX_BYTES) {
            entry.copy(data = entry.data.copyOf(LOG_HEX_BYTES))
        } else {
            entry
        }

    fun addEntry(entry: PreviewEntry) {
        val stored = normalized(entry)
        synchronized(pendingLock) {
            pendingEntries.add(stored)
            // Keep pendingEntries bounded too
            while (pendingEntries.size > maxEntries * 2) {
                pendingEntries.removeAt(0)
            }
            if (pendingEntries.size >= BATCH_SIZE) {
                flushInternal()
            } else if (pendingFlushRunnable == null) {
                pendingFlushRunnable = Runnable { flushInternal() }
                postDelayed(pendingFlushRunnable!!, FLUSH_INTERVAL_MS)
            }
        }
    }

    private fun flushInternal() {
        pendingFlushRunnable?.let { removeCallbacks(it) }
        pendingFlushRunnable = null
        if (pendingEntries.isEmpty()) return
        entries.addAll(pendingEntries)
        pendingEntries.clear()
        trimEntries()
        refreshUI()
        post { fullScroll(FOCUS_DOWN) }
    }

    private fun trimEntries() {
        while (entries.size > maxEntries) {
            entries.removeAt(0)
        }
    }

    private fun refreshUI() {
        // 复用已有的 TextView：只更新文本，避免每次刷新都 removeAllViews + 重新 new。
        // 高频刷新时（音视频帧回调）这是主线程最大的开销来源。
        while (rowViews.size < entries.size) {
            val tv = TextView(context).apply {
                textSize = ROW_TEXT_SIZE_SP
                typeface = Typeface.MONOSPACE
                setPadding(0, 0, 0, 0)
                includeFontPadding = false
            }
            rowViews.add(tv)
            container.addView(tv)
        }
        while (rowViews.size > entries.size) {
            val tv = rowViews.removeAt(rowViews.size - 1)
            container.removeView(tv)
        }
        for (i in entries.indices) {
            rowViews[i].text = entries[i].toShortString()
        }
    }
}

data class PreviewEntry(
    val timestamp: Long,
    val direction: Int,           // 0: send, 1: recv, -1: 无方向
    val data: ByteArray,
    val extra: String = ""
) {
    fun toShortString(): String {
        val timeStr = TimeUtils.formatMillis(timestamp)
        // extra 非空表示这是一条“文本日志”（例如特殊日志面板），直接显示文字
        if (extra.isNotEmpty()) {
            return "[$timeStr] $extra"
        }
        val dirStr = when (direction) {
            0 -> "send"
            1 -> "recv"
            else -> ""
        }
        val hex = HexUtils.bytesToHex(data, 16)
        return if (dirStr.isNotEmpty()) {
            "[$timeStr] $dirStr $hex"
        } else {
            "[$timeStr] $hex"
        }
    }

    override fun toString(): String = toShortString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as PreviewEntry
        if (timestamp != other.timestamp) return false
        if (direction != other.direction) return false
        if (!data.contentEquals(other.data)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = timestamp.hashCode()
        result = 31 * result + direction
        result = 31 * result + data.contentHashCode()
        return result
    }
}