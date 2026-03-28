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

    // Batching: accumulate entries, refresh at most every FLUSH_INTERVAL_MS or when batch is full
    private val pendingEntries = mutableListOf<PreviewEntry>()
    private var pendingFlushRunnable: Runnable? = null
    private val pendingLock = Any()
    private companion object {
        private const val FLUSH_INTERVAL_MS = 1000L
        private const val BATCH_SIZE = 10
    }

    init {
        addView(container)
        isVerticalScrollBarEnabled = true
        isFillViewport = true
    }

    fun setMaxEntries(max: Int) {
        maxEntries = max
        trimEntries()
    }

    fun addEntry(entry: PreviewEntry) {
        synchronized(pendingLock) {
            pendingEntries.add(entry)
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

    /**
     * Replace all entries at once (used for bulk updates), no batching.
     */
    fun setEntries(newEntries: List<PreviewEntry>) {
        synchronized(pendingLock) {
            pendingFlushRunnable?.let { removeCallbacks(it) }
            pendingFlushRunnable = null
            pendingEntries.clear()
        }
        entries.clear()
        entries.addAll(newEntries)
        trimEntries()
        refreshUI()
        post { fullScroll(FOCUS_DOWN) }
    }

    /**
     * Force flush any pending entries immediately (e.g. when stopping streaming).
     */
    fun flush() {
        synchronized(pendingLock) {
            flushInternal()
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
        container.removeAllViews()
        entries.forEach { entry ->
            val tv = TextView(context).apply {
                text = entry.toShortString()
                textSize = 5f
                typeface = Typeface.MONOSPACE
                setPadding(0, 0, 0, 0)
                includeFontPadding = false
            }
            container.addView(tv)
        }
    }

    fun clear() {
        synchronized(pendingLock) {
            pendingFlushRunnable?.let { removeCallbacks(it) }
            pendingFlushRunnable = null
            pendingEntries.clear()
        }
        entries.clear()
        refreshUI()
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