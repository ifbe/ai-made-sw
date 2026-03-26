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
        entries.add(entry)
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
                // 使用 Typeface.MONOSPACE
                typeface = Typeface.MONOSPACE
                //setPadding(2, 1, 2, 1)
                setPadding(0, 0, 0, 0)  // 减少内边距
                includeFontPadding = false  // 去除字体自带的内边距
                //TextViewCompat.setTextAppearance(this, android.R.style.TextAppearance_Small)
            }
            container.addView(tv)
        }
    }

    fun clear() {
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