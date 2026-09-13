package com.example.chatroom.ui.common

import android.content.Context
import android.util.AttributeSet
import android.widget.ScrollView

/**
 * 带最大高度上限的 ScrollView。
 *
 * `android:maxHeight` 在原生 ScrollView 上不生效（FrameLayout 也不支持），
 * 而重连面板展开时不能让参与者列表无限长把聊天区挤没，所以这里在 onMeasure
 * 里把测量高度夹到 [maxHeightPx] 以内，超出部分内部滚动。
 */
class MaxHeightScrollView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : ScrollView(context, attrs, defStyleAttr) {

    /** 最大高度（px）；<= 0 表示不限制 */
    var maxHeightPx: Int = 0

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
        if (maxHeightPx > 0 && measuredHeight > maxHeightPx) {
            setMeasuredDimension(measuredWidth, maxHeightPx)
        }
    }
}
