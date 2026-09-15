package com.example.chess.wuziqi

import android.content.Context
import android.util.AttributeSet
import com.example.chess.common.StoneBoardView

/**
 * 五子棋页：标准 15 路（连珠棋盘）。
 * 棋盘、托盘、拖拽落子、吃子（把子拖出棋盘）等逻辑全在 [StoneBoardView] 里，
 * 星位按 15 路取（四角 + 天元）。
 */
class GomokuBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : StoneBoardView(context, attrs, defStyleAttr, defaultLines = LINES) {

    companion object {
        /** 五子棋棋盘：15 路 × 15 路。 */
        const val LINES = 15
    }
}
