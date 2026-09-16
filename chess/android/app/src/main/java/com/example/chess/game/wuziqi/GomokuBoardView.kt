package com.example.chess.game.wuziqi

import android.content.Context
import android.util.AttributeSet
import com.example.chess.game.share.stone.StoneBoardView
import com.example.chess.game.share.protocol.GameKind

/**
 * 五子棋页：标准 15 路（连珠棋盘），星位也按 15 路取。
 * 棋盘、托盘、拖拽落子、吃子（把子拖出棋盘）等逻辑全在 [StoneBoardView] / `StoneGame` 里。
 */
class GomokuBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : StoneBoardView(
    context,
    attrs,
    defStyleAttr,
    defaultLines = LINES,
    defaultKind = GameKind.WUZIQI,
) {
    companion object {
        /** 五子棋棋盘：15 路 × 15 路。 */
        const val LINES = 15
    }
}
