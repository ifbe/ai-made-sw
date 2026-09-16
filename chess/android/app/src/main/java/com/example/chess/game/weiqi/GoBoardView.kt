package com.example.chess.game.weiqi

import android.content.Context
import android.util.AttributeSet
import com.example.chess.game.share.stone.StoneBoardView
import com.example.chess.game.share.protocol.GameKind

/**
 * 围棋页：标准 19 路。
 * 棋盘、托盘、拖拽落子、吃子（把子拖出棋盘）等逻辑全在 [StoneBoardView] / `StoneGame` 里。
 */
class GoBoardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : StoneBoardView(
    context,
    attrs,
    defStyleAttr,
    defaultLines = LINES,
    defaultKind = GameKind.WEIQI,
) {
    companion object {
        /** 围棋棋盘：19 路 × 19 路。 */
        const val LINES = 19
    }
}
