package com.example.chess

import android.os.Bundle
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updateLayoutParams
import com.example.chess.guojixiangqi.IntlChessBoardView
import com.example.chess.weiqi.GoBoardView
import com.example.chess.wuziqi.GomokuBoardView
import com.example.chess.xiangqi.ChessBoardView

/**
 * 唯一的 Activity：一个全屏黑底的 FrameLayout 里叠了象棋 / 国际象棋 / 围棋 / 五子棋四个页面，
 * 左上角是四个页面标签（当前页高亮），右上角是重置按钮（重置当前页）。
 */
class MainActivity : AppCompatActivity() {

    private enum class Page { CHESS, INTL_CHESS, GO, GOMOKU }

    private lateinit var chessPage: ChessBoardView
    private lateinit var intlChessPage: IntlChessBoardView
    private lateinit var goPage: GoBoardView
    private lateinit var gomokuPage: GomokuBoardView

    private lateinit var tabBar: LinearLayout
    private lateinit var tabChess: TextView
    private lateinit var tabIntlChess: TextView
    private lateinit var tabGo: TextView
    private lateinit var tabGomoku: TextView

    private lateinit var resetButton: TextView

    private var page = Page.CHESS

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 全屏（edge-to-edge）：页面底色是黑的，状态栏 / 导航栏也跟着黑。
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_main)

        chessPage = findViewById(R.id.chessPage)
        intlChessPage = findViewById(R.id.intlChessPage)
        goPage = findViewById(R.id.goPage)
        gomokuPage = findViewById(R.id.gomokuPage)

        tabBar = findViewById(R.id.tabBar)
        tabChess = findViewById(R.id.tabChess)
        tabIntlChess = findViewById(R.id.tabIntlChess)
        tabGo = findViewById(R.id.tabGo)
        tabGomoku = findViewById(R.id.tabGomoku)

        resetButton = findViewById(R.id.resetButton)

        WindowInsetsControllerCompat(window, tabChess).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }

        // 左上角的标签栏和右上角的重置按钮都避开状态栏 / 刘海。
        attachCornerInsets(tabBar, atStart = true)
        attachCornerInsets(resetButton, atStart = false)

        tabChess.setOnClickListener { show(Page.CHESS) }
        tabIntlChess.setOnClickListener { show(Page.INTL_CHESS) }
        tabGo.setOnClickListener { show(Page.GO) }
        tabGomoku.setOnClickListener { show(Page.GOMOKU) }

        // 右上角：把当前这一页重置回开局。
        resetButton.setOnClickListener {
            when (page) {
                Page.CHESS -> chessPage.reset()
                Page.INTL_CHESS -> intlChessPage.reset()
                Page.GO -> goPage.reset()
                Page.GOMOKU -> gomokuPage.reset()
            }
        }

        show(page)
    }

    private fun show(target: Page) {
        page = target
        chessPage.visibility = visibility(target == Page.CHESS)
        intlChessPage.visibility = visibility(target == Page.INTL_CHESS)
        goPage.visibility = visibility(target == Page.GO)
        gomokuPage.visibility = visibility(target == Page.GOMOKU)

        styleTab(tabChess, target == Page.CHESS)
        styleTab(tabIntlChess, target == Page.INTL_CHESS)
        styleTab(tabGo, target == Page.GO)
        styleTab(tabGomoku, target == Page.GOMOKU)
    }

    private fun visibility(shown: Boolean) = if (shown) View.VISIBLE else View.GONE

    /** 当前页的标签用黄色实心底 + 深色字，其它页是黑底描边 + 浅色字。 */
    private fun styleTab(tab: TextView, active: Boolean) {
        tab.setBackgroundResource(if (active) R.drawable.bg_tab_active else R.drawable.bg_tab)
        tab.setTextColor(if (active) 0xFF2A2110.toInt() else 0xFFF0F0F0.toInt())
    }

    /** 把自己固定在自己那个角上，并让开状态栏 / 刘海 / 屏幕圆角。 */
    private fun attachCornerInsets(view: View, atStart: Boolean) {
        val baseMargin = resources.getDimensionPixelSize(R.dimen.corner_button_margin)
        ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            v.updateLayoutParams<FrameLayout.LayoutParams> {
                topMargin = baseMargin + bars.top
                if (atStart) {
                    marginStart = baseMargin + bars.left
                } else {
                    marginEnd = baseMargin + bars.right
                }
            }
            insets
        }
        ViewCompat.requestApplyInsets(view)
    }
}
