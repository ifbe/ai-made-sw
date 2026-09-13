package com.example.chatroom.ui.common

import android.content.Context
import android.graphics.Paint
import android.util.AttributeSet
import android.view.Gravity
import android.view.View
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.example.chatroom.R

/**
 * 自定义 Session Tab 栏。
 *
 * 单个 tab 的结构（从左到右）：
 *
 * ```
 * [ⓘ]  名字  [×]
 *  ↑          ↑
 *  点它展开/收起重连面板   点它关闭该会话（首页 tab 没有 ⓘ 和 ×）
 * ```
 *
 * tab 本体点击 = 切到该会话；ⓘ / × 各自有独立点击，不会冒泡到 tab 本体。
 * 名字是会话创建时间；`strikeThrough = true`（未连接 / 链路失败）时整个字串加删除线。
 */
class SessionTabBar @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    data class Tab(
        val id: String,
        val name: String,
        val onClick: () -> Unit,
        val onClose: () -> Unit,
        /** 点名字左边的 ⓘ：展开 / 收起重连面板。null = 不显示 ⓘ（首页） */
        val onInfo: (() -> Unit)? = null,
        /** true = 名字加删除线（未连接 / 链路失败） */
        val strikeThrough: Boolean = false
    )

    private val scrollView = HorizontalScrollView(context).apply {
        layoutParams = LayoutParams(LayoutParams.MATCH_PARENT, dp(48))
        isHorizontalScrollBarEnabled = false
    }

    val tabsContainer = LinearLayout(context).apply {
        layoutParams = LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.MATCH_PARENT)
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(8), 0, dp(8), 0)
    }

    private val tabs = mutableListOf<Tab>()
    private val tabViews = mutableMapOf<String, View>()
    private val nameViews = mutableMapOf<String, TextView>()
    private val infoViews = mutableMapOf<String, TextView>()
    var selectedId: String = "home"
        private set

    var onTabSelected: ((String) -> Unit)? = null

    init {
        orientation = VERTICAL
        setBackgroundColor(ContextCompat.getColor(context, R.color.tab_bar_bg))
        scrollView.addView(tabsContainer)
        addView(scrollView)

        // 默认首页 tab，不可关闭、没有 ⓘ
        addTab("home", "首页", {}, {})
    }

    fun addTab(
        id: String,
        name: String,
        onClick: () -> Unit,
        onClose: () -> Unit,
        onInfo: (() -> Unit)? = null,
        strikeThrough: Boolean = false
    ) {
        val index = tabs.indexOfFirst { it.id == id }
        if (index >= 0) {
            // 更新已有 tab 的回调和数据
            tabs[index] = Tab(id, name, onClick, onClose, onInfo, strikeThrough)
            tabViews[id]?.setOnClickListener { onClick() }
            applyNameStyle(id)
            infoViews[id]?.let { info ->
                if (onInfo == null) {
                    info.visibility = View.GONE
                } else {
                    info.visibility = View.VISIBLE
                    info.setOnClickListener { onInfo.invoke() }
                }
            }
            selectTab(id)
            return
        }

        val tabView = makeTabView(id, name, id == "home", onClick, onClose, onInfo, strikeThrough)
        tabs.add(Tab(id, name, onClick, onClose, onInfo, strikeThrough))
        tabViews[id] = tabView
        tabsContainer.addView(tabView)
        selectTab(id)
    }

    fun removeTab(id: String) {
        if (id == "home") return
        val index = tabs.indexOfFirst { it.id == id }
        if (index < 0) return

        tabs.removeAt(index)
        tabViews.remove(id)
        nameViews.remove(id)
        infoViews.remove(id)
        tabsContainer.removeViewAt(index)

        val newIndex = (index - 1).coerceAtLeast(0)
        if (tabs.isNotEmpty()) {
            selectTab(tabs[newIndex].id)
        }
    }

    fun selectTab(id: String) {
        selectedId = id
        updateTabStyles()
        onTabSelected?.invoke(id)
    }

    /**
     * 更新已有 tab 的文案和删除线状态（连接状态变化时用）。
     * @param strikeThrough true = 未连接 / 链路失败，整个字串加删除线
     */
    fun updateTabName(id: String, name: String, strikeThrough: Boolean = false) {
        val index = tabs.indexOfFirst { it.id == id }
        if (index < 0) return
        val old = tabs[index]
        if (old.name == name && old.strikeThrough == strikeThrough) return
        tabs[index] = old.copy(name = name, strikeThrough = strikeThrough)
        applyNameStyle(id)
    }

    /** 把 Tab 里的 name / strikeThrough 落到对应的名字 TextView 上 */
    private fun applyNameStyle(id: String) {
        val tab = tabs.firstOrNull { it.id == id } ?: return
        val nameTv = nameViews[id] ?: return
        nameTv.text = tab.name
        nameTv.paintFlags = if (tab.strikeThrough) {
            nameTv.paintFlags or Paint.STRIKE_THRU_TEXT_FLAG
        } else {
            nameTv.paintFlags and Paint.STRIKE_THRU_TEXT_FLAG.inv()
        }
    }

    private fun makeTabView(
        id: String,
        name: String,
        isHome: Boolean,
        onClick: () -> Unit,
        onClose: () -> Unit,
        onInfo: (() -> Unit)?,
        strikeThrough: Boolean
    ): View {
        val root = LinearLayout(context).apply {
            layoutParams = LayoutParams(LayoutParams.WRAP_CONTENT, dp(36)).apply {
                marginStart = dp(4)
                marginEnd = dp(4)
            }
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            isFocusable = false
            isClickable = true
            setBackgroundResource(R.drawable.bg_tab)
            // tab 名是 14 字符的时间戳（YYMM-DDhh-mmss），比原来的 "💬 1" 长很多，
            // 这里放宽 padding / 最小宽度，保证加上 ⓘ 和 × 之后也不挤
            setPadding(dp(14), 0, dp(14), 0)
            minimumWidth = dp(128)
            setOnClickListener { onClick() }
        }

        // 名字左边的 ⓘ：展开 / 收起重连面板（首页不显示）
        if (!isHome && onInfo != null) {
            val infoTv = TextView(context).apply {
                text = "ⓘ"
                textSize = 15f
                setTextColor(ContextCompat.getColor(context, R.color.tab_text_selected))
                setPadding(0, dp(8), dp(8), dp(8))
                isFocusable = false
                isClickable = true
                setOnClickListener { onInfo.invoke() }
            }
            infoViews[id] = infoTv
            root.addView(infoTv)
        }

        val nameTv = TextView(context).apply {
            text = name
            textSize = 14f
            setTextColor(ContextCompat.getColor(context, R.color.tab_text_selected))
            if (strikeThrough) {
                paintFlags = paintFlags or Paint.STRIKE_THRU_TEXT_FLAG
            }
        }
        nameViews[id] = nameTv
        root.addView(nameTv)

        if (!isHome) {
            val closeTv = TextView(context).apply {
                text = "×"
                textSize = 18f
                setTextColor(ContextCompat.getColor(context, R.color.tab_text_selected))
                setPadding(dp(8), 0, 0, 0)
                isFocusable = false
                isClickable = true
                setOnClickListener { onClose() }
            }
            root.addView(closeTv)
        }

        return root
    }

    private fun updateTabStyles() {
        for (i in 0 until tabsContainer.childCount) {
            val tabLayout = tabsContainer.getChildAt(i) as? LinearLayout ?: continue
            val tab = tabs.getOrNull(i) ?: continue
            val isSelected = tab.id == selectedId

            tabLayout.setBackgroundResource(if (isSelected) R.drawable.bg_tab_selected else R.drawable.bg_tab)

            val textColorValue = ContextCompat.getColor(
                context,
                if (isSelected) R.color.tab_text_selected else R.color.tab_text_unselected
            )
            for (j in 0 until tabLayout.childCount) {
                (tabLayout.getChildAt(j) as? TextView)?.setTextColor(textColorValue)
            }
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
