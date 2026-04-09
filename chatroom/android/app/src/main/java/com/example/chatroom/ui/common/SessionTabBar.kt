package com.example.chatroom.ui.common

import android.content.Context
import android.util.AttributeSet
import android.view.Gravity
import android.view.View
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.example.chatroom.R

/** 自定义可关闭 Session Tab 栏 */
class SessionTabBar @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    data class Tab(
        val id: String,
        val name: String,
        val onClick: () -> Unit,
        val onClose: () -> Unit
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
    var selectedId: String = "home"
        private set

    var onTabSelected: ((String) -> Unit)? = null

    init {
        orientation = VERTICAL
        setBackgroundColor(ContextCompat.getColor(context, R.color.tab_bar_bg))
        scrollView.addView(tabsContainer)
        addView(scrollView)

        // 默认首页 tab，不可关闭
        addTab("home", "🏠 首页", {}, {})
    }

    fun addTab(id: String, name: String, onClick: () -> Unit, onClose: () -> Unit) {
        val index = tabs.indexOfFirst { it.id == id }
        if (index >= 0) {
            // 更新已有 tab 的回调和数据
            tabs[index] = Tab(id, name, onClick, onClose)
            // 更新已有 view 的 listener
            tabViews[id]?.setOnClickListener { onClick() }
            selectTab(id)
            return
        }

        val tabView = makeTabView(name, id == "home", onClick, onClose)
        tabs.add(Tab(id, name, onClick, onClose))
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

    private fun makeTabView(name: String, isHome: Boolean, onClick: () -> Unit, onClose: () -> Unit): View {
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
            setPadding(dp(8), 0, dp(8), 0)
            setOnClickListener { onClick() }
        }

        val nameTv = TextView(context).apply {
            text = name
            textSize = 14f
            setTextColor(ContextCompat.getColor(context, R.color.tab_text_selected))
        }
        root.addView(nameTv)

        if (!isHome) {
            val closeTv = TextView(context).apply {
                text = "×"
                textSize = 18f
                setTextColor(ContextCompat.getColor(context, R.color.tab_text_selected))
                setPadding(dp(8), 0, 0, 0)
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
