package com.example.chatroom

import android.os.Bundle
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.widget.ViewPager2
import com.example.chatroom.core.SessionManager
import com.example.chatroom.ui.chat.ChatFragment
import com.example.chatroom.ui.common.SessionPagerAdapter
import com.example.chatroom.ui.common.SessionTabBar
import com.example.chatroom.ui.home.HomeFragment

class MainActivity : FragmentActivity() {

    private lateinit var pagerAdapter: SessionPagerAdapter
    private lateinit var viewPager: ViewPager2
    private lateinit var tabBar: SessionTabBar

    // sessionId -> ViewPager index
    private val sessionToPosition = mutableMapOf<String, Int>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        pagerAdapter = SessionPagerAdapter(this)

        viewPager = ViewPager2(this).apply {
            adapter = pagerAdapter
            offscreenPageLimit = 2
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0
            ).also { it.weight = 1f }
        }

        tabBar = SessionTabBar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        // 首页 tab
        tabBar.addTab(
            id = "home",
            name = "🏠 首页",
            onClick = {
                if (viewPager.currentItem != 0) {
                    viewPager.setCurrentItem(0, true)
                } else {
                    tabBar.selectTab("home")
                }
            },
            onClose = {}
        )

        // ViewPager 切换时同步 TabBar
        viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                val id = if (position == 0) "home" else sessionToPosition.entries.find { it.value == position }?.key
                id?.let { tabBar.selectTab(it) }
            }
        })

        // 主界面监听创建 session
        val homeFragment = pagerAdapter.fragments[0] as? HomeFragment
        homeFragment?.onSessionCreated = { sessionId ->
            val position = pagerAdapter.addSession(sessionId)
            sessionToPosition[sessionId] = position
            tabBar.addTab(
                id = sessionId,
                name = "💬 ${pagerAdapter.itemCount - 1}",
                onClick = { viewPager.setCurrentItem(position, true) },
                onClose = { closeSession(sessionId, position) }
            )
            viewPager.setCurrentItem(position, true)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(viewPager)
            addView(tabBar)
        }

        setContentView(root)
    }

    private fun closeSession(sessionId: String, position: Int) {
        sessionToPosition.remove(sessionId)
        SessionManager.removeSession(sessionId)
        pagerAdapter.removeSession(position)
        tabBar.removeTab(sessionId)

        sessionToPosition.entries.forEach { (id, pos) ->
            if (pos > position) {
                sessionToPosition[id] = pos - 1
            }
        }
    }
}
