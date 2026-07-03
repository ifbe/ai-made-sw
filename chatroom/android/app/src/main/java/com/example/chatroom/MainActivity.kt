package com.example.chatroom

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.widget.ViewPager2
import com.example.chatroom.core.SessionManager
import com.example.chatroom.service.TcpForegroundService
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

        // TcpForegroundService 使用的通知 channel（API 26+ 必填）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                TcpForegroundService.CHANNEL_ID,
                "Chatroom TCP 后台",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "TCP 连接后台保持运行时的常驻通知"
                setShowBadge(false)
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }

        pagerAdapter = SessionPagerAdapter(this)

        viewPager = ViewPager2(this).apply {
            isUserInputEnabled = false    // 禁用左右滑切换会话，只通过 tabbar 切
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
            // 避开状态栏和导航栏（targetSdk=35 默认全面屏内容会延伸到屏幕边缘）
            // 系统会给 root 加 padding = status bar top + nav bar bottom
            fitsSystemWindows = true
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
