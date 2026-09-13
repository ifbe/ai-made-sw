package com.example.chatroom

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.LinearLayout
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.widget.ViewPager2
import com.example.chatroom.core.SessionManager
import com.example.chatroom.core.SessionStore
import com.example.chatroom.service.TcpForegroundService
import com.example.chatroom.ui.chat.ChatFragment
import com.example.chatroom.ui.common.SessionPagerAdapter
import com.example.chatroom.ui.common.SessionTabBar
import com.example.chatroom.ui.home.HomeFragment
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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

        // 会话持久化：先把上次进程落盘的会话读回 SessionManager（一律未连接，等用户重连），
        // 再据此建 tab / ChatFragment。进程还活着（Activity 重建）时 restoreSession 会跳过已有会话。
        SessionStore.init(applicationContext)
        SessionManager.restoreFromStore()

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
            name = "首页",
            onClick = { onHomeTabClick() },
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
        homeFragment()?.onSessionCreated = { sessionId ->
            addSessionTab(sessionId, select = true)
        }

        // 恢复上次进程保存的会话 tab（参与者信息在，但未连接 → 点 tab 展开重连面板就能重连）
        SessionManager.getSessionOrder().forEach { sessionId ->
            addSessionTab(sessionId, select = false)
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
        tabBar.selectTab("home")

        // 后台保活：Doze 会直接掐掉网络，需要用户把 chatroom 加进电池优化白名单
        maybeRequestIgnoreBatteryOptimizations()
    }

    /**
     * 请求忽略电池优化（Doze 白名单）。
     *
     * 不加白名单时：设备静止 + 未充电进入 Doze → 网络被挂起 → TCP 静默断开，
     * 前台服务也救不回来（这是系统行为，不是代码问题）。
     * 每次安装只提示一次，用户拒绝后不再弹（OEM 的"自启动/后台运行"白名单仍需手动加，见 gotchas.md）。
     */
    @SuppressLint("BatteryLife")
    private fun maybeRequestIgnoreBatteryOptimizations() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
        if (pm.isIgnoringBatteryOptimizations(packageName)) return

        val prefs = getSharedPreferences("chatroom_prefs", MODE_PRIVATE)
        if (prefs.getBoolean(KEY_ASKED_BATTERY_OPT, false)) return
        prefs.edit().putBoolean(KEY_ASKED_BATTERY_OPT, true).apply()

        AlertDialog.Builder(this)
            .setTitle("保持后台连接")
            .setMessage(
                "按 Home / 锁屏后要长时间保持 TCP 连接，需要允许 chatroom 忽略电池优化。\n\n" +
                    "否则系统进入 Doze 后会挂起网络，连接会在后台静默断开。"
            )
            .setPositiveButton("去设置") { _, _ ->
                openBatteryOptimizationSettings()
            }
            .setNegativeButton("以后再说", null)
            .show()
    }

    /** 优先直接弹系统"忽略电池优化"确认框；厂商 ROM 不支持时退回应用详情页 */
    @SuppressLint("BatteryLife")
    private fun openBatteryOptimizationSettings() {
        try {
            startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (e: Exception) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:$packageName")
                    )
                )
            } catch (e2: Exception) {
                // 实在打不开就算了，不影响主流程
            }
        }
    }

    private fun onHomeTabClick() {
        if (viewPager.currentItem != 0) {
            viewPager.setCurrentItem(0, true)
        } else {
            tabBar.selectTab("home")
        }
    }

    /**
     * 新建一个会话 tab + 对应的 ChatFragment。
     * @param select 是否立即切到该会话（新建会话 = true，启动恢复 = false）
     */
    private fun addSessionTab(sessionId: String, select: Boolean): Int {
        val position = pagerAdapter.addSession(sessionId)
        sessionToPosition[sessionId] = position
        // 连接状态变化（重连 / 连上 / 断线）→ 刷新 tab 名字的删除线
        chatFragmentAt(position)?.onConnectionStateChanged = {
            runOnUiThread { applyTabName(sessionId) }
        }
        tabBar.addTab(
            id = sessionId,
            name = sessionTimeLabel(sessionId),
            onClick = { onSessionTabClick(sessionId) },
            onClose = { closeSession(sessionId) },
            onInfo = { onSessionInfoClick(sessionId) },
            strikeThrough = !SessionManager.isSessionUp(sessionId)
        )
        if (select) viewPager.setCurrentItem(position, true)
        return position
    }

    /** 点 tab 本体：切到该会话（简化：不再兼职展开重连面板） */
    private fun onSessionTabClick(sessionId: String) {
        val position = sessionToPosition[sessionId] ?: return
        viewPager.setCurrentItem(position, true)
    }

    /**
     * 点会话名左边的 ⓘ：展开 / 收起该会话的重连面板。
     * 如果点的不是当前会话，先切过去（fragment view 还没建好时由 ChatFragment 记下，建好再展开）。
     */
    private fun onSessionInfoClick(sessionId: String) {
        val position = sessionToPosition[sessionId] ?: return
        if (viewPager.currentItem != position) {
            viewPager.setCurrentItem(position, true)
        }
        chatFragmentAt(position)?.toggleReconnectPanel()
    }

    /**
     * 取 position 对应的 ChatFragment。
     * FragmentStateAdapter 内部 tag 是 "f<position>"；Activity 重建后 FragmentManager 恢复出来的
     * 实例优先（pagerAdapter.fragments 里是新建实例，可能还没 attach，拿不到 UI）。
     */
    private fun chatFragmentAt(position: Int): ChatFragment? {
        val restored = supportFragmentManager.findFragmentByTag("f$position")
        if (restored is ChatFragment) return restored
        return pagerAdapter.fragments.getOrNull(position) as? ChatFragment
    }

    /** 同 [chatFragmentAt]：进程重启后优先拿 FragmentManager 恢复出来的首页 fragment */
    private fun homeFragment(): HomeFragment? {
        val restored = supportFragmentManager.findFragmentByTag("f0")
        if (restored is HomeFragment) return restored
        return pagerAdapter.fragments.getOrNull(0) as? HomeFragment
    }

    /**
     * tab 名字 = 会话创建时间 `YYMM-DDhh-mmss`（年月-日时-分秒，例 `2609-1301-2716`），纯文字、无 emoji。
     *
     * 从 sessionId 里的 epoch 毫秒解析（`SessionManager.createSession()` 生成的就是
     * `session_<epochMillis>`）；解析不出来（理论上不会）就用 0，显示 7001-0100-0000，至少不会崩。
     */
    private fun sessionTimeLabel(sessionId: String): String {
        val millis = sessionId.removePrefix("session_").toLongOrNull() ?: 0L
        return SimpleDateFormat("yyMM-ddHH-mmss", Locale.US).format(Date(millis))
    }

    /**
     * 刷新某会话的 tab：名字不变（就是创建时间），
     * **未连接 / 链路失败**（程序重启恢复后还没重连、连接失败、连接掉了）→ 整个字串加删除线。
     */
    private fun applyTabName(sessionId: String) {
        tabBar.updateTabName(
            sessionId,
            sessionTimeLabel(sessionId),
            strikeThrough = !SessionManager.isSessionUp(sessionId)
        )
    }

    private fun refreshAllTabNames() {
        sessionToPosition.keys.toList().forEach { applyTabName(it) }
    }

    private fun closeSession(sessionId: String) {
        val position = sessionToPosition[sessionId] ?: return
        sessionToPosition.remove(sessionId)

        // 先让会话自己做收尾（断开 service 里的网络 participant，此时配置还在），
        // 再清 SessionManager（同时会从持久化里删掉，重启后不会再恢复）。
        // fragment 被 ViewPager2 回收 / 当前没绑定时 shutdownSession() 返回 false，
        // 退回 Intent 让 service 按 sessionId 自己清（否则那条连接会一直挂在 service 里）。
        val handled = chatFragmentAt(position)?.shutdownSession() ?: false
        if (!handled && TcpForegroundService.isRunning) {
            startService(
                Intent(this, TcpForegroundService::class.java)
                    .setAction(TcpForegroundService.ACTION_REMOVE_SESSION)
                    .putExtra(TcpForegroundService.EXTRA_SESSION_ID, sessionId)
            )
        }
        SessionManager.removeSession(sessionId)

        pagerAdapter.removeSession(position)
        tabBar.removeTab(sessionId)

        sessionToPosition.entries.forEach { (id, pos) ->
            if (pos > position) {
                sessionToPosition[id] = pos - 1
            }
        }
        // 序号取自 SessionManager 的创建顺序，删完要刷新其余 tab
        refreshAllTabNames()
    }

    companion object {
        private const val KEY_ASKED_BATTERY_OPT = "asked_battery_optimization"
    }
}
