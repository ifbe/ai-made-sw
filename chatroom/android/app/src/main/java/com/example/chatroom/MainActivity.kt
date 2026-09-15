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
import android.view.View
import androidx.activity.OnBackPressedCallback
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.widget.ViewPager2
import com.example.chatroom.core.SessionManager
import com.example.chatroom.core.SessionStore
import com.example.chatroom.service.TcpForegroundService
import com.example.chatroom.ui.chat.ChatFragment
import com.example.chatroom.ui.common.SessionPagerAdapter
import com.example.chatroom.ui.home.SessionMenuView

class MainActivity : FragmentActivity() {

    private lateinit var pagerAdapter: SessionPagerAdapter
    private lateinit var viewPager: ViewPager2

    /** 菜单页：整个 App 只有这一份（Activity 层），启动时整页显示，会话里点 ☰ 再整页叠上来 */
    private lateinit var menuOverlay: View
    private lateinit var menuSessionList: SessionMenuView

    /** 菜单页当前是否盖在上面（逻辑状态；退场动画期间就已经是 false 了） */
    private var menuShown = false

    /** 菜单页宽度（= 屏幕宽）：滑入起点 / 滑出终点。布局未完成时 View.width 是 0，所以自己算 */
    private var menuWidthPx = 0

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

        setContentView(R.layout.activity_main)

        viewPager = findViewById(R.id.viewPager)
        menuOverlay = findViewById(R.id.menuOverlay)
        menuSessionList = findViewById(R.id.sessionMenu)
        menuWidthPx = resources.displayMetrics.widthPixels

        pagerAdapter = SessionPagerAdapter(this)
        viewPager.apply {
            // 禁用左右滑：切页只能由代码触发（菜单页的「回到会话」/「恢复连接」）
            isUserInputEnabled = false
            adapter = pagerAdapter
            offscreenPageLimit = 2
        }

        // 菜单页监听：新建会话 / 回到会话 / 删除会话 / 恢复连接
        menuSessionList.onSessionCreated = { sessionId -> addSessionTab(sessionId, select = true) }
        menuSessionList.onEnterSession = { sessionId -> openSession(sessionId) }
        menuSessionList.onDeleteSession = { sessionId -> closeSession(sessionId) }
        menuSessionList.onReconnectSession = { sessionId -> reconnectSession(sessionId) }

        // 恢复上次进程保存的会话（参与者信息在，但未连接 → 菜单页卡片上点「恢复连接」即可重连）
        SessionManager.getSessionOrder().forEach { sessionId ->
            addSessionTab(sessionId, select = false)
        }

        // 返回键：菜单页盖着就先收菜单，否则交回系统
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (menuShown && pagerAdapter.itemCount > 0) {
                    hideMenu()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                    isEnabled = true
                }
            }
        })

        // 启动就整页显示菜单页（会话列表）；有会话时点卡片上的「回到会话」进会话。
        // 启动这一次不播滑入动画（它就是初始界面，从屏幕外滑进来反而怪）
        showMenu(animate = false)

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

    /** 新建一个会话页 + 对应的 ChatFragment。
     * @param select 是否立即切到该会话（新建会话 = true，启动恢复 = false）
     */
    private fun addSessionTab(sessionId: String, select: Boolean): Int {
        val position = pagerAdapter.addSession(sessionId)
        sessionToPosition[sessionId] = position
        chatFragmentFor(sessionId)?.let { fragment ->
            // 连接状态变化（重连 / 连上 / 断线）→ 刷新菜单页卡片上的按钮文案
            fragment.onConnectionStateChanged = {
                runOnUiThread { refreshMenuConnectionStates() }
            }
            // 聊天页左上角 ☰ → 把 Activity 那份菜单页整页叠上来
            fragment.onMenuRequested = { showMenu() }
        }
        if (select) {
            viewPager.setCurrentItem(position, true)
            // 新建会话后直接进会话，把菜单收起来
            hideMenu()
        }
        return position
    }

    /** 切到某个已存在的会话（菜单页卡片上的「回到会话」） */
    fun openSession(sessionId: String) {
        val position = sessionToPosition[sessionId] ?: addSessionTab(sessionId, select = false)
        viewPager.setCurrentItem(position, true)
        hideMenu()
    }

    /**
     * 菜单页卡片上的「恢复连接」：把会话标记成已连接 + 切过去，让 ChatFragment 真正重连。
     *
     * 连接逻辑（建 participant、绑定前台服务）只在 ChatFragment 里，菜单页自己连不了，
     * 所以这里是「切页 + 让 fragment 重连」：
     * - fragment view 已经建好 → `reconnectNow()` 立刻断开重连
     * - view 还没建好（ViewPager2 刚创建/回收过）→ 先记在 fragment 里，onViewCreated 补一次
     */
    fun reconnectSession(sessionId: String) {
        val position = sessionToPosition[sessionId] ?: addSessionTab(sessionId, select = false)
        SessionManager.setSessionConnected(sessionId, true)
        viewPager.setCurrentItem(position, true)
        chatFragmentFor(sessionId)?.reconnectNow()
        hideMenu()
        refreshMenuConnectionStates()
    }

    /**
     * 取某会话对应的 ChatFragment。
     *
     * `FragmentStateAdapter` 内部 tag 是 `"f" + itemId`，而 itemId 现在是**由会话 id 派生的稳定值**
     * （不是 position——见 [SessionPagerAdapter] 的注释），所以这里不能再用 `"f$position"` 找。
     * Activity 重建后 FragmentManager 恢复出来的实例优先（`pagerAdapter.fragments` 里是新建实例，
     * 可能还没 attach，拿不到 UI）。
     */
    private fun chatFragmentFor(sessionId: String): ChatFragment? {
        val restored = supportFragmentManager.findFragmentByTag(pagerAdapter.fragmentTagForSession(sessionId))
        if (restored is ChatFragment) return restored
        val position = sessionToPosition[sessionId] ?: return null
        return pagerAdapter.fragments.getOrNull(position) as? ChatFragment
    }

    /**
     * 整页显示菜单页（启动时 / 会话里点 ☰）。
     *
     * 菜单页只有这一份实例，所以不需要像以前那样「多份实例之间同步」：
     * 草稿卡片、展开状态都天然一致。
     *
     * @param animate true = **从屏幕外（左侧）向右滑进屏幕到目标位置**；启动那一次传 false
     */
    fun showMenu(animate: Boolean = true) {
        if (menuShown) return
        menuShown = true
        // 每次显示都重建：会话可能刚在别处被增删 / 改过
        menuSessionList.reload()
        menuOverlay.visibility = View.VISIBLE
        // 上一次的退场动画可能还没跑完，先停掉再从头滑
        menuOverlay.animate().cancel()
        if (!animate || menuWidthPx <= 0) {
            menuOverlay.translationX = 0f
            return
        }
        menuOverlay.translationX = -menuWidthPx.toFloat()
        menuOverlay.animate().translationX(0f).setDuration(MENU_ANIM_MS).start()
    }

    /**
     * 收起菜单页，回到会话（底下的会话内容一直没动过）。
     *
     * **一个会话都没有时不允许收起**：那样只会露出一片空白，而且没有 ☰ 可以再打开菜单，
     * 用户就卡死了。菜单页上的「+ 新建会话」是这种情况下唯一的出口。
     *
     * @param animate true = **向左滑出屏幕**（点「创建会话 / 回到会话 / 恢复连接」时都是这个效果）
     */
    fun hideMenu(animate: Boolean = true) {
        if (!menuShown) return
        if (pagerAdapter.itemCount == 0) return
        menuShown = false
        // 把表单里挂着的防抖落盘刷掉
        menuSessionList.flushPendingEdits()
        menuOverlay.animate().cancel()
        if (!animate) {
            menuOverlay.translationX = 0f
            menuOverlay.visibility = View.GONE
            return
        }
        menuOverlay.animate().translationX(-menuWidthPx.toFloat()).setDuration(MENU_ANIM_MS)
            .withEndAction {
                // 动画期间又 showMenu 了（menuShown 回到 true）→ 别把菜单页藏掉
                if (!menuShown) {
                    menuOverlay.visibility = View.GONE
                    menuOverlay.translationX = 0f
                }
            }.start()
    }

    /**
     * 连接状态变化 → 刷新菜单页卡片上的按钮文案（草稿「创建会话」/ 不正常「恢复连接」/ 正常「回到会话」）。
     * 只刷折叠行，不重建二级表单，避免输入焦点丢失。
     *
     * 聊天页那份菜单由 ChatFragment 自己刷（它同时也刷这份），这里主要负责首页那份。
     */
    private fun refreshMenuConnectionStates() {
        if (::menuSessionList.isInitialized) menuSessionList.refreshConnectionStates()
    }

    /** 供菜单页调用：删除一个已有会话（跟 tab 上点 × 完全同一条路径） */
    fun closeSession(sessionId: String) {
        val position = sessionToPosition[sessionId] ?: return
        // 先在 sessionToPosition 还完整时把 fragment 拿到（chatFragmentFor 的兜底要用它）
        val fragment = chatFragmentFor(sessionId)
        sessionToPosition.remove(sessionId)

        // 先让会话自己做收尾（断开 service 里的网络 participant，此时配置还在），
        // 再清 SessionManager（同时会从持久化里删掉，重启后不会再恢复）。
        // fragment 被 ViewPager2 回收 / 当前没绑定时 shutdownSession() 返回 false，
        // 退回 Intent 让 service 按 sessionId 自己清（否则那条连接会一直挂在 service 里）。
        val handled = fragment?.shutdownSession() ?: false
        if (!handled && TcpForegroundService.isRunning) {
            startService(
                Intent(this, TcpForegroundService::class.java)
                    .setAction(TcpForegroundService.ACTION_REMOVE_SESSION)
                    .putExtra(TcpForegroundService.EXTRA_SESSION_ID, sessionId)
            )
        }
        SessionManager.removeSession(sessionId)

        // 注意：pagerAdapter.removeSession() 之后 position 会整体前移
        pagerAdapter.removeSession(position)

        sessionToPosition.entries.forEach { (id, pos) ->
            if (pos > position) {
                sessionToPosition[id] = pos - 1
            }
        }
        // 菜单页此时正显示着（用户就是在菜单里点的 ×），会话没了要立刻重建
        if (::menuSessionList.isInitialized) menuSessionList.reload()
    }

    companion object {
        private const val KEY_ASKED_BATTERY_OPT = "asked_battery_optimization"

        /** 菜单页滑入 / 滑出的时长 */
        private const val MENU_ANIM_MS = 200L
    }
}
