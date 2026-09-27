package com.example.sport

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.text.TextUtils
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updateLayoutParams
import com.example.sport.log.AppLog
import com.example.sport.net.LinkState
import com.example.sport.net.NetAddress
import com.example.sport.net.ws.WsSession
import com.example.sport.sport.basketball.BasketballView
import com.example.sport.sport.football.FootballView
import com.example.sport.sport.share.court.CourtView
import com.example.sport.sport.share.protocol.SportEvent
import com.example.sport.sport.share.protocol.SportEventSink
import com.example.sport.sport.share.protocol.SportKind
import com.example.sport.sport.share.protocol.StateChanged

/**
 * 唯一的 Activity：一个全屏黑底的 FrameLayout 里叠了足球 / 篮球 / 排球 / 乒乓球四个页面。
 *
 *  - 左上角：四个页面标签（当前页高亮）
 *  - 右上角：「重新摆位」把当前页的球员和球摆回开球站位
 *  - 左下角：联机条 `[服/客][地址][开始/状态]`，一台开服务、另一台填地址连过去
 *  - 右下角：可折叠的 app 内**特殊日志**（启动 / 切页 / 重置 / 拖起放下 / 收发），
 *    同一份日志也写到 logcat（tag = `SportApp`）
 *
 * 现在只有足球和篮球是真的，排球 / 乒乓球是占位页。
 */
class MainActivity : AppCompatActivity() {

    companion object {
        /** adb logcat 里过滤用的 tag：`adb logcat -s SportApp` */
        const val LOGCAT_TAG = "SportApp"

        /**
         * Android 16（API 36）起访问局域网要用的运行时权限。
         * 老系统上不存在这个权限，所以只在 API 36+ 才申请。
         */
        private const val LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    }

    private enum class Page(val label: String) {
        FOOTBALL("足球"),
        BASKETBALL("篮球"),
        VOLLEYBALL("排球"),
        PINGPONG("乒乓球"),
    }

    private enum class NetMode { SERVER, CLIENT }

    private lateinit var footballPage: FootballView
    private lateinit var basketballPage: BasketballView
    private lateinit var volleyballPage: View
    private lateinit var pingpongPage: View

    private lateinit var tabBar: LinearLayout
    private lateinit var tabFootball: TextView
    private lateinit var tabBasketball: TextView
    private lateinit var tabVolleyball: TextView
    private lateinit var tabPingpong: TextView
    private lateinit var resetButton: TextView

    private lateinit var netBar: LinearLayout
    private lateinit var netMode: TextView
    private lateinit var netAddress: EditText
    private lateinit var netAction: TextView

    private lateinit var logBox: LinearLayout
    private lateinit var logScroll: ScrollView
    private lateinit var logText: TextView
    private lateinit var logToggle: TextView
    private lateinit var logClear: TextView

    private var page = Page.FOOTBALL

    // ------------------------------------------------------------------ 联机状态

    private var netModeValue = NetMode.SERVER
    private var session: WsSession? = null
    private var linkState = LinkState.IDLE
    private var statusDetail = ""

    /**
     * 本次启动**手工输入过**的地址，按模式分开记：
     *  - `savedClientAddress`：客模式填过的对端地址
     *  - `savedServerAddress`：服模式改过的「本机 IP:端口」
     *
     * 空串 = 本次启动还没输入过，那就填默认值（服模式默认本机局域网 IP + 上次的端口）。
     */
    private var savedClientAddress = ""
    private var savedServerAddress = ""

    /** 每种球最后一包全量状态：切页 / 重连时用它对齐，不会丢对端的改动。 */
    private val lastState = HashMap<SportKind, StateChanged>()

    /** 服务端上次用的端口（文本框里可以改，IP 每次自动填当前本机 IP）。 */
    private var serverPort = NetAddress.DEFAULT_PORT

    /** 四个页面本地事件的统一出口：转发给当前连接（没连就等于丢掉）。 */
    private val sink = SportEventSink { events -> session?.send(events) }

    // ------------------------------------------------------------------ 日志

    /** 日志框的监听器：网络线程会直接回调，所以这里切主线程。 */
    private val logListener: (List<String>) -> Unit = { lines ->
        runOnUiThread { renderLogs(lines) }
    }

    /** 同一份日志也写进 logcat（tag = SportApp），方便 adb 抓。 */
    private val logcatSink: (String) -> Unit = { message -> Log.i(LOGCAT_TAG, message) }

    /** 「本地网络」权限的申请结果：拿到了就接着开服务 / 连对端。 */
    private val localNetworkPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                AppLog.log("已获得「本地网络」权限")
                startSessionNow()
            } else {
                AppLog.log("「本地网络」权限被拒绝：Android 16+ 没有它连不上局域网，联机不可用")
                linkState = LinkState.FAILED
                statusDetail = "缺少本地网络权限"
                session = null
                refreshNetAction()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 全屏（edge-to-edge）：页面底色是黑的，状态栏 / 导航栏也跟着黑。
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_main)

        footballPage = findViewById(R.id.footballPage)
        basketballPage = findViewById(R.id.basketballPage)
        volleyballPage = findViewById(R.id.volleyballPage)
        pingpongPage = findViewById(R.id.pingpongPage)

        tabBar = findViewById(R.id.tabBar)
        tabFootball = findViewById(R.id.tabFootball)
        tabBasketball = findViewById(R.id.tabBasketball)
        tabVolleyball = findViewById(R.id.tabVolleyball)
        tabPingpong = findViewById(R.id.tabPingpong)
        resetButton = findViewById(R.id.resetButton)

        netBar = findViewById(R.id.netBar)
        netMode = findViewById(R.id.netMode)
        netAddress = findViewById(R.id.netAddress)
        netAction = findViewById(R.id.netAction)

        logBox = findViewById(R.id.logBox)
        logScroll = findViewById(R.id.logScroll)
        logText = findViewById(R.id.logText)
        logToggle = findViewById(R.id.logToggle)
        logClear = findViewById(R.id.logClear)

        // 球场页面的本地事件都交给同一个出口（连接起来之后就是它在发）
        for (court in courtPages()) {
            court.eventSink = sink
            // View 只报「谁被拿起 / 落在哪儿」，往哪儿写由这里决定（写进 AppLog）
            court.dragListener = { message -> AppLog.log(message) }
        }

        WindowInsetsControllerCompat(window, tabFootball).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }

        // 标签栏 / 重置按钮让开状态栏和刘海；联机条和日志框让开底部导航栏。
        attachCornerInsets(tabBar, atStart = true)
        attachCornerInsets(resetButton, atStart = false)
        attachBottomInsets(netBar, atStart = true)
        attachBottomInsets(logBox, atStart = false)

        // 右下角日志框：默认折叠，点按钮展开 / 收起，展开时可以清空
        logToggle.setOnClickListener { toggleLog() }
        logClear.setOnClickListener { AppLog.clear() }
        AppLog.addSink(logcatSink)
        AppLog.addListener(logListener)
        renderLogs(AppLog.snapshot())

        tabFootball.setOnClickListener { show(Page.FOOTBALL) }
        tabBasketball.setOnClickListener { show(Page.BASKETBALL) }
        tabVolleyball.setOnClickListener { show(Page.VOLLEYBALL) }
        tabPingpong.setOnClickListener { show(Page.PINGPONG) }

        // 右上角：把当前这一页的球员和球摆回开球站位
        resetButton.setOnClickListener { resetCurrentPage("按钮") }

        // 左下角联机条：切换服 / 客、开始 / 停止
        netMode.setOnClickListener { switchNetMode() }
        netAction.setOnClickListener { toggleSession() }

        AppLog.log("应用启动，本机地址 ${NetAddress.localIpv4() ?: "（没有局域网 IP）"}")

        show(page, announce = false)
        applyNetMode()
    }

    override fun onDestroy() {
        keepScreenOn(false)
        AppLog.removeListener(logListener)
        AppLog.removeSink(logcatSink)
        session?.close()
        session = null
        super.onDestroy()
    }

    /** 所有能联机的球场页面。 */
    private fun courtPages(): List<CourtView> = listOf(footballPage, basketballPage)

    /** 当前页的球场（排球 / 乒乓球还没做，返回 null）。 */
    private fun currentCourt(): CourtView? = when (page) {
        Page.FOOTBALL -> footballPage
        Page.BASKETBALL -> basketballPage
        Page.VOLLEYBALL, Page.PINGPONG -> null
    }

    // ------------------------------------------------------------------ 页面

    private fun show(target: Page, announce: Boolean = true) {
        val changed = page != target
        page = target

        footballPage.visibility = visibility(target == Page.FOOTBALL)
        basketballPage.visibility = visibility(target == Page.BASKETBALL)
        volleyballPage.visibility = visibility(target == Page.VOLLEYBALL)
        pingpongPage.visibility = visibility(target == Page.PINGPONG)

        styleTab(tabFootball, target == Page.FOOTBALL)
        styleTab(tabBasketball, target == Page.BASKETBALL)
        styleTab(tabVolleyball, target == Page.VOLLEYBALL)
        styleTab(tabPingpong, target == Page.PINGPONG)

        // 切页时把对端发来的最新状态补上（那页在后台 / 还是 GONE 时收到的）。
        // post 一下：等这次 visibility 改动生效、isShown 变成 true 之后再应用，
        // 否则那些「隐藏就不重绘」的保护会把这帧吃掉。
        currentCourt()?.let { court ->
            val pending = lastState[court.sportKind()]
            if (pending != null) court.post { court.submitRemote(pending) }
        }

        if (!announce || !changed) return
        val label = courtLabel(target)
        AppLog.log("切到${label}页")
        refreshNetAddress()
    }

    private fun courtLabel(target: Page): String = when (target) {
        Page.FOOTBALL -> "足球（105×68 米，22 人 + 球）"
        Page.BASKETBALL -> "篮球（28×15 米，10 人 + 球）"
        Page.VOLLEYBALL -> "排球：还没实现"
        Page.PINGPONG -> "乒乓球：还没实现"
    }

    private fun visibility(shown: Boolean) = if (shown) View.VISIBLE else View.GONE

    /** 当前页的标签用黄色实心底 + 深色字，其它页是黑底描边 + 浅色字。 */
    private fun styleTab(tab: TextView, active: Boolean) {
        tab.setBackgroundResource(if (active) R.drawable.bg_tab_active else R.drawable.bg_tab)
        tab.setTextColor(if (active) 0xFF2A2110.toInt() else 0xFFF0F0F0.toInt())
    }

    /** 重置当前页。还没做的球类只写一行日志，不做无声无息的事。 */
    private fun resetCurrentPage(source: String) {
        val court = currentCourt()
        if (court == null) {
            AppLog.log("$source：${page.label}页还没做，没有可重置的内容")
            return
        }
        court.resetFormation()
        // 本地先改，再把「重置」这条事件发出去（跟象棋一样：重置也要同步给对端）
        session?.send(listOf(court.resetEvent()))
        AppLog.log("$source：${page.label}页已摆回开球站位")
    }

    // ------------------------------------------------------------------ 联机条

    /**
     * 两种模式都**可以手动编辑**：
     *  - 服务端：填「本机局域网 IP : 端口」，IP 和端口都能改，
     *    服务端按端口监听（监听地址始终是 0.0.0.0，文本框里的 IP 是给对端填的）；
     *  - 客户端：填对方的地址。
     */
    private fun applyNetMode() {
        netAddress.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        netAddress.isCursorVisible = true
        netAddress.hint = getString(R.string.net_hint)
        refreshNetAddress()
        refreshNetAction()
    }

    /** 点「服 / 客」：先把当前模式输入过的东西记下来，再切过去。 */
    private fun switchNetMode() {
        if (session != null) return // 连着呢，先关了再切
        rememberTypedAddress()
        netModeValue = if (netModeValue == NetMode.SERVER) NetMode.CLIENT else NetMode.SERVER
        AppLog.log(if (netModeValue == NetMode.SERVER) "切换为服务端模式" else "切换为客户端模式")
        refreshNetAddress()
        refreshNetAction()
    }

    /**
     * 把地址框里**用户亲手输入**的内容记到当前模式名下（没输入过就是空串 = 用默认值）。
     * 换模式、开始连接之前都调一次。
     */
    private fun rememberTypedAddress() {
        if (session != null) return
        val typed = netAddress.text.toString().trim()
        when (netModeValue) {
            NetMode.SERVER -> {
                if (typed.isEmpty()) return
                savedServerAddress = typed
                // 端口也顺手记下来：下次回到服模式默认就用这个端口
                serverPort = NetAddress.portOf(typed, serverPort)
            }

            NetMode.CLIENT -> savedClientAddress = typed
        }
    }

    /**
     * 按当前模式刷新地址框：
     *  - 本次启动在这个模式里**输入过** → 保持上次输入的；
     *  - 没输入过 → **两个模式都填「本机局域网 IP : 端口」**。
     *
     * 客模式也填本机地址，是为了少打字：连本机起的服务时地址已经是对的，
     * 连同一局域网里别的机器只要把 IP 那一段改掉就行（端口一般不用动）。
     */
    private fun refreshNetAddress() {
        if (session != null) return // 连着呢，别把用户正在看的地址冲掉
        val typed = when (netModeValue) {
            NetMode.SERVER -> savedServerAddress
            NetMode.CLIENT -> savedClientAddress
        }
        netAddress.setText(typed.ifEmpty { NetAddress.serverAddress(serverPort) })
    }

    private fun toggleSession() {
        val current = session
        if (current != null) {
            current.close()
            session = null
            linkState = LinkState.IDLE
            statusDetail = ""
            keepScreenOn(false)
            refreshNetAction()
            return
        }

        // Android 16+ 访问局域网必须先拿到「本地网络」权限，否则连接会被系统直接拦掉
        if (needsLocalNetworkPermission()) {
            AppLog.log("需要「本地网络」权限（Android 16+ 访问局域网必须授权），正在申请…")
            statusDetail = "申请本地网络权限…"
            refreshNetAction()
            localNetworkPermission.launch(LOCAL_NETWORK_PERMISSION)
            return
        }

        startSessionNow()
    }

    /** 真正开始服务 / 开始连接。 */
    private fun startSessionNow() {
        if (session != null) return

        val created = WsSession { state, detail -> onLinkState(state, detail) }
        created.listen { event -> runOnUiThread { routeRemote(event) } }
        session = created
        // 开着服务 / 连着对局的时候别黑屏，否则 App 被冻结、socket 就没人处理了
        keepScreenOn(true)

        if (netModeValue == NetMode.SERVER) {
            // 端口以文本框里的为准（IP 部分只是给对端看的，服务端绑的是 0.0.0.0）
            serverPort = NetAddress.portOf(netAddress.text.toString(), serverPort)
            AppLog.log("开始服务：端口 $serverPort，对端请连 ${netAddress.text}")
            linkState = LinkState.STARTING
            statusDetail = getString(R.string.net_starting)
            refreshNetAction()
            created.startServer(serverPort)
        } else {
            val uri = NetAddress.toWsUri(netAddress.text.toString())
            if (uri == null) {
                AppLog.log("地址不合法：${netAddress.text}")
                session = null
                linkState = LinkState.FAILED
                statusDetail = getString(R.string.net_bad_address)
                refreshNetAction()
                return
            }
            savedClientAddress = netAddress.text.toString().trim()
            linkState = LinkState.STARTING
            statusDetail = getString(R.string.net_connecting)
            refreshNetAction()
            created.startClient(uri)
        }
    }

    /** 网络线程回调 → 切到主线程改按钮文字。 */
    private fun onLinkState(state: LinkState, detail: String) {
        runOnUiThread {
            if (session == null) return@runOnUiThread
            linkState = state
            statusDetail = detail
            refreshNetAction()
        }
    }

    /** 按钮文字 = 当前状态 + 下一步动作。 */
    private fun refreshNetAction() {
        netAction.text = when {
            session == null -> getString(
                if (netModeValue == NetMode.SERVER) R.string.net_start_server else R.string.net_start_client,
            )

            statusDetail.isNotEmpty() -> statusDetail
            linkState == LinkState.STARTING -> getString(R.string.net_starting)
            linkState == LinkState.ONLINE -> getString(R.string.net_online)
            else -> getString(R.string.net_failed)
        }
    }

    /** 对端事件按球种分发给对应页面。 */
    private fun routeRemote(event: SportEvent) {
        if (event is StateChanged) lastState[event.sport] = event
        courtPages()
            .firstOrNull { it.sportKind() == event.sport }
            ?.submitRemote(event)
    }

    /**
     * API 36+ 且还没拿到「本地网络」权限时才需要申请
     * （老系统上这个权限不存在，申请会直接返回拒绝，会把用户卡住）。
     */
    private fun needsLocalNetworkPermission(): Boolean =
        Build.VERSION.SDK_INT >= 36 &&
            ContextCompat.checkSelfPermission(this, LOCAL_NETWORK_PERMISSION) !=
            PackageManager.PERMISSION_GRANTED

    /** 联机期间保持屏幕常亮（App 一进后台被冻结，socket 就没人处理了）。 */
    private fun keepScreenOn(on: Boolean) {
        if (on) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    // ------------------------------------------------------------------ 边距

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

    /** 底部这一排控件：让开底部导航栏 + 自己那一侧的刘海。 */
    private fun attachBottomInsets(view: View, atStart: Boolean) {
        val baseMargin = resources.getDimensionPixelSize(R.dimen.corner_button_margin)
        ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            v.updateLayoutParams<FrameLayout.LayoutParams> {
                bottomMargin = baseMargin + bars.bottom
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

    // ------------------------------------------------------------------ 日志框

    private fun toggleLog() {
        val expand = logScroll.visibility != View.VISIBLE
        logScroll.visibility = if (expand) View.VISIBLE else View.GONE
        logClear.visibility = if (expand) View.VISIBLE else View.GONE
        logToggle.text = getString(if (expand) R.string.log_hide else R.string.log_button)
        if (expand) {
            renderLogs(AppLog.snapshot())
            scrollLogToBottom()
        }
    }

    private fun renderLogs(lines: List<String>) {
        logText.text = if (lines.isEmpty()) "" else TextUtils.join("\n", lines)
        scrollLogToBottom()
    }

    private fun scrollLogToBottom() {
        if (logScroll.visibility != View.VISIBLE) return
        logScroll.post { logScroll.fullScroll(View.FOCUS_DOWN) }
    }
}
