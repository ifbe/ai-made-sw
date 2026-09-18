package com.example.chess

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
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
import androidx.core.widget.doAfterTextChanged
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updateLayoutParams
import com.example.chess.game.share.core.MoveEventSink
import com.example.chess.game.guojixiangqi.IntlChessBoardView
import com.example.chess.game.weiqi.GoBoardView
import com.example.chess.game.wuziqi.GomokuBoardView
import com.example.chess.game.xiangqi.XiangqiBoardView
import com.example.chess.log.AppLog
import com.example.chess.net.LinkState
import com.example.chess.net.NetAddress
import com.example.chess.net.ws.WsSession
import com.example.chess.game.share.protocol.GameKind
import com.example.chess.game.share.protocol.MoveEvent

/**
 * 唯一的 Activity：一个全屏黑底的 FrameLayout 里叠了象棋 / 国际象棋 / 围棋 / 五子棋四个页面。
 *
 *  - 左上角：四个页面标签（当前页高亮）
 *  - 右上角：重置按钮（重置当前页）
 *  - 左下角：联机条 `[服/客][地址][开始/状态]`
 */
class MainActivity : AppCompatActivity() {

    companion object {
        /** adb logcat 里过滤用的 tag：`adb logcat -s ChessApp` */
        const val LOGCAT_TAG = "ChessApp"

        /**
         * Android 16（API 36）起访问局域网要用的运行时权限。
         * 老系统上不存在这个权限，所以只在 API 36+ 才申请。
         */
        private const val LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

    }

    /** 本地网络权限的申请结果：拿到了就接着开服务 / 连对端。 */
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

    /** API 36+ 且还没拿到权限时才需要申请（老系统上这个权限不存在，别卡住用户）。 */
    private fun needsLocalNetworkPermission(): Boolean =
        Build.VERSION.SDK_INT >= 36 &&
            ContextCompat.checkSelfPermission(this, LOCAL_NETWORK_PERMISSION) !=
            PackageManager.PERMISSION_GRANTED

    private enum class Page { CHESS, INTL_CHESS, GO, GOMOKU }

    private enum class NetMode { SERVER, CLIENT }

    private lateinit var chessPage: XiangqiBoardView
    private lateinit var intlChessPage: IntlChessBoardView
    private lateinit var goPage: GoBoardView
    private lateinit var gomokuPage: GomokuBoardView

    private lateinit var tabBar: LinearLayout
    private lateinit var tabChess: TextView
    private lateinit var tabIntlChess: TextView
    private lateinit var tabGo: TextView
    private lateinit var tabGomoku: TextView
    private lateinit var resetButton: TextView

    private lateinit var netBar: LinearLayout
    private lateinit var netMode: TextView
    private lateinit var netAddress: EditText
    private lateinit var netAction: TextView

    private lateinit var logBox: LinearLayout
    private lateinit var logScroll: ScrollView
    private lateinit var logText: TextView
    private lateinit var logToggle: TextView

    /** 日志框的监听器：网络线程会直接回调，所以里面切主线程。 */
    private val logListener: (List<String>) -> Unit = { lines ->
        runOnUiThread { renderLogs(lines) }
    }

    /** 同一份日志也写进 logcat（tag = ChessApp），方便 adb 抓。 */
    private val logcatSink: (String) -> Unit = { message -> Log.i(LOGCAT_TAG, message) }

    private var page = Page.CHESS

    // ------------------------------------------------------------------ 联机状态

    private var netModeValue = NetMode.SERVER
    private var session: WsSession? = null
    private var linkState = LinkState.IDLE
    private var statusDetail = ""

    /**
     * 本次 App 启动里，**各自模式**下用户输入过的地址（含端口）。空串 = 这个模式还没输入过。
     * 两个模式各记各的：服模式改过端口不会影响客模式，反之亦然。
     */
    private var serverAddress = ""
    private var clientAddress = ""

    /** 是不是我们自己 setText（用来区分「用户输入」和「程序回填」）。 */
    private var settingAddress = false

    /** 当前模式记住的地址。 */
    private var currentAddress: String
        get() = if (netModeValue == NetMode.SERVER) serverAddress else clientAddress
        set(value) {
            if (netModeValue == NetMode.SERVER) serverAddress = value else clientAddress = value
        }

    /** 四个页面本地事件的统一出口：转发给当前连接（没连就等于丢掉）。 */
    private val sink = MoveEventSink { events -> session?.send(events) }

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

        netBar = findViewById(R.id.netBar)
        netMode = findViewById(R.id.netMode)
        netAddress = findViewById(R.id.netAddress)
        netAction = findViewById(R.id.netAction)

        logBox = findViewById(R.id.logBox)
        logScroll = findViewById(R.id.logScroll)
        logText = findViewById(R.id.logText)
        logToggle = findViewById(R.id.logToggle)

        // 四个页面的本地事件都交给同一个出口（连接起来之后就是它在发）
        chessPage.eventSink = sink
        intlChessPage.eventSink = sink
        goPage.eventSink = sink
        gomokuPage.eventSink = sink

        WindowInsetsControllerCompat(window, tabChess).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }

        // 左上角的标签栏、右上角的重置按钮、左下角的联机条都避开系统栏 / 刘海。
        attachCornerInsets(tabBar, atStart = true)
        attachCornerInsets(resetButton, atStart = false)
        attachBottomInsets(netBar, atStart = true)
        attachBottomInsets(logBox, atStart = false)

        // 右下角日志框：默认折叠，点按钮展开 / 收起
        logToggle.setOnClickListener { toggleLog() }
        AppLog.addSink(logcatSink)
        AppLog.addListener(logListener)
        renderLogs(AppLog.snapshot())

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

        netMode.setOnClickListener {
            if (session != null) return@setOnClickListener // 连着呢，先关了再切
            netModeValue = if (netModeValue == NetMode.SERVER) NetMode.CLIENT else NetMode.SERVER
            AppLog.log(if (netModeValue == NetMode.SERVER) "切换为服务端模式" else "切换为客户端模式")
            applyNetMode()
        }
        netAction.setOnClickListener { toggleSession() }

        // 用户自己改过就记下来（本次启动内一直保留），程序回填不算
        netAddress.doAfterTextChanged { text ->
            if (!settingAddress) currentAddress = text?.toString().orEmpty()
        }

        AppLog.log("应用启动，本机地址 ${NetAddress.localIpv4() ?: "（没有局域网 IP）"}")

        show(page)
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

    // ------------------------------------------------------------------ 页面

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

    // ------------------------------------------------------------------ 联机条

    /**
     * 两种模式共用同一个地址框，规则也一样：
     *  - **本次启动里用户输入过** → 就保持他输入的那个（切来切去都不丢）；
     *  - **没输入过** → 填默认值「本机局域网 IP : 端口」。
     *
     * 服务模式实际监听的是 `0.0.0.0:端口`，框里的 IP 是给对端填的；
     * 客户端模式则按框里的地址连过去。
     */
    private fun applyNetMode() {
        netAddress.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        netAddress.isCursorVisible = true
        netMode.text = getString(
            if (netModeValue == NetMode.SERVER) R.string.net_mode_server else R.string.net_mode_client,
        )
        netAddress.hint = if (netModeValue == NetMode.SERVER) {
            getString(R.string.net_hint)
        } else {
            getString(R.string.net_hint_client)
        }

        setAddressText(currentAddress.ifEmpty { defaultAddress() })
        refreshNetAction()
    }

    /** 默认地址：本机 192 网段 IP + 默认端口。 */
    private fun defaultAddress(): String {
        val ip = NetAddress.localIpv4()
        AppLog.log("本机局域网地址：${ip ?: "（没有，可能在用流量 / 没连 Wi-Fi）"}")
        return "${ip ?: "0.0.0.0"}:${NetAddress.DEFAULT_PORT}"
    }

    /** 程序回填地址（不当作「用户输入」）。 */
    private fun setAddressText(text: String) {
        settingAddress = true
        netAddress.setText(text)
        netAddress.setSelection(text.length)
        settingAddress = false
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
            val port = NetAddress.portOf(netAddress.text.toString())
            AppLog.log("开始服务：端口 $port，对端请连 ${netAddress.text}")
            linkState = LinkState.STARTING
            statusDetail = getString(R.string.net_starting)
            refreshNetAction()
            created.startServer(port)
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
        val text = when {
            session == null -> getString(
                if (netModeValue == NetMode.SERVER) R.string.net_start_server else R.string.net_start_client,
            )

            statusDetail.isNotEmpty() -> statusDetail
            linkState == LinkState.STARTING -> getString(R.string.net_starting)
            linkState == LinkState.ONLINE -> getString(R.string.net_online)
            else -> getString(R.string.net_failed)
        }
        netAction.text = text
    }

    /** 对端事件按棋种分发给对应页面。 */
    private fun routeRemote(event: MoveEvent) {
        when (event.game) {
            GameKind.XIANGQI -> chessPage.submitRemote(event)
            GameKind.INTL_CHESS -> intlChessPage.submitRemote(event)
            GameKind.WEIQI -> goPage.submitRemote(event)
            GameKind.WUZIQI -> gomokuPage.submitRemote(event)
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

    /** 联机期间保持屏幕常亮（App 一进后台被冻结，socket 就没人处理了）。 */
    private fun keepScreenOn(on: Boolean) {
        if (on) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    // ------------------------------------------------------------------ 日志框

    private fun toggleLog() {
        val expand = logScroll.visibility != View.VISIBLE
        logScroll.visibility = if (expand) View.VISIBLE else View.GONE
        logToggle.text = getString(if (expand) R.string.log_hide else R.string.log_button)
        if (expand) {
            renderLogs(AppLog.snapshot())
            scrollLogToBottom()
        }
    }

    private fun renderLogs(lines: List<String>) {
        logText.text = lines.joinToString("\n")
        scrollLogToBottom()
    }

    private fun scrollLogToBottom() {
        if (logScroll.visibility != View.VISIBLE) return
        logScroll.post { logScroll.fullScroll(View.FOCUS_DOWN) }
    }
}
