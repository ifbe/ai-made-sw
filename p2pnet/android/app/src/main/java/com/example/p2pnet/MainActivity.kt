package com.example.p2pnet

import android.Manifest
import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.repository.P2pRepository
import com.example.p2pnet.service.P2pService
import com.example.p2pnet.ui.MainScreen
import com.example.p2pnet.ui.login.LoginViewModel
import com.example.p2pnet.ui.theme.P2pnetTheme

class MainActivity : ComponentActivity() {

    private var p2pService: P2pService? = null
    private var serviceBound = false
    /** 上次弹「后台被挂起」引导的时间（elapsedRealtime），避免反复打扰 */
    private var lastSuspendWarnAt = 0L
    private lateinit var viewModel: LoginViewModel
    private val localPrefs by lazy { LocalPrefs(this) }
    private val repository by lazy { P2pRepository(localPrefs) }

    /**
     * Android 13+ 通知权限。只影响状态栏那条「后台运行中」通知：
     * 不给，前台服务照常运行、连接不断，只是通知栏看不到。
     */
    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            Log.i(TAG, "POST_NOTIFICATIONS granted=$granted")
            // 通知弹窗结束后再问电池优化，避免两个系统弹窗叠在一起
            maybeRequestIgnoreBatteryOptimizations()
        }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val b = binder as P2pService.LocalBinder
            p2pService = b.getService()
            serviceBound = true
            repository.useClient(p2pService!!.wsClient)
            // session（打洞产出的 UDP socket）归服务所有，ViewModel 只观察
            viewModel.attachSessionManager(p2pService!!.sessionManager)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            serviceBound = false
            p2pService = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        viewModel = LoginViewModel(repository)

        viewModel.onStartService = { startP2pService() }
        viewModel.onStopService = { stopP2pService() }

        // Bind to existing service if running
        bindService(
            Intent(this, P2pService::class.java),
            serviceConnection,
            Context.BIND_AUTO_CREATE
        )

        setContent {
            P2pnetTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(viewModel = viewModel)
                }
            }
        }

        // 后台保活相关的一次性引导：先要通知权限，再问电池优化白名单
        requestNotificationPermissionIfNeeded()
    }

    fun startP2pService() {
        // 状态栏那条常驻通知是「后台运行」的标志，连之前再确认一次权限
        requestNotificationPermissionIfNeeded()

        val intent = Intent(this, P2pService::class.java)
        startForegroundService(intent)
        // Rebind to get the new service instance
        if (!serviceBound) {
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }
    }

    fun stopP2pService() {
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        stopService(Intent(this, P2pService::class.java))
        repository.useClient(null)
    }

    /**
     * 回到前台：把后台服务的存活 / 心跳情况写进 App 日志（日志面板里能看到）。
     * - 「最大空档」只有几秒 → 进程一直在后台活着，问题不是被冻结
     * - 「最大空档」几十秒 ~ 几分钟 → 进程被系统冻结（前台服务没生效 / ROM 省电策略）
     * - 「无心跳记录」→ 进程被系统杀掉过（内存状态全丢）
     * - activity 销毁次数 > 0 → 进后台时系统回收过 Activity（界面会重置，但进程可能还活着）
     */
    override fun onResume() {
        super.onResume()
        P2pService.refreshPowerState(this)
        val notify = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        ) "已授予" else "未授予（通知栏看不到，但服务仍按前台服务运行）"
        try {
            viewModel.appendSystemLog("[后台服务] ${P2pService.status}；通知权限=$notify")
            viewModel.appendSystemLog("[后台服务] ${P2pService.heartbeatReport()}")
            viewModel.appendSystemLog("[后台服务] ${P2pService.diagnosis()}")
            viewModel.appendSystemLog(
                "[后台服务] 设备=${Build.MANUFACTURER} ${Build.MODEL} Android${Build.VERSION.RELEASE}(API${Build.VERSION.SDK_INT})"
            )
        } catch (t: Throwable) {
            Log.w(TAG, "append service status failed", t)
        }
        // 上一次后台被挂起过 → 引导用户加白名单（Doze / 厂商省电），否则后台必断
        val gap = P2pService.maxGapSeconds()
        if (gap >= SUSPEND_WARN_SECONDS) {
            warnBackgroundSuspended(gap)
        }
    }

    override fun onDestroy() {
        // 记一笔：用来判断「回前台界面重置」是不是系统回收 Activity 导致（进程还在）
        P2pService.noteActivityDestroyed()
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        super.onDestroy()
    }

    // ── 后台运行 / 锁屏不断网 所需的权限引导 ──

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            maybeRequestIgnoreBatteryOptimizations()
            return
        }
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            maybeRequestIgnoreBatteryOptimizations()
            return
        }
        try {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } catch (t: Throwable) {
            Log.w(TAG, "request POST_NOTIFICATIONS failed", t)
            maybeRequestIgnoreBatteryOptimizations()
        }
    }

    /**
     * 请求忽略电池优化（Doze 白名单），每次安装只提示一次。
     *
     * 不加白名单：设备静止 + 未充电进入 Doze → 系统挂起网络 → 连接在后台静默断开，
     * 这是系统行为，前台服务 + 唤醒锁都救不回来。
     * 厂商 ROM（小米/华为/OPPO…）的「自启动 / 后台运行」白名单仍需用户手动加。
     */
    @SuppressLint("BatteryLife")
    private fun maybeRequestIgnoreBatteryOptimizations() {
        if (isFinishing || isDestroyed) return
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        if (localPrefs.batteryOptAsked) return
        localPrefs.batteryOptAsked = true

        try {
            AlertDialog.Builder(this)
                .setTitle(R.string.battery_opt_title)
                .setMessage(R.string.battery_opt_message)
                .setPositiveButton(R.string.battery_opt_positive) { _, _ -> openBatteryOptimizationSettings() }
                .setNegativeButton(R.string.battery_opt_negative, null)
                .show()
        } catch (t: Throwable) {
            Log.w(TAG, "show battery-opt dialog failed", t)
        }
    }

    /**
     * 检测到「上一次在后台被系统挂起了 N 秒」时的引导。
     *
     * 进程被挂起 = 前台服务也救不了：WS 的读线程、UDP session 的读循环、心跳全停，
     * 所以对端会看到「秒级 ping/pong 停了」。只有让系统别挂起才有用：
     * - 没加 Doze 白名单 → 引导「忽略电池优化」（Doze 会挂起网络 + 忽略唤醒锁）
     * - 已经加了还是被挂起 → 是厂商 ROM 的省电/自启动策略，给出手动设置路径
     */
    @SuppressLint("BatteryLife")
    private fun warnBackgroundSuspended(gapSec: Long) {
        if (isFinishing || isDestroyed) return
        val now = SystemClock.elapsedRealtime()
        if (now - lastSuspendWarnAt < SUSPEND_WARN_INTERVAL_MS) return
        lastSuspendWarnAt = now

        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
        val exempt = pm?.isIgnoringBatteryOptimizations(packageName) == true
        try {
            viewModel.appendSystemLog(
                "[后台服务] ⚠️ 后台被挂起 ${gapSec}s → " +
                    if (exempt) "Doze 白名单已加入，问题在厂商省电/自启动策略，请手动加白名单"
                    else "Doze 白名单未加入，Doze 会挂起网络并忽略唤醒锁"
            )
        } catch (_: Throwable) {
        }

        try {
            AlertDialog.Builder(this)
                .setTitle(R.string.suspend_title)
                .setMessage(
                    getString(
                        if (exempt) R.string.suspend_message_rom else R.string.suspend_message_doze,
                        gapSec
                    )
                )
                .setPositiveButton(R.string.battery_opt_positive) { _, _ ->
                    if (exempt) openAppDetailsSettings() else openBatteryOptimizationSettings()
                }
                .setNegativeButton(R.string.battery_opt_negative, null)
                .show()
        } catch (t: Throwable) {
            Log.w(TAG, "show suspend dialog failed", t)
        }
    }

    /** 厂商 ROM 的场景：直接跳到应用详情页（自启动/省电策略都在那一层附近） */
    private fun openAppDetailsSettings() {
        try {
            startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (t: Throwable) {
            Log.w(TAG, "open app details failed", t)
        }
    }

    /** 优先弹系统「忽略电池优化」确认框；厂商 ROM 不支持时退回应用详情页 */
    @SuppressLint("BatteryLife")
    private fun openBatteryOptimizationSettings() {
        try {
            startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (t: Throwable) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:$packageName")
                    )
                )
            } catch (t2: Throwable) {
                Log.w(TAG, "open battery optimization settings failed", t2)
            }
        }
    }

    companion object {
        private const val TAG = "MainActivity"

        /** 心跳空档超过这个秒数就认为「后台被挂起过」，需要引导加白名单 */
        private const val SUSPEND_WARN_SECONDS = 60L
        /** 同一问题的引导弹窗最短间隔 */
        private const val SUSPEND_WARN_INTERVAL_MS = 3 * 60 * 1000L
    }
}
