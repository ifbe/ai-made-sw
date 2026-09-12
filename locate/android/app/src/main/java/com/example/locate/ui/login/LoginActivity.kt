package com.example.locate.ui.login

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.example.locate.data.local.SecurePrefs
import com.example.locate.ui.map.MapActivity
import com.example.locate.util.AppLog
import com.example.locate.util.Constants
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** 启动页最短展示时间 */
private const val MIN_SPLASH_MS = 600L

/**
 * 启动页。
 *
 * 只负责启动准备：预热加密存储、申请运行时权限，并保证一个最短展示时间，
 * 满足条件后进入地图页。登录本身（含用已保存凭证自动登录）由地图页自己决定，
 * 所以服务器不通或准备失败都不会卡在这一页。
 */
class LoginActivity : ComponentActivity() {

    private var prepDone = false
    private var permissionResolved = false
    private var minTimeElapsed = false
    private var navigated = false

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val granted = permissions[Manifest.permission.ACCESS_FINE_LOCATION] == true
        if (granted) {
            AppLog.i("已获得定位权限")
        } else {
            AppLog.w("定位权限被拒绝，可稍后在系统设置中开启")
        }
        markPermissionsRequested()
        permissionResolved = true
        goToMapIfReady()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme { SplashScreen() }
        }

        // 预热加密存储：首次创建要过 Android Keystore，放在启动页做掉，
        // 地图页拿 SecurePrefs 时就不用在主线程上等
        lifecycleScope.launch {
            val warmUp = withContext(Dispatchers.IO) {
                runCatching {
                    val prefs = SecurePrefs(applicationContext)
                    prefs.serverUrl
                    prefs.username
                }
            }
            warmUp.onFailure { AppLog.w("本地凭证读取失败：${it.message}") }
            prepDone = true
            AppLog.i("启动准备完成")
            goToMapIfReady()
        }

        requestPermissionsIfNeeded()

        Handler(Looper.getMainLooper()).postDelayed({
            minTimeElapsed = true
            goToMapIfReady()
        }, MIN_SPLASH_MS)
    }

    private fun requestPermissionsIfNeeded() {
        val hasLocation = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED

        if (hasLocation) {
            permissionResolved = true
            return
        }
        permissionLauncher.launch(requiredPermissions())
    }

    private fun requiredPermissions(): Array<String> {
        val permissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        return permissions.toTypedArray()
    }

    /** 记下"已经问过权限"，地图页就不会立刻二次弹窗 */
    private fun markPermissionsRequested() {
        getSharedPreferences(Constants.UI_PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putBoolean(Constants.KEY_PERMISSIONS_REQUESTED, true)
            .apply()
    }

    private fun goToMapIfReady() {
        if (navigated || !prepDone || !permissionResolved || !minTimeElapsed) return
        navigated = true
        startActivity(Intent(this, MapActivity::class.java))
        finish()
    }
}

@Composable
private fun SplashScreen() {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "旅迹定位",
            style = MaterialTheme.typography.headlineLarge
        )
        Spacer(modifier = Modifier.height(24.dp))
        CircularProgressIndicator(
            modifier = Modifier.size(28.dp),
            strokeWidth = 3.dp
        )
    }
}
